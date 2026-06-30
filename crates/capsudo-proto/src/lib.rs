//! Transport-agnostic wire protocol for capsudo.
//!
//! capsudo delegates a capability — "run this program, with these privileges" —
//! from a client to a daemon that already holds the privilege. The two speak the
//! protocol defined here over *some* transport: a local `AF_UNIX` socket today,
//! an Edera Protect IDM cross-zone channel tomorrow. Nothing in this crate knows
//! or cares which; it deals only in [`Message`] values and their byte framing.
//!
//! # Framing
//!
//! Every message is a fixed 5-byte header followed by a variable payload:
//!
//! ```text
//! +-----------+------------------+-----------------------+
//! | u8        | u32 little-endian| payload (`len` bytes) |
//! | field_type|       len        |                       |
//! +-----------+------------------+-----------------------+
//! ```
//!
//! The framing is explicitly little-endian and fixed-width so that it survives a
//! hop across a zone boundary unchanged — unlike the C implementation, which
//! writes raw native structs and therefore silently assumes both peers share an
//! ABI. A capsudo proxy bridging an `AF_UNIX` endpoint in one zone to an IDM
//! endpoint in another can forward these frames verbatim.
//!
//! # File descriptors
//!
//! Some messages ([`FieldType::Fd`]) logically carry open file descriptors (the
//! caller's stdio). Descriptors cannot live in the byte stream: on a local
//! transport they ride as `SCM_RIGHTS` ancillary data, and on a non-local
//! transport they are *simulated* via multiplexed data streams. So the framed
//! payload of an `Fd` message carries only a count — the descriptors themselves
//! are handled out-of-band by the transport layer.

use std::fmt;

/// Maximum payload length accepted when decoding, as a denial-of-service guard.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Type tag identifying the meaning of a [`Message`] payload.
///
/// The discriminants are stable wire values and must never be reused.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FieldType {
    /// One element of the target program's argument vector (UTF-8, NUL-free).
    Arg = 1,
    /// One `KEY=VALUE` environment entry to install for the target program.
    Env = 2,
    /// Process exit status of the target program (payload: `i32` little-endian).
    Exit = 3,
    /// Announces that descriptors accompany this message out-of-band.
    /// Payload: `u32` little-endian count of descriptors.
    Fd = 4,
    /// Selects interactive vs. non-interactive handling (payload: `u8`
    /// [`SessionType`]).
    SessionType = 5,
    /// A human-readable error string emitted by the daemon.
    Error = 6,
    /// An authentication secret supplied by the client (e.g. a password).
    Secret = 7,
    /// Authentication is required/failed; payload is the prompt to display.
    Unauthorized = 8,
    /// Terminal window dimensions for an interactive session. Payload: four
    /// `u16` little-endian fields — rows, cols, xpixels, ypixels — matching
    /// `struct winsize`. Sent at startup and again on each resize.
    Winsize = 9,
    /// Terminates the client's configuration phase; the daemon may now act.
    End = 255,
}

impl FieldType {
    /// Returns the wire byte for this field type.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for FieldType {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, ProtoError> {
        Ok(match value {
            1 => FieldType::Arg,
            2 => FieldType::Env,
            3 => FieldType::Exit,
            4 => FieldType::Fd,
            5 => FieldType::SessionType,
            6 => FieldType::Error,
            7 => FieldType::Secret,
            8 => FieldType::Unauthorized,
            9 => FieldType::Winsize,
            255 => FieldType::End,
            other => return Err(ProtoError::UnknownFieldType(other)),
        })
    }
}

impl fmt::Debug for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            FieldType::Arg => "Arg",
            FieldType::Env => "Env",
            FieldType::Exit => "Exit",
            FieldType::Fd => "Fd",
            FieldType::SessionType => "SessionType",
            FieldType::Error => "Error",
            FieldType::Secret => "Secret",
            FieldType::Unauthorized => "Unauthorized",
            FieldType::Winsize => "Winsize",
            FieldType::End => "End",
        };
        write!(f, "{name}")
    }
}

/// How the daemon should wire up the target program's standard streams.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum SessionType {
    /// Let the transport/endpoint decide based on whether a tty is attached.
    #[default]
    Auto = 1,
    /// Allocate a pseudo-terminal and run the program as a session leader.
    Interactive = 2,
    /// Wire stdio straight through with no pty.
    NonInteractive = 3,
}

impl SessionType {
    /// Returns the wire byte for this session type.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for SessionType {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, ProtoError> {
        Ok(match value {
            1 => SessionType::Auto,
            2 => SessionType::Interactive,
            3 => SessionType::NonInteractive,
            other => return Err(ProtoError::InvalidSessionType(other)),
        })
    }
}

/// The fixed-size message header that prefixes every payload on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// The kind of payload that follows.
    pub field_type: FieldType,
    /// Length of the payload in bytes.
    pub len: u32,
}

impl Header {
    /// Encoded size of a header in bytes.
    pub const SIZE: usize = 5;

    /// Serializes the header into its 5-byte wire form.
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.field_type.as_u8();
        buf[1..5].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    /// Parses a header from exactly [`Header::SIZE`] bytes.
    ///
    /// Enforces [`MAX_PAYLOAD`] so a hostile or corrupt peer cannot induce a
    /// huge allocation.
    pub fn decode(buf: &[u8; Self::SIZE]) -> Result<Header, ProtoError> {
        let field_type = FieldType::try_from(buf[0])?;
        let len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if len as usize > MAX_PAYLOAD {
            return Err(ProtoError::PayloadTooLarge(len));
        }
        Ok(Header { field_type, len })
    }
}

/// A single decoded protocol message: a type tag plus its raw payload bytes.
///
/// Construct outbound messages with the typed builders ([`Message::arg`],
/// [`Message::exit`], …) and read inbound payloads with the typed accessors
/// ([`Message::as_str`], [`Message::as_i32`], …).
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    field_type: FieldType,
    payload: Vec<u8>,
}

impl Message {
    /// Builds a message from a type tag and raw payload.
    pub fn new(field_type: FieldType, payload: Vec<u8>) -> Message {
        Message { field_type, payload }
    }

    /// The message's type tag.
    pub fn field_type(&self) -> FieldType {
        self.field_type
    }

    /// The message's raw payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the message, yielding its payload.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// The header that would prefix this message on the wire.
    pub fn header(&self) -> Header {
        Header {
            field_type: self.field_type,
            len: self.payload.len() as u32,
        }
    }

    /// Serializes the full message (header + payload) into a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Header::SIZE + self.payload.len());
        out.extend_from_slice(&self.header().encode());
        out.extend_from_slice(&self.payload);
        out
    }

    // ---- typed constructors -------------------------------------------------

    /// An [`FieldType::Arg`] carrying one argv element.
    pub fn arg(s: impl AsRef<str>) -> Message {
        Message::new(FieldType::Arg, s.as_ref().as_bytes().to_vec())
    }

    /// An [`FieldType::Env`] carrying one `KEY=VALUE` entry.
    pub fn env(s: impl AsRef<str>) -> Message {
        Message::new(FieldType::Env, s.as_ref().as_bytes().to_vec())
    }

    /// An [`FieldType::Exit`] carrying a process exit status.
    pub fn exit(code: i32) -> Message {
        Message::new(FieldType::Exit, code.to_le_bytes().to_vec())
    }

    /// An [`FieldType::Fd`] announcing `count` out-of-band descriptors.
    pub fn fds(count: u32) -> Message {
        Message::new(FieldType::Fd, count.to_le_bytes().to_vec())
    }

    /// An [`FieldType::SessionType`].
    pub fn session_type(ty: SessionType) -> Message {
        Message::new(FieldType::SessionType, vec![ty.as_u8()])
    }

    /// An [`FieldType::Error`] carrying a human-readable message.
    pub fn error(s: impl AsRef<str>) -> Message {
        Message::new(FieldType::Error, s.as_ref().as_bytes().to_vec())
    }

    /// An [`FieldType::Secret`] carrying an authentication secret.
    pub fn secret(s: impl AsRef<[u8]>) -> Message {
        Message::new(FieldType::Secret, s.as_ref().to_vec())
    }

    /// An [`FieldType::Unauthorized`] carrying a prompt for the client.
    pub fn unauthorized(prompt: impl AsRef<str>) -> Message {
        Message::new(FieldType::Unauthorized, prompt.as_ref().as_bytes().to_vec())
    }

    /// An [`FieldType::Winsize`] carrying `[rows, cols, xpixels, ypixels]`.
    pub fn winsize(dims: [u16; 4]) -> Message {
        let mut payload = Vec::with_capacity(8);
        for field in dims {
            payload.extend_from_slice(&field.to_le_bytes());
        }
        Message::new(FieldType::Winsize, payload)
    }

    /// An [`FieldType::End`] marking the end of the configuration phase.
    pub fn end() -> Message {
        Message::new(FieldType::End, Vec::new())
    }

    // ---- typed accessors ----------------------------------------------------

    /// Interprets the payload as UTF-8 text.
    pub fn as_str(&self) -> Result<&str, ProtoError> {
        std::str::from_utf8(&self.payload).map_err(|_| ProtoError::InvalidPayload {
            field_type: self.field_type,
            reason: "expected UTF-8 text",
        })
    }

    /// Interprets the payload as a little-endian `i32` (e.g. an exit code).
    pub fn as_i32(&self) -> Result<i32, ProtoError> {
        let bytes: [u8; 4] = self.payload.as_slice().try_into().map_err(|_| {
            ProtoError::InvalidPayload {
                field_type: self.field_type,
                reason: "expected 4-byte integer",
            }
        })?;
        Ok(i32::from_le_bytes(bytes))
    }

    /// Interprets the payload as a little-endian `u32` (e.g. an fd count).
    pub fn as_u32(&self) -> Result<u32, ProtoError> {
        let bytes: [u8; 4] = self.payload.as_slice().try_into().map_err(|_| {
            ProtoError::InvalidPayload {
                field_type: self.field_type,
                reason: "expected 4-byte integer",
            }
        })?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Interprets the payload as terminal dimensions `[rows, cols, xpixels,
    /// ypixels]`.
    pub fn as_winsize(&self) -> Result<[u16; 4], ProtoError> {
        if self.payload.len() != 8 {
            return Err(ProtoError::InvalidPayload {
                field_type: self.field_type,
                reason: "expected 8-byte window size",
            });
        }
        let mut dims = [0u16; 4];
        for (i, dim) in dims.iter_mut().enumerate() {
            *dim = u16::from_le_bytes([self.payload[i * 2], self.payload[i * 2 + 1]]);
        }
        Ok(dims)
    }

    /// Interprets the payload as a [`SessionType`].
    pub fn as_session_type(&self) -> Result<SessionType, ProtoError> {
        match self.payload.as_slice() {
            [byte] => SessionType::try_from(*byte),
            _ => Err(ProtoError::InvalidPayload {
                field_type: self.field_type,
                reason: "expected single session-type byte",
            }),
        }
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("field_type", &self.field_type)
            .field("len", &self.payload.len())
            .finish()
    }
}

/// Errors arising from protocol encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// A header named a field-type byte that is not defined.
    #[error("unknown field type byte: {0}")]
    UnknownFieldType(u8),

    /// A session-type payload held an undefined value.
    #[error("invalid session type byte: {0}")]
    InvalidSessionType(u8),

    /// A header declared a payload larger than [`MAX_PAYLOAD`].
    #[error("payload length {0} exceeds maximum")]
    PayloadTooLarge(u32),

    /// A typed accessor could not interpret the payload.
    #[error("invalid payload for {field_type:?}: {reason}")]
    InvalidPayload {
        /// The message type whose payload failed to parse.
        field_type: FieldType,
        /// Why interpretation failed.
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_type_roundtrips_through_u8() {
        for ft in [
            FieldType::Arg,
            FieldType::Env,
            FieldType::Exit,
            FieldType::Fd,
            FieldType::SessionType,
            FieldType::Error,
            FieldType::Secret,
            FieldType::Unauthorized,
            FieldType::Winsize,
            FieldType::End,
        ] {
            assert_eq!(FieldType::try_from(ft.as_u8()).unwrap(), ft);
        }
    }

    #[test]
    fn unknown_field_type_is_rejected() {
        assert!(matches!(
            FieldType::try_from(99),
            Err(ProtoError::UnknownFieldType(99))
        ));
    }

    #[test]
    fn header_encode_decode_roundtrip() {
        let hdr = Header {
            field_type: FieldType::Arg,
            len: 0x0001_0203,
        };
        let bytes = hdr.encode();
        // Explicit little-endian layout, independent of host byte order.
        assert_eq!(bytes, [1, 0x03, 0x02, 0x01, 0x00]);
        assert_eq!(Header::decode(&bytes).unwrap(), hdr);
    }

    #[test]
    fn header_rejects_oversize_payload() {
        let mut bytes = Header {
            field_type: FieldType::Arg,
            len: 0,
        }
        .encode();
        bytes[1..5].copy_from_slice(&((MAX_PAYLOAD as u32) + 1).to_le_bytes());
        assert!(matches!(
            Header::decode(&bytes),
            Err(ProtoError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn message_encode_prefixes_header() {
        let msg = Message::arg("ls");
        let encoded = msg.encode();
        assert_eq!(encoded[0], FieldType::Arg.as_u8());
        assert_eq!(&encoded[1..5], &2u32.to_le_bytes());
        assert_eq!(&encoded[5..], b"ls");
    }

    #[test]
    fn typed_accessors() {
        assert_eq!(Message::arg("hello").as_str().unwrap(), "hello");
        assert_eq!(Message::exit(-5).as_i32().unwrap(), -5);
        assert_eq!(Message::exit(42).as_i32().unwrap(), 42);
        assert_eq!(Message::fds(3).as_u32().unwrap(), 3);
        assert_eq!(
            Message::session_type(SessionType::Interactive)
                .as_session_type()
                .unwrap(),
            SessionType::Interactive
        );
    }

    #[test]
    fn winsize_roundtrip() {
        let msg = Message::winsize([24, 80, 640, 480]);
        assert_eq!(msg.field_type(), FieldType::Winsize);
        assert_eq!(msg.as_winsize().unwrap(), [24, 80, 640, 480]);
    }

    #[test]
    fn exit_code_is_little_endian() {
        assert_eq!(Message::exit(1).payload(), &[1, 0, 0, 0]);
    }

    #[test]
    fn as_i32_rejects_wrong_length() {
        assert!(Message::arg("xx").as_i32().is_err());
    }

    #[test]
    fn end_has_empty_payload() {
        assert!(Message::end().payload().is_empty());
        assert_eq!(Message::end().field_type(), FieldType::End);
    }
}
