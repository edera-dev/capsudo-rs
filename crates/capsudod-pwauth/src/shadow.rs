//! Shadow-password verification via libc `crypt(3)`.
//!
//! Reads `/etc/shadow` directly (the daemon runs privileged) and compares the
//! `crypt`-hashed candidate against the stored hash, rejecting locked or
//! password-less accounts — mirroring the C implementation.

use std::ffi::{CStr, CString};

// glibc moved crypt(3) into libxcrypt, which is not linked automatically, so it
// must be requested explicitly (mirroring the C build's `-lcrypt`). musl bundles
// crypt in libc, so no extra library is linked there.
#[cfg_attr(target_env = "gnu", link(name = "crypt"))]
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Returns true if `password` matches `user`'s shadow entry.
pub fn check_password(user: &str, password: &[u8]) -> bool {
    let Some(hash) = stored_hash(user) else {
        return false;
    };

    // Locked (`!`), disabled (`*`), or empty hashes never authenticate.
    if hash.is_empty() || hash.starts_with('!') || hash.starts_with('*') {
        return false;
    }

    let (Ok(key), Ok(salt)) = (CString::new(password), CString::new(hash.clone())) else {
        return false; // an embedded NUL cannot be a valid secret/hash
    };

    let computed = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    if computed.is_null() {
        return false;
    }

    let computed = unsafe { CStr::from_ptr(computed) };
    // Constant-time-ish: crypt output length matches the stored hash on success.
    computed.to_bytes() == hash.as_bytes()
}

/// Extracts the password-hash field for `user` from `/etc/shadow`.
fn stored_hash(user: &str) -> Option<String> {
    let contents = std::fs::read_to_string("/etc/shadow").ok()?;
    for line in contents.lines() {
        let mut fields = line.splitn(3, ':');
        let name = fields.next()?;
        if name == user {
            return fields.next().map(|hash| hash.to_owned());
        }
    }
    None
}
