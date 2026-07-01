//! Parsing of `user[:group]` ownership specs and octal permission modes for
//! listener sockets — the access-control knobs (`-o`/`-m`) shared by the
//! daemons.

use nix::unistd::{Group, User};

/// Parses a `user[:group]` spec into optional uid/gid.
///
/// Each field may be numeric or a name. As in the C implementation, naming a
/// user by name also adopts that user's primary group unless a group is given
/// explicitly. Returns `None` if the spec resolves to neither a uid nor a gid,
/// or if a named user/group does not exist.
pub fn parse_owner_spec(spec: &str) -> Option<(Option<u32>, Option<u32>)> {
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };

    let mut uid = None;
    let mut gid = None;

    if !user.is_empty() {
        if let Ok(n) = user.parse::<u32>() {
            uid = Some(n);
        } else {
            let resolved = User::from_name(user).ok().flatten()?;
            uid = Some(resolved.uid.as_raw());
            gid = Some(resolved.gid.as_raw());
        }
    }

    if let Some(group) = group {
        if !group.is_empty() {
            if let Ok(n) = group.parse::<u32>() {
                gid = Some(n);
            } else {
                let resolved = Group::from_name(group).ok().flatten()?;
                gid = Some(resolved.gid.as_raw());
            }
        }
    }

    if uid.is_none() && gid.is_none() {
        return None;
    }

    Some((uid, gid))
}

/// Parses an octal permission mode (e.g. `"0770"`). Returns `None` if it is not
/// valid octal or exceeds `07777`.
pub fn parse_mode(spec: &str) -> Option<u32> {
    let value = u32::from_str_radix(spec, 8).ok()?;
    (value <= 0o7777).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_owner_spec() {
        assert_eq!(
            parse_owner_spec("1000:1000"),
            Some((Some(1000), Some(1000)))
        );
        assert_eq!(parse_owner_spec("1000"), Some((Some(1000), None)));
        assert_eq!(parse_owner_spec(":1000"), Some((None, Some(1000))));
    }

    #[test]
    fn empty_owner_spec_is_rejected() {
        assert_eq!(parse_owner_spec(""), None);
        assert_eq!(parse_owner_spec(":"), None);
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(parse_mode("0770"), Some(0o770));
        assert_eq!(parse_mode("700"), Some(0o700));
        assert_eq!(parse_mode("7777"), Some(0o7777));
        assert_eq!(parse_mode("17777"), None); // > 07777
        assert_eq!(parse_mode("9"), None); // not octal
        assert_eq!(parse_mode("xyz"), None);
    }
}
