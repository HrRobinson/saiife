//! Credential Manager rules (plan 19b, Task 11), free of Windows calls so Linux tests
//! cover them. `ffi::cred` supplies the calls.

use std::io;

/// `CRED_MAX_CREDENTIAL_BLOB_SIZE`: the most bytes one credential holds.
pub const MAX_BLOB: usize = 2560;
/// `CRED_MAX_GENERIC_TARGET_NAME_LENGTH`, in UTF-16 units.
pub const MAX_TARGET_UNITS: usize = 32767;
/// `CRED_MAX_STRING_LENGTH`: the most UTF-16 units of a comment.
pub const MAX_COMMENT_UNITS: usize = 256;

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
}

/// A target name Windows would take whole: not empty, no NUL, not too long. It is a
/// label such as `saiife:vault-key`, never a secret, so it may go in an error.
pub fn check_target(target: &str) -> io::Result<()> {
    if target.is_empty() {
        return Err(invalid("an empty credential target"));
    }
    if target.contains('\0') {
        return Err(invalid("a NUL in a credential target"));
    }
    if target.encode_utf16().count() > MAX_TARGET_UNITS {
        return Err(invalid("a credential target that is too long"));
    }
    Ok(())
}

/// A comment Windows would take whole. It is shown to the user, so it holds no secret.
pub fn check_comment(comment: &str) -> io::Result<()> {
    if comment.contains('\0') {
        return Err(invalid("a NUL in a credential comment"));
    }
    if comment.encode_utf16().count() > MAX_COMMENT_UNITS {
        return Err(invalid("a credential comment that is too long"));
    }
    Ok(())
}

/// A blob Windows would take whole. The error says how big, never what is in it.
pub fn check_blob(blob: &[u8]) -> io::Result<()> {
    if blob.len() > MAX_BLOB {
        return Err(invalid(&format!(
            "a credential of {} bytes; Credential Manager holds at most {MAX_BLOB}",
            blob.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_checked() {
        check_target("saiife:vault-key").unwrap();
        assert!(check_target("").is_err());
        assert!(check_target("a\0b").is_err());
        assert!(check_target(&"a".repeat(MAX_TARGET_UNITS)).is_ok());
        assert!(check_target(&"a".repeat(MAX_TARGET_UNITS + 1)).is_err());
    }

    #[test]
    fn a_blob_is_capped_and_its_error_names_no_bytes() {
        check_blob(&[7u8; 32]).unwrap();
        check_blob(&[7u8; MAX_BLOB]).unwrap();
        let e = check_blob(&vec![0x41u8; MAX_BLOB + 1])
            .unwrap_err()
            .to_string();
        assert!(e.contains("2561"), "{e}");
        assert!(!e.contains("AAAA"), "{e}");
    }

    #[test]
    fn comments_are_checked() {
        check_comment("saiife personal broker: vault key").unwrap();
        assert!(check_comment("a\0").is_err());
        assert!(check_comment(&"c".repeat(MAX_COMMENT_UNITS + 1)).is_err());
    }
}
