//! `std`'s rules for `OpenOptions`, read where the real open can't run. `create` without
//! `write` or `append` is `InvalidInput` on every OS, and a fake that opens files its own way
//! never meets it: plan 19b's install lock hid behind that until CI ran it.

use std::io;

/// What a real open asks for, as far as `std`'s rules go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenSpec {
    pub write: bool,
    pub append: bool,
    pub create: bool,
}

impl OpenSpec {
    /// The error `std` gives before it asks the OS.
    pub fn check(&self) -> io::Result<()> {
        if self.create && !self.write && !self.append {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "creating or truncating a file requires write or append access",
            ));
        }
        Ok(())
    }
}

/// `ffi::acl::lock_file`.
pub const LOCK_FILE: OpenSpec = OpenSpec {
    write: true,
    append: false,
    create: true,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// This rule is `std`'s own, asked of the real thing.
    #[test]
    fn the_rule_is_stds() {
        let dir = std::env::temp_dir();
        for (write, append, create) in [(false, false, true), (true, false, true)] {
            let spec = OpenSpec {
                write,
                append,
                create,
            };
            let real = std::fs::OpenOptions::new()
                .write(write)
                .append(append)
                .create(create)
                .open(&dir);
            let refused = |e: &io::Error| e.kind() == io::ErrorKind::InvalidInput;
            assert_eq!(
                spec.check().err().as_ref().is_some_and(refused),
                real.err().as_ref().is_some_and(refused)
            );
        }
    }

    #[test]
    fn the_lock_file_can_be_opened() {
        LOCK_FILE.check().unwrap();
    }
}
