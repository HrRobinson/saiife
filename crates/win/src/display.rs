//! A path as a person reads it. `std::fs::canonicalize` on Windows answers in
//! the verbatim form (`\\?\D:\x`), which most programs cannot take back: a
//! browser, `cd` in cmd, or a file dialog. Records keep it, since it is what
//! they compare against; what is printed does not.

use std::borrow::Cow;
use std::path::Path;

/// `text` without a leading verbatim marker: `\\?\D:\x` is `D:\x`, and
/// `\\?\UNC\host\share` is `\\host\share`. Any other verbatim form
/// (`\\?\Volume{…}`) has no plain spelling and stays. Pure, so every OS tests it.
pub fn strip_verbatim(text: &str) -> Cow<'_, str> {
    let Some(rest) = text.strip_prefix(r"\\?\") else {
        return Cow::Borrowed(text);
    };
    if let Some(unc) = rest.strip_prefix(r"UNC\") {
        return Cow::Owned(format!(r"\\{unc}"));
    }
    let drive = rest.as_bytes();
    if drive.len() >= 2 && drive[0].is_ascii_alphabetic() && drive[1] == b':' {
        return Cow::Borrowed(rest);
    }
    Cow::Borrowed(text)
}

/// `path` for printing. Linux and macOS print it as it is: there a backslash is
/// an ordinary character of a file name.
pub fn shown(path: &Path) -> String {
    let text = path.display().to_string();
    if cfg!(windows) {
        strip_verbatim(&text).into_owned()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verbatim_marker_comes_off_a_drive_path_and_a_share() {
        assert_eq!(strip_verbatim(r"\\?\D:\a\b.exe"), r"D:\a\b.exe");
        assert_eq!(strip_verbatim(r"\\?\UNC\host\share\x"), r"\\host\share\x");
    }

    #[test]
    fn other_forms_stay_as_they_are() {
        for text in [
            r"D:\a",
            r"\\host\share",
            r"\\?\Volume{1234}\x",
            "/home/u/x",
            r"\\?\",
            "",
        ] {
            assert_eq!(strip_verbatim(text), text);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_posix_file_name_is_never_rewritten() {
        assert_eq!(shown(Path::new(r"\\?\D:\x")), r"\\?\D:\x");
    }
}
