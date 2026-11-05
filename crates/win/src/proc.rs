//! Process table entries (plan 19b, W17), free of Windows calls so Linux tests can use
//! them. `ffi::proc` fills them from a Toolhelp snapshot.

/// One line of a process snapshot: names only, with no start time and no command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    /// The executable's file name, as Windows gives it: `Claude.exe`.
    pub exe: String,
}

/// The name a session walk compares: lower case, without `.exe`.
pub fn comm_of(exe: &str) -> String {
    let lower = exe.to_lowercase();
    match lower.strip_suffix(".exe") {
        Some(stem) => stem.to_string(),
        None => lower,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comm_is_lower_case_without_exe() {
        assert_eq!(comm_of("Claude.EXE"), "claude");
        assert_eq!(comm_of("pwsh.exe"), "pwsh");
        assert_eq!(comm_of("System"), "system");
        assert_eq!(comm_of("a.exe.txt"), "a.exe.txt");
    }
}
