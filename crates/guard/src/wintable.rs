//! The Windows translation table (plan 19a, W5): PowerShell cmdlets, their
//! aliases and cmd builtins as the POSIX commands the packs judge, and the
//! commands nested in `powershell`, `cmd`, `iex` and `Invoke-Command`.
//!
//! A pure function of the words. Where a real parameter would confuse the
//! POSIX operand parser it is removed, not passed through: `Copy-Item -Filter`
//! holds a `t`, and `operands` would read `-t ilter` and take the wrong word as
//! the target. That is a departure from W5's "others pass through as written",
//! for `cp`, `mv` and the redirect rows.

use crate::lexer::Word;

/// How a command line is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Posix,
    PowerShell,
    Cmd,
}

/// What `nested` returns for a nested command it knows is there and cannot
/// read: an `-EncodedCommand` that does not decode, `-File`, a script block in
/// a variable, a shell fed on stdin. It reads as a variable in command
/// position, so `pwsh::split_segments_noted` gives it the unresolved outcome.
pub const UNRESOLVED: &str = "$saiife_unresolved";

const MAX_ENCODED: usize = 64 * 1024;
/// `Start-Process Start-Process …`: how many times the table re-enters itself.
const MAX_START_DEPTH: u32 = 8;

pub(crate) const NOTE_AMBIGUOUS: &str = "a PowerShell parameter is ambiguous";
const NOTE_UNKNOWN: &str = "a PowerShell parameter is not in the table";
const NOTE_PIPELINE: &str = "a path comes from the pipeline";
const NOTE_TARGET: &str = "a PowerShell file command has no visible target";
const NOTE_LINK: &str = "a link is created: later paths may go through it";
const NOTE_ITEM_TYPE: &str = "New-Item has an item type that cannot be read";
const NOTE_WORKDIR: &str = "Start-Process changes its working directory";
const NOTE_START: &str = "Start-Process has no readable program";
const NOTE_PURGE: &str = "robocopy deletes files in its target";
const NOTE_ROBOCOPY: &str = "robocopy has no readable source and target";
const NOTE_FUNCTION: &str = "a function or alias is defined through its drive";
pub(crate) const NOTE_TOO_LONG: &str = "a path list too long to join";

/// Bytes the paths joined from a list and a name may come to: `ni a,a,… -Name
/// bbb…` is a product, and the hook runs on every call. Past this they stay
/// apart, and the note says so.
pub(crate) const MAX_JOINED: usize = 4 * 1024 * 1024;

/// PowerShell's common parameters, on every cmdlet. None names a path.
const COMMON: &[(&str, Act)] = &[
    ("ErrorAction", Act::Skip),
    ("ea", Act::Skip),
    ("WarningAction", Act::Skip),
    ("wa", Act::Skip),
    ("InformationAction", Act::Skip),
    ("infa", Act::Skip),
    ("ProgressAction", Act::Skip),
    ("proga", Act::Skip),
    ("ErrorVariable", Act::Skip),
    ("ev", Act::Skip),
    ("WarningVariable", Act::Skip),
    ("wv", Act::Skip),
    ("InformationVariable", Act::Skip),
    ("iv", Act::Skip),
    ("OutVariable", Act::Skip),
    ("ov", Act::Skip),
    ("OutBuffer", Act::Skip),
    ("ob", Act::Skip),
    ("PipelineVariable", Act::Skip),
    ("pv", Act::Skip),
    ("Verbose", Act::Drop),
    ("vb", Act::Drop),
    ("Debug", Act::Drop),
    ("db", Act::Drop),
    ("WhatIf", Act::Drop),
    ("wi", Act::Drop),
    ("Confirm", Act::Drop),
    ("cf", Act::Drop),
];

/// What one parameter does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    /// Becomes this POSIX flag; any value (`-Recurse:$true`) is dropped.
    Flag(&'static str),
    /// Its value is an operand; wildcards expand.
    Path,
    /// Its value is an operand, taken literally.
    Literal,
    /// Its value is the copy or move target, or `curl -o`.
    Target,
    /// `Select-String -Pattern`.
    Pattern,
    /// `Invoke-WebRequest -InFile`.
    InFile,
    /// `Stop-Process -Name`.
    ProcName,
    /// `New-Item -ItemType`.
    ItemType,
    /// `New-Item -Name`.
    ItemName,
    /// `New-Item -Value`: file contents, or a link's target.
    ItemValue,
    /// `Start-Process -ArgumentList`.
    Args,
    /// `Start-Process -RedirectStandardOutput`.
    Out,
    /// `Start-Process -RedirectStandardInput`.
    In,
    /// A real parameter left as written.
    Keep,
    /// A real switch that names no path: removed.
    Drop,
    /// A real parameter that names no path: removed with its value.
    Skip,
    /// `taskkill /fi "imagename eq x"`: which processes a filter selects.
    ProcFilter,
    /// Removed with its value; the command is not fully read.
    Unread(&'static str),
    /// A switch removed; the command is not fully read.
    UnreadSwitch(&'static str),
}

impl Act {
    fn takes_value(self) -> bool {
        !matches!(
            self,
            Act::Flag(_) | Act::Keep | Act::Drop | Act::UnreadSwitch(_)
        )
    }

    /// Two spellings of one thing are no ambiguity (`-l`: `LiteralPath`, `LP`).
    fn same(self, other: Act) -> bool {
        let class = |a| match a {
            Act::Literal => Act::Path,
            a => a,
        };
        class(self) == class(other)
    }
}

/// What a row becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum To {
    Rm,
    Cp,
    Robocopy,
    Mv,
    Rename,
    Cat,
    Write,
    NewItem,
    Ls,
    Grep,
    Cd,
    Pushd,
    Popd,
    Kill,
    Curl,
    Start,
}

struct Row {
    /// Lower case: the PowerShell names, then the cmd names.
    ps: &'static [&'static str],
    cmd: &'static [&'static str],
    to: To,
    params: &'static [(&'static str, Act)],
    /// `/x` switches. Read in both dialects: `del /s /q C:\` must not pass
    /// under PowerShell, where it fails, as if it were harmless.
    slash: &'static [(&'static str, Act)],
}

const LITERAL: [(&str, Act); 3] = [
    ("LiteralPath", Act::Literal),
    ("LP", Act::Literal),
    ("PSPath", Act::Literal),
];

macro_rules! with_literal {
    ($($p:expr),* $(,)?) => {
        &[LITERAL[0], LITERAL[1], LITERAL[2], ("Path", Act::Path), $($p),*]
    };
}

const WRITE_PARAMS: &[(&str, Act)] = with_literal![
    ("FilePath", Act::Path),
    ("Value", Act::Skip),
    ("InputObject", Act::Skip),
    ("Encoding", Act::Skip),
    ("Width", Act::Skip),
    ("Stream", Act::Skip),
    ("Filter", Act::Skip),
    ("Include", Act::Skip),
    ("Exclude", Act::Skip),
    ("Credential", Act::Skip),
    ("Append", Act::Drop),
    ("Force", Act::Drop),
    ("NoClobber", Act::Drop),
    ("NoNewline", Act::Drop),
    ("PassThru", Act::Drop),
    ("AsByteStream", Act::Drop),
    ("WhatIf", Act::Drop),
    ("Confirm", Act::Drop),
];

/// `Tee-Object`, `Export-Csv`, `Export-Clixml`: the file they write.
const OUTPUT_PARAMS: &[(&str, Act)] = with_literal![
    ("FilePath", Act::Path),
    ("Variable", Act::Skip),
    ("InputObject", Act::Skip),
    ("Encoding", Act::Skip),
    ("Delimiter", Act::Skip),
    ("Depth", Act::Skip),
    ("QuoteFields", Act::Skip),
    ("UseQuotes", Act::Skip),
    ("Append", Act::Drop),
    ("Force", Act::Drop),
    ("NoClobber", Act::Drop),
    ("NoTypeInformation", Act::Drop),
    ("NTI", Act::Drop),
    ("IncludeTypeInformation", Act::Drop),
    ("ITI", Act::Drop),
    ("UseCulture", Act::Drop),
];

const COPY_RECURSE: &[(&str, Act)] = &[
    ("s", Act::Flag("-r")),
    ("e", Act::Flag("-r")),
    ("mir", Act::Flag("-r")),
];

const TABLE: &[Row] = &[
    Row {
        ps: &["remove-item", "ri", "rm", "rmdir", "del", "erase", "rd"],
        cmd: &["del", "erase", "rd", "rmdir"],
        to: To::Rm,
        params: with_literal![
            ("Recurse", Act::Flag("-r")),
            ("Force", Act::Flag("-f")),
            ("Filter", Act::Keep),
            ("Include", Act::Keep),
            ("Exclude", Act::Keep),
            ("Credential", Act::Keep),
            ("Stream", Act::Keep),
        ],
        slash: &[
            ("s", Act::Flag("-r")),
            ("q", Act::Flag("-f")),
            ("f", Act::Flag("-f")),
            ("a", Act::Drop),
            ("p", Act::Drop),
        ],
    },
    Row {
        ps: &["copy-item", "cp", "copy", "cpi", "xcopy"],
        cmd: &["copy", "xcopy"],
        to: To::Cp,
        params: with_literal![
            ("Recurse", Act::Flag("-r")),
            ("Destination", Act::Target),
            ("Force", Act::Drop),
            ("PassThru", Act::Drop),
            ("Container", Act::Drop),
            ("WhatIf", Act::Drop),
            ("Confirm", Act::Drop),
            ("Filter", Act::Skip),
            ("Include", Act::Skip),
            ("Exclude", Act::Skip),
            ("Credential", Act::Skip),
            ("FromSession", Act::Skip),
            ("ToSession", Act::Skip),
        ],
        slash: COPY_RECURSE,
    },
    // An archive reads its sources and writes its destination.
    Row {
        ps: &["compress-archive", "expand-archive"],
        cmd: &[],
        to: To::Cp,
        params: with_literal![
            ("DestinationPath", Act::Target),
            ("CompressionLevel", Act::Skip),
            ("Force", Act::Drop),
            ("Update", Act::Drop),
            ("PassThru", Act::Drop),
        ],
        slash: &[],
    },
    Row {
        ps: &["robocopy"],
        cmd: &["robocopy"],
        to: To::Robocopy,
        params: &[],
        slash: &[
            ("s", Act::Flag("-r")),
            ("e", Act::Flag("-r")),
            ("mir", Act::Flag("-r")),
            ("mov", Act::Flag("--move")),
            ("move", Act::Flag("--move")),
            ("purge", Act::UnreadSwitch(NOTE_PURGE)),
        ],
    },
    Row {
        ps: &["move-item", "mv", "move", "mi"],
        cmd: &["move"],
        to: To::Mv,
        params: with_literal![
            ("Destination", Act::Target),
            ("Force", Act::Drop),
            ("PassThru", Act::Drop),
            ("WhatIf", Act::Drop),
            ("Confirm", Act::Drop),
            ("Filter", Act::Skip),
            ("Include", Act::Skip),
            ("Exclude", Act::Skip),
            ("Credential", Act::Skip),
        ],
        slash: &[],
    },
    Row {
        ps: &["rename-item", "ren", "rni"],
        cmd: &["ren", "rename"],
        to: To::Rename,
        params: with_literal![
            ("NewName", Act::Target),
            ("Force", Act::Drop),
            ("PassThru", Act::Drop),
            ("WhatIf", Act::Drop),
            ("Confirm", Act::Drop),
            ("Credential", Act::Skip),
        ],
        slash: &[],
    },
    Row {
        ps: &["get-content", "gc", "cat", "type"],
        cmd: &["type"],
        to: To::Cat,
        params: with_literal![
            ("Tail", Act::Keep),
            ("TotalCount", Act::Keep),
            ("Head", Act::Keep),
            ("First", Act::Keep),
            ("ReadCount", Act::Keep),
            ("Raw", Act::Keep),
            ("Encoding", Act::Keep),
            ("Delimiter", Act::Keep),
            ("Wait", Act::Keep),
            ("Stream", Act::Keep),
            ("Filter", Act::Keep),
            ("Include", Act::Keep),
            ("Exclude", Act::Keep),
            ("Force", Act::Keep),
            ("Credential", Act::Keep),
            ("AsByteStream", Act::Keep),
        ],
        slash: &[],
    },
    Row {
        ps: &[
            "set-content",
            "sc",
            "add-content",
            "ac",
            "out-file",
            "clear-content",
            "clc",
        ],
        cmd: &[],
        to: To::Write,
        params: WRITE_PARAMS,
        slash: &[],
    },
    Row {
        ps: &["tee-object", "tee", "export-csv", "epcsv", "export-clixml"],
        cmd: &[],
        to: To::Write,
        params: OUTPUT_PARAMS,
        slash: &[],
    },
    Row {
        ps: &["set-acl"],
        cmd: &[],
        to: To::Write,
        params: with_literal![
            ("AclObject", Act::Skip),
            ("InputObject", Act::Skip),
            ("CentralAccessPolicy", Act::Skip),
            ("Filter", Act::Skip),
            ("Include", Act::Skip),
            ("Exclude", Act::Skip),
            ("ClearCentralAccessPolicy", Act::Drop),
            ("PassThru", Act::Drop),
        ],
        slash: &[],
    },
    Row {
        ps: &["start-transcript", "export-alias", "epal"],
        cmd: &[],
        to: To::Write,
        params: with_literal![
            ("OutputDirectory", Act::Path),
            ("Name", Act::Skip),
            ("As", Act::Skip),
            ("Description", Act::Skip),
            ("Scope", Act::Skip),
            ("Append", Act::Drop),
            ("Force", Act::Drop),
            ("NoClobber", Act::Drop),
            ("IncludeInvocationHeader", Act::Drop),
            ("UseMinimalHeader", Act::Drop),
            ("PassThru", Act::Drop),
        ],
        slash: &[],
    },
    Row {
        ps: &["new-item", "ni", "md", "mkdir"],
        cmd: &[],
        to: To::NewItem,
        params: &[
            ("Path", Act::Path),
            ("Name", Act::ItemName),
            ("ItemType", Act::ItemType),
            ("Type", Act::ItemType),
            ("Value", Act::ItemValue),
            ("Target", Act::ItemValue),
            ("Force", Act::Drop),
            ("WhatIf", Act::Drop),
            ("Confirm", Act::Drop),
            ("Credential", Act::Skip),
        ],
        slash: &[],
    },
    Row {
        ps: &["get-childitem", "gci", "ls", "dir"],
        cmd: &["dir"],
        to: To::Ls,
        params: with_literal![
            ("Recurse", Act::Flag("-R")),
            ("s", Act::Flag("-R")),
            ("Filter", Act::Keep),
            ("Include", Act::Keep),
            ("Exclude", Act::Keep),
            ("Force", Act::Keep),
            ("Name", Act::Keep),
            ("Depth", Act::Keep),
            ("Attributes", Act::Keep),
            ("Directory", Act::Keep),
            ("File", Act::Keep),
            ("Hidden", Act::Keep),
            ("ReadOnly", Act::Keep),
            ("System", Act::Keep),
            ("FollowSymlink", Act::Keep),
        ],
        slash: &[("s", Act::Flag("-R"))],
    },
    Row {
        ps: &["select-string", "sls", "findstr"],
        cmd: &["findstr"],
        to: To::Grep,
        params: with_literal![
            ("Pattern", Act::Pattern),
            ("InputObject", Act::Skip),
            ("Context", Act::Skip),
            ("Culture", Act::Skip),
            ("Encoding", Act::Skip),
            ("Exclude", Act::Skip),
            ("Include", Act::Skip),
            ("AllMatches", Act::Drop),
            ("CaseSensitive", Act::Drop),
            ("List", Act::Drop),
            ("NoEmphasis", Act::Drop),
            ("NotMatch", Act::Drop),
            ("Quiet", Act::Drop),
            ("Raw", Act::Drop),
            ("SimpleMatch", Act::Drop),
        ],
        slash: &[
            ("c", Act::Pattern),
            ("r", Act::Pattern),
            ("f", Act::Path),
            ("g", Act::Path),
        ],
    },
    Row {
        ps: &["set-location", "cd", "sl", "chdir"],
        cmd: &["cd", "chdir"],
        to: To::Cd,
        params: with_literal![("PassThru", Act::Drop), ("StackName", Act::Skip)],
        slash: &[],
    },
    Row {
        ps: &["push-location", "pushd"],
        cmd: &["pushd"],
        to: To::Pushd,
        params: with_literal![("PassThru", Act::Drop), ("StackName", Act::Skip)],
        slash: &[],
    },
    Row {
        ps: &["pop-location", "popd"],
        cmd: &["popd"],
        to: To::Popd,
        params: &[],
        slash: &[],
    },
    Row {
        ps: &["stop-process", "kill", "spps", "taskkill"],
        cmd: &["taskkill"],
        to: To::Kill,
        params: &[
            ("Id", Act::Path),
            ("PID", Act::Path),
            ("Name", Act::ProcName),
            ("ProcessName", Act::ProcName),
            ("InputObject", Act::Keep),
            ("Force", Act::Keep),
            ("PassThru", Act::Keep),
        ],
        slash: &[
            ("pid", Act::Path),
            ("im", Act::ProcName),
            ("f", Act::Drop),
            ("t", Act::Drop),
            ("fi", Act::ProcFilter),
            ("s", Act::Skip),
            ("u", Act::Skip),
            ("p", Act::Skip),
        ],
    },
    Row {
        ps: &[
            "invoke-webrequest",
            "iwr",
            "curl",
            "wget",
            "invoke-restmethod",
            "irm",
        ],
        cmd: &[],
        to: To::Curl,
        params: &[
            ("Uri", Act::Path),
            ("OutFile", Act::Target),
            ("InFile", Act::InFile),
            ("Body", Act::Keep),
            ("Method", Act::Keep),
            ("Headers", Act::Keep),
            ("Form", Act::Keep),
            ("ContentType", Act::Keep),
            ("UseBasicParsing", Act::Keep),
            ("UseDefaultCredentials", Act::Keep),
            ("UserAgent", Act::Keep),
            ("TimeoutSec", Act::Keep),
            ("Token", Act::Keep),
            ("TransferEncoding", Act::Keep),
            ("Proxy", Act::Keep),
            ("Credential", Act::Keep),
            ("Certificate", Act::Keep),
            ("WebSession", Act::Keep),
            ("SessionVariable", Act::Keep),
            ("DisableKeepAlive", Act::Keep),
            ("MaximumRedirection", Act::Keep),
            ("PassThru", Act::Keep),
            ("FollowRelLink", Act::Keep),
            ("HttpVersion", Act::Keep),
        ],
        slash: &[],
    },
    Row {
        ps: &["start-process", "saps", "start"],
        cmd: &["start"],
        to: To::Start,
        params: &[
            ("FilePath", Act::Path),
            ("Path", Act::Path),
            ("PSPath", Act::Path),
            ("ArgumentList", Act::Args),
            ("Args", Act::Args),
            ("RedirectStandardOutput", Act::Out),
            ("RSO", Act::Out),
            ("RedirectStandardError", Act::Out),
            ("RSE", Act::Out),
            ("RedirectStandardInput", Act::In),
            ("RSI", Act::In),
            ("WorkingDirectory", Act::Unread(NOTE_WORKDIR)),
            ("Verb", Act::Skip),
            ("WindowStyle", Act::Skip),
            ("Credential", Act::Skip),
            ("Environment", Act::Skip),
            ("Wait", Act::Drop),
            ("NoNewWindow", Act::Drop),
            ("PassThru", Act::Drop),
            ("UseNewEnvironment", Act::Drop),
            ("LoadUserProfile", Act::Drop),
        ],
        slash: &[("d", Act::Unread(NOTE_WORKDIR))],
    },
];

/// Programs with `/x` switches on every shell: read the cmd way in both
/// dialects, since PowerShell just hands them the words.
const SLASH_PROGRAMS: &[&str] = &["taskkill", "xcopy", "robocopy", "findstr"];

/// A name with a path or an extension is a program, not an alias: these keep
/// their own (POSIX) options. `rm.exe -rf x`, `curl.exe -i URL`.
const POSIX_PROGRAMS: &[&str] = &[
    "rm", "cp", "mv", "cat", "ls", "curl", "wget", "kill", "mkdir", "rmdir", "sc",
];

/// PowerShell's own aliases on Windows, 5.1 and 7 together, for those the table
/// has no row of (and `tee`, whose row keeps the real program's reading): from
/// the shells' `InitialSessionState` and module manifests.
/// `scripts/differential-windows.ps1` checks this against `Get-Alias` on both
/// versions. Not here, because they read the same either way: what `TABLE` lists,
/// and `sc`, `curl` and `wget`, which are aliases in 5.1 and real programs in 7
/// (their rows read both). Only on a Windows-style host: elsewhere many of these
/// are real programs (`ps`, `sort`, `tee`, `diff`).
#[rustfmt::skip]
const POWERSHELL_ALIASES: &[(&str, &str)] = &[
    ("%", "ForEach-Object"), ("?", "Where-Object"), ("asnp", "Add-PSSnapin"), ("cfs", "ConvertFrom-String"),
    ("clear", "Clear-Host"), ("clhy", "Clear-History"), ("cli", "Clear-Item"), ("clp", "Clear-ItemProperty"),
    ("cls", "Clear-Host"), ("clv", "Clear-Variable"), ("cnsn", "Connect-PSSession"), ("compare", "Compare-Object"),
    ("cpp", "Copy-ItemProperty"), ("cvpa", "Convert-Path"), ("dbp", "Disable-PSBreakpoint"), ("diff", "Compare-Object"),
    ("dnsn", "Disconnect-PSSession"), ("ebp", "Enable-PSBreakpoint"), ("echo", "Write-Output"), ("epsn", "Export-PSSession"),
    ("etsn", "Enter-PSSession"), ("exsn", "Exit-PSSession"), ("fc", "Format-Custom"), ("fhx", "Format-Hex"),
    ("fl", "Format-List"), ("foreach", "ForEach-Object"), ("ft", "Format-Table"), ("fw", "Format-Wide"),
    ("gal", "Get-Alias"), ("gbp", "Get-PSBreakpoint"), ("gcai", "Get-CimAssociatedInstance"), ("gcb", "Get-Clipboard"), ("gcim", "Get-CimInstance"),
    ("gcls", "Get-CimClass"), ("gcms", "Get-CimSession"), ("ncms", "New-CimSession"), ("ncso", "New-CimSessionOption"),
    ("rcie", "Register-CimIndicationEvent"), ("rcms", "Remove-CimSession"),
    ("gcm", "Get-Command"), ("gcs", "Get-PSCallStack"), ("gdr", "Get-PSDrive"), ("gerr", "Get-Error"),
    ("ghy", "Get-History"), ("gi", "Get-Item"), ("gin", "Get-ComputerInfo"), ("gjb", "Get-Job"),
    ("gl", "Get-Location"), ("gm", "Get-Member"), ("gmo", "Get-Module"), ("gp", "Get-ItemProperty"),
    ("gps", "Get-Process"), ("gpv", "Get-ItemPropertyValue"), ("group", "Group-Object"), ("gsn", "Get-PSSession"),
    ("gsnp", "Get-PSSnapin"), ("gsv", "Get-Service"), ("gtz", "Get-TimeZone"), ("gu", "Get-Unique"),
    ("gv", "Get-Variable"), ("gwmi", "Get-WmiObject"), ("h", "Get-History"), ("history", "Get-History"),
    ("icim", "Invoke-CimMethod"), ("icm", "Invoke-Command"), ("iex", "Invoke-Expression"), ("ihy", "Invoke-History"),
    ("ii", "Invoke-Item"), ("ipal", "Import-Alias"), ("ipcsv", "Import-Csv"), ("ipmo", "Import-Module"),
    ("ipsn", "Import-PSSession"), ("ise", "powershell_ise"), ("iwmi", "Invoke-WmiMethod"), ("lp", "Out-Printer"),
    ("man", "help"), ("measure", "Measure-Object"), ("mount", "New-PSDrive"), ("mp", "Move-ItemProperty"),
    ("nal", "New-Alias"), ("ncim", "New-CimInstance"), ("ndr", "New-PSDrive"), ("nmo", "New-Module"),
    ("npssc", "New-PSSessionConfigurationFile"), ("nsn", "New-PSSession"), ("nv", "New-Variable"), ("ogv", "Out-GridView"),
    ("oh", "Out-Host"), ("ps", "Get-Process"), ("pwd", "Get-Location"), ("r", "Invoke-History"),
    ("rbp", "Remove-PSBreakpoint"), ("rcim", "Remove-CimInstance"), ("rcjb", "Receive-Job"), ("rcsn", "Receive-PSSession"),
    ("rdr", "Remove-PSDrive"), ("rjb", "Remove-Job"), ("rmo", "Remove-Module"), ("rnp", "Rename-ItemProperty"),
    ("rp", "Remove-ItemProperty"), ("rsn", "Remove-PSSession"), ("rsnp", "Remove-PSSnapin"), ("rujb", "Resume-Job"),
    ("rv", "Remove-Variable"), ("rvpa", "Resolve-Path"), ("rwmi", "Remove-WmiObject"), ("sajb", "Start-Job"),
    ("sal", "Set-Alias"), ("sasv", "Start-Service"), ("sbp", "Set-PSBreakpoint"), ("scb", "Set-Clipboard"),
    ("scim", "Set-CimInstance"), ("select", "Select-Object"), ("set", "Set-Variable"), ("shcm", "Show-Command"),
    ("si", "Set-Item"), ("sleep", "Start-Sleep"), ("sort", "Sort-Object"), ("sp", "Set-ItemProperty"),
    ("spjb", "Stop-Job"), ("spsv", "Stop-Service"), ("stz", "Set-TimeZone"), ("sujb", "Suspend-Job"),
    ("sv", "Set-Variable"), ("swmi", "Set-WmiInstance"), ("tee", "Tee-Object"), ("trcm", "Trace-Command"),
    ("where", "Where-Object"), ("wjb", "Wait-Job"), ("write", "Write-Output"),
];

/// What PowerShell runs for this name, when it is an alias: a name with a
/// directory or an extension is a program.
pub(crate) fn powershell_alias(name: &CommandName) -> Option<&'static str> {
    if name.program {
        return None;
    }
    let lower = name.lower();
    POWERSHELL_ALIASES
        .iter()
        .find(|(alias, _)| *alias == lower)
        .map(|(_, command)| *command)
}

/// The translation's context beyond the words: the reader knows these.
#[derive(Default)]
pub(crate) struct Context<'a> {
    /// Input arrives on the pipeline (`x | Remove-Item`).
    pub piped: bool,
    /// `array[i]`: `argv[i]` followed a comma, so it extends the array before
    /// it (`Set-Content a,b hello`: `b` is a path, `hello` the value).
    pub array: &'a [bool],
    /// `from_quote[i]`: `argv[i]` started with a quote, so it is a string
    /// even when it reads `-Path:x`. `Word.quoted` cannot tell that from
    /// `-Path:'x'`, which is the parameter.
    pub from_quote: &'a [bool],
    pub depth: u32,
    /// The pipeline's input is every process (`Get-Process | Stop-Process`).
    pub all_processes: bool,
    /// A Windows-style host: PowerShell's aliases are in force
    /// (`POWERSHELL_ALIASES`).
    pub windows: bool,
}

/// The W5 table: `argv` as the POSIX command the packs judge. `argv[0]` is
/// matched without case, directory or extension; parameters by unambiguous
/// prefix among the row's entries. An ambiguous prefix stays as written.
pub fn translate(argv: &[Word], dialect: Dialect) -> Vec<Word> {
    translate_noted(argv, dialect, &Context::default()).0
}

/// `translate`, plus why the words were not fully read.
pub(crate) fn translate_noted(
    argv: &[Word],
    dialect: Dialect,
    cx: &Context,
) -> (Vec<Word>, Option<&'static str>) {
    let Some(first) = argv.first() else {
        return (Vec::new(), None);
    };
    if dialect == Dialect::Posix || first.has_substitution {
        return (argv.to_vec(), None);
    }
    let name = CommandName::of(&first.text);
    let alias = (dialect == Dialect::PowerShell && cx.windows)
        .then(|| powershell_alias(&name))
        .flatten();
    let lower = alias.map_or_else(|| name.lower(), str::to_lowercase);
    let renamed = || {
        let mut out = argv.to_vec();
        out[0].text = alias.unwrap_or(name.base).to_string();
        out
    };
    if name.program && POSIX_PROGRAMS.contains(&lower.as_str()) {
        return (renamed(), None);
    }
    let names = |r: &Row| match dialect {
        Dialect::Cmd => r.cmd.contains(&lower.as_str()),
        _ => r.ps.contains(&lower.as_str()),
    };
    let Some(row) = TABLE.iter().find(|r| names(r)) else {
        return (renamed(), None);
    };
    let mut b = Builder {
        dialect,
        note: None,
        redirects: Vec::new(),
    };
    let cmd_mode = dialect == Dialect::Cmd || SLASH_PROGRAMS.contains(&lower.as_str());
    let array = cx.array.get(1..).unwrap_or(&[]);
    let from_quote = cx.from_quote.get(1..).unwrap_or(&[]);
    let items = b.parse(row, &argv[1..], array, from_quote, cmd_mode);
    let mut out = match row.to {
        To::Rm => b.in_order("rm", items, cx.piped),
        To::Cat => b.in_order("cat", items, cx.piped),
        To::Ls => b.in_order("ls", items, false),
        To::Cd => b.in_order("cd", items, cx.piped),
        To::Pushd => b.in_order("pushd", items, cx.piped),
        To::Popd => vec![plain("popd")],
        To::Cp => b.copy("cp", items, false, cx.piped),
        To::Mv => b.copy("mv", items, false, cx.piped),
        To::Rename => b.copy("mv", items, true, cx.piped),
        To::Robocopy => b.robocopy(items),
        To::Write => b.write(&lower, &argv[1..], items),
        To::NewItem => b.new_item(&lower, items),
        To::Grep => b.grep(items),
        To::Kill => b.kill(items, cx.piped, cx.all_processes),
        To::Curl => b.curl(items),
        To::Start => b.start(items, cx.depth),
    };
    out.append(&mut b.redirects);
    if out.iter().skip(1).any(|w| names_function_drive(&w.text)) {
        b.noted(NOTE_FUNCTION);
    }
    (out, b.note)
}

/// The processes `taskkill /fi` selects, as operands of `kill`: a name, a pid, or
/// `*` for a filter that does not name them. A title names no process that
/// matters here.
fn filter_targets(value: &Word) -> Vec<Word> {
    if value.has_substitution {
        return vec![value.clone()];
    }
    let lower = value.text.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split_whitespace().collect();
    let original: Vec<&str> = value.text.split_whitespace().collect();
    match parts.as_slice() {
        ["imagename", "eq", ..] if original.len() >= 3 => {
            vec![plain("-n"), plain(&original[2..].join(" "))]
        }
        ["services", "eq", ..] if original.len() >= 3 => {
            vec![plain("-n"), plain(&original[2..].join(" "))]
        }
        ["pid", "eq", pid] if pid.bytes().all(|b| b.is_ascii_digit()) => vec![plain(pid)],
        ["windowtitle", ..] => Vec::new(),
        _ => vec![plain("*")],
    }
}

/// `Set-ItemProperty` and its kind: no table row, since they change items and no
/// file's bytes. The path they change.
const ITEM_WRITERS: &[&str] = &[
    "set-itemproperty",
    "sp",
    "new-itemproperty",
    "remove-itemproperty",
    "rp",
    "rename-itemproperty",
    "rnp",
    "copy-itemproperty",
    "cpp",
    "move-itemproperty",
    "mp",
    "clear-itemproperty",
    "clp",
    "set-item",
    "si",
    "clear-item",
    "cli",
    "import-certificate",
    "import-pfxcertificate",
    "new-selfsignedcertificate",
];

/// `touch` of what an `ITEM_WRITERS` command changes: its first word when that
/// is an operand, its `-Path`, and every word on a provider drive. Parameters may
/// be switches or take values, which is not known here, so any provider word
/// counts, wherever it stands.
pub(crate) fn companion_write(seg: &[Word]) -> Option<Vec<Word>> {
    let first = seg.first()?;
    if first.redirect
        || first.has_substitution
        || !ITEM_WRITERS.contains(&first.text.to_lowercase().as_str())
    {
        return None;
    }
    let b = Builder {
        dialect: Dialect::PowerShell,
        note: None,
        redirects: Vec::new(),
    };
    let mut out = vec![plain("touch")];
    let mut path_next = false;
    let mut words = seg[1..].iter().enumerate();
    while let Some((i, w)) = words.next() {
        if w.redirect {
            words.next();
            continue;
        }
        if w.has_substitution {
            path_next = false;
            continue;
        }
        let shape = is_parameter(w).then(|| param_shape(w)).flatten();
        let is_path = |name: &str| {
            let name = name.to_ascii_lowercase();
            abbreviates(&name, "path", 1)
                || abbreviates(&name, "literalpath", 1)
                || name == "lp"
                || name == "pspath"
                || abbreviates(&name, "certstorelocation", 1)
        };
        let named = shape.filter(|(n, _)| is_path(n));
        let target = if let Some((_, Some(v))) = named {
            Some(v)
        } else if shape.is_some() {
            path_next = named.is_some();
            shape
                .and_then(|(_, v)| v)
                .filter(|v| crate::winpath::is_data_provider(v))
        } else if path_next || i == 0 || crate::winpath::is_data_provider(&w.text) {
            path_next = false;
            Some(w.text.as_str())
        } else {
            None
        };
        if let Some(t) = target {
            out.push(b.operand(
                &Word {
                    text: t.to_string(),
                    ..w.clone()
                },
                false,
            ));
        }
    }
    (out.len() > 1).then_some(out)
}

/// `function:foo`, `alias:foo`: what is written there is a command later.
fn names_function_drive(text: &str) -> bool {
    ["function:", "alias:"].iter().any(|d| {
        text.get(..d.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(d))
    })
}

/// Does the table have a row for this command name?
fn has_row(lower: &str, dialect: Dialect) -> bool {
    TABLE.iter().any(|r| match dialect {
        Dialect::Cmd => r.cmd.contains(&lower),
        _ => r.ps.contains(&lower),
    })
}

/// Path-shaped: it holds a separator or a wildcard, or starts like a relative
/// or home path.
fn path_shaped(text: &str) -> bool {
    text.contains(['\\', '/', '*', '?', '[']) || text.starts_with('.') || text.starts_with('~')
}

/// Can this word name a file? Not a URL. Not a bare word no file can be called
/// (`a|b`, `<a>`, blanks): the path rules would call it unreadable and deny
/// `Where-Object Name -match 'a|b'`, with no file at stake. A word with a path's
/// shape stays, whatever else is in it.
fn may_be_a_file(text: &str) -> bool {
    let impossible = text.trim().is_empty()
        || text.contains(|c: char| matches!(c, '<' | '>' | '"' | '|') || c.is_control());
    let constant = ["$true", "$false", "$null"]
        .iter()
        .any(|k| text.eq_ignore_ascii_case(k));
    !constant && !text.contains("://") && (path_shaped(text) || !impossible)
}

/// The parts of an argument that may name a file: the value of `-x=v`, `-x:v`
/// and `--x=v`, and for `k=v` the word, its first value and its last
/// (`--from-file=k=.env`). At most three, so a word of `=` stays linear.
fn file_parts(text: &str) -> Vec<&str> {
    let body = if text.starts_with('-') {
        match text.find(['=', ':']) {
            Some(at) => &text[at + 1..],
            None => return Vec::new(),
        }
    } else {
        text
    };
    let mut parts = vec![body];
    if let (Some(first), Some(last)) = (body.find('='), body.rfind('=')) {
        parts.push(&body[first + 1..]);
        if last != first {
            parts.push(&body[last + 1..]);
        }
    }
    parts.retain(|p| may_be_a_file(p));
    parts
}

/// `Get-Date`'s `-Format` and `-UFormat`, by any prefix.
fn is_format_parameter(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    abbreviates(&name, "format", 1) || abbreviates(&name, "uformat", 1)
}

/// `h:mm`, `h:mm:ss tt`: a one-letter `x:` that a drive-relative path would look
/// like, followed by text no such path needs. `c:.env` and `c:\x` are not this.
fn is_time_format(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b' '))
}

/// The default for a command the table and `operands` do not know: `cat` of
/// every word that may name a file, parameter values included, so the read
/// rules see them. A bare word counts: `notepad id_rsa` reads the file in the
/// working directory, and nothing tells it from `npm test`, whose read matches
/// no rule. `Test-Path .env` is denied by this, an accepted cost: `Format-Hex`,
/// `Get-FileHash`, `Send-MailMessage -Attachments`, `notepad` and `certutil` all
/// read, and no list of them could be complete.
pub(crate) fn companion_read(seg: &[Word], dialect: Dialect) -> Option<Vec<Word>> {
    let first = seg.first()?;
    if first.redirect || first.has_substitution {
        return None;
    }
    let lower = first.text.to_lowercase();
    if lower == "echo"
        || lower == "write"
        || lower.starts_with("write-")
        || is_nesting_command(&lower)
        || matches!(lower.as_str(), "invoke-command" | "icm")
        || has_row(&lower, dialect)
        || crate::operands::understood(&lower)
    {
        return None;
    }
    let b = Builder {
        dialect,
        note: None,
        redirects: Vec::new(),
    };
    let mut out = vec![plain("cat")];
    let mut words = seg[1..].iter();
    let date = lower == "get-date";
    let mut format_next = false;
    while let Some(w) = words.next() {
        if w.redirect {
            words.next();
            continue;
        }
        if w.has_substitution {
            continue;
        }
        if date {
            let is_value = format_next;
            let shape = param_shape(w).filter(|(n, _)| is_format_parameter(n));
            format_next = shape.is_some_and(|(_, v)| v.is_none());
            let value = if is_value {
                Some(w.text.as_str())
            } else {
                shape.and_then(|(_, v)| v)
            };
            if value.is_some_and(is_time_format) {
                continue;
            }
        }
        for part in file_parts(&w.text) {
            out.push(b.operand(
                &Word {
                    text: part.to_string(),
                    ..w.clone()
                },
                false,
            ));
        }
    }
    (out.len() > 1).then_some(out)
}

/// `cat` of the strings a pipeline starts with.
pub(crate) fn value_read(values: &[Word]) -> Option<Vec<Word>> {
    let b = Builder {
        dialect: Dialect::PowerShell,
        note: None,
        redirects: Vec::new(),
    };
    let mut out = vec![plain("cat")];
    for w in values.iter().filter(|w| may_be_a_file(&w.text)) {
        out.push(b.operand(w, false));
    }
    (out.len() > 1).then_some(out)
}

/// A command word without its directory and extension.
pub(crate) struct CommandName<'a> {
    pub base: &'a str,
    /// It had a directory or an extension: a program, not an alias. A module
    /// qualifier (`Microsoft.PowerShell.Management\Remove-Item`) does not count.
    pub program: bool,
}

impl<'a> CommandName<'a> {
    pub fn of(text: &'a str) -> Self {
        let trimmed = text.trim_end_matches(['.', ' ']);
        let (dir, file) = match trimmed.rfind(['\\', '/']) {
            Some(at) => (&trimmed[..at], &trimmed[at + 1..]),
            None => ("", trimmed),
        };
        if file.is_empty() {
            return CommandName {
                base: text,
                program: false,
            };
        }
        let stem = file.rfind('.').and_then(|at| {
            let ext = &file[at + 1..];
            (at > 0
                && ["exe", "com", "cmd", "bat"]
                    .iter()
                    .any(|e| ext.eq_ignore_ascii_case(e)))
            .then(|| &file[..at])
        });
        let module = dir
            .get(.."microsoft.powershell.".len())
            .is_some_and(|d| d.eq_ignore_ascii_case("microsoft.powershell."));
        CommandName {
            base: stem.unwrap_or(file),
            program: stem.is_some() || (!dir.is_empty() && !module),
        }
    }

    pub fn lower(&self) -> String {
        self.base.to_lowercase()
    }
}

fn plain(text: &str) -> Word {
    Word {
        text: text.to_string(),
        ..Word::default()
    }
}

fn redirect(text: &str) -> Word {
    Word {
        text: text.to_string(),
        redirect: true,
        ..Word::default()
    }
}

/// A leading `//` as `\\`, for a Windows-style host: `normalize::build_argv`
/// collapses leading slashes, and `//host/s` is a share there. The engine calls
/// this, so a forced style and real Windows run one branch.
pub(crate) fn unc_text(text: &str) -> Option<String> {
    let rest = text.trim_start_matches('/');
    (text.len() - rest.len() >= 2).then(|| format!(r"\\{rest}"))
}

/// `$env:USERPROFILE` and `$env:HOME` as `$HOME`, which every path style reads.
fn home_spelled(text: &str) -> Option<String> {
    for prefix in [
        "$env:userprofile",
        "${env:userprofile}",
        "$env:home",
        "${env:home}",
        "$home",
    ] {
        let Some(head) = text.get(..prefix.len()) else {
            continue;
        };
        let rest = &text[prefix.len()..];
        let ends = !rest
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if head.eq_ignore_ascii_case(prefix) && ends {
            return Some(format!("$HOME{rest}"));
        }
    }
    None
}

/// Is every `$` of two joined words literal? One live `$` makes the whole
/// word live, so the path is read as the shell would expand it.
fn joined_dollars_literal(a: &Word, b: &Word) -> bool {
    let fine = |w: &Word| w.literal_dollars || !w.text.contains('$');
    fine(a) && fine(b) && (a.text.contains('$') || b.text.contains('$'))
}

/// `\` as `/`, the leading run kept apart: `engine.rs` finds a directory by a
/// trailing `/` and a base name after the last `/`.
fn forward(text: &str) -> String {
    let rest = text.trim_start_matches('\\');
    format!(
        "{}{}",
        &text[..text.len() - rest.len()],
        rest.replace('\\', "/")
    )
}

enum Item {
    Param {
        act: Act,
        value: Option<Word>,
        written: Word,
    },
    Pos {
        word: Word,
        /// It followed a comma.
        cont: bool,
    },
    Raw(Word),
}

struct Builder {
    dialect: Dialect,
    note: Option<&'static str>,
    redirects: Vec<Word>,
}

impl Builder {
    fn noted(&mut self, why: &'static str) {
        self.note.get_or_insert(why);
    }

    /// The row's words as parameters and positionals; redirections go aside.
    fn parse(
        &mut self,
        row: &Row,
        args: &[Word],
        array: &[bool],
        from_quote: &[bool],
        cmd_mode: bool,
    ) -> Vec<Item> {
        let mut out = Vec::new();
        let mut done = false;
        let mut seen_pos = false;
        let mut i = 0;
        while i < args.len() {
            let w = &args[i];
            let at = i;
            i += 1;
            if w.redirect {
                self.redirects.push(w.clone());
                if let Some(t) = args.get(i) {
                    self.redirects.push(t.clone());
                    i += 1;
                }
                continue;
            }
            if !done && w.text == "--" {
                done = true;
                out.push(Item::Raw(w.clone()));
                continue;
            }
            if !done && !w.has_substitution && w.text.starts_with('/') && w.text.len() > 1 {
                if let Some(parts) = slash_parts(row, &w.text, cmd_mode) {
                    for part in parts {
                        self.slash_item(row, part, w, args, &mut i, &mut out);
                    }
                    continue;
                }
            }
            if !done && !from_quote.get(at).copied().unwrap_or(false) && is_parameter(w) {
                if let Some((name, value)) = param_shape(w) {
                    match resolve(row.params, name) {
                        Lookup::Found(act) => {
                            let value = take_value(act, value, w, args, &mut i);
                            let extends = act.takes_value() && value.is_some();
                            out.push(Item::Param {
                                act,
                                value,
                                written: w.clone(),
                            });
                            // `-Value a,b`: `b` is the parameter's too.
                            while extends && array.get(i) == Some(&true) && i < args.len() {
                                out.push(Item::Param {
                                    act,
                                    value: Some(args[i].clone()),
                                    written: w.clone(),
                                });
                                i += 1;
                            }
                            continue;
                        }
                        Lookup::Ambiguous => {
                            self.noted(NOTE_AMBIGUOUS);
                            out.push(Item::Raw(w.clone()));
                            continue;
                        }
                        Lookup::Unknown => {
                            out.push(Item::Raw(w.clone()));
                            continue;
                        }
                    }
                }
            }
            // `start "title" prog`: the first quoted word is cmd's title. All
            // after the program belongs to the program.
            if row.to == To::Start && cmd_mode && !seen_pos {
                if w.quoted {
                    continue;
                }
                done = true;
            }
            seen_pos = true;
            out.push(Item::Pos {
                word: w.clone(),
                cont: array.get(at).copied().unwrap_or(false),
            });
        }
        out
    }

    fn slash_item(
        &mut self,
        row: &Row,
        part: &str,
        w: &Word,
        args: &[Word],
        i: &mut usize,
        out: &mut Vec<Item>,
    ) {
        let (name, attached) = match part.split_once(':') {
            Some((n, v)) => (n, Some(v)),
            None => (part, None),
        };
        let Some(&(_, act)) = row.slash.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) else {
            return;
        };
        let value = take_value(act, attached, w, args, i);
        out.push(Item::Param {
            act,
            value,
            written: w.clone(),
        });
    }

    /// A word as an operand of a file cmdlet: readable spellings, and whether
    /// the cmdlet expands wildcards. PowerShell's do so even inside quotes.
    fn operand(&self, w: &Word, literal: bool) -> Word {
        let mut out = w.clone();
        if w.has_substitution {
            return out;
        }
        // In single quotes it is a name, and names no variable to respell.
        if !out.literal_dollars {
            if let Some(home) = home_spelled(&out.text) {
                out.text = home;
            }
        }
        // Only a quoted word gets here with a dash: a file so named, which
        // `operands` must not read as POSIX options.
        if out.text.len() > 1 && out.text.starts_with('-') {
            out.text = format!("./{}", out.text);
        }
        let meta: &[char] = match self.dialect {
            Dialect::Cmd => &['*', '?'],
            _ => &['*', '?', '['],
        };
        let wild = !literal && out.text.contains(meta);
        out.glob = wild;
        out.glob_dots = wild;
        if wild {
            out.text = forward(&out.text);
        }
        out
    }

    fn path(&self, w: &Word, literal: bool) -> Word {
        let mut out = self.operand(w, literal);
        if !out.has_substitution {
            out.text = forward(&out.text);
        }
        out
    }

    fn unknown_from_pipeline(&mut self) -> Word {
        self.noted(NOTE_PIPELINE);
        Word {
            text: "$input".to_string(),
            has_substitution: true,
            ..Word::default()
        }
    }

    /// `rm`, `cat`, `ls`, `cd`, `pushd`: the words in place.
    fn in_order(&mut self, name: &str, items: Vec<Item>, piped: bool) -> Vec<Word> {
        let mut out = vec![plain(name)];
        let mut operands = 0;
        for item in items {
            match item {
                Item::Param {
                    act,
                    value,
                    written,
                } => match (act, value) {
                    (Act::Flag(f), _) => out.push(plain(f)),
                    (Act::Keep, _) => out.push(written),
                    (Act::Path, Some(v)) => {
                        operands += 1;
                        out.push(self.operand(&v, false));
                    }
                    (Act::Literal, Some(v)) => {
                        operands += 1;
                        out.push(self.operand(&v, true));
                    }
                    (act, _) => self.dropped(act),
                },
                Item::Pos { word, .. } => {
                    operands += 1;
                    out.push(self.operand(&word, false));
                }
                Item::Raw(w) => out.push(w),
            }
        }
        if piped && operands == 0 {
            out.push(self.unknown_from_pipeline());
        }
        out
    }

    fn dropped(&mut self, act: Act) {
        if let Act::Unread(why) | Act::UnreadSwitch(why) = act {
            self.noted(why);
        }
    }

    /// `cp` and `mv`: flags, sources, and the target last. Nothing of
    /// PowerShell's stays: `operands` would read a `t` in it as `-t`.
    fn copy(&mut self, name: &str, items: Vec<Item>, rename: bool, piped: bool) -> Vec<Word> {
        let mut flags = Vec::new();
        let mut sources = Vec::new();
        let mut target = None;
        for item in items {
            match item {
                Item::Param { act, value, .. } => match (act, value) {
                    (Act::Flag(f), _) => flags.push(plain(f)),
                    (Act::Path, Some(v)) => sources.push(self.path(&v, false)),
                    (Act::Literal, Some(v)) => sources.push(self.path(&v, true)),
                    (Act::Target, Some(v)) => target = Some(self.path(&v, false)),
                    (act, _) => self.dropped(act),
                },
                Item::Pos { word, .. } => sources.push(self.path(&word, false)),
                Item::Raw(w) if w.text == "--" => {}
                Item::Raw(_) => self.noted(NOTE_UNKNOWN),
            }
        }
        if piped && sources.is_empty() {
            sources.push(self.unknown_from_pipeline());
        }
        if target.is_none() && sources.len() >= 2 {
            target = sources.pop();
        }
        let mut target = target.unwrap_or_else(|| plain("./"));
        if target.has_substitution {
            self.noted(NOTE_TARGET);
        }
        if rename {
            // `-NewName` is a name beside the item, not under the cwd.
            let source = sources.first().filter(|s| !s.has_substitution);
            let parent = source.and_then(|s| s.text.rfind('/').map(|at| (s, at)));
            if let Some((source, at)) = parent {
                if !target.has_substitution && !target.text.contains('/') {
                    target.literal_dollars = joined_dollars_literal(source, &target);
                    target.text = format!("{}/{}", &source.text[..at], target.text);
                }
            }
        }
        let mut out = vec![plain(name)];
        out.append(&mut flags);
        out.append(&mut sources);
        out.push(target);
        out
    }

    /// `robocopy SRC DST [FILE…]`: the files are names under `SRC`.
    fn robocopy(&mut self, items: Vec<Item>) -> Vec<Word> {
        let mut flags = Vec::new();
        let mut name = "cp";
        let mut pos = Vec::new();
        for item in items {
            match item {
                Item::Param {
                    act: Act::Flag("--move"),
                    ..
                } => name = "mv",
                Item::Param {
                    act: Act::Flag(f), ..
                } => flags.push(plain(f)),
                Item::Param { act, .. } => self.dropped(act),
                Item::Pos { word, .. } => pos.push(self.path(&word, false)),
                Item::Raw(_) => {}
            }
        }
        if pos.len() < 2 {
            self.noted(NOTE_ROBOCOPY);
            let mut out = vec![plain(name)];
            out.append(&mut pos);
            return out;
        }
        let dir = |w: &Word| {
            let mut out = w.clone();
            if !out.text.ends_with('/') {
                out.text.push('/');
            }
            out
        };
        let src = dir(&pos[0]);
        let dst = dir(&pos[1]);
        let mut out = vec![plain(name)];
        out.append(&mut flags);
        let files = &pos[2..];
        let joined: usize = files.iter().map(|f| f.text.len()).sum::<usize>()
            + files.len().saturating_mul(src.text.len());
        if files.is_empty() || joined > MAX_JOINED {
            out.push(src.clone());
        }
        if joined > MAX_JOINED {
            self.noted(NOTE_TOO_LONG);
            out.extend(files.iter().cloned());
        } else {
            for file in files {
                let mut f = file.clone();
                f.literal_dollars = joined_dollars_literal(&src, file);
                f.text = format!("{}{}", src.text, file.text);
                f.has_substitution |= src.has_substitution;
                out.push(f);
            }
        }
        out.push(dst);
        out
    }

    /// `Set-Content` and friends: `> path` for each target. The first
    /// positional is the path, the next the value; array items go with the
    /// one before them.
    fn write(&mut self, lower: &str, args: &[Word], items: Vec<Item>) -> Vec<Word> {
        let mut targets = Vec::new();
        let mut last_was_target = false;
        for item in items {
            match item {
                Item::Param { act, value, .. } => {
                    last_was_target = false;
                    match (act, value) {
                        (Act::Path, Some(v)) => {
                            targets.push(self.operand(&v, false));
                            last_was_target = true;
                        }
                        (Act::Literal, Some(v)) => {
                            targets.push(self.operand(&v, true));
                            last_was_target = true;
                        }
                        (act, _) => self.dropped(act),
                    }
                }
                Item::Pos { word, cont } => {
                    // `Tee-Object` has one, but the real `tee` writes them all.
                    let tee = lower == "tee";
                    if targets.is_empty() || (cont && last_was_target) || tee {
                        targets.push(self.operand(&word, false));
                        last_was_target = true;
                    } else {
                        last_was_target = false;
                    }
                }
                Item::Raw(w) if w.text == "--" => {}
                Item::Raw(_) => self.noted(NOTE_UNKNOWN),
            }
        }
        if targets.is_empty() || targets.iter().any(|t| t.has_substitution) {
            self.noted(NOTE_TARGET);
        }
        // `sc` is `Set-Content` in 5.1 and `sc.exe` in 7: both stay readable.
        // `Set-Acl` is a write and a name the packs know.
        let mut out = Vec::new();
        let named = match lower {
            "sc" => Some("sc"),
            "set-acl" => Some("Set-Acl"),
            _ => None,
        };
        if let Some(name) = named {
            out.push(plain(name));
            out.extend(args.iter().filter(|w| !w.redirect).cloned());
        }
        for t in targets {
            out.push(redirect(">"));
            out.push(t);
        }
        out
    }

    /// `New-Item`: `touch`, `mkdir`, or `ln -s` for a link. A link is judged by
    /// its target, and noted: what comes after may go through it.
    fn new_item(&mut self, lower: &str, items: Vec<Item>) -> Vec<Word> {
        let mut paths = Vec::new();
        let mut leaf = None;
        let mut kind = None;
        let mut value = None;
        let mut rest = Vec::new();
        for item in items {
            match item {
                Item::Param { act, value: v, .. } => match (act, v) {
                    (Act::Path, Some(v)) => paths.push(self.path(&v, false)),
                    (Act::ItemName, Some(v)) => leaf = Some(v),
                    (Act::ItemType, Some(v)) => kind = Some(v),
                    (Act::ItemValue, Some(v)) => value = Some(v),
                    (act, _) => self.dropped(act),
                },
                Item::Pos { word, .. } => paths.push(self.path(&word, false)),
                Item::Raw(w) if w.text == "--" => {}
                Item::Raw(w) => rest.push(w),
            }
        }
        if let Some(leaf) = leaf {
            let joined: usize = paths.iter().map(|p| p.text.len()).sum::<usize>()
                + paths.len().saturating_mul(leaf.text.len());
            if joined > MAX_JOINED {
                self.noted(NOTE_TOO_LONG);
                paths.push(self.path(&leaf, false));
            } else if paths.is_empty() {
                paths.push(self.path(&leaf, false));
            } else {
                for p in &mut paths {
                    p.literal_dollars = joined_dollars_literal(p, &leaf);
                    p.text = format!("{}/{}", p.text.trim_end_matches('/'), forward(&leaf.text));
                    p.has_substitution |= leaf.has_substitution;
                }
            }
        }
        let is_kind = |full: &str, w: &Word| {
            let t = w.text.to_lowercase();
            !t.is_empty() && full.starts_with(&t)
        };
        let (name, link) = match &kind {
            Some(k) if k.has_substitution => {
                self.noted(NOTE_ITEM_TYPE);
                ("touch", false)
            }
            Some(k) if is_kind("directory", k) => ("mkdir", false),
            Some(k) if is_kind("file", k) => ("touch", false),
            Some(k)
                if is_kind("symboliclink", k)
                    || is_kind("junction", k)
                    || is_kind("hardlink", k) =>
            {
                ("ln", true)
            }
            Some(_) => {
                self.noted(NOTE_ITEM_TYPE);
                ("touch", false)
            }
            None if lower == "md" || lower == "mkdir" => ("mkdir", false),
            None => ("touch", false),
        };
        let mut out = vec![plain(name)];
        if link {
            self.noted(NOTE_LINK);
            out.push(plain("-s"));
            if let Some(v) = value {
                out.push(self.path(&v, true));
            }
        }
        out.append(&mut paths);
        out.append(&mut rest);
        out
    }

    /// `grep PATTERN PATH…`: the pattern must come first for `operands`.
    fn grep(&mut self, items: Vec<Item>) -> Vec<Word> {
        let mut pattern = None;
        let mut paths = Vec::new();
        let mut positional = Vec::new();
        let mut rest = Vec::new();
        for item in items {
            match item {
                Item::Param { act, value, .. } => match (act, value) {
                    (Act::Pattern, Some(v)) => pattern = Some(v),
                    (Act::Path, Some(v)) => paths.push(self.operand(&v, false)),
                    (Act::Literal, Some(v)) => paths.push(self.operand(&v, true)),
                    (act, _) => self.dropped(act),
                },
                Item::Pos { word, .. } => positional.push(word),
                Item::Raw(w) => rest.push(w),
            }
        }
        // Only the first positional can be the pattern. `operands` skips its
        // first operand as the pattern: an empty one holds the place, and an
        // unknown one must not be left out, or a file would be skipped instead.
        let mut positional = positional.into_iter();
        let mut out = vec![plain("grep")];
        if pattern.is_none() {
            pattern = positional.next();
        }
        match pattern {
            Some(p) => out.push(Word {
                has_substitution: false,
                ..p
            }),
            None if !paths.is_empty() => out.push(plain("")),
            None => {}
        }
        out.append(&mut paths);
        for p in positional {
            out.push(self.operand(&p, false));
        }
        out.append(&mut rest);
        out
    }

    fn kill(&mut self, items: Vec<Item>, piped: bool, all_processes: bool) -> Vec<Word> {
        let mut out = vec![plain("kill")];
        let mut targets = 0;
        let mut in_names = false;
        for item in items {
            match item {
                Item::Param {
                    act,
                    value,
                    written,
                } => {
                    in_names = false;
                    match (act, value) {
                        (Act::Path, Some(v)) => {
                            targets += 1;
                            out.push(v);
                        }
                        (Act::ProcName, Some(v)) => {
                            targets += 1;
                            in_names = true;
                            out.push(plain("-n"));
                            out.push(v);
                        }
                        (Act::ProcFilter, Some(v)) => {
                            targets += 1;
                            out.extend(filter_targets(&v));
                        }
                        (Act::Keep, _) => out.push(written),
                        (act, _) => self.dropped(act),
                    }
                }
                Item::Pos { word, cont } => {
                    targets += 1;
                    if cont && in_names {
                        out.push(plain("-n"));
                    } else {
                        in_names = false;
                    }
                    out.push(word);
                }
                Item::Raw(w) => out.push(w),
            }
        }
        if piped && targets == 0 {
            if all_processes {
                out.push(plain("*"));
            }
            out.push(self.unknown_from_pipeline());
        }
        out
    }

    fn curl(&mut self, items: Vec<Item>) -> Vec<Word> {
        let mut out = vec![plain("curl")];
        for item in items {
            match item {
                Item::Param {
                    act,
                    value,
                    written,
                } => match (act, value) {
                    (Act::Path, Some(v)) => out.push(v),
                    (Act::Target, Some(v)) => {
                        out.push(plain("-o"));
                        out.push(self.operand(&v, true));
                    }
                    // PowerShell 7's bare `curl` is the real one: `curl -i URL`.
                    (Act::InFile, Some(v)) if v.text.contains("://") => {
                        out.push(written);
                        out.push(v);
                    }
                    (Act::InFile, Some(v)) => {
                        let file = self.operand(&v, true);
                        out.push(plain("--data-binary"));
                        out.push(Word {
                            text: format!("@{}", file.text),
                            ..file
                        });
                    }
                    (Act::Keep, _) => out.push(written),
                    (act, _) => self.dropped(act),
                },
                Item::Pos { word, .. } => out.push(word),
                Item::Raw(w) => out.push(w),
            }
        }
        out
    }

    /// `Start-Process`: the argv it starts, read again as a command.
    fn start(&mut self, items: Vec<Item>, depth: u32) -> Vec<Word> {
        let mut file = None;
        let mut args = Vec::new();
        for item in items {
            match item {
                Item::Param { act, value, .. } => match (act, value) {
                    (Act::Path, Some(v)) => file = Some(v),
                    (Act::Args, Some(v)) => args.extend(split_arguments(&v)),
                    (Act::Out, Some(v)) => {
                        self.redirects.push(redirect(">"));
                        self.redirects.push(self.operand(&v, true));
                    }
                    (Act::In, Some(v)) => {
                        self.redirects.push(redirect("<"));
                        self.redirects.push(self.operand(&v, true));
                    }
                    (act, _) => self.dropped(act),
                },
                Item::Pos { word, .. } => {
                    if file.is_none() {
                        file = Some(word);
                    } else {
                        args.extend(split_arguments(&word));
                    }
                }
                Item::Raw(w) if w.text == "--" => {}
                Item::Raw(w) => {
                    self.noted(NOTE_UNKNOWN);
                    args.push(w);
                }
            }
        }
        let Some(file) = file else {
            self.noted(NOTE_START);
            return vec![plain("start-process")];
        };
        let mut argv = vec![file];
        argv.append(&mut args);
        if depth >= MAX_START_DEPTH {
            self.noted(NOTE_START);
            return argv;
        }
        let cx = Context {
            depth: depth + 1,
            ..Context::default()
        };
        let (out, note) = translate_noted(&argv, self.dialect, &cx);
        if let Some(n) = note {
            self.noted(n);
        }
        out
    }
}

/// The `/x` switches of a word, when it is switches here. In cmd anything with
/// a leading `/` is; elsewhere only what the row knows, or `/tmp` would go.
fn slash_parts<'a>(row: &Row, text: &'a str, cmd_mode: bool) -> Option<Vec<&'a str>> {
    let parts: Vec<&str> = text[1..].split('/').collect();
    let known = |p: &&str| {
        let name = p.split(':').next().unwrap_or(p);
        row.slash.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
    };
    (cmd_mode || parts.iter().all(known)).then_some(parts)
}

/// Can the word be a parameter? A quoted word never is, but a quote in the
/// value is fine: `-Path:'x'`. The reader tells `'-Path:x'` apart.
fn is_parameter(w: &Word) -> bool {
    param_shape(w).is_some() && (!w.quoted || w.text.contains(':'))
}

/// `-Name` or `-Name:value`, when the word has that shape.
fn param_shape(w: &Word) -> Option<(&str, Option<&str>)> {
    let rest = w.text.strip_prefix('-')?;
    let (name, value) = match rest.split_once(':') {
        Some((n, v)) => (n, Some(v)),
        None => (rest, None),
    };
    let first = name.chars().next()?;
    (first.is_alphabetic() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .then_some((name, value))
}

enum Lookup {
    Found(Act),
    Ambiguous,
    Unknown,
}

/// A parameter of the row or a common one: exact names first.
fn resolve(params: &[(&str, Act)], name: &str) -> Lookup {
    let exact = |list: &[(&str, Act)]| {
        list.iter()
            .find(|(p, _)| p.eq_ignore_ascii_case(name))
            .map(|&(_, act)| act)
    };
    if let Some(act) = exact(params).or_else(|| exact(COMMON)) {
        return Lookup::Found(act);
    }
    match lookup(params, name) {
        Lookup::Unknown => lookup(COMMON, name),
        found => found,
    }
}

fn lookup(params: &[(&str, Act)], name: &str) -> Lookup {
    if let Some(&(_, act)) = params.iter().find(|(p, _)| p.eq_ignore_ascii_case(name)) {
        return Lookup::Found(act);
    }
    let mut hits = params.iter().filter(|(p, _)| {
        p.get(..name.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(name))
    });
    let Some(&(_, act)) = hits.next() else {
        return Lookup::Unknown;
    };
    if hits.all(|&(_, other)| act.same(other)) {
        Lookup::Found(act)
    } else {
        Lookup::Ambiguous
    }
}

/// The value of a parameter: attached, or the next word. A `-Word` there is
/// the next parameter (PowerShell would refuse the line).
fn take_value(
    act: Act,
    attached: Option<&str>,
    w: &Word,
    args: &[Word],
    i: &mut usize,
) -> Option<Word> {
    let attached = attached.filter(|a| !a.is_empty());
    if let Some(a) = attached {
        return Some(Word {
            text: a.to_string(),
            ..w.clone()
        });
    }
    if !act.takes_value() {
        // `-Recurse: $false`: the value of a switch, when spelled with a colon.
        if w.text.ends_with(':') && args.get(*i).is_some_and(|n| !n.redirect) {
            *i += 1;
        }
        return None;
    }
    let next = args.get(*i)?;
    if next.redirect || (!next.quoted && param_shape(next).is_some()) {
        return None;
    }
    *i += 1;
    Some(next.clone())
}

/// `-ArgumentList` strings hold whole command lines: split them on blanks, with
/// double quotes grouping, as the program would.
fn split_arguments(w: &Word) -> Vec<Word> {
    if w.has_substitution {
        return vec![w.clone()];
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut in_quote = false;
    for c in w.text.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                in_word = true;
            }
            c if c.is_whitespace() && !in_quote => {
                if in_word {
                    out.push(plain(&std::mem::take(&mut cur)));
                    in_word = false;
                }
            }
            c => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(plain(&cur));
    }
    out
}

/// The nested command of `powershell`/`pwsh -Command|-c|-EncodedCommand|-enc|-e`,
/// `cmd /c|/k`, `iex '<literal>'` and `Invoke-Command -ScriptBlock {…}`. A form
/// it recognizes and cannot read gives `UNRESOLVED`, in PowerShell.
pub fn nested(argv: &[Word]) -> Option<(Dialect, String)> {
    let first = argv.first()?;
    if first.has_substitution {
        return None;
    }
    let args = &argv[1..];
    let ps = |s: String| Some((Dialect::PowerShell, s));
    match CommandName::of(&first.text).lower().as_str() {
        "powershell" | "pwsh" => powershell_nested(args).and_then(ps),
        "cmd" => cmd_nested(args).map(|s| (Dialect::Cmd, s)),
        "iex" | "invoke-expression" => iex_nested(args).and_then(ps),
        "invoke-command" | "icm" => invoke_command_nested(args).and_then(ps),
        _ => None,
    }
}

/// Is it a shell, or `iex`: a command whose text `nested` reads?
pub(crate) fn is_nesting_command(text: &str) -> bool {
    matches!(
        CommandName::of(text).lower().as_str(),
        "powershell" | "pwsh" | "cmd" | "iex" | "invoke-expression"
    )
}

/// A POSIX shell by name, as `operands` and `inline_payload` know them.
pub(crate) fn is_posix_shell(name: &str) -> bool {
    POSIX_SHELLS.contains(&name)
}

const POSIX_SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh"];

/// `words` without the redirections of the outer shell and their targets.
pub(crate) fn without_redirects(words: &[Word]) -> Vec<Word> {
    let mut out = Vec::with_capacity(words.len());
    let mut it = words.iter();
    while let Some(w) = it.next() {
        if w.redirect {
            it.next();
        } else {
            out.push(w.clone());
        }
    }
    out
}

const NOTE_STDIN: &str = "this shell has no command here, so it reads its commands from stdin";
pub(crate) const NOTE_WSL: &str =
    "wsl with no command, or with an option the guard does not know, cannot be judged";

/// A shell (`argv`, program name stripped) given no command to read: it runs what
/// is on its stdin (`echo 'rd /s /q C:\\' | cmd`), which nothing here sees. An
/// option that only asks the shell about itself is not that. The reason, if so.
/// `wsl` has its own reading (`wsl_lines`).
pub(crate) fn unread_shell(argv: &[Word]) -> Option<&'static str> {
    let (first, args) = argv.split_first()?;
    if first.has_substitution {
        return None;
    }
    let name = CommandName::of(&first.text).lower();
    let text = |w: &'_ Word| w.text.to_ascii_lowercase();
    match name.as_str() {
        "cmd" => {
            let about = args.iter().any(|w| text(w) == "/?");
            (!about && nested(argv).is_none()).then_some(NOTE_STDIN)
        }
        "powershell" | "pwsh" => {
            let about = args.iter().any(|w| {
                matches!(
                    text(w).as_str(),
                    "-?" | "/?"
                        | "-h"
                        | "-help"
                        | "--help"
                        | "/help"
                        | "-v"
                        | "-version"
                        | "--version"
                )
            });
            (!about && nested(argv).is_none()).then_some(NOTE_STDIN)
        }
        n if is_posix_shell(n) => {
            let about = args
                .iter()
                .any(|w| matches!(w.text.as_str(), "--version" | "--help"));
            // `-s`: stdin, whatever follows. A first word that is no option is a
            // script, and `-c` has its text read by `inline_payload`.
            let dashed = |w: &&Word| w.text.starts_with('-') && !w.text.starts_with("--");
            let stdin = args.iter().filter(dashed).any(|w| w.text.contains('s'));
            let command = args
                .iter()
                .filter(|w| w.has_substitution || !w.text.starts_with('-'))
                .count();
            let inline = args.iter().filter(dashed).any(|w| w.text.contains('c'))
                || args.iter().any(|w| w.text.starts_with("--command"));
            (!about && !inline && (stdin || command == 0)).then_some(NOTE_STDIN)
        }
        _ => None,
    }
}

/// `wsl [options] [--] line`: the POSIX lines the Linux side may run, for the
/// engine to judge. Empty when it only reports on itself, and `UNRESOLVED` when
/// nothing can be read (no command: stdin; an option not known here, which
/// `--unregister` is). `wsl` hands its raw command line to a shell, so `bash -c
/// 'a b'` may reach it with its quotes or without them. Both are judged.
pub(crate) fn wsl_lines(argv: &[Word]) -> Option<Vec<String>> {
    let (first, args) = argv.split_first()?;
    if first.has_substitution || CommandName::of(&first.text).lower() != "wsl" {
        return None;
    }
    let unread = || Some(vec![UNRESOLVED.to_string()]);
    let mut i = 0;
    let command = loop {
        let Some(w) = args.get(i) else {
            return unread();
        };
        if w.has_substitution {
            return unread();
        }
        i += 1;
        match w.text.as_str() {
            "--" | "-e" | "--exec" => break &args[i..],
            "-d" | "--distribution" | "--distribution-id" | "-u" | "--user" | "--cd"
            | "--shell-type" => i += 1,
            "--system" => {}
            "-l" | "--list" | "--status" | "--version" | "-v" | "--help" | "-h" => {
                return Some(Vec::new());
            }
            t if t.starts_with('-') => return unread(),
            _ => break &args[i - 1..],
        }
    };
    if command.first().is_none_or(|w| w.has_substitution) {
        return unread();
    }
    let plain = joined(None, command);
    let quoted = command
        .iter()
        .map(|w| {
            if w.text.contains(char::is_whitespace) {
                format!("'{}'", w.text.replace('\'', r"'\''"))
            } else {
                w.text.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut lines = vec![quoted];
    if lines[0] != plain {
        lines.push(plain);
    }
    Some(lines)
}

fn abbreviates(name: &str, full: &str, min: usize) -> bool {
    name.len() >= min && full.starts_with(name)
}

fn joined(head: Option<&str>, rest: &[Word]) -> String {
    head.into_iter()
        .chain(rest.iter().map(|w| w.text.as_str()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn powershell_nested(args: &[Word]) -> Option<String> {
    let unresolved = || Some(UNRESOLVED.to_string());
    let mut i = 0;
    while i < args.len() {
        let w = &args[i];
        i += 1;
        if w.text == "-" {
            return unresolved();
        }
        let option = ["--", "-", "/"].iter().find_map(|p| w.text.strip_prefix(p));
        // Quotes do not count: PowerShell strips them for a native program, so
        // `powershell '-c' 'x'` is `-c x`. Blanks mean a string, not an option.
        let option = option.filter(|o| !w.has_substitution && !o.contains(char::is_whitespace));
        // `/tmp/x.ps1` is no `/option`: that name holds no path or extension.
        if w.text.starts_with('/')
            && option.is_some_and(|o| {
                o.split(':')
                    .next()
                    .is_some_and(|n| n.contains(['/', '\\', '.']))
            })
        {
            return unresolved();
        }
        let Some(option) = option else {
            // `powershell.exe`'s default parameter is -Command. `pwsh` takes a
            // file there: the text is judged either way.
            return Some(joined(None, &args[i - 1..]));
        };
        let (name, attached) = match option.split_once(':') {
            Some((n, v)) => (n, Some(v).filter(|v| !v.is_empty())),
            None => (option, None),
        };
        let name = name.to_ascii_lowercase();
        let n = name.as_str();
        let takes_value = abbreviates(n, "executionpolicy", 2)
            || abbreviates(n, "inputformat", 2)
            || abbreviates(n, "outputformat", 1)
            || abbreviates(n, "windowstyle", 1)
            || abbreviates(n, "configurationname", 4)
            || abbreviates(n, "configurationfile", 8)
            || abbreviates(n, "psconsolefile", 2)
            || abbreviates(n, "version", 1)
            || abbreviates(n, "workingdirectory", 2)
            || abbreviates(n, "custompipename", 2)
            || abbreviates(n, "settingsfile", 2)
            || abbreviates(n, "encodedarguments", 8)
            || matches!(n, "ep" | "if" | "of" | "wd" | "ea");
        if takes_value {
            if attached.is_none() {
                i += 1;
            }
        } else if abbreviates(n, "file", 1) {
            return unresolved();
        } else if n == "ec" || abbreviates(n, "encodedcommand", 1) {
            return match attached {
                Some(text) => decode_encoded(text),
                None => match args.get(i) {
                    Some(v) if !v.has_substitution => decode_encoded(&v.text),
                    _ => None,
                },
            }
            .or_else(unresolved);
        } else if abbreviates(n, "command", 1) {
            let text = joined(attached, &args[i..]);
            return if text.is_empty() || text == "-" {
                unresolved()
            } else {
                Some(text)
            };
        }
    }
    None
}

fn cmd_nested(args: &[Word]) -> Option<String> {
    for (i, w) in args.iter().enumerate() {
        // cmd skips these in front of a switch: `cmd;/c`, `cmd =/c`.
        let mut s = w.text.trim_start_matches([',', ';', '=']);
        while s.starts_with('/') {
            let end = s[1..].find('/').map_or(s.len(), |at| at + 1);
            let letter = s[1..].chars().next().map(|c| c.to_ascii_lowercase());
            if matches!(letter, Some('c' | 'k' | 'r')) {
                let head = s.get(2..).filter(|h| !h.is_empty());
                let text = joined(head, &args[i + 1..]);
                return (!text.is_empty()).then_some(text);
            }
            s = &s[end..];
        }
    }
    None
}

/// All of `iex`'s words that are not parameters or their values, joined: it
/// has one positional, so more than one word is a line PowerShell refuses.
fn iex_nested(args: &[Word]) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let w = &args[i];
        i += 1;
        let shape = param_shape(w).filter(|_| is_parameter(w));
        let Some((name, value)) = shape else {
            parts.push(&w.text);
            continue;
        };
        let value = value.filter(|v| !v.is_empty());
        if abbreviates(&name.to_ascii_lowercase(), "command", 1) {
            match value {
                Some(v) => parts.push(v),
                None => match args.get(i) {
                    Some(next) => {
                        parts.push(&next.text);
                        i += 1;
                    }
                    None => return Some(UNRESOLVED.to_string()),
                },
            }
        } else if value.is_none()
            && (w.text.ends_with(':') || matches!(lookup(COMMON, name), Lookup::Found(Act::Skip)))
        {
            // `-Verbose: $true`: a trailing colon takes the next word.
            i += 1;
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn invoke_command_nested(args: &[Word]) -> Option<String> {
    let block = args.iter().find_map(|w| {
        (!w.quoted)
            .then(|| w.text.strip_prefix('{')?.strip_suffix('}'))
            .flatten()
    });
    if let Some(body) = block {
        return Some(body.to_string());
    }
    let script_file = args.iter().any(|w| {
        param_shape(w).is_some_and(|(n, _)| abbreviates(&n.to_ascii_lowercase(), "filepath", 1))
    });
    (script_file || args.iter().any(|w| w.has_substitution)).then(|| UNRESOLVED.to_string())
}

/// Base64 of UTF-16LE, at most `MAX_ENCODED` decoded. As strict as .NET's
/// `Convert.FromBase64String`, apart from blanks.
fn decode_encoded(text: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut bits = 0u32;
    let mut held = 0u32;
    let mut count = 0usize;
    let mut padding = 0usize;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                count += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        if padding > 0 {
            return None;
        }
        count += 1;
        bits = (bits << 6) | u32::from(v);
        held += 6;
        if held >= 8 {
            held -= 8;
            bytes.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
            if bytes.len() > MAX_ENCODED {
                return None;
            }
        }
    }
    if count == 0 || !count.is_multiple_of(4) || padding > 2 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let text = String::from_utf16(&units).ok()?;
    Some(text.strip_prefix('\u{feff}').unwrap_or(&text).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Word {
        Word {
            text: text.to_string(),
            ..Word::default()
        }
    }

    fn tr(argv: &[&str], d: Dialect) -> Vec<String> {
        let words: Vec<Word> = argv.iter().map(|a| w(a)).collect();
        translate(&words, d).into_iter().map(|w| w.text).collect()
    }

    fn nest(argv: &[&str]) -> Option<(Dialect, String)> {
        let words: Vec<Word> = argv.iter().map(|a| w(a)).collect();
        nested(&words)
    }

    /// Base64 of the UTF-16LE of `s`, as `powershell -enc` takes it.
    fn encode(s: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn posix_is_untouched() {
        // The table only: on a Windows-style host the engine strips argv[0]
        // before the POSIX reading (`normalize::windows_program_names`).
        assert_eq!(tr(&["del", "/s", "x"], Dialect::Posix), ["del", "/s", "x"]);
        assert_eq!(tr(&["git.exe"], Dialect::Posix), ["git.exe"]);
    }

    #[test]
    fn an_empty_argv_stays_empty() {
        assert!(translate(&[], Dialect::PowerShell).is_empty());
        assert_eq!(nested(&[]), None);
    }

    #[test]
    fn a_substitution_in_command_position_is_kept() {
        let words = [
            Word {
                text: "$x".into(),
                has_substitution: true,
                ..Word::default()
            },
            w("-Recurse"),
        ];
        let out = translate(&words, Dialect::PowerShell);
        assert!(out[0].has_substitution);
        assert_eq!(out[1].text, "-Recurse");
    }

    #[test]
    fn matching_ignores_case_directory_and_extension() {
        for name in [
            "Remove-Item",
            "REMOVE-ITEM",
            r"Microsoft.PowerShell.Management\Remove-Item",
            "ri",
            "RI",
        ] {
            assert_eq!(
                tr(&[name, "-r", "x"], Dialect::PowerShell),
                ["rm", "-r", "x"],
                "{name}"
            );
        }
    }

    #[test]
    fn parameters_match_by_unambiguous_prefix() {
        for p in ["-r", "-R", "-re", "-rec", "-Recu", "-Recurse", "-RECURSE"] {
            assert_eq!(tr(&["ri", p, "x"], Dialect::PowerShell), ["rm", "-r", "x"]);
        }
        for p in ["-fo", "-Fo", "-for", "-Force"] {
            assert_eq!(tr(&["ri", p, "x"], Dialect::PowerShell), ["rm", "-f", "x"]);
        }
        // Force and Filter: ambiguous, so as written whatever the case.
        assert_eq!(
            tr(&["ri", "-f", "x"], Dialect::PowerShell),
            ["rm", "-f", "x"]
        );
        assert_eq!(
            tr(&["ri", "-F", "x"], Dialect::PowerShell),
            ["rm", "-F", "x"]
        );
        // Not a prefix of anything: as written, its value still an operand.
        assert_eq!(
            tr(&["ri", "-Nope", "x"], Dialect::PowerShell),
            ["rm", "-Nope", "x"]
        );
        assert_eq!(
            tr(&["ri", "-rf", "x"], Dialect::PowerShell),
            ["rm", "-rf", "x"]
        );
    }

    #[test]
    fn cmd_rows() {
        let cmd = Dialect::Cmd;
        assert_eq!(
            tr(&["rd", "/s", "/q", r"C:\"], cmd),
            ["rm", "-r", "-f", r"C:\"]
        );
        assert_eq!(
            tr(&["RMDIR", "/S", "/Q", "x"], cmd),
            ["rm", "-r", "-f", "x"]
        );
        assert_eq!(
            tr(&["del", "/s", "/q", "/f", r"C:\Users\a"], cmd),
            ["rm", "-r", "-f", "-f", r"C:\Users\a"]
        );
        assert_eq!(tr(&["del", "/s/q", "x"], cmd), ["rm", "-r", "-f", "x"]);
        assert_eq!(tr(&["erase", "/p", "x"], cmd), ["rm", "x"]);
        assert_eq!(tr(&["copy", "/y", "a", "b"], cmd), ["cp", "a", "b"]);
        assert_eq!(tr(&["copy", "a", "b", "/y"], cmd), ["cp", "a", "b"]);
        assert_eq!(tr(&["xcopy", "/e", "a", "b"], cmd), ["cp", "-r", "a", "b"]);
        assert_eq!(tr(&["move", "/y", "a", "b"], cmd), ["mv", "a", "b"]);
        assert_eq!(tr(&["ren", "a", "b"], cmd), ["mv", "a", "b"]);
        assert_eq!(tr(&["type", "a"], cmd), ["cat", "a"]);
        assert_eq!(tr(&["dir", "/s", "/b", "src"], cmd), ["ls", "-R", "src"]);
        assert_eq!(
            tr(&["findstr", "/s", "key", "a"], cmd),
            ["grep", "key", "a"]
        );
        assert_eq!(tr(&["findstr", "/c:key", "a"], cmd), ["grep", "key", "a"]);
        assert_eq!(tr(&["cd", "/d", "x"], cmd), ["cd", "x"]);
        assert_eq!(tr(&["chdir", "x"], cmd), ["cd", "x"]);
        assert_eq!(tr(&["pushd", "x"], cmd), ["pushd", "x"]);
        assert_eq!(
            tr(&["taskkill", "/f", "/im", "saiife.exe"], cmd),
            ["kill", "-n", "saiife.exe"]
        );
        assert_eq!(
            tr(&["start", "/b", "cmd", "/c", "x"], cmd),
            ["cmd", "/c", "x"]
        );
        // The `/` switches of an alias stay paths in PowerShell, except the
        // ones the review needs in both readings.
        assert_eq!(
            tr(&["del", "/s", "/q", r"C:\"], Dialect::PowerShell),
            ["rm", "-r", "-f", r"C:\"]
        );
        assert_eq!(tr(&["ls", "/tmp"], Dialect::PowerShell), ["ls", "/tmp"]);
        assert_eq!(tr(&["cat", "/s"], Dialect::PowerShell), ["cat", "/s"]);
    }

    #[test]
    fn cmd_title_of_start_is_no_program() {
        let words = [
            w("start"),
            Word {
                text: "t".into(),
                quoted: true,
                ..Word::default()
            },
            w("rd"),
            w("/s"),
            w("x"),
        ];
        let out: Vec<_> = translate(&words, Dialect::Cmd)
            .into_iter()
            .map(|w| w.text)
            .collect();
        assert_eq!(out, ["rm", "-r", "x"]);
    }

    #[test]
    fn robocopy_sources_join_their_directory() {
        let cmd = Dialect::Cmd;
        assert_eq!(
            tr(&["robocopy", r"C:\a", r"C:\b", ".env", "/s"], cmd),
            ["cp", "-r", "C:/a/.env", "C:/b/"]
        );
        assert_eq!(
            tr(&["robocopy", r"C:\a", r"C:\b"], cmd),
            ["cp", "C:/a/", "C:/b/"]
        );
        assert_eq!(
            tr(&["robocopy", r"C:\a", r"C:\b", "/mov"], cmd),
            ["mv", "C:/a/", "C:/b/"]
        );
    }

    #[test]
    fn leading_slashes_of_a_share_survive_on_windows() {
        assert_eq!(unc_text("//host/s").as_deref(), Some(r"\\host/s"));
        assert_eq!(unc_text("///host/s").as_deref(), Some(r"\\host/s"));
        assert_eq!(unc_text("/x"), None);
        assert_eq!(unc_text(r"\\host\s"), None);
    }

    #[test]
    fn nested_powershell_forms() {
        for flag in [
            "-c",
            "-C",
            "-co",
            "-Command",
            "-COMMAND",
            "/c",
            "/Command",
            "--command",
        ] {
            assert_eq!(
                nest(&["powershell", flag, "rm", "x"]),
                Some((Dialect::PowerShell, "rm x".to_string())),
                "{flag}"
            );
        }
        assert_eq!(
            nest(&[
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "-nop",
                "-w",
                "hidden",
                "-c",
                "rm x"
            ]),
            Some((Dialect::PowerShell, "rm x".to_string()))
        );
        assert_eq!(
            nest(&[
                "pwsh",
                "-NoLogo",
                "-ExecutionPolicy",
                "Bypass",
                "-Command:rm",
                "x"
            ]),
            Some((Dialect::PowerShell, "rm x".to_string()))
        );
        // powershell.exe's default parameter is -Command.
        assert_eq!(
            nest(&["powershell", "rm x"]),
            Some((Dialect::PowerShell, "rm x".to_string()))
        );
        assert_eq!(nest(&["powershell"]), None);
        assert_eq!(nest(&["powershell", "-NoProfile"]), None);
        assert_eq!(nest(&["git", "-c", "rm x"]), None);
        for unread in [
            vec!["pwsh", "-File", "x.ps1"],
            vec!["pwsh", "-f", "x.ps1"],
            vec!["powershell", "-"],
            vec!["powershell", "-Command", "-"],
            vec!["powershell", "-Command"],
        ] {
            assert_eq!(
                nest(&unread),
                Some((Dialect::PowerShell, UNRESOLVED.to_string())),
                "{unread:?}"
            );
        }
    }

    #[test]
    fn nested_encoded_command() {
        let inner = r"Remove-Item -Recurse -Force C:\";
        let b64 = encode(inner);
        for flag in [
            "-e",
            "-E",
            "-ec",
            "-en",
            "-enc",
            "-Enc",
            "-EncodedCommand",
            "/enc",
            "/e",
        ] {
            assert_eq!(
                nest(&["powershell", flag, &b64]),
                Some((Dialect::PowerShell, inner.to_string())),
                "{flag}"
            );
        }
        assert_eq!(
            nest(&["pwsh", "-EncodedCommand:", &b64]).map(|n| n.1),
            Some(inner.to_string())
        );
        assert_eq!(
            nest(&["pwsh", &format!("-enc:{b64}")]).map(|n| n.1),
            Some(inner.to_string())
        );
    }

    #[test]
    fn a_bad_encoded_command_is_unresolved() {
        let unresolved = Some((Dialect::PowerShell, UNRESOLVED.to_string()));
        for bad in [
            "!!notbase64",
            "abc",  // .NET refuses what is not padded to four
            "QQ==", // one byte: not UTF-16
            "AND$", // not base64
            "ANg=", // half of a surrogate pair
        ] {
            assert_eq!(nest(&["pwsh", "-e", bad]), unresolved, "{bad}");
        }
        assert_eq!(nest(&["pwsh", "-enc"]), unresolved);
        let words = [
            w("pwsh"),
            w("-enc"),
            Word {
                text: "$x".into(),
                has_substitution: true,
                ..Word::default()
            },
        ];
        assert_eq!(nested(&words), unresolved);
    }

    #[test]
    fn encoded_size_limit() {
        let fits = "a".repeat(64 * 1024 / 2);
        assert_eq!(
            nest(&["pwsh", "-e", &encode(&fits)]).map(|n| n.1),
            Some(fits)
        );
        let over = "a".repeat(64 * 1024 / 2 + 1);
        assert_eq!(
            nest(&["pwsh", "-e", &encode(&over)]).map(|n| n.1),
            Some(UNRESOLVED.to_string())
        );
    }

    #[test]
    fn nested_cmd_forms() {
        for argv in [
            vec!["cmd", "/c", "rd", "/s", "x"],
            vec!["cmd", "/C", "rd /s x"],
            vec!["cmd.exe", "/k", "rd /s x"],
            vec!["CMD.EXE", "/K", "rd /s x"],
            vec![r"C:\Windows\System32\cmd.exe", "/c", "rd /s x"],
            vec!["cmd", "/d", "/s", "/c", "rd /s x"],
            vec!["cmd", "/s/c", "rd /s x"],
            vec!["cmd", "/crd /s x"],
            vec!["cmd", "/c", "rd", "/s x"],
            vec!["cmd", "/q", "/v:on", "/e:on", "/c", "rd /s x"],
            vec!["cmd", "/r", "rd /s x"],
        ] {
            assert_eq!(
                nest(&argv),
                Some((Dialect::Cmd, "rd /s x".to_string())),
                "{argv:?}"
            );
        }
        assert_eq!(nest(&["cmd"]), None);
        assert_eq!(nest(&["cmd", "/q"]), None);
    }

    #[test]
    fn nested_iex_and_invoke_command() {
        let ps = |s: &str| Some((Dialect::PowerShell, s.to_string()));
        assert_eq!(nest(&["iex", "rm x"]), ps("rm x"));
        assert_eq!(nest(&["IEX", "rm x"]), ps("rm x"));
        assert_eq!(nest(&["Invoke-Expression", "rm x"]), ps("rm x"));
        assert_eq!(nest(&["Invoke-Expression", "-Command", "rm x"]), ps("rm x"));
        assert_eq!(nest(&["iex", "-c", "rm x"]), ps("rm x"));
        assert_eq!(nest(&["iex", "-Command:rm x"]), ps("rm x"));
        assert_eq!(nest(&["iex"]), None);

        let block = Word {
            text: "{ rm x }".into(),
            has_substitution: true,
            ..Word::default()
        };
        for argv in [
            vec![w("Invoke-Command"), w("-ScriptBlock"), block.clone()],
            vec![w("icm"), block.clone()],
            vec![w("ICM"), w("-ComputerName"), w("h"), w("-s"), block.clone()],
        ] {
            assert_eq!(nested(&argv), ps(" rm x "), "{argv:?}");
        }
        // A quoted brace is a string.
        let quoted = Word {
            text: "{ rm x }".into(),
            quoted: true,
            ..Word::default()
        };
        assert_eq!(nested(&[w("icm"), quoted]), None);
        let var = Word {
            text: "$sb".into(),
            has_substitution: true,
            ..Word::default()
        };
        assert_eq!(nested(&[w("icm"), w("-ScriptBlock"), var]), ps(UNRESOLVED));
        assert_eq!(nest(&["icm", "-FilePath", "x.ps1"]), ps(UNRESOLVED));
    }
}
