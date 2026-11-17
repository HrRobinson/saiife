//! The FIDO helper: hello, one request on stdin, one answer on stdout
//! (`saiife-fido/1`). Only the HID calls and the line protocol; no output
//! other than the protocol lines (the library's keep-alive text is off).

use std::ffi::OsString;
use std::process::ExitCode;

use saiife_fido::helper::{args_ok, serve, Backend};
use saiife_fido::hid;
use saiife_fido::proto::{AssertParts, AssertReq, EnrolReq};

struct HidBackend;

impl Backend for HidBackend {
    fn devices(&self) -> usize {
        hid::device_count()
    }
    fn assert(&self, r: &AssertReq) -> Result<AssertParts, String> {
        hid::assert(r)
    }
    fn enrol(&self, r: &EnrolReq) -> Result<Vec<u8>, String> {
        hid::enrol(r)
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if !args_ok(&args) {
        eprintln!("saiife-fido takes no arguments");
        return ExitCode::from(2);
    }
    ExitCode::from(serve(
        std::io::stdin().lock(),
        std::io::stdout().lock(),
        &HidBackend,
    ))
}
