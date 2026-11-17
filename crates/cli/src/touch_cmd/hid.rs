//! A FIDO2 key over USB HID (feature `fido-hid`), in this process: the
//! `Transport` over `saiife_fido::hid`. Never run in tests.

use std::time::Duration;

use saiife_fido::hid;
use saiife_fido::proto::{AssertReq, EnrolReq};
use saiife_touch::TouchError;

use super::{run_touch, Transport};

/// The CTAP calls on a worker thread, bounded by the prompt limit (D4).
pub(crate) struct InProcess;

impl Transport for InProcess {
    fn devices(&self) -> Result<usize, TouchError> {
        Ok(hid::device_count())
    }

    fn assert(
        &self,
        r: AssertReq,
        limit: Duration,
    ) -> Result<Result<(Vec<u8>, Vec<u8>, Vec<u8>), String>, TouchError> {
        run_touch(move || Ok(hid::assert(&r)), limit)
    }

    fn enrol(&self, r: EnrolReq, limit: Duration) -> Result<Result<Vec<u8>, String>, TouchError> {
        run_touch(move || Ok(hid::enrol(&r)), limit)
    }
}
