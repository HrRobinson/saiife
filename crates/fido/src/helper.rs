//! The helper's serving loop (plan 41 task 2): hello, one request, one
//! answer. No printing: the binaries own stdout and stderr.

use std::ffi::OsString;
use std::io::{BufRead, Read, Write};

use zeroize::Zeroizing;

use crate::proto::{
    decode, encode, Answer, AssertParts, AssertReq, EnrolReq, Hello, Request, MAX_LINE, PROTO,
};

/// What answers the requests: the HID key, or a double.
pub trait Backend {
    fn devices(&self) -> usize;
    fn assert(&self, r: &AssertReq) -> Result<AssertParts, String>;
    fn enrol(&self, r: &EnrolReq) -> Result<Vec<u8>, String>;
}

/// `saiife-fido` takes no arguments (`args` is argv without the program).
pub fn args_ok(args: &[OsString]) -> bool {
    args.is_empty()
}

/// The hello this build sends.
pub fn hello(devices: usize) -> Hello {
    Hello {
        proto: PROTO,
        version: env!("CARGO_PKG_VERSION").to_string(),
        devices,
    }
}

/// Reads one line, at most `MAX_LINE + 1` bytes (so an oversized line is
/// seen as such and never buffered whole). `None` on EOF before any byte.
pub(crate) fn read_line(mut input: impl BufRead) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut line = Zeroizing::new(Vec::new());
    let mut limited = (&mut input).take(MAX_LINE as u64 + 1);
    let n = limited.read_until(b'\n', &mut line)?;
    Ok((n > 0).then_some(line))
}

/// Hello, one request, one answer. The exit code: 0, or 2 for a bad request.
pub fn serve(input: impl BufRead, output: impl Write, b: &dyn Backend) -> u8 {
    serve_hello(hello(b.devices()), input, output, b)
}

/// `serve` with a chosen hello (the fake alters it).
pub fn serve_hello(
    hello: Hello,
    input: impl BufRead,
    mut output: impl Write,
    b: &dyn Backend,
) -> u8 {
    if write_line(&mut output, &Answer::Hello(hello)).is_err() {
        return 1;
    }
    let line = match read_line(input) {
        Ok(Some(l)) => l,
        Ok(None) => return 0,
        Err(_) => return 1,
    };
    let (answer, code) = match decode::<Request>(&line) {
        Err(why) => (Answer::error(&format!("bad request: {why}")), 2),
        Ok(Request::Assert(r)) => (
            match b.assert(&r) {
                Ok((credential_id, auth_data, signature)) => Answer::Assertion {
                    credential_id,
                    auth_data,
                    signature,
                },
                Err(e) => Answer::error(&e),
            },
            0,
        ),
        Ok(Request::Enrol(r)) => (
            match b.enrol(&r) {
                Ok(auth_data) => Answer::Attestation { auth_data },
                Err(e) => Answer::error(&e),
            },
            0,
        ),
    };
    if write_line(&mut output, &answer).is_err() {
        return 1;
    }
    code
}

pub(crate) fn write_line(out: &mut impl Write, a: &Answer) -> std::io::Result<()> {
    out.write_all(&encode(a))?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::io::Cursor;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct Out(Rc<RefCell<Vec<u8>>>);
    impl Write for Out {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Fails the test if asked for input before the hello is in the output.
    struct Input {
        out: Out,
        data: Cursor<Vec<u8>>,
        reads: Rc<Cell<usize>>,
    }
    impl Read for Input {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.data.read(b)
        }
    }
    impl BufRead for Input {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            {
                let o = self.out.0.borrow();
                assert_eq!(o.iter().filter(|c| **c == b'\n').count(), 1, "hello first");
                assert!(o.starts_with(b"{\"t\":\"hello\""));
            }
            self.reads.set(self.reads.get() + 1);
            self.data.fill_buf()
        }
        fn consume(&mut self, n: usize) {
            self.data.consume(n);
        }
    }

    #[derive(Default)]
    struct Double {
        calls: Cell<usize>,
        err: Option<String>,
    }
    impl Backend for Double {
        fn devices(&self) -> usize {
            1
        }
        fn assert(&self, _: &AssertReq) -> Result<AssertParts, String> {
            self.calls.set(self.calls.get() + 1);
            match &self.err {
                Some(e) => Err(e.clone()),
                None => Ok((vec![1], vec![2], vec![3])),
            }
        }
        fn enrol(&self, _: &EnrolReq) -> Result<Vec<u8>, String> {
            self.calls.set(self.calls.get() + 1);
            Ok(vec![9])
        }
    }

    const ASSERT: &str = r#"{"op":"assert","rp_id":"x","challenge":"0000000000000000000000000000000000000000000000000000000000000000","allow":[]}"#;

    type Ran = (u8, Vec<String>, Rc<Cell<usize>>, Cursor<Vec<u8>>);
    fn run(data: Vec<u8>, b: &Double) -> Ran {
        let out = Out::default();
        let reads = Rc::new(Cell::new(0));
        let mut input = Input {
            out: out.clone(),
            data: Cursor::new(data),
            reads: reads.clone(),
        };
        let code = serve(&mut input, out.clone(), b);
        let text = String::from_utf8(out.0.borrow().clone()).unwrap();
        let lines = text.lines().map(str::to_string).collect();
        (code, lines, reads, input.data)
    }

    #[test]
    fn hello_comes_first() {
        let b = Double::default();
        let (code, lines, reads, _) = run(format!("{ASSERT}\n").into_bytes(), &b);
        assert_eq!(code, 0);
        assert!(reads.get() >= 1);
        let h: Answer = decode(lines[0].as_bytes()).unwrap();
        assert_eq!(
            h,
            Answer::Hello(Hello {
                proto: PROTO,
                version: env!("CARGO_PKG_VERSION").into(),
                devices: 1
            })
        );
    }

    #[test]
    fn eof_after_hello_touches_nothing() {
        let b = Double::default();
        let (code, lines, _, _) = run(Vec::new(), &b);
        assert_eq!((code, lines.len(), b.calls.get()), (0, 1, 0));
    }

    #[test]
    fn one_request_one_answer() {
        let b = Double::default();
        let (code, lines, _, rest) = run(format!("{ASSERT}\n{ASSERT}\n").into_bytes(), &b);
        assert_eq!(code, 0);
        assert_eq!(lines.len(), 2);
        assert!(matches!(
            decode::<Answer>(lines[1].as_bytes()),
            Ok(Answer::Assertion { .. })
        ));
        assert_eq!(b.calls.get(), 1);
        // The second line was never consumed.
        assert_eq!(rest.position() as usize, ASSERT.len() + 1);
    }

    #[test]
    fn bad_request_is_an_error_answer() {
        let b = Double::default();
        let (code, lines, _, _) = run(b"{\"op\":\"assert\"}\n".to_vec(), &b);
        assert_eq!(code, 2);
        match decode::<Answer>(lines[1].as_bytes()) {
            Ok(Answer::Error { error }) => assert!(error.starts_with("bad request:"), "{error}"),
            o => panic!("{o:?}"),
        }
        assert_eq!(b.calls.get(), 0);
    }

    #[test]
    fn oversized_request_is_refused() {
        let b = Double::default();
        let mut data = vec![b'a'; MAX_LINE + 10];
        data.push(b'\n');
        let (code, lines, _, rest) = run(data, &b);
        assert_eq!(code, 2);
        assert!(lines[1].contains("bad request:"), "{}", lines[1]);
        assert_eq!(b.calls.get(), 0);
        // Not buffered whole: at most MAX_LINE + 1 bytes were taken.
        assert!(rest.position() as usize <= MAX_LINE + 1);
    }

    #[test]
    fn backend_error_text_is_cut() {
        let b = Double {
            err: Some("e".repeat(2000)),
            ..Double::default()
        };
        let (code, lines, _, _) = run(format!("{ASSERT}\n").into_bytes(), &b);
        assert_eq!(code, 0);
        match decode::<Answer>(lines[1].as_bytes()) {
            Ok(Answer::Error { error }) => assert!(error.chars().count() <= 512),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn args_ok_only_without_arguments() {
        assert!(args_ok(&[]));
        assert!(!args_ok(&[OsString::from("--help")]));
        assert!(!args_ok(&[OsString::from("")]));
    }
}
