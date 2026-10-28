# AWS SigV4 signing test suite (header signing)

These cases are vendored, unmodified, from the AWS Common Runtime auth library:

- Repository: https://github.com/awslabs/aws-c-auth
- Directory: `tests/aws-signing-test-suite/v4/`
- Commit: `3d29adcecf5c032131acee9f4125a636d2aaea6a` (fetched 2026-10-28)
- License: Apache License 2.0 (https://github.com/awslabs/aws-c-auth/blob/3d29adcecf5c032131acee9f4125a636d2aaea6a/LICENSE)

Only the header-signing files are kept from each case: `context.json`,
`request.txt`, `header-canonical-request.txt`, `header-string-to-sign.txt`,
`header-signature.txt` and `header-signed-request.txt`. The `query-*` files
(presigned URLs) are not vendored.

The credentials are the suite's documentation placeholders (`AKIDEXAMPLE`
and its example secret; two cases carry example session tokens). They are
not real keys.

`crates/broker/tests/sigv4_suite.rs` runs every directory here. It checks the
canonical request, the string to sign and the signature byte for byte, and,
where the request target is a valid ASCII URI (not `get-utf8` or the space
cases, whose raw paths are sent percent-encoded), that `sigv4::sign` produces the
`Authorization` line of `header-signed-request.txt`.

## Excluded cases

- `get-header-value-multiline`: its header value is folded over several
  lines (obsolete HTTP line folding). saiife never sends such a header, and
  `http::HeaderValue` cannot hold one.
