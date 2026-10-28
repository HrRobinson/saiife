# Plan 15 — Cloud connectors (AWS SigV4 and STS, GCP and Azure tokens) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An agent reaches AWS, GCP and Azure through `saiifed` without ever holding a cloud credential.
- In `mode = "sign"` (the default), the daemon signs each request with AWS SigV4, or attaches an OAuth2 access token that it mints from a GCP service account or an Azure service principal held in the vault.
- In `mode = "sts"` (AWS only, opt-in and labelled), `saiife run --cloud <service> -- <cmd>` mints a 15-minute `sts:AssumeRole` credential. It carries an inline session policy built from the saiife allow list, and it goes only into that one command's environment.
- Capabilities follow the IAM action (`s3:GetObject` → `s3:read:arn:aws:s3:::<bucket>/<key>`).
- Cloud key shapes are masked.
- Each cloud connector gets a docs page.

**Architecture:**
- `crates/broker` gains a `cloud` module:
  - `sigv4`: a pure, sync signer, tested on the official AWS vectors;
  - `jwt`: the GCP RS256 assertion;
  - `token`: the GCP and Azure token exchange over the existing `Upstream`;
  - `sts`: AssumeRole, with a minimal XML reader;
  - `session_policy`: turns the saiife policy into an IAM session policy and refuses anything wider.
- Plan 14's manifest schema is **extended, never redefined**. It gains:
  - in-label host placeholders;
  - a `raw` body kind;
  - per-operation `headers`, `fixed_query` and `iam_action`;
  - two object-key parameter types;
  - three cloud auth kinds.
- Five embedded manifests: `aws-s3`, `aws-sts`, `gcp-storage`, `azure-arm` and `azure-blob`.
- Plan 14's credential path becomes one hook and one cache:
  - `Env::oauth_token` becomes `Env::credential`;
  - `daemon::oauth::TokenCache` is keyed by (secret, scope);
  - oauth2, GCP, Azure and the AWS assumed role all go through them.
- The pipeline signs, or attaches the token, at step 9, after the final headers are set.
- The daemon gains the cloud vault kinds and a `cloud.lease` op.
- The CLI gains `run --cloud`, the cloud forms of `secret add`, and cloud support in `connect`.
- `doctor` lists every STS-mode service.

**Tech Stack:** Rust workspace, with no new crates. The plan reuses what Cargo.lock holds:
- `ring` 0.17.14, a transitive dependency of rustls, becomes a direct dependency of `broker` for HMAC-SHA256 and RSASSA-PKCS1-v1_5-SHA256;
- `sha2` 0.10.9, `base64` 0.23.1 and `rustls-pemfile` 2.2.0;
- `percent-encoding`, `serde_json` and `time`;
- `rcgen` 0.14.10 (dev).

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers:
- §15.2 row 15;
- §6.13;
- §6.6 (the vault kinds `aws`, `gcp_sa` and `azure_sp`, and the refresh-failure record);
- §6.7.1 steps 9–10 for cloud auth;
- §6.8.1, and the Cloud row of §6.8.3;
- §8.4 (the schema additions);
- §7 row `saiife run --cloud`;
- §6.16 (doctor);
- §13 (golden requests, masking, offline).

Plans 10, 12 and 14 set the style and the connector pattern (manifest, `Env::secret`, `request::build`, `Upstream`).

## Global Constraints

- **No privileged or process-control tools on the dev machine.** Never run sudo, root, systemctl, polkit tools, docker, kill, pkill, killall or pgrep. CI-only scripts are checked with `bash -n` only.
- **Test isolation:** set `TMPDIR` and `SAIIFE_TEST_TMP` to a short directory made by `mktemp -d -p /home/jonas/projects/personal/saiife`, and remove it afterwards. Never use /tmp, the real home or `~/.claude`.
- **Internet:** implementers may use web access **only** to fetch public reference data: the AWS SigV4 test-suite vectors (Task 1) and vendor API docs (the paths and API versions in Task 8). Tests never use the network.
  - Every cloud endpoint in a test is a loopback mock with an `rcgen` certificate for the real host name, trusted through `Upstream::with_roots`. A test `Resolver` maps the real name to `127.0.0.1:<port>`.
  - `scripts/test-offline.sh` stays green.
- **Test seams** are gated on `debug_assertions`, not `cfg(test)`, whenever an integration test drives the CLI binary.
- **Hook path untouched:** `guard`, `audit`, `policy`, `ipc` and `system` stay tokio-free. The `scripts/bench-check.sh` medians for `saiife check` stay within +1 ms of `main`. `broker` keeps `#![forbid(unsafe_code)]`.
- **Secret values never leave the daemon**, except in the upstream request, a token-endpoint request or a `cloud.lease` answer.
  - This covers access keys, secret keys, session tokens, private keys, JWT assertions, client secrets and minted tokens.
  - These values never appear in a record, an error, a log line, `Debug` output or a panic.
  - Each new test greps its audit files and stderr for every secret value it used.
- **Commits:**
  - Branch `plan-15-cloud` from `main`, after plans 16 and 14 have merged. Plan 15 merges **before** plan 17.
  - Each task is committed in its worktree and cherry-picked, with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - Never commit `.superpowers/`.
  - Never commit token-shaped literals. Build `AKIA…`/`ASIA…` (including the docs' `AKIAIOSFODNN7EXAMPLE`), `ya29.…`, `AIza…`, JWTs and PEM `BEGIN PRIVATE KEY` lines at runtime with `concat!`.
  - `gh` needs `GH_CONFIG_DIR=$HOME/.config/gh-personal`.
  - No tags.
- **Spec values, verbatim:**
  - `mode = "sign"` (default): "the daemon signs each request itself (AWS SigV4; GCP and Azure OAuth2 access tokens from a service account or service principal held in the vault)". "The agent never sees credentials."
  - "Capabilities follow the IAM action (`s3:GetObject` maps to `s3:read:<arn>`)."
  - `mode = "sts"` (opt-in, labelled): `saiife run --cloud aws -- <command>` "mints credentials that last at most 15 minutes with `sts:AssumeRole` and an inline session policy built from the saiife allow list, and puts them only in that command's environment."
  - "`doctor` lists every service in STS mode."
  - Vault kinds are `aws`, `gcp_sa` and `azure_sp`. "A secret can only be used by services named in that list."
  - "A failed refresh is a `secret`/`refresh_failed` record and a notification."
  - Steps 1–8 never touch the network. Agent-supplied `Authorization`, `Cookie` and `Host` are always dropped.
  - Each vault value in use is masked in these forms: raw, base64 (standard and URL-safe, padded and unpadded), URL-encoded and hex. Minted tokens and session credentials count as vault values in use.
  - `saiife run` exit codes are those of `run --secret`: 2 refused, 5 unavailable, otherwise the command's own code.
- **Consumes (from plans 14 and 16; these are their exact names):**
  - Plan 14 owns the connector schema:
    - host placeholders (`hosts = ["{param}"]`, a whole host);
    - the body kinds `json|form|text` and `graphql`;
    - the manifest-wide `Manifest.headers` (literal or `{param}` values, which win over the agent's headers, with its list of banned names);
    - `crates/broker/build.rs` as the built-in list;
    - `crates/broker/tests/docs_pages.rs` (one page per connector id, `## Locked mode` and `## Suggested policy`, toml blocks valid with zero warnings, and the "every write under `ask`" block).
  - Plan 14 owns oauth2:
    - `Env::oauth_token` (with `force` for the 401 retry);
    - `daemon::oauth::TokenCache` (single-flight, with `TokenCache::forget` called on `secret rotate` and `secret remove`);
    - `Event::RefreshFailed` (with a `reason` field, notified at most once per secret per hour);
    - the `secret`/`refresh_failed` record.
  - Plan 14 owns environments: `policy::environment::ServiceOverride`, which uses `deny_unknown_fields` and has no `mode` or `cloud` field.
  - Plan 14 owns masking: the RULES count test `one_extra_pass_only` in `audit/src/mask.rs`.
  - Plan 16 owns `Ctx.mode` and the `CtxInit` defaults (later fields are added with `..` defaults). `vault.bin` stays the store in both daemons; only the key moves to the keychain. `cloud.lease` and `run --cloud` behave in personal mode as `secret.lease` and `run --secret` do.
- **Decisions this plan makes** (each is restated in its task):
  1. **No new crates.** HMAC and RS256 come from `ring = "=0.17.14"` (with the house comment). No `hmac` crate, no AWS, GCP or Azure SDK, no XML or JWT crate. Check that `cargo tree -i ring -e features` shows `alloc`.
  2. **One manifest per cloud API**, each with one base URL, one auth entry, and one SigV4 service or OAuth scope. The admin names the service. For example, `[services.aws] connector = "aws-s3"` gives the spec's `saiife api aws s3.get_object …`.
  3. **S3 uses path-style addressing:** `https://s3.{region}.amazonaws.com/{bucket}/{key}`. With virtual-hosted style the agent would choose the host. A bucket in another region answers 301, which is `redirect_refused`, and the docs say to set `params.region`.
  4. **SigV4 rules follow the service name.**
     - For `s3`: no double encoding, no path normalization, and an `x-amz-content-sha256` header.
     - For every other service: double encoding and path normalization, with no content header.
     - The signer rewrites the URI in AWS `UriEncode` form, so what is signed is what is sent.
     - Every header present at signing time is signed.
  5. **Object keys hold `/`**, through two new parameter types:
     - `objectkey` (S3 and Azure): `/` is kept and each segment is percent-encoded. It may only be the last whole path segment, and it is reachable by proxy as the path's tail.
     - `objectname` (GCS): the whole value is encoded, so `/` becomes `%2F`. It is named-only.

     Both refuse an empty value, more than 1024 bytes, a control character, `\`, an empty segment, and a `.` or `..` segment.
  6. **Token endpoints are pinned in code:**
     - GCP: `https://oauth2.googleapis.com/token`. A key file's `token_uri` is ignored.
     - Azure: `https://{authority}/{tenant}/oauth2/v2.0/token`, where `authority` is `login.microsoftonline.com` (the default), `login.microsoftonline.us` or `login.chinacloudapi.cn`.

     Tests reach them through the `Resolver` seam only.
  7. **One credential cache.** Plan 14's `TokenCache` is re-keyed to `(secret, scope)`.
     - The scope is the manifest `scope` for GCP and Azure, `sts:<role_arn>` for the AWS assumed role, and `""` for oauth2.
     - Plan 14's refresh rule (`expires_in` − 60 s), single-flight and `forget(secret)` (which now drops every scope of that secret) apply to every kind.
     - A failed mint is never cached.
     - Token responses are read up to 64 KiB, and redirects are not followed.
  8. **Sign mode may assume a role.** With `[services.x.cloud] role_arn`, the daemon signs with `AssumeRole` credentials (3600 s, no session policy) held in the cache. Without one, it signs with the vault keys.
  9. **STS mode is AWS only for now.** GCP and Azure cannot scope a token down in general, so `mode = "sts"` on those connectors is a config error. (Spec note; owner confirm.)
  10. **The session policy never widens the saiife policy.**
      - An `allow` pattern gives `Allow <op.iam_action>` on its qualifier. A missing qualifier becomes `*`, and a trailing `**` becomes `*`.
      - A single `*`, `?`, `$`, `{` or `}` in an allow qualifier makes the service unrepresentable (refused): IAM's `*` crosses `/`, and `?` and `${…}` are IAM syntax.
      - An `allow` rule with `when` is refused.
      - `ask` and `deny` patterns, and `ask` or `deny` rules (with `when` ignored), become `Deny` statements.
      - The output is deterministic JSON of at most 2048 bytes. Its SHA-256 goes in the lease record.
  11. **STS mode needs `role_arn` and `[services.x.cloud] run_allow`.** `run_allow` is checked like `[secrets.*] run_allow`. Each lease lasts `DurationSeconds = 900`, which is both the AWS minimum and the spec's maximum. The session name is `saiife-<uid>-<8 hex>`.
  12. **Environments cannot set `mode` or `cloud`:** `ServiceOverride` has no such fields. They can still override `secret` and `params` (for example `region`).
  13. **The STS response is read with a minimal tag extractor:** the `Credentials` fields and `Error/Code`, each exactly once, with the five XML entities unescaped. S3 and Azure XML bodies pass through as text and are masked as today.
  14. **The SigV4 vectors** come from `awslabs/aws-c-auth` `tests/aws-signing-test-suite/v4/` (Apache-2.0), at a pinned commit, fetched by the Task 1 implementer.
      - Only the header-signing cases are vendored.
      - The fixture README records the URL, the commit and the license.
      - Cases with multi-line header values are excluded and listed there.
  15. **The GCP test key** is a 2048-bit RSA PKCS#8 DER, generated once with `openssl` and committed as hex. The PEM is built at runtime.
  16. **`run --cloud` scrubs the inherited AWS environment:**
      - It removes `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_CONTAINER_*` and the three credential variables.
      - It sets the three credentials, `AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_SHARED_CREDENTIALS_FILE=/dev/null` and `AWS_CONFIG_FILE=/dev/null`.
      - It masks the three values in the output.
      - It cannot be combined with `--secret`.
  17. **A lease counts as one request against `requests_per_minute`.** Other limits cannot bind a handed-out credential, and `policy check` warns about that.
  18. **Cloud error codes** come only from the OAuth `error` field or the STS `Error/Code`, sanitized to `[A-Za-z0-9_.]{1,64}`. An `error_description` or `Message` is never recorded or printed.
- **Spec notes** (added to the spec in Task 12):
  - §8.4: object keys may contain `/`, through the two new parameter types `objectkey` and `objectname` (decision 5). Every other path parameter still may not.
  - §6.13: STS mode is AWS only for now (decision 9). This goes to Owner handwork → confirm.

## Review Focus

1. **S3 key encoding:** a space, `+`, `%`, `~`, `=`, `&`, non-ASCII or `!*'()`. Expected: the bytes on the wire equal the signed canonical URI, and `+` is never sent as a space (Task 1: `sent_uri_equals_canonical_for_awkward_keys`; Task 8: `s3_get_object_awkward_key_golden`).
2. **A signature at the UTC date boundary** (23:59:59.9). Expected: `X-Amz-Date` and the scope date come from the same instant (Task 1: `scope_date_and_amz_date_same_instant`).
3. **A minted token or session credential echoed back** in a response body, an STS error or a token-endpoint error. Expected: `[MASKED]`, and the assertion, the client secret and the private key never appear in a record or an error (Task 9: `minted_token_masked_in_response`; Task 6: `mint_errors_hold_no_secret`).
4. **A burst of calls just after expiry, or a token endpoint that is down.** Expected: one mint per (secret, scope), no cached failure, and the next call retries (Task 9: `single_flight_per_secret_and_scope`, `failed_mint_not_cached`).
5. **A session policy wider than the saiife policy:** a single `*`, `?`, `${aws:username}`, an allow rule with `when`, or an `ask` pattern. Expected: refused, or turned into `Deny` (Task 7: `session_policy_never_wider`).

---

## Task order and parallelism

- **Wave 1** (in parallel, file-disjoint): Tasks 1, 2, 3, 4 and 5.
- **Wave 2:**
  - Task 6 needs 1.
  - Task 7 needs 1, 2 and 5.
  - Task 8 needs 1 and 5.
- **Wave 3** (in parallel):
  - Task 9 needs 3, 6, 7 and 8.
  - Task 10 needs 2, 3 and 7.
  - Task 11 needs 2, 7 and 8.
  - Tasks 9 and 10 both touch `daemon/src/ops.rs` and `secret_ops.rs`, in disjoint hunks. Cherry-pick 9 first.
- **Wave 4:** Task 12.
- **Then:** the review, one fix wave, the gates, push, PR and CI. The owner merges.

**Shared files with plan 17.** Plan 15 merges first, and plan 17 rebases. Each change to these is small and additive:
- `ipc/src/msg.rs`: one const.
- `daemon/src/ops.rs`: one dispatch arm.
- `cli/src/main.rs`: the `Run` args.
- `broker/src/pipeline.rs`: step 9, plus the `Env::credential` rename.
- `broker/src/manifest.rs`: the Task 5 schema additions.
- **Plan 17 owns** the MCP schema mapping for `objectkey`, `objectname` and `body = "raw"`.

---

### Task 1: SigV4 signer and the AWS test-suite vectors

**Files:**
- Create:
  - `crates/broker/src/cloud/mod.rs` (`pub mod sigv4;` and `CloudError`);
  - `crates/broker/src/cloud/sigv4.rs`;
  - `crates/broker/tests/sigv4_suite.rs`;
  - `crates/broker/tests/fixtures/sigv4/` (the cases and a `README.md`).
- Modify: `crates/broker/src/lib.rs`, and `crates/broker/Cargo.toml` (`ring = "=0.17.14"` with the comment "already in Cargo.lock through rustls; ring only").

**Interfaces:**
- `pub enum CloudError { Key(String), Endpoint { code: String }, Response(String), Transport(BrokerError), Unrepresentable { pattern: String, why: &'static str }, TooLarge }`. It derives `thiserror`, and no message holds a value.
- `pub struct AwsCreds { pub access_key_id: Zeroizing<String>, pub secret_access_key: Zeroizing<String>, pub session_token: Option<Zeroizing<String>> }`. Its `Debug` prints `AwsCreds{..}`.
- `pub struct SignOpts { pub region, pub service, pub double_encode: bool, pub normalize_path: bool, pub content_sha256_header: bool, pub omit_session_token: bool }`, built by `pub fn for_service(region, service) -> SignOpts` (decision 4).
- `pub fn canonical_request(method, path, query, headers: &[(String, String)], payload_sha256_hex, o: &SignOpts) -> (String, String /*signed headers*/)`. The rules are those of the AWS SigV4 docs, and the vectors pin them.
- `pub fn string_to_sign(at: OffsetDateTime, scope: &str, creq: &str) -> String`
- `pub fn scope(at, region, service) -> String`
- `pub fn signing_key(secret, date, region, service) -> [u8; 32]`
- `pub fn sign(b: &mut Built, c: &AwsCreds, o: &SignOpts, at: OffsetDateTime) -> Result<(), CloudError>`:
  - it rewrites `b.uri` into the canonical encoding;
  - it sets or replaces `host` (the authority `Upstream::once` sends), `x-amz-date`, `x-amz-security-token`, `x-amz-content-sha256` (when set) and `authorization`, all from the same `at`.

- [ ] **Step 1: Fetch and vendor the vectors** (decision 14; web access is allowed for this step only). `git diff --stat` must show no `AKIA`/`ASIA`-shaped string; the suite's `AKIDEXAMPLE` is not token-shaped.
- [ ] **Step 2: Failing tests:**
  - `aws_suite_vectors`: for every case, the canonical request, the string to sign and the signature equal the files byte for byte, with at least 20 cases run.
  - `signing_key_matches_aws_docs_example`: `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, `20120215`, `us-east-1`, `iam` → `c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9`.
  - `s3_get_object_docs_example`: the S3 "GET Object" example from the AWS docs, with the expected signature copied from that page. The key id is built with `concat!`.
  - `scope_date_and_amz_date_same_instant`: at `2026-10-28T23:59:59.900Z`, both say `20261028`.
  - `sent_uri_equals_canonical_for_awkward_keys`: the key `a b+c/ü~%=&!*'()`, where `+` → `%2B`.
  - `existing_signing_headers_replaced`
  - `session_token_signed_unless_omitted`
  - `debug_hides_creds`
- [ ] **Step 3:** Run `cargo test -p saiife-broker --test sigv4_suite` and check that it fails.
- [ ] **Step 4:** Implement with `ring::hmac::HMAC_SHA256` and `sha2`.
- [ ] **Step 5:** Get it green with clippy clean, then commit `feat(broker): SigV4 signer tested on the AWS signing test suite`.

### Task 2: policy — `mode` and `[services.x.cloud]`

**Files:** Modify `crates/policy/src/service.rs` and `crates/policy/src/load.rs` (`validate_services`). Tests go in the modules.

**Interfaces:**
- `pub enum CloudMode { #[default] Sign, Sts }`, lowercase.
- `ServiceCfg.mode: CloudMode` and `ServiceCfg.cloud: CloudCfg`, both `#[serde(default)]`.
- `pub struct CloudCfg { pub role_arn: Option<String>, pub external_id: Option<String>, pub run_allow: Vec<PathBuf>, pub authority_host: Option<String> }`, with `deny_unknown_fields`.
- Validation:
  - `role_arn` matches `^arn:aws(-cn|-us-gov)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`;
  - `external_id` matches `^[A-Za-z0-9+=,.@:/_-]{2,1224}$`;
  - `authority_host` is one of the three Azure hosts (decision 6);
  - `mode = "sts"` needs a `role_arn` and a non-empty `run_allow` of absolute, non-interpreter paths (`is_interpreter`).
- The effective-policy hash covers `mode` and `cloud`.
- Checks that need the manifest are in Task 11.

- [ ] **Step 1: Failing tests:**
  - `mode_defaults_to_sign`
  - `sts_needs_role_arn_and_run_allow`
  - `bad_role_arn_refused`
  - `run_allow_interpreter_refused_in_cloud`
  - `authority_host_allowlist`
  - `cloud_unknown_key_refused`
  - `environment_cannot_set_mode_or_cloud`: a `ServiceOverride` with `mode` or `cloud` is refused, and the error names the key.
  - `policy_hash_changes_with_mode`
- [ ] Steps 2–5. Commit `feat(policy): cloud mode and [services.*.cloud]`.

### Task 3: vault kinds `aws`, `gcp_sa` and `azure_sp`; `secret add` and `import`

**Files:** Modify:
- `crates/daemon/src/vault.rs` (`Kind`);
- `crates/daemon/src/secret_ops.rs` (`parse_kind`, `field_names`, `check_fields`);
- `crates/daemon/src/api_ops.rs` (`kind_str` only; `spec_for` returns `None` for the cloud kinds until Task 9);
- `crates/cli/src/secret_cmd.rs`, `crates/cli/src/import_cmd.rs`, and `crates/cli/src/run_cmd.rs::mask_values`.

**Interfaces:**
- `Kind::{Aws, GcpSa, AzureSp}`, serialized as `aws`, `gcp_sa` and `azure_sp`. Plan 14's message "comes with plan 15" goes away.
- Fields:
  - `aws`: `{access_key_id, secret_access_key, session_token?}`. The key id matches `^(AKIA|ASIA)[A-Z0-9]{16}$`.
  - `gcp_sa`: `{client_email, private_key, private_key_id, project_id?}`. `client_email` ends in `.iam.gserviceaccount.com`, and `private_key` has PEM framing. The key itself is parsed in Task 6.
  - `azure_sp`: `{tenant_id, client_id, client_secret}`. Each id is a GUID; the tenant may also be a domain.
- `secret add`:
  - `--from-file` takes a JSON object with the field names, or, for `gcp_sa`, Google's key file (`type = "service_account"`; `token_uri` is dropped with a note).
  - Interactive input prompts for each field without echo.
  - `--from-env` is refused for kinds with several fields.
- `secret import`: each `~/.aws/credentials` profile that has both keys becomes an `aws` candidate named `aws-<profile>`, with the guessed service `aws-s3`.

- [ ] **Step 1: Failing tests:**
  - `cloud_kinds_roundtrip_vault`
  - `aws_fields_checked`
  - `gcp_key_file_parsed_token_uri_ignored`
  - `gcp_wrong_type_refused`
  - `azure_ids_checked`
  - `from_env_refused_for_multi_field`
  - `import_aws_profiles_as_aws_kind`
  - `cloud_values_never_in_records_or_errors`
  - `mask_values_cover_every_cloud_field`

  Every literal is built with `concat!`.
- [ ] Steps 2–5. Commit `feat(vault): aws, gcp_sa and azure_sp secret kinds`.

### Task 4: masking cloud key shapes

**Files:** Modify `crates/audit/src/mask.rs`.

**Interfaces:** Add two `RULES` entries after plan 14's alternation, which keeps the extra passes to two:
- **Full mask** (one alternation):
  - `ya29\.[A-Za-z0-9_-]{20,}`
  - `AIza[0-9A-Za-z_-]{35}`
  - `\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`
- **Prefix kept** (one alternation in group 1, replaced by `${1}[MASKED]`):
  - `"(?:SecretAccessKey|SessionToken|secret_access_key|session_token|private_key|client_secret|access_token|refresh_token)"\s*:\s*"`
  - `<(?:SecretAccessKey|SessionToken)>`
  - `(?i:AccountKey=|SharedAccessSignature=)`
  - `[?&]sig=`

  The group is followed by `[^"<;&\s]{8,}`.

- [ ] **Step 1: Failing tests** (literals built at runtime):
  - `gcp_access_token`
  - `google_api_key`
  - `jwt_needs_three_parts`
  - `sa_json_private_key_escaped_newlines`
  - `sts_xml_and_json_secret_and_token`
  - `azure_account_key_and_sas`
  - `plain_words_untouched`
  - Plan 14's `one_extra_pass_only` now expects plan 14's count plus 2.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Run `cargo test -p saiife-audit -p saiife-guard`.
- [ ] **Step 4:** Run `scripts/bench-check.sh` against `main`; the result must stay within +1 ms.
- [ ] **Step 5:** Commit `feat(audit): mask cloud key shapes`.

### Task 5: extend plan 14's manifest schema for cloud APIs

**Files:** Modify `crates/broker/src/manifest.rs`, `params.rs`, `request.rs` and `resolve.rs`. Tests go in `crates/broker/tests/schema.rs` (plan 14's file).

**Interfaces** (additions only; plan 14's keys keep their meaning):
- **In-label host placeholder.** Besides plan 14's whole-host `{param}`, a `hosts` entry and the `base_url` host may hold `{param}` inside a label, as in `s3.{region}.amazonaws.com` or `{account}.blob.core.windows.net`.
  - The param must be `required`, with an anchored `pattern`.
  - The value must be one DNS label (`[a-z0-9-]`, **no dots**), checked again at `catalog::validate` and at build time.
- **`body = "raw"`**, next to `json|form|text`. The agent's bytes are sent as they are. The strict-JSON parse and the amount step are skipped, so an operation with `amount` and a raw body is a manifest error. `body_sha256` is the hash of the bytes sent.
- **Per-operation `headers`** (the same syntax and banned names as `Manifest.headers`; the operation's value wins over the manifest's), plus **`fixed_query: BTreeMap<String, String>`**:
  - fixed query values are appended after the agent's query;
  - a named call that sets a fixed-query name gets `UnknownParam`;
  - a proxy query that sets one must carry exactly the fixed value, or it gets `BadPath`.
- **`iam_action: Option<String>`** (`^[A-Za-z0-9.:/*-]{1,128}$`).
- **`ParamType::{ObjectKey, ObjectName}`** per decision 5. The proxy matches an `objectkey` tail and skips operations with an `objectname`.
- **`AuthSpec` gains `service`** (required for `aws_sigv4`) **and `scope`** (an `https://` URL, required for `gcp_sa` and `azure_sp`). `AUTH_KINDS` gains these three kinds, and none of them takes a `secret_field`. `auth_header` returns `None` for them, because Task 9 adds the auth.

- [ ] **Step 1: Failing tests:**
  - `in_label_host_placeholder_pinned`
  - `in_label_host_value_with_dot_refused` (for example `region = "x.evil"`)
  - `objectkey_segments_encoded_slash_kept`
  - `objectkey_dot_and_empty_segments_refused`
  - `objectname_slash_encoded`
  - `objectkey_must_be_last_whole_segment`
  - `raw_body_sent_verbatim_skips_json_and_amount`
  - `raw_body_with_amount_refused`
  - `op_headers_win_over_manifest_and_agent`
  - `op_header_banned_names_refused`
  - `fixed_query_cannot_be_set_by_agent`
  - `proxy_fixed_query_mismatch_refused`
  - `proxy_objectkey_tail_matches`
  - `proxy_objectname_op_unreachable`
  - `cloud_auth_kinds_need_service_or_scope`
- [ ] Steps 2–5. Commit `feat(broker): cloud schema additions (in-label hosts, raw body, per-op headers and fixed query, object keys)`.

### Task 6: GCP JWT and the GCP and Azure token exchange

**Files:** Create `crates/broker/src/cloud/{jwt.rs, token.rs}`, `crates/broker/tests/cloud_tokens.rs` and `crates/broker/tests/fixtures/gcp/test-rsa-2048.pk8.hex`. Modify `cloud/mod.rs`.

**Interfaces** (pure broker functions; the cache lives in the daemon, see Task 9):
- `pub struct GcpKey { pub client_email, pub key_id, pair: RsaKeyPair }`. Its `Debug` shows the email only.
- `pub fn parse_gcp_key(fields) -> Result<GcpKey, CloudError>`: `rustls_pemfile`, then `RsaKeyPair::from_pkcs8`, for RSA keys of 2048 bits or more.
- `pub fn assertion(k: &GcpKey, scope: &str, now) -> Result<Zeroizing<String>, CloudError>`: the RS256 JWT of Google's service-account flow, with `aud = GCP_TOKEN_URL` and a lifetime of 3600 s.
- `pub fn gcp_request(k, scope, now) -> Result<Built, CloudError>` and `pub fn azure_request(fields, authority: Option<&str>, scope) -> Result<Built, CloudError>`: form POSTs to the decision 6 endpoints (the `jwt-bearer` and `client_credentials` grants).
- `pub fn parse_token_response(status, body, now) -> Result<Token, CloudError>`. It returns plan 14's `Token`, extended with an `expires_at` if one is needed.
  - `token_type` must be `Bearer`.
  - `access_token` is printable ASCII of at most 8 KiB.
  - `expires_in` is in `1..=86400`; a numeric string is accepted.
  - An error answer gives `Endpoint { code }` (decision 18).
- `pub async fn mint(up: &Upstream, req: Built) -> Result<Token, CloudError>`: a 64 KiB cap, and a 3xx is an error.

- [ ] **Step 1: Failing tests** (loopback with rcgen certificates for `oauth2.googleapis.com` and `login.microsoftonline.com`):
  - `gcp_assertion_verifies_with_public_key`: the mock checks the signature with `UnparsedPublicKey`, plus `iss`, `aud`, `scope`, the lifetime and the grant.
  - `gcp_mint_against_loopback`
  - `azure_mint_against_loopback`: the tenant in the path and the form fields.
  - `azure_authority_not_listed_refused`
  - `token_response_table`: a missing `expires_in`, `token_type = "mac"`, more than 64 KiB, non-JSON, and a 400 `invalid_grant` whose description is absent from the error.
  - `mint_errors_hold_no_secret`
  - `token_endpoint_redirect_refused`
- [ ] Steps 2–5. Commit `feat(broker): GCP and Azure OAuth2 token exchange`.

### Task 7: STS AssumeRole and the session policy

**Files:** Create `crates/broker/src/cloud/{sts.rs, session_policy.rs}` and `crates/broker/tests/cloud_sts.rs`. Modify `cloud/mod.rs`.

**Interfaces:**
- `pub struct AssumeRole<'a> { pub role_arn: &'a str, pub session_name: String, pub duration_s: u32, pub policy: Option<&'a str>, pub external_id: Option<&'a str> }`
- `pub fn session_name(uid: u32) -> String`
- `pub fn assume_role_request(region, p) -> Result<Built, CloudError>`: the STS Query API `AssumeRole` call (`Version=2011-06-15`), as a form POST to `https://sts.{region}.amazonaws.com/`.
- `pub fn parse_assume_role(status, body) -> Result<(AwsCreds, OffsetDateTime), CloudError>` (decision 13).
- `pub async fn assume(up, base: &AwsCreds, region, p, now) -> Result<(AwsCreds, OffsetDateTime), CloudError>`: signed for `sts`. The expiry is the earlier of the returned `Expiration` and `now + duration_s`.
- `pub struct SessionPolicy { pub json: String, pub sha256: String }`
- `pub fn build(svc: &ServiceCfg, m: &Manifest) -> Result<SessionPolicy, CloudError>` (decision 10). An allow pattern matching an operation without an `iam_action` is `Unrepresentable`.

- [ ] **Step 1: Failing tests:**
  - `parse_assume_role_fixture` (the AWS docs response shape, with values built at runtime)
  - `sts_error_code_only`
  - `xml_entities_unescaped`
  - `duplicate_or_missing_credentials_refused`
  - `assume_role_signed_and_sent_to_loopback` (the mock checks `DurationSeconds=900`, the `Policy` and the `…/sts/aws4_request` scope)
  - `expiration_capped_at_requested_duration`
  - `session_policy_table`:
    - `s3:read:arn:aws:s3:::reports/**` → `Allow s3:GetObject` on `arn:aws:s3:::reports/*`;
    - `s3:read` → `Resource "*"`.
  - `session_policy_never_wider` (`reports/*`, `rep?rts/**`, `${aws:username}/**`, an allow rule with `when`)
  - `ask_and_deny_become_deny`
  - `policy_too_large`
  - `policy_deterministic`
- [ ] Steps 2–5. Commit `feat(broker): STS AssumeRole and session policies that never widen the saiife policy`.

### Task 8: the five cloud manifests

**Files:** Create `crates/broker/connectors/{aws-s3,aws-sts,gcp-storage,azure-arm,azure-blob}.toml`, `crates/broker/tests/cloud_manifests.rs` and `crates/broker/tests/golden/cloud/*.txt`. Plan 14's `build.rs` picks up the files, so no list is edited.

**Interfaces:**
- Each file cites the vendor docs URL for every path and API version, as `github.toml` does.
- The Task 8 implementer may look up the paths and current versions in the public vendor docs (web access for reference data only). The owner confirms the versions (see Owner handwork).
- The paths follow the vendor docs, so they are not repeated here.
- Each line below lists: operation → capability [qualifier] / `iam_action`.
- **aws-s3**:
  - host `s3.{region}.amazonaws.com`, path-style;
  - `aws_sigv4`, service `s3`;
  - `key` is `objectkey`.

  The operations:
  - `s3.list_objects` (ListObjectsV2) → `s3:read` [`arn:aws:s3:::{bucket}`] / `s3:ListBucket`
  - `s3.get_object` and `s3.head_object` → `s3:read` [`arn:aws:s3:::{bucket}/{key}`] / `s3:GetObject`
  - `s3.put_object` (`body = "raw"`) → `s3:write` / `s3:PutObject`
  - `s3.delete_object` → `s3:delete` / `s3:DeleteObject`
- **aws-sts**: `sts.get_caller_identity` (`fixed_query` Action/Version) → `sts:read` / `sts:GetCallerIdentity`.
- **gcp-storage**:
  - `gcp_sa`, scope `…/auth/devstorage.read_write`;
  - `object` is `objectname`.

  The operations:
  - `storage.objects.list` (cursor `pageToken`/`nextPageToken`) → `storage:read` [`projects/_/buckets/{bucket}`]
  - `storage.objects.get` and `storage.objects.download` (`alt=media`) → `storage:read` [`projects/_/buckets/{bucket}/objects/{object}`]
  - `storage.objects.insert` (`raw`) → `storage:write`
  - `storage.objects.delete` → `storage:delete`

  The `iam_action`s are the `storage.objects.*` permissions.
- **azure-arm**:
  - `azure_sp`, scope `https://management.azure.com/.default`;
  - `api-version` set through `fixed_query`.

  The operations:
  - `resourcegroups.list` → `resourcegroups:read` [`/subscriptions/{subscription_id}`]
  - `resources.list` → `resources:read`
  - `vms.list` → `vms:read`
  - `vms.restart` → `vms:write`

  The `iam_action`s are the `Microsoft.*` actions. `nextLink` paging is not followed.
- **azure-blob**:
  - host `{account}.blob.core.windows.net`;
  - `azure_sp`, scope `https://storage.azure.com/.default`;
  - per-operation `headers` set `x-ms-version` (and `x-ms-blob-type = "BlockBlob"` on put);
  - `blob` is `objectkey`.

  The operations:
  - `blobs.list` → `blobs:read` [`{container}`]
  - `blobs.get` → `blobs:read` [`{container}/{blob}`]
  - `blobs.put` (`raw`) → `blobs:write`
  - `blobs.delete` → `blobs:delete`

  The `iam_action`s are the blob data actions.

- [ ] **Step 1: Failing tests:**
  - `build_rs_lists_every_connector_file` (plan 14) is still green with the 5 new files;
  - `cloud_ops_have_iam_action`;
  - one golden request per operation (§13): method, URI, sorted headers and auth placement, with a fixed clock and fake credentials; the full SigV4 `Authorization` is in the golden;
  - `s3_get_object_awkward_key_golden`;
  - `sts_get_caller_identity_path_is_slash`.
- [ ] Steps 2–5. Commit `feat(connectors): aws-s3, aws-sts, gcp-storage, azure-arm and azure-blob`.

### Task 9: one credential hook and cache; sign mode in the pipeline and daemon

**Files:**
- Modify:
  - `crates/broker/src/pipeline.rs` (step 9: rename `Env::oauth_token` to `Env::credential`);
  - `crates/daemon/src/oauth.rs` (`TokenCache` key and value);
  - `crates/daemon/src/api_ops.rs` (`spec_for` and `DaemonEnv::credential`);
  - `crates/daemon/src/secret_ops.rs` (`forget` drops every scope of the secret).
- Test: `crates/daemon/tests/cloud_sign.rs`, plus plan 14's oauth2 tests, which stay green.

**Interfaces:**
- `fn credential<'a>(&'a self, secret: &'a str, service: &'a str, spec: &'a AuthSpec, svc: &'a ServiceCfg, force: bool) -> CredFuture<'a>`, where `CredFuture<'a>` resolves to `Result<Arc<Cred>, &'static str>`.
  - It replaces `Env::oauth_token`, with the same default (`Err("secret_missing")`) and the same 401/`force` behaviour for oauth2.
  - `pub enum Cred { Bearer(Zeroizing<String>), Aws(AwsCreds) }`.
- `TokenCache` keys are `(secret, scope)` (decision 7). The entry holds a `Cred` with plan 14's `obtained` and `ttl`. There is no second cache.
- In step 9, after the `Accept-Encoding`/`Content-Type` inserts:
  - `aws_sigv4` → `Cred::Aws` (the vault keys, or the sign-mode assumed role from decision 8), then `sigv4::sign` with `for_service(params.region, spec.service)`.
  - `oauth2`, `gcp_sa` and `azure_sp` → `Cred::Bearer`, then `Authorization: Bearer`.
  - The `Masker` is rebuilt with the minted values.
- Nothing is minted before step 9.
- A failed mint or assume:
  - is denied with `token_mint_failed`;
  - records plan 14's `secret`/`refresh_failed` (`reason = "endpoint:<code>"`, or `network` / `bad_response`);
  - raises `Event::RefreshFailed` at most once per secret per hour.
- `spec_for` maps `Kind::Aws` to `aws_sigv4`, `GcpSa` to `gcp_sa` and `AzureSp` to `azure_sp`.
- An STS-mode service also serves `saiife api` (it signs with the assumed role).

- [ ] **Step 1: Failing tests** (daemon level, loopback S3, GCP and Azure):
  - `s3_get_object_signed_end_to_end`: the mock recomputes the signature from the received bytes, and the record names the secret but holds no value.
  - `sign_mode_assume_role_cached`: one STS call for 3 requests.
  - `gcp_storage_list_with_minted_token`
  - `azure_arm_list_with_minted_token`
  - `single_flight_per_secret_and_scope`: 20 concurrent calls give 1 mint, and two scopes of one secret give 2.
  - `failed_mint_not_cached`
  - `minted_token_masked_in_response`
  - `denied_request_mints_nothing`
  - `mint_failure_records_refresh_failed_and_notifies_once_per_hour`
  - `rotate_forgets_every_scope`
  - `oauth2_still_refreshes_and_retries_on_401` (plan 14's behaviour through `credential`)
  - `wrong_kind_for_connector_is_secret_missing`
  - `agent_authorization_and_x_amz_headers_dropped`
- [ ] Steps 2–5. Commit `feat(gateway): one credential hook and cache; sign cloud requests at step 9`.

### Task 10: STS mode — `cloud.lease` and `saiife run --cloud`

**Files:**
- Create: `crates/daemon/src/cloud_ops.rs`.
- Modify:
  - `crates/ipc/src/msg.rs` (`OP_CLOUD_LEASE = "cloud.lease"`);
  - `crates/daemon/src/ops.rs` (one arm);
  - `crates/daemon/src/secret_ops.rs` (`check_exe` and `entry_is_canonical` become `pub(crate)`);
  - `crates/cli/src/run_cmd.rs`;
  - `crates/cli/src/main.rs`.
- Test: `crates/daemon/tests/cloud_lease.rs` and the `run_cmd` unit tests.

**Interfaces:**
- `cloud.lease {service, exe}` → `{env, expires, session}`.
- The checks run in this order:
  1. lockdown → `lockdown`;
  2. scope → `no_scope`;
  3. the service mode → `sts_not_enabled`;
  4. `cloud.run_allow` → `exe_not_allowed`;
  5. an `aws` secret allowed for the service → `secret_missing` / `secret_not_allowed_for_service`;
  6. `requests_per_minute` → `limit = "requests_per_minute"`;
  7. the session policy → `session_policy_unrepresentable` / `session_policy_too_large`;
  8. AssumeRole for 900 s, with the policy and the `external_id` → `token_mint_failed`.
- Each lease writes one `secret` record with `event = "cloud_lease"` and the fields `service`, `role_arn`, `session`, `expires`, `policy_sha256` and `exe`. No value is ever in it.
- `saiife run --cloud <service> -- <cmd>`:
  - it uses a clap `ArgGroup` with `--secret`: exactly one of the two;
  - it runs the command as `run --secret` does;
  - it scrubs and sets the environment per decision 16;
  - it masks through `pump`;
  - it prints one line to stderr: `saiife: AWS credentials for <service> (STS mode) expire at <time>; this command and anything it starts can read them`.

- [ ] **Step 1: Failing tests:**
  - `lease_requires_sts_mode`
  - `lease_exe_not_listed_refused`
  - `lease_outside_scope_no_scope`
  - `lease_during_lockdown_denied`
  - `lease_sends_session_policy_and_900s`
  - `lease_record_has_no_values`
  - `lease_sts_error_code_recorded_message_not`
  - `lease_counts_requests_per_minute`
  - `cloud_env_scrubs_inherited_aws_vars`
  - `cloud_values_masked_in_output` (a token split across reads)
  - `secret_and_cloud_conflict`
- [ ] Steps 2–5. Commit `feat(cloud): STS mode with saiife run --cloud`.

### Task 11: config checks, doctor and `connect`

**Files:** Modify `crates/broker/src/catalog.rs` (`validate`), `crates/system/src/doctor/system.rs` and `crates/cli/src/connect_cmd.rs`.

**Interfaces:**
- `catalog::validate` errors:
  - `mode = "sts"` without `aws_sigv4` (decision 9);
  - `role_arn` or `external_id` on a connector that is not AWS;
  - `authority_host` on a connector that is not Azure;
  - an STS service whose session policy fails to build (the message names the pattern and the reason).
- `catalog::validate` warnings:
  - an STS service with limits or amount caps: `limits apply to saiife api calls, not to run --cloud credentials`;
  - an allow pattern that matches an operation without an `iam_action`.
- Doctor check `cloud_sts`: one `warn` line per STS service: `service <s> is in STS mode: run --cloud hands a 15-minute AWS credential to agent-controlled code, which can copy it`.
- `connect`:
  - maps each auth kind to its vault kind;
  - requires `--from-file` for `gcp_sa`;
  - writes a commented `# mode = "sts"` block with a `cloud` example and the docs link;
  - prompts for the region or account param.

- [ ] **Step 1: Failing tests:**
  - `sts_on_gcp_refused`
  - `role_arn_on_azure_refused`
  - `sts_unrepresentable_pattern_reported`
  - `sts_limits_warned`
  - `doctor_lists_every_sts_service`
  - `doctor_silent_without_sts`
  - `connect_aws_writes_commented_sts_block`
  - `connect_gcp_needs_from_file`
- [ ] Steps 2–5. Commit `feat(cloud): policy checks, doctor STS listing and connect`.

### Task 12: docs pages and spec notes

**Files:**
- Create one page per connector id: `docs/connectors/{aws-s3,aws-sts,gcp-storage,azure-arm,azure-blob}.md`.
- Modify:
  - `docs/connectors/README.md`;
  - `README.md` (the connector table);
  - `docs/threats.md` (the STS row);
  - `CHANGELOG.md`;
  - the spec, which gets the two spec notes (§8.4 and §6.13).

**Content:** each page must pass plan 14's `docs_pages.rs`: `## Locked mode` and `## Suggested policy`, toml blocks valid with zero warnings, and an "every write under `ask`" block. Each page also covers:
- the operations;
- the capability ↔ IAM action table;
- the vault kind and how to add it;
- the minimum cloud-side permissions.

`aws-s3.md` adds:
- sign mode vs STS mode, with the §6.13 label verbatim: "This hands a credential to agent-controlled code. It is scoped and short-lived, but an agent can copy it.";
- path-style addressing and the region;
- what the session policy can express (decision 10).

The STS example on that page sets no limits, so it passes with zero warnings. The known limits go on the pages they concern:
- ARM paging;
- folder-marker keys;
- no GCP or Azure STS.

- [ ] Write the pages. Run `cargo test -p saiife-broker --test docs_pages`, then add a check that `aws-s3.md` holds the §6.13 label. Commit `docs(connectors): cloud connector pages and spec notes`.

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`;
  - clippy with `-D warnings`;
  - the tokio gate, which prints 0;
  - `cargo test --workspace` and `scripts/test-offline.sh`, with `TMPDIR` and `SAIIFE_TEST_TMP` set;
  - the macOS-target check (with a fake `cc`);
  - `scripts/bench-check.sh` against `main`;
  - `cargo tree -d`, which shows no new duplicate of `ring`, `sha2` or `base64`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR, CI. The owner merges. No tag.

## Self-review

- **Spec coverage:**
  - §6.13 sign mode: Tasks 1, 5, 6, 8 and 9.
  - The IAM capabilities: Task 8.
  - STS mode: Tasks 7 and 10.
  - Doctor: Task 11.
  - §6.6: Tasks 3 and 9.
  - Masking: Tasks 4 and 9.
  - Docs: Task 12.
  - §13: Tasks 8 and 9.
- **Types:**
  - Tasks 1 and 6 produce `AwsCreds`, `SignOpts`, `CloudError` and `GcpKey`.
  - Task 9 produces `Cred` and `Env::credential`.
  - Task 2 produces `CloudMode` and `CloudCfg`.
  - Task 5 produces `ObjectKey`/`ObjectName`, the per-op `headers`, `fixed_query` and `iam_action`.
  - Task 9 renames plan 14's `oauth_token`. Every later mention uses `credential`.

## Owner handwork

- [ ] **Confirm:** STS mode is AWS only for now (spec §6.13 note). GCP and Azure stay in sign mode until they have a way to scope tokens down.
- [ ] **Confirm:** object keys may contain `/`, through the two new parameter types (spec §8.4 note).
- [ ] **Confirm:** the ARM `api-version` and Blob `x-ms-version` values pinned in Task 8 are current.
- [ ] Test on a real AWS account:
  - an IAM user that may only `sts:AssumeRole` on a role with S3 read access to a test bucket;
  - `saiife api aws s3.list_objects`/`s3.get_object`;
  - `saiife run --cloud aws -- /usr/bin/aws s3 ls s3://<bucket>`: the credential must stop working after 15 minutes, and actions outside the allow list must be denied.
- [ ] Test on a real GCP project: a service-account key with `roles/storage.objectViewer`, added with `secret add --kind gcp_sa --from-file`; then list and download.
- [ ] Test on a real Azure tenant: a service principal with Reader on a subscription and Storage Blob Data Reader; then `resourcegroups.list` and `blobs.get`.
- [ ] If push protection flags the vendored SigV4 fixtures, approve them as test data, or have the controller build them at runtime.

## Appendix: red-team cases (for the owner's suite)

- **Spoofed signing headers.** `Authorization`, `X-Amz-Security-Token`, `X-Amz-Date` or `x-ms-version` sent through `/v1/proxy`. Expected: dropped or overwritten, and the signature binds the daemon's values.
- **S3 key path tricks.** `a/../../other-bucket/x`, `%2e%2e`, a trailing `/`, `\`. Expected: refused before signing.
- **Host injection.** A `region` or `account` value with a dot or a port. Expected: refused at config load.
- **A copied `run --cloud` credential.** Expected: it works until it expires (15 minutes at most), within the session policy. This is known not covered; the lease record shows who took it.
- **A lease through `/usr/bin/env aws`.** Expected: refused, because `env` counts as an interpreter.
- **A lease for a sign-mode or GCP service.** Expected: `sts_not_enabled`, or a config error.
- **A GCP key file whose `token_uri` points to an attacker's host.** Expected: ignored.
