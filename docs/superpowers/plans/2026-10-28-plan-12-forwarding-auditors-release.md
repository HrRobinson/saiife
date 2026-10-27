# Plan 12 — Forwarding, auditor access, policy tools, release prep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The audit trail leaves the machine. The daemon forwards every record, in order and at least once, to syslog, files and HTTPS, with a cursor per target. `saiife audit verify --external <copy>` proves that the local log was not cut or rewritten against a forwarded copy. Auditors read everything, and other users see only their own records through the daemon. `saiife policy check|test|show|reload` lets admins keep policy in git with a CI check. The report gains connector, approval and outage sections. The docs reach the v2.0 definition of done (threats per setup, agent and connector locked-mode sections, egress recipe). A 5-minute locked demo runs in CI. Version 0.2.0 is prepared, but not tagged.

**Architecture:**
- The daemon gains `forwarder.rs`: one worker per `[audit.forward.<name>]` target. Each worker tails the chain files after its cursor (`state/forward-<name>.cursor`) and sends through a transport: syslog (local datagram, or remote TCP+TLS with octet counting), file (JSONL per host and month) or https (batches; Splunk HEC format option).
- Target state changes become `forward` records and `forward_failing` notifications.
- The `audit` crate gains `verify_external`.
- The daemon gains `audit.query`, plus `policy.show` and `policy.reload` if they are missing.
- The CLI gains `audit` via the daemon for non-auditors, `audit verify --external`, `policy check|test|show|reload`, report sections and the locked demo script.
- No new crates. Any new dependency is pinned older than 14 days.

**Tech Stack:** Rust workspace. It reuses the `saiife_broker::upstream::Upstream` TLS stack for remote syslog and HTTPS.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers:
- §6.4.3 (item 3 and the external copy), §6.4.5, §6.5;
- §6.19 (the remaining report sections), §6.20;
- §7 rows `audit verify [--external]`, `audit [filters]` (`--kind`, `--service`), `policy show|check|test|reload`;
- §8.1 `[audit.forward.*]` and `[[example]]`;
- §9.4 (record labelling);
- §10 (the docs);
- §13 (forwarding outage, `verify --external` cut-off tail);
- §14 points 5, 8 (policy tools), 10, 11, 12, plus the release prep for 0.2.0.

Plans 10 and 11 set the style.

## Global Constraints

- **No privileged or process-control tools on the dev machine.** Never run sudo, root, systemctl, polkit tools, docker, kill, pkill, killall or pgrep. This holds for implementers and reviewers. CI-only scripts (`scripts/locked-linux/*`, the new `scripts/demo-locked.sh`) are validated with `bash -n` only, never run locally. Shellcheck, if installed, is fine; never run it through docker.
- **Test isolation:** set `TMPDIR` and `SAIIFE_TEST_TMP` to a short dir made by `mktemp -d -p /home/jonas/projects/personal/saiife`, and remove it afterwards. Never use /tmp, the real home or `~/.claude`. No internet: syslog, file and HTTPS targets are tested against loopback mocks with `rcgen` certificates.
- **Hook path untouched:** `guard`, `audit`, `policy`, `ipc` and `system` stay tokio-free. `verify_external` lives in `audit` and stays sync.
- **Fail-closed rule for forwarding:** forwarding never blocks or slows the audit writer or the hooks. A failing target builds a backlog and is never allowed to stall. Records are dropped only when retention deletes month files the cursor still needs (`backlog_dropped`).
- **Commits:**
  - The branch is `plan-12-forwarding` from `main`.
  - Each task is committed in its worktree and cherry-picked onto the plan branch, with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - Never commit `.superpowers/`.
  - Never commit token-shaped test literals (GitHub push protection blocks them). Build fake tokens at runtime with `concat!`.
  - `gh` needs `GH_CONFIG_DIR=$HOME/.config/gh-personal`.
- **Spec values, verbatim:**
  - Forward types `syslog` | `file` | `https`.
  - Syslog formats: RFC 5424 (`rfc5424-json` puts the exact JSONL line in MSG unchanged). Remote is `tls://host:port` (RFC 5425).
  - HTTPS batches carry at most 500 records or 1 MiB, with an optional `Authorization` from the vault (`auth_secret`), and `format = "splunk-hec"` for Splunk HEC.
  - The payload is the exact JSONL line.
  - Cursor: `state/forward-<name>.cursor`, holding the last sent `seq`.
  - Forward records: `kind = "forward"`, `event` ∈ `connected|failing|recovered|backlog_dropped`. Individual batches are not recorded.
  - `audit verify`: exit 0 intact, 1 break, 2 unreadable. `--external <file or dir>`: the local chain must contain every checkpoint the external copy has.
  - Auditors: group `saiife-audit`, read files directly. Others go through `audit.query`, which returns only that uid's records across the guard, connector and approval kinds. The v1 home log is labelled `v1, before locked mode, not tamper-evident`.
  - `policy test <file>`: exit 1 on any mismatch. `policy check <file>` validates without loading, including overlapping scopes.
  - Report labels: guard records "reported by the agent's hook"; connector records "seen by saiife".
  - The §10 wording rule, verbatim, in docs, README and status: "the agent never holds a credential for a brokered service; it holds its own model-provider login unless you run a local model".
- **Decisions this plan makes** (the spec is silent; each is restated in its task):
  1. **The forwarder reads the files, not memory.** Each worker tails the month files after its cursor. It is woken by a notify on each append, and polls every 1 s. A restart resumes from the cursor. The cursor advances only after the target confirms. Delivery is at least once; duplicates after a crash are possible and documented.
  2. **Retries:** exponential backoff from 1 s to 60 s, forever. `failing` is recorded after the first failure lasting more than 30 s. `recovered` follows the next success. `forward_failing` is notified when failing lasts more than 5 min, once per outage.
  3. **Syslog:** facility `local0` (configurable `facility`), severity `info` (`warning` for deny/error decisions), APP-NAME `saiife`, MSGID = the record kind. Local: datagram to `/dev/log`, with messages over 8 KiB sent via TCP octet-counting to `/dev/log` if it is a stream socket, else truncated with a marker. Remote: TCP+TLS with octet-counting framing (RFC 6587/5425), using the system roots plus `[audit.forward.x] ca` or `/etc/saiife/ca`.
  4. **File target:** `<path>/<host id>-YYYY-MM.jsonl`, opened append-only. The dir must exist (not created). Each written file is fsynced after each batch.
  5. **HTTPS:** a 2xx answer means accepted. 429/5xx and network errors retry. Other 4xx count as failing and are retried with backoff; nothing is ever dropped for a 4xx. Timeout 30 s. No redirects.
  6. **Auditor membership** is checked on the current groups at each request (`audit.query` with `all: true`).
  7. **`verify --external`:**
     - For each checkpoint in the external copy, the local log must have a checkpoint with the same `head_seq`, `head` and `sig`. A missing one is a "rewritten or cut" break.
     - If the external copy's highest seq exceeds the local highest, that is a "cut-off tail" break.
     - The external copy itself is chain-verified too, with its breaks reported separately.
  8. **`[[example]]` syntax:** `{ user, request = "<service> <op> [k=v…]", expect = "allow|ask|deny" }` or `{ user, command = "<shell>", agent = "claude", expect = … }`. Connector examples go through scope + resolve + decide (no limits, no network). Command examples go through the guard with the active packs and `[guard] ask`.
  9. **The demo** (`scripts/demo-locked.sh`) runs only in the CI `locked-linux` job. It uses a generic `http` connector named `shop` pointing at a loopback HTTPS mock with a CI-installed CA in `/etc/saiife/ca`; there is no internet.
  10. **Release:** this plan bumps the version to 0.2.0 and prepares the CHANGELOG, README and release workflow. It does NOT tag or publish. The tag waits for the 9c red-team suite (spec §14 point 3) and the owner's go.

## Review Focus

1. **A forwarding target that is down for hours.** The audit writer and the hooks must not slow down. The backlog is read from disk and nothing is lost until retention deletes the file. Then one `backlog_dropped` record names the seq range (Task 2: `outage_builds_backlog_not_latency`, `retention_drop_is_recorded`).
2. **A forwarded copy used to hide tampering.** `verify --external` must catch:
   - a local log truncated after forwarding;
   - a locally re-signed rewritten history;
   - an external copy that is itself edited, reported as an external break, not a local one.

   (Task 4 table test.)
3. **Another user's records leaking through `audit.query`.** This includes filters such as `--project` or `--service`, and records where the uid is missing. Expected: a non-auditor gets only `uid == peer.uid`, and kinds without a uid are excluded (Task 5).
4. **`policy test` that passes on a broken policy.** A typo in an `[[example]]` field, or an unknown user, must fail the test run (exit 1 or 2), never pass silently (Task 6).
5. **Exact payload.** The syslog MSG and the HTTPS body must hold the exact JSONL line bytes, so that the SIEM can run `verify` on its copy. Splunk HEC wraps the line as `{"event": <line as a JSON string>}` (Task 3).

---

## Task order and parallelism

- Wave 1, in parallel: Tasks 1, 4, 5, 6, 7.
- Wave 2: Task 2 (needs 1), Task 8 (docs; needs nothing, but go last-ish to describe the final behaviour).
- Wave 3: Task 3 (needs 2), Task 9 (demo; needs 2 and 3), Task 11 (carry-overs).
- Last: Task 10 (release prep), then the whole-branch review, one fix wave, the gates, push, PR and CI. The owner merges. No tag.

---

### Task 1: typed forward config

**Files:** Modify `crates/policy/src/system.rs` (`forward: BTreeMap<String, ForwardCfg>`), `crates/policy/src/load.rs`.

**Interfaces:**
- `pub enum ForwardCfg { Syslog { address: String /* "unix:/dev/log" | "tls://host:port" */, format: SyslogFormat /* rfc5424 | rfc5424-json */, facility: Option<String>, ca: Option<PathBuf> }, File { path: PathBuf }, Https { url: String, auth_secret: Option<String>, format: HttpsFormat /* json | splunk-hec */, ca: Option<PathBuf> } }`
- Tagged `type`, with `deny_unknown_fields`.
- Validation:
  - the URL is https;
  - the address scheme is `unix:` or `tls:`;
  - paths are absolute;
  - the facility is one of `local0`…`local7`, `user` or `daemon`;
  - the target name matches `[a-z0-9_-]{1,32}`.
- The `ForwardFailing` notify event exists already.

- [ ] **Step 1: failing tests:** `forward_types_parse`, `unknown_key_is_error`, `http_url_refused`, `relative_path_refused`, `bad_facility_refused`, `bad_target_name_refused`.
- [ ] Steps 2–5. Commit `feat(policy): typed [audit.forward.*] targets`.

### Task 2: forwarder core

**Files:** Create `crates/daemon/src/forwarder.rs`. Modify `crates/daemon/src/{ops.rs, start.rs, writer.rs}`: an append notify, a `Ctx.forwarders` handle, start and stop, and reload (targets added, removed or changed).

**Interfaces:**
- `pub trait Transport: Send + Sync { async fn send(&self, lines: &[Bytes]) -> Result<(), SendError>; fn max_batch(&self) -> (usize, usize); }`
- `SendError::{Retry(String), Fatal(String)}`, where Fatal is a config error: stop the target and record it.
- Per-target worker:
  - reads the month files in order from `cursor + 1`, using the existing store readers that accept v1/v2;
  - batches up to `max_batch`;
  - sends;
  - writes the cursor atomically (0600) after success;
  - backs off per decision 2;
  - records `forward` state changes;
  - notifies `forward_failing` after 5 min.
- When retention has deleted the month file containing `cursor + 1`, jump to the oldest available seq and record `backlog_dropped` with `from_seq`/`to_seq`.
- Records written by the forwarder go through the normal writer, and get forwarded too. Batch-level events are never recorded.
- A test-only `MemoryTransport` captures lines, and `FlakyTransport` fails N times.

- [ ] **Step 1: failing tests:**
  - `forwards_every_record_in_order`
  - `cursor_survives_restart_no_gap`
  - `outage_builds_backlog_not_latency`: the writer's append latency stays unchanged while the transport fails (measure with a generous bound)
  - `failing_recorded_after_30s_recovered_after_success` (with the clock seam)
  - `forward_failing_notified_after_5min_once`
  - `retention_drop_is_recorded`
  - `reload_adds_and_removes_targets`
  - `exact_bytes_forwarded` (byte equality with the file lines)
- [ ] Steps 2–5. Commit `feat(daemon): audit forwarder with per-target cursors`.

### Task 3: transports (syslog, file, https)

**Files:** Create `crates/daemon/src/forward_syslog.rs`, `forward_file.rs`, `forward_https.rs`.

**Interfaces:** Each implements `Transport` per decisions 3–5.
- Syslog RFC 5424 header: `<PRI>1 TIMESTAMP HOSTNAME saiife - KIND -` followed by the MSG, which is the exact line.
- `rfc5424` (non-JSON) uses the same MSG; the format difference is only an `[saiife@32473 seq="…"]` structured data element in `rfc5424`, and `-` in `rfc5424-json`.
- Remote TLS uses `Upstream`'s TLS connector without ALPN (as for SMTP), with host pinning to the configured host and a 30 s timeout.
- HTTPS: the body for `json` is a JSON array of the line strings parsed as raw JSON values, so it stays byte-exact inside, via `serde_json::value::RawValue`. For `splunk-hec` it is newline-separated `{"event": <line as string>, "sourcetype": "saiife"}` objects. `Authorization` comes from the vault secret (header kind: the value; token kind: `Bearer <token>`).

- [ ] **Step 1: failing tests:**
  - `syslog_local_datagram_header_and_exact_msg` (a unixgram socket in the test dir)
  - `syslog_tls_octet_counting_framing` (an rcgen loopback server)
  - `syslog_tls_untrusted_cert_refused`
  - `file_target_per_host_month_append_fsync`
  - `file_target_missing_dir_is_failing_not_created`
  - `https_batch_limits_500_and_1mib`
  - `https_auth_from_vault_never_logged`
  - `https_splunk_hec_shape`
  - `https_4xx_retries_not_drops`
  - `https_no_redirect`
- [ ] Steps 2–5. Commit `feat(daemon): syslog, file and https forwarding transports`.

### Task 4: `audit verify --external`

**Files:** Modify `crates/audit/src/verify.rs` (`pub fn verify_external(local: &Path, external: &Path) -> ExternalReport`), `crates/cli/src/audit_cmd.rs` (`--external <file|dir>`), `crates/cli/src/main.rs`.

**Interfaces:** Per decision 7. `ExternalReport { local: VerifyReport, external: VerifyReport, missing_checkpoints: Vec<u64 /*head_seq*/>, cut_tail: Option<(u64 /*local max*/, u64 /*external max*/)> }`, with exit 1 on any local break, missing checkpoint or cut tail. External-only breaks are printed and exit 1 too, labelled `external copy damaged`.
- Locked mode: the default local dir is `[audit] dir` from the system config. It needs `saiife-audit` membership or root; otherwise it exits 2 with `audit files need the saiife-audit group; ask an auditor`.

- [ ] **Step 1: failing tests**, a table over synthetic chains with signed checkpoints, reusing the audit crate's test helpers:
  - `intact_copy_ok`
  - `local_tail_cut_detected`
  - `local_rewritten_and_resigned_detected`
  - `external_edited_reported_as_external`
  - `external_dir_with_month_files`
  - `v1_files_listed_not_failed`
- [ ] Steps 2–5. Commit `feat(audit): verify --external against a forwarded copy`.

### Task 5: auditor access and `audit.query`

**Files:** Create `crates/daemon/src/audit_query.rs`. Modify `crates/ipc/src/msg.rs` (`audit.query`), `crates/daemon/src/ops.rs`, `crates/cli/src/audit_cmd.rs`.

**Interfaces:**
- `audit.query {since?, kind?, service?, agent?, project?, blocked?, all?: bool, limit (≤ 5000), after_seq?}` → `{records: […], more: bool, next_seq?}`.
- Non-auditors get only records with `uid == peer.uid`; records without a uid are excluded. `all: true` requires `saiife-audit` membership or root (decision 6).
- CLI `saiife audit [filters] [--kind connector|approval|guard] [--service s]`, in locked mode:
  - a member of `saiife-audit`, or root, reads the files directly (the existing code path, with the locked dir);
  - anyone else uses `audit.query`;
  - the user's home v1 log is appended to the table under the label `v1, before locked mode, not tamper-evident`;
  - `--report` uses the same data source.
- Developer mode is unchanged.

- [ ] **Step 1: failing tests:**
  - `non_auditor_sees_only_own_uid`
  - `records_without_uid_excluded`
  - `all_requires_auditor_group`
  - `filters_apply_after_uid_scope`
  - `pagination_after_seq`
  - `cli_locked_non_auditor_uses_daemon`
  - `v1_home_log_labelled`
- [ ] Steps 2–5. Commit `feat(audit): auditor group and per-user audit.query`.

### Task 6: `saiife policy check|test|show|reload`

**Files:** Create `crates/cli/src/policy_cmd.rs`. Modify `crates/policy/src/system.rs` (typed `Example`), `crates/cli/src/main.rs`, and the daemon ops if `policy.show` or `policy.reload` are missing.

**Interfaces:**
- `saiife policy check <config.toml>` loads the file plus its `policy.d`, checks scopes against the directory (overlaps), runs `catalog::validate` and the `[guard] ask` rule checks. It prints every error. Exit 0 ok, 1 invalid, 2 unreadable.
- `saiife policy test <config.toml>` runs every `[[example]]` per decision 8, printing `ok`/`FAIL` per example with the actual verdict. Exit 1 on any mismatch; exit 2 on a malformed example or an unknown user (refuse unknown fields).
- `saiife policy show [--effective] [--user <u>]`:
  - anyone sees their own scope;
  - admins see any user's;
  - it prints the merged effective policy and its hash;
  - it uses `policy.show` via the daemon in locked mode, and the file in developer mode.
- `saiife policy reload`: admin only; same as SIGHUP; it prints the result (`loaded` or `rejected: <reason>`).

- [ ] **Step 1: failing tests:**
  - `check_valid_config_exit_0`
  - `check_overlapping_scopes_exit_1`
  - `check_unknown_connector_exit_1`
  - `test_examples_pass_and_fail`
  - `test_unknown_example_field_exit_2`
  - `test_unknown_user_exit_2`
  - `test_command_example_uses_guard_and_ask`
  - `show_own_scope_only_for_non_admin`
  - `reload_admin_only`
- [ ] Steps 2–5. Commit `feat(cli): policy check, test, show and reload`.

### Task 7: report sections

**Files:** Modify `crates/cli/src/report.rs`, `report_html.rs`.

**Interfaces:**
- The §6.19 remaining sections:
  - **Connector activity per service:** requests, denies, limits hit, approvals.
  - **Approvals:** id, requester, decider, decision, time-to-decision, type and summary, all masked.
  - **`error_denied` events, daemon restarts** (`daemon`/`start` with `previous_clean_stop = false`) and **forwarding outages** (`forward` failing→recovered spans).
- Every guard row is labelled "reported by the agent's hook" and every connector row "seen by saiife" (§9.4).
- All text goes through the existing sanitize path. Self-contained HTML, no network resources.

- [ ] **Step 1: failing tests:**
  - `connector_activity_counts`
  - `approvals_section_latency_and_decider`
  - `restarts_and_outages_listed`
  - `record_source_labels`
  - `hostile_text_inert_in_new_sections`
- [ ] Steps 2–5. Commit `feat(report): connectors, approvals, restarts and forwarding outages`.

### Task 8: docs to the v2.0 definition of done

**Files:**
- `docs/threats.md`: one section per setup from §10, generated by hand from the table, with the verbatim wording rule.
- `docs/agents/{claude-code,codex,gemini}.md`: a "Locked mode" section with the lock label (plan 7 gate: Claude Code lockable; Codex and Gemini unverified, so no lock claim) and the fail-closed matrix row (§9.3).
- `docs/connectors/*.md`: confirm each has a locked-mode section.
- New `docs/forwarding.md`, `docs/auditors.md`, `docs/egress.md` (§6.20 nftables recipe with `meta skuid`, allowing DNS, the model provider or local model, and saiife's daemon traffic; macOS caveat).
- `docs/approvals.md`: note that the spec's §8.5 example shows `"rule":"force-push"` while records carry `rule_id`.
- `docs/connectors/README.md`: the 16 MiB answer-frame note.
- README.

**Doctor:** add the egress hint. For each scope user that is a dedicated account (no login shell, or listed in a new optional `[doctor] dedicated_accounts`), check for an nftables table named `saiife_egress`. Use `nft list tables` only when the binary exists and is root-owned; never run it in tests, where a fake binary seam is used. If missing, it is `info` with a pointer to docs/egress.md.

- [ ] Steps:
  - write the docs;
  - add a docs test that greps every docs page and the README for the forbidden phrase "the agent never holds a credential" not followed by "for a brokered service";
  - doctor tests with a fake `nft`;
  - commit `docs: threats per setup, locked-mode sections, forwarding, auditors, egress recipe`.

### Task 9: 5-minute locked demo (CI only)

**Files:** Create `scripts/demo-locked.sh`. Modify `scripts/locked-linux/run.sh` (a `demo` phase) and `docs/demo.md`. These run only on the CI runner; validate with `bash -n`.

Flow, per spec §14 point 12:
1. Install locked, with a `shop` generic http connector against a loopback HTTPS mock. The mock is a tiny static server started by the script, with a CI-generated CA copied root-owned to `/etc/saiife/ca`.
2. As `agent-ci`, attempt these; each must fail, and the attempts are recorded:
   - remove the managed hook;
   - kill the daemon (by MainPID only);
   - read the vault key.
3. `saiife api shop orders.list` → allowed, and JSON is printed.
4. `saiife api shop products.update …` → pending; `approver-ci` approves; `saiife api result <id>` → done.
5. `saiife audit verify` → intact.
6. `saiife audit --report` → an HTML file exists, containing the connector and approvals sections.

The whole flow must take under 5 minutes.

- [ ] Write it. `bash -n` passes. Commit `ci(demo): locked end-to-end demo in the locked-linux job`.

### Task 10: release prep 0.2.0 (no tag)

**Files:** `Cargo.toml` (workspace version 0.2.0), `Cargo.lock`, `CHANGELOG.md` (Unreleased → `## 0.2.0 — unreleased (waiting for red-team suite)`), `README.md` (locked mode on Linux, the wording rule), `.github/workflows/release.yml` (confirm it builds the musl static binary and runs `install-test`; adjust for new crates only if needed), `docs/install.md` (locked install steps).

- [ ] Steps:
  - bump;
  - `cargo build --release --locked`;
  - a `release.yml` dry-read (do not trigger);
  - commit `chore(release): prepare 0.2.0 (not tagged; blocked on the 9c red-team suite)`.

### Task 11: carry-overs from plans 10 and 11

**Files:** As needed. Each item gets a test.
1. `masked_content`: compare `mask_bytes(body)` with the raw bytes, not the lossy UTF-8 view (crates/broker/src/pipeline.rs). Refuse a non-UTF-8 body on an ask path with `masked_content`.
2. The flaky `approvers::tests::may_decide_table` `reauth_busy`: make the process-wide `InFlight` per test instance (inject it) or use unique uids per row.
3. `lockdown_cmd` maps `unrecorded` to exit 5, like `approvals_cmd`.
4. `reauth::clean_detail` also strips Unicode Cf and bidi characters.
5. Doctor: the rules-mention warning no longer hides action-file problems (report both). Non-root doctor says `cannot read /etc/polkit-1/rules.d (run as root)` instead of passing silently.
6. The timing-flaky tests (`status_with_fifo_config_does_not_hang`, `targeted_kills_are_allowed`, `long_chain_with_trailing_wrapper…`, `corpus_lock::signal_words_do_not_hide_options`): widen their time bounds or mark them so CI runs them serially. Do not weaken what they assert.

- [ ] Commit `fix: plan 10/11 carry-overs`.

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`, clippy `-D warnings`, the tokio gate;
  - `cargo test --workspace` and `scripts/test-offline.sh` with TMPDIR and SAIIFE_TEST_TMP set;
  - the macOS-target check (`RUSTFLAGS="-D warnings" cargo check --workspace --all-targets --target x86_64-apple-darwin` with a fake `cc`);
  - the developer-mode `scripts/bench-check.sh` vs `main`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR, CI. The owner merges. No tag.
