//! saiife-policy — the locked-mode policy (spec §8.1, §8.2, §18).
//!
//! Reads `/etc/saiife/config.toml` and its `policy.d/*.toml` drop-ins, checks
//! that every uid falls in at most one `[[scope]]`, merges a project config
//! add-only, and computes the effective-policy hash. No tokio, no network:
//! the managed hook links this crate.

#![forbid(unsafe_code)]

pub mod capability;
pub mod decide;
pub mod duration;
pub mod effective;
pub mod environment;
pub mod installed;
pub mod load;
pub mod mcp;
pub mod project;
pub mod scope;
pub mod service;
pub mod system;
pub mod users;
pub mod view;

pub use capability::Capability;
pub use decide::{decide, Request, Verdict};
pub use duration::parse_duration;
pub use effective::{active_packs, canonical_json, effective_policy, policy_hash, PackInfo};
pub use environment::{
    applied_for, env_for, env_hashes, EnvGuard, EnvironmentCfg, ServiceOverride,
};
pub use load::{
    check_guard_ask, load_system, load_system_with, split_ask, LoadedPolicy, PolicyError,
};
pub use mcp::{decide_tool, tool_kind, valid_server_name, McpServerCfg, Sandbox};
pub use project::{merge_project, parse_project, Merged, Mode, ProjectOverlay, ServiceOverlay};
pub use scope::{check_scopes, load_and_check, load_and_check_with, scope_for};
pub use service::{
    is_interpreter, valid_external_id, valid_role_arn, Action, AmountCap, AuthCfg, CloudCfg,
    CloudMode, HttpOperationCfg, LimitsCfg, RedactCfg, RuleCfg, SecretCfg, ServiceCfg,
    AZURE_AUTHORITIES,
};
pub use system::{
    facility_code, valid_address, AdminCfg, ApprovalCfg, AuditCfg, CommandCfg, DaemonCfg,
    DoctorCfg, Event, Example, Expect, Fail, ForwardCfg, Fsync, GatewayCfg, GuardCfg, HttpsFormat,
    McpCfg, NotifyCfg, SameUser, Scope, SmtpCfg, SyslogFormat, SystemConfig, TargetCfg, WebhookCfg,
    RESERVED_SERVICES,
};
pub use users::{Directory, FixedDirectory, Getent, GroupEntry, UserEntry};
