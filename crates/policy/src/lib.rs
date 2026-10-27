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
pub mod installed;
pub mod load;
pub mod project;
pub mod scope;
pub mod service;
pub mod system;
pub mod users;

pub use capability::Capability;
pub use decide::{decide, Request, Verdict};
pub use duration::parse_duration;
pub use effective::{active_packs, canonical_json, effective_policy, policy_hash, PackInfo};
pub use load::{load_system, LoadedPolicy, PolicyError};
pub use project::{merge_project, parse_project, Merged, Mode, ProjectOverlay, ServiceOverlay};
pub use scope::{check_scopes, load_and_check, scope_for};
pub use service::{
    is_interpreter, Action, AmountCap, AuthCfg, HttpOperationCfg, LimitsCfg, RedactCfg, RuleCfg,
    SecretCfg, ServiceCfg,
};
pub use system::{
    AdminCfg, ApprovalCfg, AuditCfg, CommandCfg, DaemonCfg, Event, Fail, Fsync, GatewayCfg,
    GuardCfg, McpCfg, NotifyCfg, SameUser, Scope, SmtpCfg, SystemConfig, TargetCfg, WebhookCfg,
};
pub use users::{Directory, FixedDirectory, Getent, GroupEntry, UserEntry};
