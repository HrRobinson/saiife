//! The box base image ops (plan 36, Task 5): `box.image.ls`, `.import`,
//! `.default` and `.rm` over the image store
//! (`saiife_boxhost::image::Store`). They are served from
//! `crate::box_ops::handle`, behind the same "no box manager: unavailable"
//! gate as every box op.
//!
//! The store is split (plan 35's final layout): the manifests and `default`
//! in a daemon-only records dir, the raw disks and kernels in the
//! VMM-readable images dir ([`ImagePaths`]).
//!
//! Import takes the image as passed descriptors (`box.fds` first, as
//! `box.spawn` does): `[raw, kernel?]`, as many as the manifest boots. Each
//! must be a regular file (`fstat`), the raw at most [`RAW_MAX_BYTES`] and
//! the kernel at most [`KERNEL_MAX_BYTES`]. Both are copied (holes kept)
//! into a fresh `<images>/.incoming/<16 hex>/` (0700, files created
//! `O_EXCL|O_NOFOLLOW`, plan 37's intake helpers in `crate::box_repo`),
//! the daemon's own copies are hashed against the manifest, renamed into
//! the images dir, and the manifest is written to the records dir last
//! (`Store::adopt`). On any failure nothing stays in `.incoming` or in the
//! store.
//!
//! Import, default and rm need root or an `[admin] groups` member in locked
//! mode, and the daemon's own user in personal mode; ls is open to any
//! local peer. Each change is a `box` record of plan 34's shape (`box:
//! null`) plus `{image, sha256, signed, ubuntu, claude}`.

use crate::ops::Mode;
use saiife_ipc::msg::{
    OP_BOX_IMAGE_DEFAULT, OP_BOX_IMAGE_IMPORT, OP_BOX_IMAGE_LS, OP_BOX_IMAGE_RM,
};
use std::path::{Path, PathBuf};

/// The ops this module serves.
pub const OPS: &[&str] = &[
    OP_BOX_IMAGE_LS,
    OP_BOX_IMAGE_IMPORT,
    OP_BOX_IMAGE_DEFAULT,
    OP_BOX_IMAGE_RM,
];
/// The largest raw base image taken.
pub const RAW_MAX_BYTES: u64 = 64 << 30;
/// The largest kernel taken.
pub const KERNEL_MAX_BYTES: u64 = 256 << 20;
/// The answer when the daemon has no image store.
pub const NO_STORE: &str = "box images are not available in this daemon";

/// Where the daemon keeps its image store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePaths {
    /// Daemon-only (0700): the manifests and `default`.
    pub records: PathBuf,
    /// VMM-readable: the raw disks and kernels.
    pub images: PathBuf,
}

/// The image store of a daemon with `state_dir`. Personal: records in
/// `<state>/image-records`, images in the personal layout's
/// `<state>/images`. Locked: records in `<state>/images`
/// (`/var/lib/saiife/images`), images in the locked layout's
/// `/var/lib/saiife-box/images`.
pub fn paths_for(state_dir: &Path, mode: &Mode) -> ImagePaths {
    match mode {
        Mode::Personal => ImagePaths {
            records: state_dir.join("image-records"),
            images: personal_images(state_dir),
        },
        Mode::Locked => ImagePaths {
            records: state_dir.join("images"),
            images: locked_images(),
        },
    }
}

#[cfg(unix)]
fn personal_images(state_dir: &Path) -> PathBuf {
    saiife_boxhost::layout::images_in(state_dir)
}

#[cfg(unix)]
fn locked_images() -> PathBuf {
    saiife_boxhost::layout::Layout::locked().images
}

// No boxes off Unix (no box host crate there); the same paths.
#[cfg(not(unix))]
fn personal_images(state_dir: &Path) -> PathBuf {
    state_dir.join("images")
}

#[cfg(not(unix))]
fn locked_images() -> PathBuf {
    PathBuf::from("/var/lib/saiife-box/images")
}

#[cfg(unix)]
pub(crate) use imp::handle;

#[cfg(unix)]
mod imp {
    use super::{ImagePaths, KERNEL_MAX_BYTES, NO_STORE, RAW_MAX_BYTES};
    use crate::box_repo::{copy_in, incoming_dir, open_dir, random_hex, regular, remove_sub};
    use crate::ops::{Ctx, Mode};
    use saiife_audit::Record;
    use saiife_boxes::manager::Manager;
    use saiife_boxhost::image::{parse_image_id, Manifest, ManifestBoot, Store};
    use saiife_boxhost::layout::incoming_in;
    use saiife_ipc::msg::{
        err, ok, ErrorCode, Request, OP_BOX_IMAGE_DEFAULT, OP_BOX_IMAGE_IMPORT, OP_BOX_IMAGE_LS,
        OP_BOX_IMAGE_RM,
    };
    use saiife_ipc::peer::PeerCred;
    use serde_json::{Map, Value};
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::sync::Arc;

    /// The copies' names in their incoming dir.
    const RAW_NAME: &str = "base.raw";
    const KERNEL_NAME: &str = "base.vmlinuz";
    /// Why a peer may not change the store.
    const ADMIN_ONLY: &str = "changing the box images needs root or a member of an [admin] group";

    /// A refusal: the error code and its message.
    type Refusal = (ErrorCode, String);

    fn bad(m: impl Into<String>) -> Refusal {
        (ErrorCode::BadRequest, m.into())
    }

    /// Store work off the runtime thread.
    async fn blocking<T: Send + 'static>(
        f: impl FnOnce() -> Result<T, Refusal> + Send + 'static,
    ) -> Result<T, Refusal> {
        tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| {
            Err((
                ErrorCode::Unavailable,
                format!("the image store did not finish: {e}"),
            ))
        })
    }

    fn open(p: &ImagePaths) -> Result<Store, Refusal> {
        Store::open(p.records.clone(), p.images.clone())
            .map_err(|e| (ErrorCode::Unavailable, format!("the image store: {e}")))
    }

    /// Root or an `[admin] groups` member (locked); the daemon's own user
    /// (personal).
    async fn may_change(ctx: &Ctx, peer: &PeerCred) -> bool {
        match ctx.mode {
            Mode::Personal => peer.uid == ctx.own_uid,
            Mode::Locked => (peer.sid.is_none() && peer.uid == 0) || ctx.peer_is_admin(peer).await,
        }
    }

    /// The `image` argument: a `base-<64 hex>` id.
    fn arg_image(a: &Map<String, Value>) -> Result<String, Refusal> {
        match a.get("image") {
            Some(Value::String(s)) => {
                parse_image_id(s).map_err(bad)?;
                Ok(s.clone())
            }
            _ => Err(bad("image must be an image id (base-<64 hex>)")),
        }
    }

    /// One `box` record of an image change (plan 34's shape, `box: null`).
    fn image_rec(ctx: &Ctx, action: &str, id: &str, m: Option<&Manifest>) -> Record {
        let mut r = crate::box_ops::box_rec(ctx, action, None, None, None, None, "cli");
        r.input = format!("{action} {id}");
        let x = &mut r.extra;
        x.insert("image".into(), id.into());
        x.insert(
            "sha256".into(),
            m.map_or(Value::Null, |m| m.sha256.clone().into()),
        );
        x.insert(
            "signed".into(),
            Value::Bool(m.is_some_and(|m| m.signature.is_some())),
        );
        x.insert(
            "ubuntu".into(),
            m.map_or(Value::Null, |m| m.ubuntu.image_sha256.clone().into()),
        );
        x.insert(
            "claude".into(),
            m.map_or(Value::Null, |m| m.claude.version.clone().into()),
        );
        r
    }

    /// Every op in [`super::OPS`]. `passed`: the descriptors of the
    /// `box.fds` before an import (closed for any other op).
    pub(crate) async fn handle(
        ctx: &Ctx,
        mgr: &Arc<Manager>,
        peer: &PeerCred,
        req: Request,
        passed: Vec<OwnedFd>,
    ) -> Value {
        let id = req.id;
        let Some(paths) = ctx.box_images.clone() else {
            return err(id, ErrorCode::Unavailable, NO_STORE);
        };
        let mut passed = passed;
        if req.op != OP_BOX_IMAGE_IMPORT {
            passed.clear();
        }
        let admin = may_change(ctx, peer).await;
        if req.op != OP_BOX_IMAGE_LS && !admin {
            return err(id, ErrorCode::Forbidden, ADMIN_ONLY);
        }
        let user = ctx.peer_name(peer).await;
        let with_peer = |mut r: Record| {
            r.uid = Some(peer.uid);
            r.sid = peer.sid.clone();
            r.user = user.clone();
            r
        };
        let done = match req.op.as_str() {
            OP_BOX_IMAGE_LS => ls(mgr, &paths, peer.uid, admin).await,
            OP_BOX_IMAGE_IMPORT => import(ctx, &paths, &req.args, passed, &with_peer).await,
            OP_BOX_IMAGE_DEFAULT => set_default(ctx, &paths, &req.args, &with_peer).await,
            OP_BOX_IMAGE_RM => rm(ctx, mgr, &paths, &req.args, &with_peer).await,
            _ => Err(bad("not a box image op")),
        };
        match done {
            Ok(a) => ok(id, a),
            Err((code, m)) => err(id, code, &m),
        }
    }

    /// Writes `rec`; a failed write is `unrecorded` (the change is made).
    async fn append(ctx: &Ctx, rec: Record, what: &str) -> Result<(), Refusal> {
        ctx.writer.append(rec).await.map(drop).map_err(|e| {
            (
                ErrorCode::Unrecorded,
                format!("{what} is done, but its record could not be written: {e}"),
            )
        })
    }

    /// `{images: [Manifest + {default, in_use}], warnings}`. `in_use`
    /// names the boxes whose record names the image, among those the
    /// caller may see (an admin: all of them).
    async fn ls(
        mgr: &Arc<Manager>,
        paths: &ImagePaths,
        uid: u32,
        admin: bool,
    ) -> Result<Map<String, Value>, Refusal> {
        let (m, p) = (Arc::clone(mgr), paths.clone());
        blocking(move || {
            let store = open(&p)?;
            let (entries, mut warnings) = store.list();
            let default = store.default_id();
            let boxes = m.list();
            let images: Vec<Value> = entries
                .into_iter()
                .map(|(man, warn)| {
                    warnings.extend(warn.into_iter().map(|w| format!("{}: {w}", man.id)));
                    let in_use: Vec<Value> = boxes
                        .iter()
                        .filter(|b| b.image.as_deref() == Some(man.id.as_str()))
                        .filter(|b| admin || b.owner_uid == uid)
                        .map(|b| b.id.as_str().into())
                        .collect();
                    let is_default = default.as_deref() == Some(man.id.as_str());
                    let mut v = serde_json::to_value(&man).unwrap_or_default();
                    if let Value::Object(o) = &mut v {
                        o.insert("default".into(), Value::Bool(is_default));
                        o.insert("in_use".into(), Value::Array(in_use));
                    }
                    v
                })
                .collect();
            let mut a = Map::new();
            a.insert("images".into(), Value::Array(images));
            a.insert(
                "warnings".into(),
                warnings.into_iter().map(Value::from).collect(),
            );
            Ok(a)
        })
        .await
    }

    /// `{manifest, default?}` + `[raw, kernel?]` -> `{image}`: one
    /// `image_import` record, and one `image_default` more with `default`.
    async fn import(
        ctx: &Ctx,
        paths: &ImagePaths,
        a: &Map<String, Value>,
        passed: Vec<OwnedFd>,
        with_peer: &(dyn Fn(Record) -> Record + Sync),
    ) -> Result<Map<String, Value>, Refusal> {
        let manifest = match a.get("manifest") {
            Some(v @ Value::Object(_)) => {
                let text = serde_json::to_string(v).map_err(|e| bad(e.to_string()))?;
                Manifest::parse(&text).map_err(bad)?
            }
            _ => return Err(bad("manifest must be the image's manifest (an object)")),
        };
        let make_default = match a.get("default") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(bad("default must be true or false")),
        };
        let (p, m) = (paths.clone(), manifest.clone());
        blocking(move || {
            let store = open(&p)?;
            intake(&store, passed, &m).map_err(bad)
        })
        .await?;
        let image = manifest.id.clone();
        append(
            ctx,
            with_peer(image_rec(ctx, "image_import", &image, Some(&manifest))),
            "box.image.import",
        )
        .await?;
        if make_default {
            let (p, i) = (paths.clone(), image.clone());
            blocking(move || open(&p)?.set_default(&i).map_err(bad)).await?;
            append(
                ctx,
                with_peer(image_rec(ctx, "image_default", &image, Some(&manifest))),
                "box.image.import --default",
            )
            .await?;
        }
        let mut out = Map::new();
        out.insert("image".into(), image.into());
        Ok(out)
    }

    /// The passed `[raw, kernel?]` into the store (see the module docs).
    fn intake(store: &Store, fds: Vec<OwnedFd>, m: &Manifest) -> Result<(), String> {
        let kernel = matches!(m.boot, ManifestBoot::Kernel { .. });
        let want = if kernel { 2 } else { 1 };
        if fds.len() != want {
            let what = if kernel {
                "the raw image and its kernel"
            } else {
                "the raw image"
            };
            return Err(format!(
                "{} takes {want} descriptor(s) ({what}), not {}",
                m.id,
                fds.len()
            ));
        }
        let mut it = fds.into_iter().map(File::from);
        let Some(raw) = it.next() else {
            return Err("no image was passed".into());
        };
        let k = it.next();
        let raw_len = regular(&raw, "image", RAW_MAX_BYTES)?;
        let k_len = match &k {
            Some(f) => Some(regular(f, "kernel", KERNEL_MAX_BYTES)?),
            None => None,
        };
        let images = store.images_dir();
        let inc = incoming_dir(images, true)?;
        let sub = random_hex()?;
        let dir = incoming_in(images).join(&sub);
        rustix::fs::mkdirat(&inc, sub.as_str(), rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
        let r = (|| {
            let d = open_dir(&inc, sub.as_str()).map_err(|e| format!("{}: {e}", dir.display()))?;
            copy_in(&d, RAW_NAME, 0o600, &raw, raw_len)?;
            if let (Some(f), Some(len)) = (&k, k_len) {
                copy_in(&d, KERNEL_NAME, 0o600, f, len)?;
            }
            let kp = dir.join(KERNEL_NAME);
            store.adopt(&dir.join(RAW_NAME), k.as_ref().map(|_| kp.as_path()), m)
        })();
        remove_sub(&inc, &sub, &[RAW_NAME, KERNEL_NAME]);
        r
    }

    /// `{image}` -> `{}`: one `image_default` record.
    async fn set_default(
        ctx: &Ctx,
        paths: &ImagePaths,
        a: &Map<String, Value>,
        with_peer: &(dyn Fn(Record) -> Record + Sync),
    ) -> Result<Map<String, Value>, Refusal> {
        let image = arg_image(a)?;
        let (p, i) = (paths.clone(), image.clone());
        let m = blocking(move || {
            let store = open(&p)?;
            store.set_default(&i).map_err(bad)?;
            store.get(&i).map_err(bad)
        })
        .await?;
        append(
            ctx,
            with_peer(image_rec(ctx, "image_default", &image, Some(&m))),
            "box.image.default",
        )
        .await?;
        Ok(Map::new())
    }

    /// `{image}` -> `{}`: refused while any box record (any owner, any
    /// state) names the image, or while it is the default; one
    /// `image_remove` record.
    async fn rm(
        ctx: &Ctx,
        mgr: &Arc<Manager>,
        paths: &ImagePaths,
        a: &Map<String, Value>,
        with_peer: &(dyn Fn(Record) -> Record + Sync),
    ) -> Result<Map<String, Value>, Refusal> {
        let image = arg_image(a)?;
        let (m, p, i) = (Arc::clone(mgr), paths.clone(), image.clone());
        let man = blocking(move || {
            let users: Vec<String> = m
                .list()
                .into_iter()
                .filter(|b| b.image.as_deref() == Some(i.as_str()))
                .map(|b| b.id.as_str().to_string())
                .collect();
            if !users.is_empty() {
                return Err(bad(format!(
                    "{i} is in use by box {}; discard and gc those boxes first",
                    users.join(", ")
                )));
            }
            let store = open(&p)?;
            let man = store.get(&i).ok();
            store.remove(&i).map_err(bad)?;
            Ok(man)
        })
        .await?;
        append(
            ctx,
            with_peer(image_rec(ctx, "image_remove", &image, man.as_ref())),
            "box.image.rm",
        )
        .await?;
        Ok(Map::new())
    }
}
