//! The Postgres source (R47-4): `tokio-postgres` without TLS, so a Unix
//! socket dir or a loopback host only. The session is read only; each
//! table is read inside `BEGIN READ ONLY` with `SELECT <listed columns>`
//! through `query_raw`, and its rows stream into a bounded
//! `std::sync::mpsc::sync_channel` that the blocking build thread drains
//! (ruling P47-5: never all rows in memory). The snapshot reads every table
//! twice, so each [`RowSource::rows`] runs the query again.
//!
//! Errors are fixed texts with the table name and at most a SQLSTATE code:
//! a server message can quote a value.

use crate::ops::Ctx;
use crate::vault::{Kind, VaultState};
use futures_util::StreamExt;
use saiife_policy::blind::BlindSource;
use saiife_shield::source::{Cell, RowIter, RowSource, SourceTable};
use saiife_shield::ShieldError;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::time::Duration;
use tokio_postgres::types::Type;
use zeroize::Zeroizing;

/// The rows a table's reader may be ahead of the build.
pub const CHANNEL_ROWS: usize = 4096;
/// What errors and the snapshot call this source.
const FILE: &str = "postgres";
const ENDED: &str = "the database connection ended early";
const READ: &str = "could not read the table";

/// One message from a table's reader.
pub enum PgMsg {
    Row(Vec<Cell>),
    /// The read failed; nothing follows.
    Fail(ShieldError),
    /// Every row was sent. A reader that stops without this is an error.
    End,
}

/// The rows of one table, as they come.
pub type RowReceiver = Receiver<PgMsg>;

/// Starts reading one table; the rows arrive on the receiver.
pub type Fetch = Box<dyn FnMut(&str) -> Result<RowReceiver, ShieldError> + Send>;

/// A bounded channel of [`CHANNEL_ROWS`] rows.
pub fn row_channel() -> (SyncSender<PgMsg>, RowReceiver) {
    sync_channel(CHANNEL_ROWS)
}

/// A [`RowSource`] over a [`Fetch`]: each `rows` call starts a new read.
pub struct PgSource {
    tables: Vec<SourceTable>,
    fetch: Fetch,
}

impl std::fmt::Debug for PgSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSource")
            .field("tables", &self.tables)
            .finish_non_exhaustive()
    }
}

impl PgSource {
    /// The bridge over any reader (the database, or a test's thread).
    pub fn from_fetch(tables: Vec<SourceTable>, fetch: Fetch) -> PgSource {
        PgSource { tables, fetch }
    }
}

fn src_err(table: &str, why: &'static str) -> ShieldError {
    ShieldError::Source {
        file: FILE.into(),
        table: Some(table.to_string()),
        column: None,
        row: None,
        why,
    }
}

impl RowSource for PgSource {
    fn tables(&self) -> Vec<SourceTable> {
        self.tables.clone()
    }

    fn rows(&mut self, table: &str) -> Result<RowIter<'_>, ShieldError> {
        if !self.tables.iter().any(|t| t.name == table) {
            return Err(src_err(table, "no such table in the source"));
        }
        let rx = (self.fetch)(table)?;
        Ok(Box::new(Rows {
            rx,
            table: table.to_string(),
            done: false,
        }))
    }

    fn file_name(&self) -> &str {
        FILE
    }
}

struct Rows {
    rx: RowReceiver,
    table: String,
    done: bool,
}

impl Iterator for Rows {
    type Item = Result<Vec<Cell>, ShieldError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.rx.recv() {
            Ok(PgMsg::Row(r)) => Some(Ok(r)),
            Ok(PgMsg::End) => {
                self.done = true;
                None
            }
            Ok(PgMsg::Fail(e)) => {
                self.done = true;
                Some(Err(e))
            }
            // The reader stopped without `End`: never a short table.
            Err(_) => {
                self.done = true;
                Some(Err(src_err(&self.table, ENDED)))
            }
        }
    }
}

/// How a column is read: native types as they are, a date as ISO text,
/// anything else as its text form.
#[derive(Debug, Clone, Copy)]
enum ColKind {
    Bool,
    I16,
    I32,
    I64,
    F32,
    F64,
    Text,
    Date,
}

/// `"a"."b"` from `a.b` or `"b"` from `b`; `""` doubled.
fn quote_table(t: &str) -> Option<String> {
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() > 2 || parts.iter().any(|p| p.is_empty() || p.contains('\0')) {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|p| quote_ident(p))
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// A select item and how to read it, by the column's type.
fn select_item(name: &str, ty: &Type) -> (String, ColKind) {
    let q = quote_ident(name);
    let raw = |k| (q.clone(), k);
    match *ty {
        Type::BOOL => raw(ColKind::Bool),
        Type::INT2 => raw(ColKind::I16),
        Type::INT4 => raw(ColKind::I32),
        Type::INT8 => raw(ColKind::I64),
        Type::FLOAT4 => raw(ColKind::F32),
        Type::FLOAT8 => raw(ColKind::F64),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => raw(ColKind::Text),
        Type::DATE => (format!("to_char({q}, 'YYYY-MM-DD') AS {q}"), ColKind::Date),
        _ => (format!("{q}::text AS {q}"), ColKind::Text),
    }
}

fn cell(row: &tokio_postgres::Row, i: usize, k: ColKind) -> Result<Cell, tokio_postgres::Error> {
    fn opt<T>(v: Option<T>, f: impl FnOnce(T) -> Cell) -> Cell {
        v.map_or(Cell::Null, f)
    }
    Ok(match k {
        ColKind::Bool => opt(row.try_get::<_, Option<bool>>(i)?, Cell::Bool),
        ColKind::I16 => opt(row.try_get::<_, Option<i16>>(i)?, |v| Cell::Int(v.into())),
        ColKind::I32 => opt(row.try_get::<_, Option<i32>>(i)?, |v| Cell::Int(v.into())),
        ColKind::I64 => opt(row.try_get::<_, Option<i64>>(i)?, Cell::Int),
        ColKind::F32 => opt(row.try_get::<_, Option<f32>>(i)?, |v| Cell::Real(v.into())),
        ColKind::F64 => opt(row.try_get::<_, Option<f64>>(i)?, Cell::Real),
        ColKind::Text => opt(row.try_get::<_, Option<String>>(i)?, Cell::Text),
        ColKind::Date => opt(row.try_get::<_, Option<String>>(i)?, Cell::Date),
    })
}

/// A fixed text, plus the SQLSTATE code when the server sent one (never
/// its message, which can quote a value).
fn pg_err(what: &str, e: &tokio_postgres::Error) -> String {
    match e.as_db_error() {
        Some(db) => format!("{what} (SQLSTATE {})", db.code().code()),
        None => what.to_string(),
    }
}

/// The password from the vault: a `basic` secret's `password` or a `token`
/// secret's `token`, read now and kept in memory only for the connect.
fn password(ctx: &Ctx, name: &str) -> Result<Zeroizing<String>, String> {
    let missing = || {
        format!(
            "the vault has no secret {name} with a password: \
             saiife secret add {name} --kind basic"
        )
    };
    let mut g = ctx.vault.lock();
    let VaultState::Ready(v) = &mut *g else {
        return Err("the vault is unavailable".to_string());
    };
    let e = v.get(name).ok_or_else(missing)?;
    let p = match e.kind {
        Kind::Basic => e.fields.get("password"),
        Kind::Token => e.fields.get("token"),
        _ => None,
    }
    .cloned()
    .ok_or_else(missing)?;
    v.touch(name, &crate::ops::now_ts());
    Ok(p)
}

/// One table's query, prepared at connect time.
#[derive(Clone)]
struct Plan {
    table: String,
    sql: String,
    kinds: Vec<ColKind>,
}

/// Connects to the policy's local database (a socket dir or a loopback
/// host; a remote one is a later stage) and reads each table's columns.
/// The rows are read later, by the build, one table at a time.
pub async fn pg_source(ctx: &Ctx, src: &BlindSource) -> Result<PgSource, String> {
    let BlindSource::Postgres {
        host,
        port,
        dbname,
        user,
        password_secret,
        tables,
    } = src
    else {
        return Err("not a Postgres source".to_string());
    };
    let socket = host.starts_with('/');
    if !socket && !matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
        return Err("remote Postgres needs TLS, which is a later stage".to_string());
    }
    let pass = password(ctx, password_secret)?;
    let mut cfg = tokio_postgres::Config::new();
    if socket {
        cfg.host_path(host);
    } else {
        cfg.host(host);
    }
    if let Some(p) = port {
        cfg.port(*p);
    }
    cfg.dbname(dbname)
        .user(user)
        .password(pass.as_bytes())
        .application_name("saiife-blind")
        .connect_timeout(Duration::from_secs(10));
    let (client, conn) = cfg
        .connect(tokio_postgres::NoTls)
        .await
        .map_err(|e| pg_err("could not connect to the database", &e))?;
    drop(pass);
    tokio::spawn(async move {
        // Its error is the session's end; each read reports its own.
        let _ = conn.await;
    });
    client
        .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        .await
        .map_err(|e| pg_err("could not make the session read only", &e))?;
    let mut plans = Vec::new();
    let mut listed = Vec::new();
    for t in tables {
        let q = quote_table(t).ok_or_else(|| format!("table {t}: not a table name"))?;
        let stmt = client
            .prepare(&format!("SELECT * FROM {q} LIMIT 0"))
            .await
            .map_err(|e| pg_err(&format!("table {t}: could not read its columns"), &e))?;
        let mut items = Vec::new();
        let mut kinds = Vec::new();
        let mut names = Vec::new();
        for c in stmt.columns() {
            let (item, k) = select_item(c.name(), c.type_());
            items.push(item);
            kinds.push(k);
            names.push(c.name().to_string());
        }
        if items.is_empty() {
            return Err(format!("table {t}: has no columns"));
        }
        plans.push(Plan {
            table: t.clone(),
            sql: format!("SELECT {} FROM {q}", items.join(", ")),
            kinds,
        });
        listed.push(SourceTable {
            name: t.clone(),
            columns: names,
        });
    }
    let client = Arc::new(client);
    let rt = tokio::runtime::Handle::current();
    let mut prev: Option<std::thread::JoinHandle<()>> = None;
    let fetch: Fetch = Box::new(move |table: &str| {
        // One read at a time on the session: the last one is over first (a
        // reader whose rows are no longer wanted stops at its next send).
        if let Some(p) = prev.take() {
            let _ = p.join();
        }
        let plan = plans
            .iter()
            .find(|p| p.table == table)
            .cloned()
            .ok_or_else(|| src_err(table, "no such table in the source"))?;
        let (tx, rx) = row_channel();
        let (client, rt) = (Arc::clone(&client), rt.clone());
        let h = std::thread::Builder::new()
            .name("saiife-blind-pg".into())
            .spawn(move || rt.block_on(produce(&client, &plan, &tx)))
            .map_err(|_| ShieldError::Io("could not start the database reader".into()))?;
        prev = Some(h);
        Ok(rx)
    });
    Ok(PgSource::from_fetch(listed, fetch))
}

/// Reads one table into `tx`, inside a read-only transaction that is
/// always rolled back. Runs on its own thread, so a full channel blocks it
/// and not the runtime.
async fn produce(client: &tokio_postgres::Client, plan: &Plan, tx: &SyncSender<PgMsg>) {
    let fail = |why: &'static str| PgMsg::Fail(src_err(&plan.table, why));
    if client.batch_execute("BEGIN READ ONLY").await.is_err() {
        let _ = tx.send(fail("could not start a read-only transaction"));
        return;
    }
    let read = async {
        let stream = client
            .query_raw(plan.sql.as_str(), std::iter::empty::<i32>())
            .await
            .map_err(|_| READ)?;
        let mut stream = std::pin::pin!(stream);
        while let Some(row) = stream.next().await {
            let row = row.map_err(|_| READ)?;
            let mut cells = Vec::with_capacity(plan.kinds.len());
            for (i, k) in plan.kinds.iter().enumerate() {
                cells.push(cell(&row, i, *k).map_err(|_| READ)?);
            }
            if tx.send(PgMsg::Row(cells)).is_err() {
                // The build stopped reading.
                return Ok(false);
            }
        }
        Ok::<bool, &'static str>(true)
    }
    .await;
    let _ = client.batch_execute("ROLLBACK").await;
    let _ = match read {
        Ok(true) => tx.send(PgMsg::End),
        Ok(false) => Ok(()),
        Err(why) => tx.send(fail(why)),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote_table("customers").unwrap(), "\"customers\"");
        assert_eq!(quote_table("crm.cust").unwrap(), "\"crm\".\"cust\"");
        assert_eq!(quote_table("a\"b").unwrap(), "\"a\"\"b\"");
        assert!(quote_table("a.b.c").is_none());
        assert!(quote_table("a.").is_none());
        assert!(quote_table("").is_none());
        let (item, _) = select_item("born", &Type::DATE);
        assert_eq!(item, "to_char(\"born\", 'YYYY-MM-DD') AS \"born\"");
        let (item, _) = select_item("amount", &Type::NUMERIC);
        assert_eq!(item, "\"amount\"::text AS \"amount\"");
        let (item, _) = select_item("n", &Type::INT4);
        assert_eq!(item, "\"n\"");
    }
}
