//! Plan 44 T5: the typed cloud envelope of exact mode (spec §2.2.5,
//! §2.3.1).
//!
//! Every part is typed: the schema as cloud names, row bands, types and
//! classes; the k-floor public values; the synthetic rows; the parameterized
//! question with its parameter types and entity stand-ins; the context of
//! earlier turns; an optional retry. Nothing here holds a real value: the
//! parameters' bounds and displays stay in the [`Draft`].
//!
//! [`Envelope::canonical`] is the only encoding: JSON with every object's
//! keys sorted (bytewise) and no whitespace. The same bytes are hashed
//! ([`Envelope::sha256`]), scanned (`Firewall::check_bytes`), written to
//! the outbox and sent (plan 47), so a field order change between hashing
//! and sending is impossible. The writer sorts keys itself: it does not
//! depend on `serde_json`'s map order (the workspace turns on
//! `preserve_order` for another crate).
//!
//! `build_envelope` writes no file and does not touch the session's turns:
//! the caller pushes the turn after the firewall passed (plan 48).

use crate::public::PublicValues;
use crate::question::Draft;
use crate::schema::{rows_band, Bound, ColType, ColumnClass, Lang, ParamType, Schema};
use crate::session::{Session, Turn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

/// The envelope kind (plan 44 fixed values).
pub const ENVELOPE_KIND: &str = "saiife-blind-plan";
/// The envelope version.
pub const ENVELOPE_VERSION: u32 = 1;

/// Synthetic rows: cloud table name -> rows of cloud column name -> value.
pub type SyntheticRows = BTreeMap<String, Vec<BTreeMap<String, Value>>>;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u32,
    pub kind: String,
    pub lang: Lang,
    pub schema: CloudSchema,
    pub synthetic: SyntheticRows,
    pub question: String,
    pub params: Vec<CloudParam>,
    pub context: Vec<CloudTurn>,
    pub retry: Option<Retry>,
    pub list_cap: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSchema {
    pub tables: Vec<CloudTable>,
    /// The key relations a method may join on, by cloud names (plan 48 C1,
    /// ruling P47-28). Left out of the bytes when empty, so a schema
    /// without joins hashes as it did before this field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub joins: Vec<CloudJoin>,
}

/// One key relation ([`crate::schema::KeyJoin`]) as the cloud sees it:
/// every name is the cloud name (the alias if there is one). The column
/// `table.column` holds keys of the entity `entity.key`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudJoin {
    /// The entity's cloud table and the cloud name of its key column.
    pub entity: String,
    pub key: String,
    /// The FK side: another cloud table and its INTEGER column.
    pub table: String,
    pub column: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudTable {
    pub name: String,
    /// The row count as a band ([`rows_band`]).
    pub rows: String,
    pub columns: Vec<CloudColumn>,
    /// The entity word (English) when the table is an entity.
    pub entity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudColumn {
    pub name: String,
    pub ty: ColType,
    pub class: ColumnClass,
    /// A `public` column's k-floor values only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudParam {
    /// `p1`, `p2`, ...
    pub name: String,
    /// The type tag: `entity`, `amount`, `integer`, `percent`, `date`,
    /// `date_range` or `text`; an entity may name its cloud table
    /// (`entity:<table>`) and a text its cloud column
    /// (`text:<table>.<column>`).
    pub ty: String,
    /// The entity's stand-in (R44-4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudTurn {
    /// The earlier parameterized question.
    pub question: String,
    pub params: Vec<CloudParam>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retry {
    /// [`method_sha256`] of the method the planner sent before (plan 48
    /// C1, ruling R-C11): the method text itself never goes back out.
    pub previous_method_sha256: String,
    /// A plan 45 R45-8 planner class, optionally one space and a cloud name.
    pub error_class: String,
}

impl Retry {
    /// The retry after `previous_method` (the method text as the daemon
    /// received it from the planner) failed with `error_class`. Only the
    /// method's hash is kept. The caller gives the firewall the same
    /// [`method_sha256`] of the method it received, never this field.
    pub fn new(previous_method: &str, error_class: &str) -> Retry {
        Retry {
            previous_method_sha256: method_sha256(previous_method),
            error_class: error_class.to_string(),
        }
    }
}

/// What a sent envelope held, for the audit record (plan 47).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentSummary {
    pub tables: usize,
    pub synthetic_rows: usize,
    pub params: usize,
    /// Counted, not assumed: the pattern hits (email, phone, IBAN, CPR,
    /// birth date) the firewall's index-free scans find in the envelope.
    /// 0 for every envelope that passed the firewall in exact mode.
    pub personal_values: usize,
}

/// The envelope prints counts and fixed fields only: a blocked envelope
/// may hold what the firewall found.
impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("v", &self.v)
            .field("lang", &self.lang)
            .field("tables", &self.schema.tables.len())
            .field("params", &self.params.len())
            .field("context", &self.context.len())
            .field("retry", &self.retry.is_some())
            .field("list_cap", &self.list_cap)
            .finish_non_exhaustive()
    }
}

/// The type tag of a parameter, with cloud names only.
fn param_tag(schema: &Schema, ty: &ParamType) -> String {
    match ty {
        ParamType::Entity { table, .. } => {
            format!("entity:{}", schema.cloud_name(table, None))
        }
        ParamType::Text { table, column } => format!(
            "text:{}.{}",
            schema.cloud_name(table, None),
            schema.cloud_name(table, Some(column))
        ),
        ParamType::Amount => "amount".into(),
        ParamType::Integer => "integer".into(),
        ParamType::Percent => "percent".into(),
        ParamType::Date => "date".into(),
        ParamType::DateRange => "date_range".into(),
    }
}

/// The schema part of every envelope of a dataset: the one builder, used by
/// [`build_envelope`] and by the caller that hashes it for the firewall
/// ([`schema_sha256`], ruling P-26). Cloud names, row bands, types,
/// classes, each public column's k-floor list as `public_values` gives it,
/// the English entity word, and the key relations by cloud names (the
/// schema's joins; a schema without stored joins gets the C-G1 ones, as
/// the validator does), sorted, without duplicates.
pub fn cloud_schema(schema: &Schema, public: &[PublicValues]) -> CloudSchema {
    let tables = schema
        .tables
        .iter()
        .map(|t| CloudTable {
            name: schema.cloud_name(&t.name, None),
            rows: rows_band(t.rows),
            columns: t
                .columns
                .iter()
                .map(|c| CloudColumn {
                    name: schema.cloud_name(&t.name, Some(&c.name)),
                    ty: c.ty,
                    class: c.class,
                    values: (c.class == ColumnClass::Public)
                        .then(|| {
                            let key = format!("{}.{}", t.name, c.name);
                            public
                                .iter()
                                .find(|p| p.column == key)
                                .map(|p| p.passing.clone())
                        })
                        .flatten(),
                })
                .collect(),
            entity: schema.entity_for(&t.name).map(|e| e.word.clone()),
        })
        .collect();
    let keyed = if schema.joins.is_empty() {
        schema.conventional_joins()
    } else {
        schema.joins.clone()
    };
    let mut joins: Vec<CloudJoin> = keyed
        .iter()
        .map(|j| CloudJoin {
            entity: schema.cloud_name(&j.entity, None),
            key: schema.cloud_name(&j.entity, Some(&j.key)),
            table: schema.cloud_name(&j.table, None),
            column: schema.cloud_name(&j.table, Some(&j.column)),
        })
        .collect();
    joins.sort();
    joins.dedup();
    CloudSchema { tables, joins }
}

/// Builds the envelope of a draft. An entity parameter gets its session
/// stand-in when it is bound to exactly one key; otherwise it has no symbol
/// and the firewall refuses the envelope (`bad_part`). The context is the
/// session's last turns (at most 10), each entity typed by its cloud table
/// when the session can still reverse the symbol.
pub fn build_envelope(
    d: &Draft,
    session: &mut Session,
    schema: &Schema,
    public: &[PublicValues],
    synthetic: SyntheticRows,
    list_cap: u32,
    retry: Option<Retry>,
) -> Envelope {
    let schema_part = cloud_schema(schema, public);

    let mut params = Vec::with_capacity(d.params.len());
    for p in &d.params {
        let symbol = match (&p.ty, &p.bound) {
            (ParamType::Entity { table, word }, Some(Bound::Keys(keys))) if keys.len() == 1 => {
                let w = schema
                    .entity_for(table)
                    .map_or(word.as_str(), |e| e.word.as_str())
                    .to_string();
                Some(session.symbol_for(&w, table, keys[0]))
            }
            _ => None,
        };
        params.push(CloudParam {
            name: p.name.clone(),
            ty: param_tag(schema, &p.ty),
            symbol,
        });
    }

    let context = session
        .turns
        .iter()
        .map(|t| context_turn(t, session, schema))
        .collect();

    Envelope {
        v: ENVELOPE_VERSION,
        kind: ENVELOPE_KIND.to_string(),
        lang: d.lang,
        schema: schema_part,
        synthetic,
        question: d.text.clone(),
        params,
        context,
        retry,
        list_cap,
    }
}

/// The text a context turn shows for a parameter that is not an entity
/// (its type is not kept in the turn).
pub const CONTEXT_VALUE: &str = "(value)";

/// A context turn as the firewall wants it (P-22): its entity parameters
/// renamed `p1..pK` in order of first use, each with its stand-in; any other
/// `:pN` in the text becomes [`CONTEXT_VALUE`]. Every offset comes from the
/// turn's own text and every slice goes through `str::get`.
fn context_turn(t: &Turn, session: &Session, schema: &Schema) -> CloudTurn {
    let q = t.question.as_str();
    let mut out = String::with_capacity(q.len());
    let mut renamed: Vec<(&str, String)> = Vec::new();
    let mut params = Vec::new();
    let mut last = 0;
    for (a, b, name) in crate::firewall::param_refs(q) {
        out.push_str(q.get(last..a).unwrap_or(""));
        last = b;
        let Some((_, sym)) = t.symbols.iter().find(|(n, _)| n == name) else {
            out.push_str(CONTEXT_VALUE);
            continue;
        };
        let new = match renamed.iter().find(|(n, _)| *n == name) {
            Some((_, new)) => new.clone(),
            None => {
                let new = format!("p{}", renamed.len() + 1);
                renamed.push((name, new.clone()));
                params.push(CloudParam {
                    name: new.clone(),
                    ty: session.key_for_symbol(sym).map_or_else(
                        || "entity".to_string(),
                        |(table, _)| format!("entity:{}", schema.cloud_name(&table, None)),
                    ),
                    symbol: Some(sym.clone()),
                });
                new
            }
        };
        out.push(':');
        out.push_str(&new);
    }
    out.push_str(q.get(last..).unwrap_or(""));
    CloudTurn {
        question: out,
        params,
    }
}

/// `sha256:` + hex of the canonical JSON of any serializable part.
fn part_sha256<T: Serialize + ?Sized>(part: &T) -> String {
    let v = serde_json::to_value(part).unwrap_or(Value::Null);
    let mut out = Vec::new();
    write_canonical(&v, &mut out);
    sha256_hex(&out)
}

/// The hash the firewall compares the envelope's schema part with (P-26):
/// the caller hashes [`cloud_schema`]'s output when it builds the envelope.
pub fn schema_sha256(schema: &CloudSchema) -> String {
    part_sha256(schema)
}

/// The hash of a retry's previous method, as the caller received it from
/// the planner (P-26): canonical JSON of the string. [`Retry::new`] puts it
/// in the envelope; the caller gives the firewall its own copy.
pub fn method_sha256(method: &str) -> String {
    part_sha256(method)
}

/// `sha256:` + hex of the canonical JSON of synthetic rows: the caller
/// hashes `synthetic_rows`' output before `build_envelope` and gives the
/// hash to the firewall, which hashes the envelope's rows the same way
/// (P-22).
pub fn synthetic_sha256(rows: &SyntheticRows) -> String {
    part_sha256(rows)
}

/// Canonical JSON of a value: object keys sorted bytewise, no whitespace,
/// strings escaped by `serde_json`.
pub(crate) fn write_canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => push_str(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(x, out);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                push_str(k, out);
                out.push(b':');
                if let Some(x) = m.get(k) {
                    write_canonical(x, out);
                }
            }
            out.push(b'}');
        }
    }
}

fn push_str(s: &str, out: &mut Vec<u8>) {
    // Serializing a &str to JSON cannot fail.
    out.extend_from_slice(serde_json::to_string(s).unwrap_or_default().as_bytes());
}

impl Envelope {
    /// The one encoding: canonical JSON (sorted keys, no spaces).
    pub fn canonical(&self) -> Vec<u8> {
        // Every key of the envelope is a string and every number is a u32 or
        // a JSON number already, so `to_value` cannot fail; `null` would not
        // pass `check_bytes` as an envelope anyway.
        let v = serde_json::to_value(self).unwrap_or(Value::Null);
        let mut out = Vec::with_capacity(4096);
        write_canonical(&v, &mut out);
        out
    }

    /// `sha256:` + hex of [`Self::canonical`].
    pub fn sha256(&self) -> String {
        sha256_hex(&self.canonical())
    }

    pub fn summary(&self) -> SentSummary {
        SentSummary {
            tables: self.schema.tables.len(),
            synthetic_rows: self.synthetic.values().map(Vec::len).sum(),
            params: self.params.len(),
            personal_values: crate::firewall::standalone_hits(self).len(),
        }
    }
}

/// `sha256:` + 64 lowercase hex.
pub fn sha256_hex(b: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, b);
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for x in d.as_ref() {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_sorts_keys_and_has_no_spaces() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":{"d":[1,"x y"],"c":null}}"#).unwrap();
        let mut out = Vec::new();
        write_canonical(&v, &mut out);
        assert_eq!(out, br#"{"a":{"c":null,"d":[1,"x y"]},"b":1}"#);
    }

    /// Plan 48 C1: a schema without joins has the bytes (and so the hash)
    /// it had before `joins` existed, and those bytes still parse.
    #[test]
    fn empty_joins_leave_the_schema_bytes_unchanged() {
        const BEFORE: &str = r#"{"tables":[{"columns":[{"class":"quasi","name":"city","ty":"text"}],"entity":"customer","name":"customers","rows":"<100"}]}"#;
        let s = CloudSchema {
            tables: vec![CloudTable {
                name: "customers".into(),
                rows: "<100".into(),
                columns: vec![CloudColumn {
                    name: "city".into(),
                    ty: ColType::Text,
                    class: ColumnClass::Quasi,
                    values: None,
                }],
                entity: Some("customer".into()),
            }],
            joins: vec![],
        };
        let mut out = Vec::new();
        write_canonical(&serde_json::to_value(&s).unwrap(), &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), BEFORE);
        assert_eq!(
            schema_sha256(&s),
            "sha256:37d1ca0e2fac6aec9d76194a4e38e48cf05c128539cd52d9a0af0b5a71703863"
        );
        assert_eq!(serde_json::from_str::<CloudSchema>(BEFORE).unwrap(), s);
        let mut j = s.clone();
        j.joins.push(CloudJoin {
            entity: "customers".into(),
            key: "id".into(),
            table: "invoices".into(),
            column: "customer_id".into(),
        });
        assert_ne!(schema_sha256(&j), schema_sha256(&s));
    }

    #[test]
    fn retry_holds_the_hash_and_class_only() {
        let r = Retry::new("SELECT 18420 FROM t", "literal_not_allowed");
        assert_eq!(
            r.previous_method_sha256,
            method_sha256("SELECT 18420 FROM t")
        );
        let v = serde_json::to_value(&r).unwrap();
        let mut out = Vec::new();
        write_canonical(&v, &mut out);
        let c = String::from_utf8(out).unwrap();
        assert!(!c.contains("18420") && !c.contains("SELECT"), "{c}");
        assert!(serde_json::from_str::<Retry>(
            r#"{"previous_method":"SELECT 1","error_class":"syntax"}"#
        )
        .is_err());
    }

    #[test]
    fn sha256_hex_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
