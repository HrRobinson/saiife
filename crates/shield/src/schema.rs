//! The shared vocabulary: dataset names, column classes, the cloud-visible
//! schema, rows bands, and the parameter types plans 44 and 45 share.

use crate::error::ShieldError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// A dataset name (R43-2): `[a-z][a-z0-9-]{0,31}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DatasetName(String);

impl DatasetName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DatasetName {
    type Err = ShieldError;
    fn from_str(s: &str) -> Result<Self, ShieldError> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 32
            && b[0].is_ascii_lowercase()
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
        if ok {
            Ok(DatasetName(s.to_string()))
        } else {
            Err(ShieldError::BadName)
        }
    }
}

impl fmt::Display for DatasetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for DatasetName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DatasetName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnClass {
    Identifier,
    Quasi,
    Sensitive,
    FreeText,
    Public,
}

impl ColumnClass {
    /// Public 0, Quasi 1, Identifier 2, FreeText 3, Sensitive 4.
    pub fn strictness(self) -> u8 {
        match self {
            ColumnClass::Public => 0,
            ColumnClass::Quasi => 1,
            ColumnClass::Identifier => 2,
            ColumnClass::FreeText => 3,
            ColumnClass::Sensitive => 4,
        }
    }

    pub fn is_looser_than(self, o: ColumnClass) -> bool {
        self.strictness() < o.strictness()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColType {
    Integer,
    Real,
    Text,
    Date,
    Bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnInfo {
    pub name: String,
    pub ty: ColType,
    pub class: ColumnClass,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableInfo {
    pub name: String,
    pub alias: Option<String>,
    pub rows: u64,
    pub columns: Vec<ColumnInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitySpec {
    pub table: String,
    pub key: String,
    pub names: Vec<String>,
    pub show: Vec<String>,
    pub word: String,
    pub word_da: String,
}

/// One declared key relation (plan 45 ruling C-G1): the INTEGER column
/// `table.column` holds keys of the entity `entity.key`. Snapshot names
/// throughout (never aliases).
///
/// **Invariant (plan 48 C5, owner ruling D51-4):** in a built dataset the
/// key side `entity.key` is UNIQUE and NON-NULL (no NULL, no empty value,
/// no value on two rows); `dataset::finish` refuses a build otherwise. So
/// each FK row matches at most one key row, and the validator's join rules
/// (`sql.rs`: a key-side row repeats only along a fan edge) hold. The FK
/// side `table.column` may repeat.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyJoin {
    /// The entity's table ([`EntitySpec::table`]) and its key column.
    pub entity: String,
    pub key: String,
    /// The FK side: another table and its INTEGER column.
    pub table: String,
    pub column: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub dataset: DatasetName,
    pub tables: Vec<TableInfo>,
    pub entities: Vec<EntitySpec>,
    /// The key relations a method may join on, sorted and without
    /// duplicates. `dataset::finish` checks the ones a policy declares and
    /// adds [`Schema::conventional_joins`]; a manifest of version 1 has none
    /// stored and gets the conventional ones on load.
    #[serde(default)]
    pub joins: Vec<KeyJoin>,
}

/// Plan 45 (S1) names its own CTEs and aliases `_p_...`: no snapshot table
/// or column and no alias may start with this prefix, in any case.
pub const RESERVED_PREFIX: &str = "_p_";

/// The name starts with [`RESERVED_PREFIX`], ASCII case-insensitively
/// (SQLite names are case-insensitive).
pub fn is_reserved_name(name: &str) -> bool {
    name.as_bytes()
        .get(..RESERVED_PREFIX.len())
        .is_some_and(|b| b.eq_ignore_ascii_case(RESERVED_PREFIX.as_bytes()))
}

impl Schema {
    pub fn table(&self, t: &str) -> Option<&TableInfo> {
        self.tables.iter().find(|x| x.name == t)
    }

    pub fn column(&self, t: &str, c: &str) -> Option<&ColumnInfo> {
        self.table(t)?.columns.iter().find(|x| x.name == c)
    }

    pub fn entity_for(&self, table: &str) -> Option<&EntitySpec> {
        self.entities.iter().find(|e| e.table == table)
    }

    /// Ruling C-G1 as plan 45 applies it, on cloud names only (its review
    /// F1): for every entity, each INTEGER column of another table whose
    /// cloud name is `<word>_<cloud name of the key>` (ASCII lower case),
    /// with an INTEGER key. Sorted, no duplicates.
    pub fn conventional_joins(&self) -> Vec<KeyJoin> {
        let mut out = Vec::new();
        for e in &self.entities {
            if self.column(&e.table, &e.key).map(|c| c.ty) != Some(ColType::Integer) {
                continue;
            }
            let fk = format!("{}_{}", e.word, self.cloud_name(&e.table, Some(&e.key)))
                .to_ascii_lowercase();
            for t in self.tables.iter().filter(|t| t.name != e.table) {
                for c in &t.columns {
                    if c.ty == ColType::Integer && self.cloud_name(&t.name, Some(&c.name)) == fk {
                        out.push(KeyJoin {
                            entity: e.table.clone(),
                            key: e.key.clone(),
                            table: t.name.clone(),
                            column: c.name.clone(),
                        });
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// The declared join between two snapshot columns `(table, column)`, in
    /// either order, and whether `a` is the entity-key side.
    pub fn key_join(&self, a: (&str, &str), b: (&str, &str)) -> Option<(&KeyJoin, bool)> {
        let key = |j: &KeyJoin, x: (&str, &str)| x == (j.entity.as_str(), j.key.as_str());
        let fk = |j: &KeyJoin, x: (&str, &str)| x == (j.table.as_str(), j.column.as_str());
        self.joins.iter().find_map(|j| {
            if key(j, a) && fk(j, b) {
                Some((j, true))
            } else if key(j, b) && fk(j, a) {
                Some((j, false))
            } else {
                None
            }
        })
    }

    /// The name the cloud sees: the alias if there is one, else the name.
    /// An unknown table or column gives the name unchanged.
    pub fn cloud_name(&self, t: &str, c: Option<&str>) -> String {
        match c {
            None => self
                .table(t)
                .and_then(|x| x.alias.clone())
                .unwrap_or_else(|| t.to_string()),
            Some(c) => self
                .column(t, c)
                .and_then(|x| x.alias.clone())
                .unwrap_or_else(|| c.to_string()),
        }
    }
}

/// A row count as a band: under 100, else one significant figure.
pub fn rows_band(n: u64) -> String {
    if n < 100 {
        return "<100".to_string();
    }
    let mut mag: u64 = 1;
    while n / mag >= 10 {
        mag *= 10;
    }
    let r = n.saturating_add(mag / 2) / mag * mag;
    let (v, unit) = if r >= 1_000_000_000 {
        (r / 1_000_000_000, " billion")
    } else if r >= 1_000_000 {
        (r / 1_000_000, " million")
    } else if r >= 1_000 {
        (r / 1_000, " thousand")
    } else {
        (r, "")
    };
    format!("about {v}{unit}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    En,
    Da,
}

// ---- the parameter vocabulary (spec §2.1.6, §2.3.1) ----

/// An exact decimal: `units / 10^scale`. Equality and order are by value.
#[derive(Debug, Clone, Copy)]
pub struct Decimal {
    pub units: i128,
    pub scale: u8,
}

const MAX_SCALE: u8 = 38;

fn pow10(n: u8) -> Option<i128> {
    10i128.checked_pow(u32::from(n))
}

impl Decimal {
    /// `-?digits[.digits]`: no sign `+`, no exponent, no spaces.
    pub fn parse_plain(s: &str) -> Option<Decimal> {
        let (neg, rest) = match s.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, s),
        };
        let (int, frac) = match rest.split_once('.') {
            Some((i, f)) => (i, f),
            None => (rest, ""),
        };
        if int.is_empty()
            || !int.bytes().all(|b| b.is_ascii_digit())
            || !frac.bytes().all(|b| b.is_ascii_digit())
            || (rest.contains('.') && frac.is_empty())
            || frac.len() > usize::from(MAX_SCALE)
        {
            return None;
        }
        let mut units: i128 = 0;
        for b in int.bytes().chain(frac.bytes()) {
            units = units.checked_mul(10)?.checked_add(i128::from(b - b'0'))?;
        }
        if neg {
            units = -units;
        }
        Some(Decimal {
            units,
            scale: frac.len() as u8,
        })
    }

    /// Plain notation with exactly `scale` places: `-0.30`.
    pub fn to_plain(&self) -> String {
        let neg = self.units < 0;
        let digits = self.units.unsigned_abs().to_string();
        let sc = usize::from(self.scale);
        let body = if sc == 0 {
            digits
        } else {
            let padded = format!("{digits:0>width$}", width = sc + 1);
            let (i, f) = padded.split_at(padded.len() - sc);
            format!("{i}.{f}")
        };
        if neg {
            format!("-{body}")
        } else {
            body
        }
    }

    /// Round to `places` decimals, ties to the even digit.
    pub fn round_half_even(&self, places: u8) -> Decimal {
        if places >= self.scale {
            return *self;
        }
        let Some(div) = pow10(self.scale - places) else {
            return Decimal {
                units: 0,
                scale: places,
            };
        };
        let q = self.units / div;
        let r = self.units % div;
        let twice = r.unsigned_abs().checked_mul(2);
        let half = div.unsigned_abs();
        let away = match twice.map(|t| t.cmp(&half)) {
            Some(Ordering::Greater) => true,
            Some(Ordering::Less) => false,
            _ => q % 2 != 0,
        };
        let units = if away {
            q + if self.units < 0 { -1 } else { 1 }
        } else {
            q
        };
        Decimal {
            units,
            scale: places,
        }
    }

    fn normalized(&self) -> (i128, u8) {
        let (mut u, mut s) = (self.units, self.scale);
        while s > 0 && u % 10 == 0 {
            u /= 10;
            s -= 1;
        }
        if u == 0 {
            s = 0;
        }
        (u, s)
    }
}

impl PartialEq for Decimal {
    fn eq(&self, o: &Decimal) -> bool {
        self.normalized() == o.normalized()
    }
}
impl Eq for Decimal {}

impl Hash for Decimal {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.normalized().hash(h);
    }
}

impl Ord for Decimal {
    fn cmp(&self, o: &Decimal) -> Ordering {
        let (au, asc) = self.normalized();
        let (bu, bsc) = o.normalized();
        match asc.cmp(&bsc) {
            Ordering::Equal => au.cmp(&bu),
            Ordering::Less => {
                // Scale a up to b's scale; an overflow means |a| is larger.
                match pow10(bsc - asc).and_then(|p| au.checked_mul(p)) {
                    Some(a2) => a2.cmp(&bu),
                    None if au > 0 => Ordering::Greater,
                    None => Ordering::Less,
                }
            }
            Ordering::Greater => o.cmp(self).reverse(),
        }
    }
}
impl PartialOrd for Decimal {
    fn partial_cmp(&self, o: &Decimal) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_plain())
    }
}

impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Decimal::parse_plain(&s).ok_or_else(|| serde::de::Error::custom("not a plain decimal"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    Entity { table: String, word: String },
    Amount,
    Integer,
    Percent,
    Date,
    DateRange,
    Text { table: String, column: String },
}

impl ParamType {
    /// `entity:customers`, `amount`, `date_range`, `text:customers.city`, ...
    pub fn tag(&self) -> String {
        match self {
            ParamType::Entity { table, .. } => format!("entity:{table}"),
            ParamType::Amount => "amount".to_string(),
            ParamType::Integer => "integer".to_string(),
            ParamType::Percent => "percent".to_string(),
            ParamType::Date => "date".to_string(),
            ParamType::DateRange => "date_range".to_string(),
            ParamType::Text { table, column } => format!("text:{table}.{column}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bound {
    Keys(Vec<i64>),
    Amount(Decimal),
    Integer(i64),
    Percent(Decimal),
    Date(String),
    DateRange(String, String),
    Text(String),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Param {
    /// `p1`, `p2`, ...
    pub name: String,
    pub ty: ParamType,
    pub bound: Option<Bound>,
    /// Local only: never sent to the cloud.
    pub display: String,
}

/// I8: a bound holds real values (keys, amounts, dates, text): `Debug`
/// shows the kind only, and for keys their count.
impl fmt::Debug for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bound::Keys(k) => write!(f, "Keys(<{} keys>)", k.len()),
            Bound::Amount(_) => f.write_str("Amount(..)"),
            Bound::Integer(_) => f.write_str("Integer(..)"),
            Bound::Percent(_) => f.write_str("Percent(..)"),
            Bound::Date(_) => f.write_str("Date(..)"),
            Bound::DateRange(..) => f.write_str("DateRange(..)"),
            Bound::Text(_) => f.write_str("Text(..)"),
        }
    }
}

/// I8: the name, the type and the bound's kind; never `display`.
impl fmt::Debug for Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Param")
            .field("name", &self.name)
            .field("ty", &self.ty)
            .field("bound", &self.bound)
            .field("display", &"..")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &str) -> Decimal {
        Decimal::parse_plain(s).unwrap()
    }

    #[test]
    fn dataset_names() {
        for ok in ["crm", "crm-2024"] {
            assert_eq!(ok.parse::<DatasetName>().unwrap().to_string(), ok);
        }
        for bad in ["Crm", "2crm", "crm_x", "", &"a".repeat(33)] {
            assert!(matches!(
                bad.parse::<DatasetName>(),
                Err(ShieldError::BadName)
            ));
        }
        assert!("a".repeat(32).parse::<DatasetName>().is_ok());
        let n: DatasetName = serde_json::from_str("\"crm\"").unwrap();
        assert_eq!(serde_json::to_string(&n).unwrap(), "\"crm\"");
        assert!(serde_json::from_str::<DatasetName>("\"Crm\"").is_err());
    }

    #[test]
    fn class_strictness_order() {
        use ColumnClass::*;
        assert!(Public.is_looser_than(Sensitive));
        assert!(!Sensitive.is_looser_than(Public));
        assert!(Identifier.is_looser_than(FreeText));
        assert!(!Public.is_looser_than(Public));
        assert_eq!(Quasi.strictness(), 1);
    }

    #[test]
    fn rows_band_values() {
        assert_eq!(rows_band(0), "<100");
        assert_eq!(rows_band(99), "<100");
        assert_eq!(rows_band(100), "about 100");
        assert_eq!(rows_band(3_041_227), "about 3 million");
        assert_eq!(rows_band(1_500), "about 2 thousand");
        assert_eq!(rows_band(1_000), "about 1 thousand");
        assert_eq!(rows_band(999_999), "about 1 million");
        assert_eq!(rows_band(5_000_000_000), "about 5 billion");
        let _ = rows_band(u64::MAX); // must not overflow
    }

    #[test]
    fn class_serde_names() {
        assert_eq!(
            serde_json::to_string(&ColumnClass::FreeText).unwrap(),
            "\"free_text\""
        );
        assert_eq!(
            serde_json::to_string(&ColumnClass::Public).unwrap(),
            "\"public\""
        );
        assert_eq!(serde_json::to_string(&Lang::Da).unwrap(), "\"da\"");
        assert_eq!(serde_json::to_string(&ColType::Bool).unwrap(), "\"bool\"");
    }

    #[test]
    fn decimal_value_eq() {
        assert_eq!(dec("1.50"), dec("1.5"));
        assert!(dec("1.5") < dec("1.51"));
        assert!(dec("-2") < dec("-1.99"));
        let m = dec("-0.30");
        assert_eq!((m.units, m.scale), (-30, 2));
        assert_eq!(m.to_plain(), "-0.30");
        assert_eq!(dec("0.05").to_plain(), "0.05");
        assert_eq!(dec("2.345").round_half_even(2).to_plain(), "2.34");
        assert_eq!(dec("2.355").round_half_even(2).to_plain(), "2.36");
        assert_eq!(dec("-2.345").round_half_even(2).to_plain(), "-2.34");
        for bad in ["", "-", ".5", "5.", "+1", "1e3", "1 ", "--1"] {
            assert!(Decimal::parse_plain(bad).is_none(), "{bad}");
        }
        let j = serde_json::to_string(&dec("1.50")).unwrap();
        assert_eq!(j, "\"1.50\"");
    }

    #[test]
    fn param_tags() {
        let e = ParamType::Entity {
            table: "customers".into(),
            word: "customer".into(),
        };
        assert_eq!(e.tag(), "entity:customers");
        let t = ParamType::Text {
            table: "customers".into(),
            column: "city".into(),
        };
        assert_eq!(t.tag(), "text:customers.city");
        assert_eq!(ParamType::DateRange.tag(), "date_range");
        assert_eq!(ParamType::Amount.tag(), "amount");
    }

    /// I8: the Debug text of a parameter carries no real value.
    #[test]
    fn param_debug_has_no_values() {
        let p = Param {
            name: "p1".into(),
            ty: ParamType::Entity {
                table: "customers".into(),
                word: "customer".into(),
            },
            bound: Some(Bound::Keys(vec![4411, 4412])),
            display: "Anna Berg (customer #4411)".into(),
        };
        let d = format!("{p:?}");
        assert!(!d.contains("Anna") && !d.contains("4411"), "{d}");
        assert!(d.contains("p1") && d.contains("customers"), "{d}");
        for b in [
            Bound::Text("Anna Berg".into()),
            Bound::Keys(vec![4411]),
            Bound::Amount(dec("4411.50")),
            Bound::Integer(4411),
            Bound::Percent(dec("44.11")),
            Bound::Date("1980-04-11".into()),
            Bound::DateRange("1980-04-11".into(), "1980-04-12".into()),
        ] {
            let d = format!("{b:?}");
            assert!(
                !d.contains("Anna") && !d.contains("4411") && !d.contains("1980"),
                "{d}"
            );
            assert!(!format!("{:?}", Some(b)).contains("44"));
        }
    }

    #[test]
    fn schema_lookup_and_cloud_name() {
        let s = Schema {
            dataset: "crm".parse().unwrap(),
            tables: vec![TableInfo {
                name: "customers".into(),
                alias: Some("t1".into()),
                rows: 5,
                columns: vec![ColumnInfo {
                    name: "city".into(),
                    ty: ColType::Text,
                    class: ColumnClass::Quasi,
                    alias: None,
                }],
            }],
            entities: vec![],
            joins: vec![],
        };
        assert_eq!(s.cloud_name("customers", None), "t1");
        assert_eq!(s.cloud_name("customers", Some("city")), "city");
        assert!(s.column("customers", "nope").is_none());
        assert!(s.entity_for("customers").is_none());
    }

    #[test]
    fn reserved_names() {
        for n in ["_p_", "_p_x", "_P_total", "_p_1"] {
            assert!(is_reserved_name(n), "{n}");
        }
        for n in ["", "_p", "p_x", "x_p_", "_q_x", "ø_p_"] {
            assert!(!is_reserved_name(n), "{n}");
        }
    }

    fn icol(name: &str, alias: Option<&str>) -> ColumnInfo {
        ColumnInfo {
            name: name.into(),
            ty: ColType::Integer,
            class: ColumnClass::Sensitive,
            alias: alias.map(str::to_string),
        }
    }

    #[test]
    fn conventional_joins_use_cloud_names() {
        let mut s = Schema {
            dataset: "crm".parse().unwrap(),
            tables: vec![
                TableInfo {
                    name: "customers".into(),
                    alias: None,
                    rows: 0,
                    columns: vec![icol("id", None)],
                },
                TableInfo {
                    name: "invoices".into(),
                    alias: None,
                    rows: 0,
                    columns: vec![
                        icol("customer_id", None),
                        // Hidden name matches, cloud name does not.
                        icol("kunde_id", Some("buyer")),
                        // Cloud name matches through an alias.
                        icol("cust", Some("Customer_id")),
                        ColumnInfo {
                            ty: ColType::Text,
                            ..icol("customer_id_text", Some("customer_id"))
                        },
                    ],
                },
            ],
            entities: vec![EntitySpec {
                table: "customers".into(),
                key: "id".into(),
                names: vec!["id".into()],
                show: vec![],
                word: "customer".into(),
                word_da: "kunde".into(),
            }],
            joins: vec![],
        };
        let j = |c: &str| KeyJoin {
            entity: "customers".into(),
            key: "id".into(),
            table: "invoices".into(),
            column: c.into(),
        };
        // `Customer_id` is not lower case: cloud names compare exactly, as
        // plan 45's validator does.
        assert_eq!(s.conventional_joins(), vec![j("customer_id")]);
        s.tables[1].columns[2].alias = Some("customer_id".into());
        s.tables[1].columns[0].alias = Some("first".into());
        assert_eq!(s.conventional_joins(), vec![j("cust")]);
        s.joins = s.conventional_joins();
        assert_eq!(
            s.key_join(("customers", "id"), ("invoices", "cust")),
            Some((&j("cust"), true))
        );
        assert_eq!(
            s.key_join(("invoices", "cust"), ("customers", "id")),
            Some((&j("cust"), false))
        );
        assert!(s
            .key_join(("invoices", "customer_id"), ("customers", "id"))
            .is_none());
        // An alias on the key renames the FK the convention looks for.
        s.tables[0].columns[0].alias = Some("nr".into());
        s.tables[1].columns[1].alias = Some("customer_nr".into());
        assert_eq!(s.conventional_joins(), vec![j("kunde_id")]);
    }
}
