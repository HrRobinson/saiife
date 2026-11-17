//! Plan 44 R44-6: synthetic sample rows built from the schema and the k-floor
//! public lists only. The signature takes no connection, path or row, so the
//! output cannot derive from real data.

use crate::dataset::Format;
use crate::public::PublicValues;
use crate::schema::{ColType, ColumnClass, Schema};
use serde_json::Value;
use std::collections::BTreeMap;

/// xorshift128+ seeded from the OS. The values are not secret; the point is
/// that two envelopes never share a seed. If the OS source fails, the seed is
/// built from the clock, a process-wide counter and a stack address: never a
/// fixed constant, and good enough for non-secret sample data.
pub fn os_rng() -> impl FnMut() -> u64 {
    let mut seed = [0u8; 16];
    if getrandom::fill(&mut seed).is_err() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
        let c = CTR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let a = &seed as *const _ as usize as u64;
        seed[..8].copy_from_slice(&(c ^ t.rotate_left(17)).to_le_bytes());
        seed[8..].copy_from_slice(&(a ^ c.rotate_left(29) ^ t).to_le_bytes());
    }
    let mut s0 = u64::from_le_bytes(seed[..8].try_into().unwrap_or([1; 8]));
    let mut s1 = u64::from_le_bytes(seed[8..].try_into().unwrap_or([2; 8]));
    if s0 == 0 && s1 == 0 {
        s1 = 0x9E37_79B9_7F4A_7C15;
    }
    move || {
        let mut x = s0;
        let y = s1;
        s0 = y;
        x ^= x << 23;
        s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
        s1.wrapping_add(y)
    }
}

/// Uniform in `lo..=hi` (modulo bias is irrelevant for sample data).
fn range(rng: &mut dyn FnMut() -> u64, lo: u64, hi: u64) -> u64 {
    lo + rng() % (hi - lo + 1)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn date_string(rng: &mut dyn FnMut() -> u64) -> String {
    let lo = days_from_civil(2000, 1, 1) as u64;
    let hi = days_from_civil(2030, 12, 31) as u64;
    let (y, m, d) = civil_from_days(range(rng, lo, hi) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

fn real_value(rng: &mut dyn FnMut() -> u64) -> Value {
    // Integer cents, rendered with two decimals and parsed as a JSON number.
    let cents = range(rng, 0, 9_999_999);
    let s = format!("{}.{:02}", cents / 100, cents % 100);
    serde_json::from_str(&s).unwrap_or(Value::Null)
}

/// Five (`per_table`) synthetic rows per table, keyed by cloud table name and
/// cloud column name.
pub fn synthetic_rows(
    schema: &Schema,
    formats: &BTreeMap<String, Format>,
    public: &[PublicValues],
    per_table: usize,
    rng: &mut dyn FnMut() -> u64,
) -> BTreeMap<String, Vec<BTreeMap<String, Value>>> {
    let mut out = BTreeMap::new();
    for t in &schema.tables {
        let mut rows = Vec::with_capacity(per_table);
        for _ in 0..per_table {
            let mut row = BTreeMap::new();
            for c in &t.columns {
                let key = format!("{}.{}", t.name, c.name);
                let v = match (c.class, c.ty) {
                    (ColumnClass::Public, _) => match public.iter().find(|p| p.column == key) {
                        Some(p) if !p.passing.is_empty() => {
                            let i = range(rng, 0, p.passing.len() as u64 - 1) as usize;
                            Value::String(p.passing[i].clone())
                        }
                        _ => Value::Null,
                    },
                    (ColumnClass::FreeText, _) => Value::String("(free text)".into()),
                    (_, ColType::Integer) => Value::from(range(rng, 1, 99_999)),
                    (_, ColType::Real) => real_value(rng),
                    (_, ColType::Date) => Value::String(date_string(rng)),
                    (_, ColType::Bool) => Value::Bool(rng() & 1 == 1),
                    (class, ColType::Text) => {
                        let n = range(rng, 1, 99_999);
                        if formats.get(&key) == Some(&Format::Email) {
                            Value::String(format!("synthetic{n}@example.invalid"))
                        } else if class == ColumnClass::Identifier {
                            Value::String(format!("Synthetic_{n}"))
                        } else {
                            // The cloud name: an alias hides the real one.
                            Value::String(format!(
                                "Synthetic_{}_{n}",
                                schema.cloud_name(&t.name, Some(&c.name))
                            ))
                        }
                    }
                };
                row.insert(schema.cloud_name(&t.name, Some(&c.name)), v);
            }
            rows.push(row);
        }
        out.insert(schema.cloud_name(&t.name, None), rows);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ColumnInfo, TableInfo};

    fn col(n: &str, ty: ColType, class: ColumnClass, alias: Option<&str>) -> ColumnInfo {
        ColumnInfo {
            name: n.into(),
            ty,
            class,
            alias: alias.map(Into::into),
        }
    }

    fn schema() -> Schema {
        use ColumnClass::*;
        Schema {
            dataset: "demo".parse().unwrap(),
            entities: vec![],
            tables: vec![TableInfo {
                name: "emp".into(),
                alias: Some("staff".into()),
                rows: 10,
                columns: vec![
                    col("id", ColType::Integer, Quasi, None),
                    col("navn", ColType::Text, Identifier, None),
                    col("mail", ColType::Text, Identifier, None),
                    col("tlf", ColType::Text, Identifier, None),
                    col("by", ColType::Text, Quasi, None),
                    col("loen", ColType::Real, Sensitive, Some("salary")),
                    col("ansat", ColType::Date, Quasi, None),
                    col("aktiv", ColType::Bool, Quasi, None),
                    col("note", ColType::Text, FreeText, None),
                    col("afd", ColType::Text, Public, None),
                    col("land", ColType::Text, Public, None),
                ],
            }],
        }
    }

    fn inputs() -> (BTreeMap<String, Format>, Vec<PublicValues>) {
        let f = BTreeMap::from([
            ("emp.mail".to_string(), Format::Email),
            ("emp.tlf".to_string(), Format::Phone),
        ]);
        let p = vec![PublicValues {
            column: "emp.afd".into(),
            passing: vec!["Salg".into(), "IT".into()],
            total_distinct: 2,
        }];
        (f, p)
    }

    fn counter() -> impl FnMut() -> u64 {
        let mut x = 12345u64;
        move || {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            x >> 11
        }
    }

    #[test]
    fn rows_follow_types_and_classes() {
        let (f, p) = inputs();
        let mut r = counter();
        let out = synthetic_rows(&schema(), &f, &p, 5, &mut r);
        let rows = &out["staff"];
        assert_eq!(rows.len(), 5);
        for row in rows {
            let id = row["id"].as_u64().unwrap();
            assert!((1..=99_999).contains(&id));
            let n = row["navn"].as_str().unwrap();
            assert!(n.starts_with("Synthetic_") && n[10..].parse::<u32>().is_ok());
            let m = row["mail"].as_str().unwrap();
            assert!(m.starts_with("synthetic") && m.ends_with("@example.invalid"));
            assert!(m["synthetic".len()..m.len() - 16].parse::<u32>().is_ok());
            // P-8: a phone-formatted column gets the plain identifier form.
            let t = row["tlf"].as_str().unwrap();
            assert!(t.starts_with("Synthetic_") && t[10..].parse::<u32>().is_ok());
            assert!(row["by"].as_str().unwrap().starts_with("Synthetic_by_"));
            let sal = row["salary"].as_f64().unwrap();
            assert!((0.0..=99_999.99).contains(&sal));
            assert!(row.get("loen").is_none());
            let d = row["ansat"].as_str().unwrap();
            assert!(("2000-01-01"..="2030-12-31").contains(&d) && d.len() == 10);
            assert!(row["aktiv"].is_boolean());
            assert_eq!(row["note"], "(free text)");
            assert!(["Salg", "IT"].contains(&row["afd"].as_str().unwrap()));
            // P-9: no PublicValues entry gives null.
            assert!(row["land"].is_null());
        }
    }

    #[test]
    fn aliased_column_uses_the_cloud_name() {
        let mut s = schema();
        s.tables[0].columns[4].alias = Some("town".into());
        let (f, p) = inputs();
        let out = synthetic_rows(&s, &f, &p, 5, &mut counter());
        for row in &out["staff"] {
            assert!(!row.contains_key("by"));
            let v = row["town"].as_str().unwrap();
            assert!(v.starts_with("Synthetic_town_"), "{v}");
            assert!(!v.contains("by"), "the real column name never shows");
        }
    }

    #[test]
    fn empty_passing_list_is_null() {
        let (f, mut p) = inputs();
        p[0].passing.clear();
        let out = synthetic_rows(&schema(), &f, &p, 2, &mut counter());
        assert!(out["staff"].iter().all(|r| r["afd"].is_null()));
    }

    #[test]
    fn never_reads_real_rows() {
        // The signature takes only the schema, formats, public lists and an
        // rng; every text value matches a synthetic pattern.
        let (f, p) = inputs();
        let out = synthetic_rows(&schema(), &f, &p, 5, &mut os_rng());
        for row in &out["staff"] {
            for (k, v) in row {
                if let Some(s) = v.as_str() {
                    let ok = s.starts_with("Synthetic_")
                        || s.starts_with("synthetic")
                        || s == "(free text)"
                        || s.len() == 10 && s.as_bytes()[4] == b'-'
                        || (k == "afd" && ["Salg", "IT"].contains(&s));
                    assert!(ok, "{k}");
                }
            }
        }
    }

    #[test]
    fn fresh_each_time() {
        let (f, p) = inputs();
        let a = synthetic_rows(&schema(), &f, &p, 5, &mut os_rng());
        let b = synthetic_rows(&schema(), &f, &p, 5, &mut os_rng());
        assert_ne!(a, b);
    }

    #[test]
    fn aliases_used() {
        let (f, p) = inputs();
        let out = synthetic_rows(&schema(), &f, &p, 1, &mut counter());
        assert!(out.contains_key("staff") && !out.contains_key("emp"));
        assert!(out["staff"][0].contains_key("salary"));
    }

    #[test]
    fn date_roundtrip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(
            civil_from_days(days_from_civil(2030, 12, 31)),
            (2030, 12, 31)
        );
        assert_eq!(civil_from_days(days_from_civil(2000, 2, 29)), (2000, 2, 29));
    }
}
