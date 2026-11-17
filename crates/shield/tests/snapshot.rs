//! Plan 43 T3: the sources and the read-only snapshot.

#[path = "fixtures.rs"]
mod fixtures;

use saiife_shield::schema::ColType;
use saiife_shield::snapshot::{build_snapshot, open_ro, SnapshotInfo};
use saiife_shield::source::{
    Cell, CsvSource, RowSource, SourceTable, SqliteSource, VecSource, XlsxSource,
};
use saiife_shield::ShieldError;
use std::io::Write;
use std::path::Path;

fn csv_src(bytes: &[u8], name: &str) -> CsvSource {
    CsvSource::open(Box::new(std::io::Cursor::new(bytes.to_vec())), name).unwrap()
}

fn build(src: &mut dyn RowSource, dir: &Path) -> Result<SnapshotInfo, ShieldError> {
    build_snapshot(src, &dir.join("ds"), &mut |_| {})
}

fn col_types(info: &SnapshotInfo, table: &str) -> Vec<(String, ColType)> {
    let t = info.tables.iter().find(|t| t.0 == table).unwrap();
    t.3.iter().map(|c| (c.0.clone(), c.2)).collect()
}

#[test]
fn csv_round_trip_types() {
    let dir = tempfile::tempdir().unwrap();
    let data = "id,amount,issued,flag,name\n\
                1,10.5,2024-01-31,true,Anna\n\
                2,7,31-01-2024,false,Berg\n\
                3,12.25,01.02.2024,TRUE,Søren\n\
                4,,02/02/2024,false,\n\
                5,0.5,2024-02-29,False,Åse\n";
    let mut src = csv_src(data.as_bytes(), "t.csv");
    let info = build(&mut src, dir.path()).unwrap();
    assert_eq!(
        col_types(&info, "t"),
        vec![
            ("id".into(), ColType::Integer),
            ("amount".into(), ColType::Real),
            ("issued".into(), ColType::Date),
            ("flag".into(), ColType::Bool),
            ("name".into(), ColType::Text),
        ]
    );
    assert_eq!(info.tables[0].2, 5);
    let c = open_ro(&info.path).unwrap();
    let a: f64 = c
        .query_row("SELECT amount FROM t WHERE id=3", [], |r| r.get(0))
        .unwrap();
    assert_eq!(a, 12.25);
    let d: String = c
        .query_row("SELECT issued FROM t WHERE id=2", [], |r| r.get(0))
        .unwrap();
    assert_eq!(d, "2024-01-31");
    let (b, n): (i64, Option<String>) = c
        .query_row("SELECT flag, name FROM t WHERE id=4", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((b, n), (0, None));
    let null_amount: Option<f64> = c
        .query_row("SELECT amount FROM t WHERE id=4", [], |r| r.get(0))
        .unwrap();
    assert_eq!(null_amount, None);
    let decl: String = c
        .query_row(
            "SELECT group_concat(type, ',') FROM pragma_table_info('t')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(decl, "INTEGER,INTEGER,REAL,DATE,BOOL,TEXT");
}

#[test]
fn semicolon_csv_and_bom() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice("Kunde;Beløb\n1;\"a;b\"\n2;x\n".as_bytes());
    let mut src = csv_src(&bytes, "kunder.csv");
    let t = src.tables();
    assert_eq!(t[0].name, "kunder");
    assert_eq!(t[0].columns, vec!["Kunde", "Beløb"]);
    let info = build(&mut src, dir.path()).unwrap();
    assert_eq!(info.tables[0].3[1].0, "beloeb");
    let c = open_ro(&info.path).unwrap();
    let v: String = c
        .query_row("SELECT beloeb FROM kunder WHERE kunde=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "a;b");

    // Tab-separated works too; UTF-16 and Latin-1 refuse.
    let mut tsv = csv_src(b"a\tb\n1\t2\n", "x.tsv");
    assert_eq!(tsv.tables()[0].columns, vec!["a", "b"]);
    assert!(tsv.rows("x").unwrap().next().is_some());
    let utf16 = CsvSource::open(
        Box::new(std::io::Cursor::new(vec![0xFF, 0xFE, b'a', 0])),
        "u.csv",
    );
    assert!(utf16.is_err());
    let latin1 = CsvSource::open(
        Box::new(std::io::Cursor::new(b"name\nS\xF8ren\n".to_vec())),
        "l.csv",
    );
    let err = match latin1 {
        Err(e) => e,
        Ok(mut s) => build(&mut s, dir.path().join("l").as_path()).unwrap_err(),
    };
    assert!(matches!(err, ShieldError::Source { .. }), "{err}");
}

// ---- a minimal xlsx, assembled here (no binary fixture is checked in) ----

fn xml_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn sheet_xml(rows: &[Vec<&str>], strings: &mut Vec<String>) -> String {
    let mut x = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#,
    );
    for (ri, row) in rows.iter().enumerate() {
        x.push_str(&format!(r#"<row r="{}">"#, ri + 1));
        for (ci, v) in row.iter().enumerate() {
            let r = format!("{}{}", (b'A' + ci as u8) as char, ri + 1);
            if v.is_empty() {
                continue;
            }
            if v.parse::<f64>().is_ok() {
                x.push_str(&format!(r#"<c r="{r}"><v>{v}</v></c>"#));
            } else {
                strings.push(v.to_string());
                x.push_str(&format!(
                    r#"<c r="{r}" t="s"><v>{}</v></c>"#,
                    strings.len() - 1
                ));
            }
        }
        x.push_str("</row>");
    }
    x.push_str("</sheetData></worksheet>");
    x
}

fn write_xlsx(path: &Path, sheets: &[(&str, Vec<Vec<&str>>)]) {
    use zip::write::SimpleFileOptions;
    let mut strings = Vec::new();
    let sheet_xmls: Vec<String> = sheets
        .iter()
        .map(|(_, rows)| sheet_xml(rows, &mut strings))
        .collect();
    let opt = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut z = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    let mut put = |name: &str, body: &str| {
        z.start_file(name, opt).unwrap();
        z.write_all(body.as_bytes()).unwrap();
    };
    let mut ct = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>"#,
    );
    let mut wb = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>"#,
    );
    let mut rels = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for (i, (name, _)) in sheets.iter().enumerate() {
        let n = i + 1;
        ct.push_str(&format!(r#"<Override PartName="/xl/worksheets/sheet{n}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#));
        wb.push_str(&format!(
            r#"<sheet name="{}" sheetId="{n}" r:id="rId{n}"/>"#,
            xml_esc(name)
        ));
        rels.push_str(&format!(r#"<Relationship Id="rId{n}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{n}.xml"/>"#));
    }
    let ss_id = sheets.len() + 1;
    rels.push_str(&format!(r#"<Relationship Id="rId{ss_id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>"#));
    ct.push_str("</Types>");
    wb.push_str("</sheets></workbook>");
    let mut ss = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{0}" uniqueCount="{0}">"#,
        strings.len()
    );
    for s in &strings {
        ss.push_str(&format!("<si><t>{}</t></si>", xml_esc(s)));
    }
    ss.push_str("</sst>");
    put("[Content_Types].xml", &ct);
    put(
        "_rels/.rels",
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#,
    );
    put("xl/workbook.xml", &wb);
    put("xl/_rels/workbook.xml.rels", &rels);
    for (i, x) in sheet_xmls.iter().enumerate() {
        put(&format!("xl/worksheets/sheet{}.xml", i + 1), x);
    }
    put("xl/sharedStrings.xml", &ss);
    z.finish().unwrap();
}

#[test]
fn xlsx_two_sheets_two_tables() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("book.xlsx");
    write_xlsx(
        &p,
        &[
            (
                "Kunder",
                vec![
                    vec!["Kunde Nr.", "Navn", "By"],
                    vec!["1", "Søren Østergård", "Ærøskøbing"],
                    vec!["2", "Åse Berg", "Aarhus"],
                ],
            ),
            (
                "Fakturaer",
                vec![
                    vec!["id", "kunde", "beløb"],
                    vec!["10", "1", "99.5"],
                    vec!["11", "2", "12"],
                    vec!["12", "2", ""],
                ],
            ),
        ],
    );
    let mut src = XlsxSource::open(std::fs::File::open(&p).unwrap(), "book.xlsx").unwrap();
    let names: Vec<String> = src.tables().into_iter().map(|t| t.name).collect();
    assert_eq!(names, vec!["Kunder", "Fakturaer"]);
    let info = build(&mut src, dir.path()).unwrap();
    assert_eq!(info.tables.len(), 2);
    assert_eq!(info.tables[0].0, "kunder");
    assert_eq!(info.tables[0].1, "Kunder");
    assert_eq!(info.tables[0].2, 2);
    assert_eq!(info.tables[1].2, 3);
    assert_eq!(
        col_types(&info, "kunder"),
        vec![
            ("kunde_nr".into(), ColType::Integer),
            ("navn".into(), ColType::Text),
            ("by".into(), ColType::Text),
        ]
    );
    assert_eq!(
        col_types(&info, "fakturaer")[2],
        ("beloeb".into(), ColType::Real)
    );
    let c = open_ro(&info.path).unwrap();
    let n: String = c
        .query_row("SELECT navn FROM kunder WHERE kunde_nr=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, "Søren Østergård");
}

#[test]
fn sqlite_source_skips_views() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("src.db");
    {
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch(
            "CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT, born TEXT);
             INSERT INTO people VALUES (1, 'Anna', '1980-05-01'), (2, 'Søren', '1975-12-24');
             CREATE TABLE tags (tag TEXT PRIMARY KEY, n INTEGER) WITHOUT ROWID;
             INSERT INTO tags VALUES ('a', 1), ('b', 2), ('c', NULL);
             CREATE VIEW v_people AS SELECT name FROM people;
             CREATE INDEX people_name ON people(name);",
        )
        .unwrap();
    }
    let mut src = SqliteSource::open(&p).unwrap();
    let names: Vec<String> = src.tables().into_iter().map(|t| t.name).collect();
    assert_eq!(names, vec!["people", "tags"]);
    let info = build(&mut src, dir.path()).unwrap();
    assert_eq!(
        col_types(&info, "people"),
        vec![
            ("id".into(), ColType::Integer),
            ("name".into(), ColType::Text),
            ("born".into(), ColType::Date),
        ]
    );
    assert_eq!(info.tables[1].2, 3);
    // The source file is untouched (opened immutable, read-only).
    let c = open_ro(&info.path).unwrap();
    let s: String = c
        .query_row("SELECT name FROM people WHERE id=2", [], |r| r.get(0))
        .unwrap();
    assert_eq!(s, "Søren");
}

#[test]
fn names_are_cleaned() {
    let dir = tempfile::tempdir().unwrap();
    let mut src = VecSource {
        tables: vec![
            (
                SourceTable {
                    name: "Kunde Data".into(),
                    columns: vec!["Kunde Nr.".into(), "kunde-nr".into(), "Kunde_Nr".into()],
                },
                vec![vec![Cell::Int(1), Cell::Int(2), Cell::Int(3)]],
            ),
            (
                SourceTable {
                    name: "kunde.data".into(),
                    columns: vec!["x".into()],
                },
                vec![vec![Cell::Null]],
            ),
        ],
    };
    let info = build(&mut src, dir.path()).unwrap();
    assert_eq!(info.tables[0].0, "kunde_data");
    assert_eq!(info.tables[1].0, "kunde_data_2");
    assert_eq!(info.tables[1].1, "kunde.data");
    let cols: Vec<&str> = info.tables[0].3.iter().map(|c| c.0.as_str()).collect();
    assert_eq!(cols, vec!["kunde_nr", "kunde_nr_2", "kunde_nr_3"]);
    assert_eq!(info.tables[0].3[0].1, "Kunde Nr.");
    // An all-empty column is TEXT.
    assert_eq!(info.tables[1].3[0].2, ColType::Text);
}

#[test]
fn limits_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let big = "x".repeat(64 * 1024 + 1);
    let mut src = VecSource {
        tables: vec![(
            SourceTable {
                name: "t".into(),
                columns: vec!["note".into()],
            },
            vec![vec![Cell::Text("ok".into())], vec![Cell::Text(big.clone())]],
        )],
    };
    let err = build(&mut src, dir.path()).unwrap_err();
    let text = err.to_string();
    assert!(
        matches!(&err, ShieldError::Source { table: Some(t), column: Some(c), why, .. }
            if t == "t" && c == "note" && why.contains("64 KiB")),
        "{text}"
    );
    assert!(!text.contains("xxxx"));
    // Nothing is left behind after a refusal.
    assert!(!dir.path().join("ds").join("snapshot.sqlite").exists());
    assert!(!dir.path().join("ds").join("snapshot.sqlite.part").exists());

    // Exactly 64 KiB is fine.
    let mut ok = VecSource {
        tables: vec![(
            SourceTable {
                name: "t".into(),
                columns: vec!["note".into()],
            },
            vec![vec![Cell::Text("y".repeat(64 * 1024))]],
        )],
    };
    build(&mut ok, &dir.path().join("ok")).unwrap();

    // 65 tables and 513 columns refuse with Limit.
    let many = VecSource {
        tables: (0..65)
            .map(|i| {
                (
                    SourceTable {
                        name: format!("t{i}"),
                        columns: vec!["a".into()],
                    },
                    vec![],
                )
            })
            .collect(),
    };
    let mut many = many;
    assert!(matches!(
        build(&mut many, &dir.path().join("m")),
        Err(ShieldError::Limit(_))
    ));
    let mut wide = VecSource {
        tables: vec![(
            SourceTable {
                name: "w".into(),
                columns: (0..513).map(|i| format!("c{i}")).collect(),
            },
            vec![],
        )],
    };
    assert!(matches!(
        build(&mut wide, &dir.path().join("w")),
        Err(ShieldError::Limit(_))
    ));
}

#[test]
fn errors_never_quote_cells() {
    let dir = tempfile::tempdir().unwrap();
    let data = "id,name\n1,Anna\n2,Søren Ærø,extra\n";
    let mut src = csv_src(data.as_bytes(), "people.csv");
    let err = build(&mut src, dir.path()).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("people.csv"), "{text}");
    assert!(text.contains("row 3"), "{text}");
    assert!(!text.contains("Søren"), "{text}");
    assert!(!text.contains("Ærø"), "{text}");
    assert!(!format!("{err:?}").contains("Søren"));
}

#[test]
fn snapshot_is_read_only_and_hashed() {
    let dir = tempfile::tempdir().unwrap();
    let fx = dir.path().join("fx");
    std::fs::create_dir(&fx).unwrap();
    fixtures::write_fixture(&fx, 200, 1).unwrap();
    let f = std::fs::File::open(fx.join("customers.csv")).unwrap();
    let mut src = CsvSource::open(Box::new(f), "customers.csv").unwrap();
    let mut seen = 0;
    let info = build_snapshot(&mut src, &dir.path().join("ds"), &mut |p| {
        assert_eq!(p.table, "customers");
        seen = p.rows_done;
    })
    .unwrap();
    assert_eq!(seen, 200);
    assert_eq!(info.path, dir.path().join("ds").join("snapshot.sqlite"));
    let hex = info.sha256.strip_prefix("sha256:").unwrap();
    assert_eq!(hex.len(), 64);
    assert!(hex
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    // The spool copy is gone.
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    let mut left = left;
    left.sort();
    assert_eq!(left, vec!["ds", "fx"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&info.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o400);
    }
    assert_eq!(
        col_types(&info, "customers")
            .into_iter()
            .map(|c| c.1)
            .collect::<Vec<_>>(),
        vec![
            ColType::Integer,
            ColType::Text,
            ColType::Text,
            ColType::Text,
            ColType::Text,
            ColType::Text,
            ColType::Integer,
            ColType::Date,
            ColType::Text,
            ColType::Real,
            ColType::Text,
        ]
    );
    let c = open_ro(&info.path).unwrap();
    assert!(c
        .execute("INSERT INTO customers (id) VALUES (999)", [])
        .is_err());
    let n: i64 = c
        .query_row("SELECT count(*) FROM customers", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 200);
    drop(c);
    // The hash is of the file bytes.
    let bytes = std::fs::read(&info.path).unwrap();
    let d = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let want: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, want);
    // Written once: a second build into the same dir refuses.
    let mut again = csv_src(b"a\n1\n", "customers.csv");
    assert!(build_snapshot(&mut again, &dir.path().join("ds"), &mut |_| {}).is_err());
}

#[test]
fn danish_text_survives() {
    let dir = tempfile::tempdir().unwrap();
    let data = "id,navn,by\n1,Søren Østergård,Ærø\n2,Åse Berg,København\n3,ÆØÅ æøå,Højer\n";
    let mut src = csv_src(data.as_bytes(), "navne.csv");
    let info = build(&mut src, dir.path()).unwrap();
    let c = open_ro(&info.path).unwrap();
    let mut st = c.prepare("SELECT navn, by FROM navne ORDER BY id").unwrap();
    let got: Vec<(String, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(
        got,
        vec![
            ("Søren Østergård".into(), "Ærø".into()),
            ("Åse Berg".into(), "København".into()),
            ("ÆØÅ æøå".into(), "Højer".into()),
        ]
    );
}

// ---- fix round 1: private files, spool inside the stage, small items ----

#[test]
fn spool_stays_inside_the_stage() {
    let dir = tempfile::tempdir().unwrap();
    let stage = dir.path().join("crm").join("stage");
    let fx = dir.path().join("fx");
    std::fs::create_dir(&fx).unwrap();
    fixtures::write_fixture(&fx, 30, 3).unwrap();
    let f = std::fs::File::open(fx.join("customers.csv")).unwrap();
    let mut src = CsvSource::open(Box::new(f), "customers.csv").unwrap();
    let mut spool_in_stage = false;
    let mut spool_outside = false;
    build_snapshot(&mut src, &stage, &mut |_| {
        let names = |p: &Path| -> Vec<String> {
            std::fs::read_dir(p)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect()
        };
        spool_in_stage |= names(&stage)
            .iter()
            .any(|n| n.starts_with(".saiife-import-"));
        spool_outside |= names(&dir.path().join("crm"))
            .iter()
            .any(|n| n.starts_with(".saiife-import-"));
    })
    .unwrap();
    assert!(spool_in_stage && !spool_outside);
    let left: Vec<_> = std::fs::read_dir(&stage)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left, vec!["snapshot.sqlite"]);
}

#[test]
fn failed_csv_build_leaves_no_spool() {
    let dir = tempfile::tempdir().unwrap();
    let stage = dir.path().join("stage");
    let mut src = csv_src(b"a,b\n1,2\n3,4,5\n", "bad.csv");
    assert!(build_snapshot(&mut src, &stage, &mut |_| {}).is_err());
    drop(src);
    let left: Vec<_> = std::fs::read_dir(&stage).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
    let top: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(top, vec!["stage"]);
}

#[cfg(unix)]
fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn no_sidecars(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().all(|e| {
        let n = e.unwrap().file_name().into_string().unwrap();
        !(n.ends_with("-journal") || n.ends_with("-wal") || n.ends_with("-shm"))
    })
}

#[cfg(unix)]
#[test]
fn part_file_is_private_and_no_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a").join("b");
    let mut src = csv_src(b"id,name\n1,Anna\n2,Berg\n", "p.csv");
    let mut checked = 0;
    build_snapshot(&mut src, &out, &mut |_| {
        assert_eq!(mode_of(&out.join("snapshot.sqlite.part")), 0o600);
        assert!(no_sidecars(&out));
        checked += 1;
    })
    .unwrap();
    assert!(checked > 0);
    assert!(no_sidecars(&out));
    assert_eq!(mode_of(&out.join("snapshot.sqlite")), 0o400);
    // Every dir it made is 0700.
    assert_eq!(mode_of(&out), 0o700);
    assert_eq!(mode_of(&dir.path().join("a")), 0o700);
}

#[cfg(unix)]
#[test]
fn loose_out_dir_is_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("ds");
    std::fs::create_dir(&out).unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut src = csv_src(b"a\n1\n", "x.csv");
    build_snapshot(&mut src, &out, &mut |_| {}).unwrap();
    assert_eq!(mode_of(&out), 0o700);
}

#[cfg(unix)]
#[test]
fn symlinked_part_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("ds");
    std::fs::create_dir(&out).unwrap();
    let target = dir.path().join("victim.txt");
    std::fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, out.join("snapshot.sqlite.part")).unwrap();
    let mut src = csv_src(b"a\n1\n", "x.csv");
    assert!(build_snapshot(&mut src, &out, &mut |_| {}).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert!(!out.join("snapshot.sqlite").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_out_dir_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("ds");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut src = csv_src(b"a\n1\n", "x.csv");
    assert!(build_snapshot(&mut src, &link, &mut |_| {}).is_err());
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
}

#[test]
fn sqlite_with_unsaved_wal_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("w.db");
    {
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch("CREATE TABLE t (a INTEGER); INSERT INTO t VALUES (1);")
            .unwrap();
    }
    std::fs::write(dir.path().join("w.db-wal"), b"pending").unwrap();
    let err = match SqliteSource::open(&p) {
        Err(e) => e,
        Ok(_) => panic!("a database with a -wal file must refuse"),
    };
    assert!(err.to_string().contains("-wal"), "{err}");
    // An empty -wal is fine.
    std::fs::write(dir.path().join("w.db-wal"), b"").unwrap();
    assert!(SqliteSource::open(&p).is_ok());
}

#[test]
fn sqlite_keeps_the_lowest_rowid_and_orders_without_rowid() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("k.db");
    {
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch(
            "CREATE TABLE t (a TEXT);
             INSERT INTO t (rowid, a) VALUES (-9223372036854775808, 'min'), (5, 'five');
             CREATE TABLE w (k INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID;
             INSERT INTO w VALUES (3, 'c'), (1, 'a'), (2, 'b');",
        )
        .unwrap();
    }
    let mut src = SqliteSource::open(&p).unwrap();
    let rows: Vec<Vec<Cell>> = src.rows("t").unwrap().map(|r| r.unwrap()).collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec![Cell::Text("min".into())]);
    let ks: Vec<Cell> = src
        .rows("w")
        .unwrap()
        .map(|r| r.unwrap()[0].clone())
        .collect();
    assert_eq!(ks, vec![Cell::Int(1), Cell::Int(2), Cell::Int(3)]);
}

#[test]
fn huge_digit_strings_stay_text() {
    let dir = tempfile::tempdir().unwrap();
    let mut src = csv_src(
        b"acct,mixed\n12345678901234567890,1.5\n1,99999999999999999999\n",
        "a.csv",
    );
    let info = build(&mut src, dir.path()).unwrap();
    assert_eq!(
        col_types(&info, "a"),
        vec![
            ("acct".into(), ColType::Text),
            ("mixed".into(), ColType::Text)
        ]
    );
    let c = open_ro(&info.path).unwrap();
    let v: String = c
        .query_row("SELECT acct FROM a WHERE _rowid=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "12345678901234567890");
}

// ---- fix round 2 ----

#[cfg(unix)]
#[test]
fn builds_through_a_symlinked_ancestor() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let out = link.join("crm").join("stage");
    let mut src = csv_src(b"id,name\n1,Anna\n", "p.csv");
    let info = build_snapshot(&mut src, &out, &mut |_| {}).unwrap();
    assert!(real.join("crm/stage/snapshot.sqlite").exists());
    let c = open_ro(&info.path).unwrap();
    let n: String = c
        .query_row("SELECT name FROM p WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, "Anna");
    // And a SQLite source reached through the symlink.
    let db = real.join("s.db");
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch("CREATE TABLE t (a INTEGER); INSERT INTO t VALUES (7);")
        .unwrap();
    let mut s = SqliteSource::open(&link.join("s.db")).unwrap();
    assert_eq!(s.rows("t").unwrap().count(), 1);
}

#[test]
fn sqlite_table_with_only_blob_columns_and_no_key() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("b.db");
    rusqlite::Connection::open(&p)
        .unwrap()
        .execute_batch(
            "CREATE TABLE b (rowid BLOB, _rowid_ BLOB, oid BLOB);
             INSERT INTO b VALUES (x'01', x'02', x'03'), (x'04', x'05', x'06');",
        )
        .unwrap();
    let mut src = SqliteSource::open(&p).unwrap();
    let rows: Vec<_> = src.rows("b").unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(rows, vec![Vec::<Cell>::new(), Vec::new()]);
}

#[test]
fn open_ro_temp_store_is_memory() {
    let dir = tempfile::tempdir().unwrap();
    let mut src = csv_src(b"a,b\n1,x\n", "t.csv");
    let info = build(&mut src, dir.path()).unwrap();
    let c = open_ro(&info.path).unwrap();
    let ts: i64 = c.query_row("PRAGMA temp_store", [], |r| r.get(0)).unwrap();
    assert_eq!(ts, 2, "sorts must never spill values to temp files");
}
