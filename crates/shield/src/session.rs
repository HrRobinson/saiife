//! Sessions (plan 44, R44-5): per uid and dataset, 30 minutes from the first
//! question. The session key is HKDF-SHA-256 over the dataset stand-in key, so
//! symbols are stable inside a session and unrelated across sessions.

use crate::error::ShieldError;
use crate::schema::DatasetName;
use crate::standin::{random_bytes, standin, KeySet};
use ring::hkdf;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;
use zeroize::Zeroizing;

const HKDF_INFO: &[u8] = b"saiife-blind-session-v1";
const MAX_TURNS: usize = 10;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub [u8; 16]);

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    /// The parameterized question.
    pub question: String,
    /// `(parameter name, symbol)`, e.g. `("p1", "Customer_K7QF")`.
    pub symbols: Vec<(String, String)>,
    /// The names a `blind:name` touch released in this turn (ruling P-28):
    /// the turn's question is resent as context, so its released names stay
    /// released while the turn is alive. Local only, never sent.
    pub released: Vec<String>,
}

struct Len32;
impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// HKDF-SHA-256 with a 16-byte session id as salt.
pub(crate) fn derive_session_key(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ShieldError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, Len32)
        .map_err(|_| ShieldError::Corrupt("session key derivation"))?;
    okm.fill(&mut out[..])
        .map_err(|_| ShieldError::Corrupt("session key derivation"))?;
    Ok(out)
}

pub struct Session {
    pub id: SessionId,
    pub uid: u32,
    pub dataset: DatasetName,
    pub started_unix: u64,
    key: Zeroizing<[u8; 32]>,
    pub turns: VecDeque<Turn>,
    /// (table, key) -> symbol.
    symbols: BTreeMap<(String, i64), String>,
    /// Shortened forms that collided; they resolve to nothing (fail closed).
    collided: BTreeSet<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("uid", &self.uid)
            .field("dataset", &self.dataset)
            .field("started_unix", &self.started_unix)
            .field("turns", &self.turns.len())
            .finish_non_exhaustive()
    }
}

fn word_of(symbol: &str) -> &str {
    symbol.split_once('_').map_or(symbol, |(w, _)| w)
}

impl Session {
    pub fn new(
        uid: u32,
        dataset: DatasetName,
        keys: &KeySet,
        now_unix: u64,
    ) -> Result<Session, ShieldError> {
        let id = SessionId(random_bytes::<16>()?);
        let key = derive_session_key(&id.0, &keys.standin[..], HKDF_INFO)?;
        Ok(Session {
            id,
            uid,
            dataset,
            started_unix: now_unix,
            key,
            turns: VecDeque::new(),
            symbols: BTreeMap::new(),
            collided: BTreeSet::new(),
        })
    }

    pub fn expired(&self, now_unix: u64, length: Duration) -> bool {
        now_unix >= self.started_unix.saturating_add(length.as_secs())
    }

    /// Stable within the session; 4 base32 characters, 6 for both entities
    /// when two share the same 4.
    pub fn symbol_for(&mut self, word: &str, table: &str, key: i64) -> String {
        let k = self.key.clone();
        self.symbol_for_with(word, table, key, &|w, t, id, len| {
            standin(&k, w, t, id, len)
        })
    }

    /// `symbol_for` with the derivation injected, so tests can force a collision.
    pub(crate) fn symbol_for_with(
        &mut self,
        word: &str,
        table: &str,
        key: i64,
        derive: &dyn Fn(&str, &str, i64, usize) -> String,
    ) -> String {
        if let Some(s) = self.symbols.get(&(table.to_string(), key)) {
            return s.clone();
        }
        self.place(word, table, key, 4, derive)
    }

    fn place(
        &mut self,
        word: &str,
        table: &str,
        key: i64,
        start: usize,
        derive: &dyn Fn(&str, &str, i64, usize) -> String,
    ) -> String {
        let mut len = start;
        loop {
            let cand = derive(word, table, key, len);
            if len < crate::standin::MAX_CODE_LEN && self.collided.contains(&cand) {
                len += 2;
                continue;
            }
            let other = self
                .symbols
                .iter()
                .find(|(_, s)| **s == cand)
                .map(|(k, _)| k.clone());
            match other {
                Some(ok) if len < crate::standin::MAX_CODE_LEN => {
                    self.collided.insert(cand.clone());
                    self.symbols.remove(&ok);
                    let ow = word_of(&cand).to_string();
                    let longer = self.place(&ow, &ok.0, ok.1, len + 2, derive);
                    for t in &mut self.turns {
                        for (_, sym) in &mut t.symbols {
                            if *sym == cand {
                                *sym = longer.clone();
                            }
                        }
                    }
                    len += 2;
                }
                _ => {
                    self.symbols.insert((table.to_string(), key), cand.clone());
                    return cand;
                }
            }
        }
    }

    /// Reversal, daemon only. A collided short form resolves to nothing.
    pub fn key_for_symbol(&self, symbol: &str) -> Option<(String, i64)> {
        if self.collided.contains(symbol) {
            return None;
        }
        self.symbols
            .iter()
            .find(|(_, s)| s.as_str() == symbol)
            .map(|(k, _)| k.clone())
    }

    /// Every stand-in the session has issued and that still resolves (the
    /// live map's values; a collided short form is gone from it), sorted.
    /// This is the source of [`crate::firewall::Expected::symbols`] (P-25).
    /// Call it **after** [`crate::envelope::build_envelope`]: building the
    /// envelope issues the symbols of the new question's entities.
    pub fn issued_symbols(&self) -> Vec<String> {
        let mut v: Vec<String> = self.symbols.values().cloned().collect();
        v.sort();
        v.dedup();
        v
    }

    /// The names released by `blind:name` in the live turns (ruling P-28),
    /// deduplicated. The firewall's `released_names` is this ask's releases
    /// together with these.
    pub fn released_names(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for n in self.turns.iter().flat_map(|t| t.released.iter()) {
            if !v.contains(n) {
                v.push(n.clone());
            }
        }
        v
    }

    /// The entities the live context turns name (R44-5), each once: what a
    /// planner reply may refer to by symbol
    /// ([`crate::envelope::bind_context`]). Only symbols that a kept turn
    /// holds and that still resolve (a collided short form does not);
    /// take it when the envelope is built, so it is the context that was
    /// sent.
    pub fn context_entities(&self) -> Vec<ContextEntity> {
        let mut v: Vec<ContextEntity> = Vec::new();
        for (_, sym) in self.turns.iter().flat_map(|t| t.symbols.iter()) {
            if v.iter().any(|e| e.symbol == *sym) {
                continue;
            }
            if let Some((table, key)) = self.key_for_symbol(sym) {
                v.push(ContextEntity {
                    symbol: sym.clone(),
                    table,
                    key,
                });
            }
        }
        v
    }

    /// Keeps the last 10 turns.
    pub fn push_turn(&mut self, t: Turn) {
        self.turns.push_back(t);
        while self.turns.len() > MAX_TURNS {
            self.turns.pop_front();
        }
    }
}

/// An entity of the session's context: its stand-in and the key it stands
/// for. Local only (the key never leaves); `Debug` shows the symbol and
/// table, never the key.
#[derive(Clone, PartialEq, Eq)]
pub struct ContextEntity {
    pub symbol: String,
    pub table: String,
    pub key: i64,
}

impl std::fmt::Debug for ContextEntity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextEntity")
            .field("symbol", &self.symbol)
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct Sessions {
    map: BTreeMap<(u32, DatasetName), Session>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions::default()
    }

    /// The live session for `(uid, ds)`; a new one when none exists, it has
    /// expired, or `fresh` (`--new-session`) asks for it.
    pub fn get_or_new(
        &mut self,
        uid: u32,
        ds: &DatasetName,
        keys: &KeySet,
        now_unix: u64,
        length: Duration,
        fresh: bool,
    ) -> Result<&mut Session, ShieldError> {
        match self.map.entry((uid, ds.clone())) {
            Entry::Occupied(o) => {
                let s = o.into_mut();
                if fresh || s.expired(now_unix, length) {
                    *s = Session::new(uid, ds.clone(), keys, now_unix)?;
                }
                Ok(s)
            }
            Entry::Vacant(v) => Ok(v.insert(Session::new(uid, ds.clone(), keys, now_unix)?)),
        }
    }

    /// How many live sessions `uid` has (`blind status`).
    pub fn count_for(&self, uid: u32) -> usize {
        self.map.keys().filter(|(u, _)| *u == uid).count()
    }

    pub fn drop_dataset(&mut self, ds: &DatasetName) {
        self.map.retain(|(_, d), _| d != ds);
    }

    pub fn sweep(&mut self, now_unix: u64, length: Duration) {
        self.map.retain(|_, s| !s.expired(now_unix, length));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HALF_HOUR: Duration = Duration::from_secs(1800);

    fn ds(n: &str) -> DatasetName {
        n.parse().unwrap()
    }

    fn keys() -> KeySet {
        KeySet::generate("2026-01-01T00:00:00Z").unwrap()
    }

    #[test]
    fn hkdf_vector() {
        let ikm = concat!("dataset-", "standin-", "key-", "for-the-vector-test").as_bytes();
        let out = derive_session_key(b"0123456789abcdef", ikm, HKDF_INFO).unwrap();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "fa6b47ca5f94fe96da49d362521c9bc78f4c70b9615290ca873f6f4c0f05db59"
        );
    }

    #[test]
    fn symbols_are_stable_and_reversible() {
        let mut s = Session::new(1, ds("sales"), &keys(), 1000).unwrap();
        let a = s.symbol_for("customer", "customers", 7);
        assert_eq!(a, s.symbol_for("customer", "customers", 7));
        assert_eq!(s.key_for_symbol(&a), Some(("customers".to_string(), 7)));
        assert_eq!(s.key_for_symbol("Customer_ZZZZ"), None);
        let b = s.symbol_for("customer", "customers", 8);
        assert_ne!(a, b);
    }

    #[test]
    fn collision_extends_both() {
        let mut s = Session::new(1, ds("sales"), &keys(), 1000).unwrap();
        // Every entity shares the 4-char code; 6 chars add the id.
        let derive = |w: &str, _t: &str, id: i64, len: usize| -> String {
            if len == 4 {
                format!("{w}_AAAA")
            } else {
                format!("{w}_AAAA{id:02}")
            }
        };
        let a = s.symbol_for_with("Customer", "customers", 1, &derive);
        assert_eq!(a, "Customer_AAAA");
        s.push_turn(Turn {
            question: "q".into(),
            symbols: vec![("p1".into(), a.clone())],
            released: vec![],
        });
        let b = s.symbol_for_with("Customer", "customers", 2, &derive);
        assert_eq!(b, "Customer_AAAA02");
        let a2 = s.symbol_for_with("Customer", "customers", 1, &derive);
        assert_eq!(a2, "Customer_AAAA01");
        assert_eq!(s.turns[0].symbols[0].1, "Customer_AAAA01");
        assert_eq!(s.key_for_symbol("Customer_AAAA"), None);
        assert_eq!(
            s.key_for_symbol("Customer_AAAA01"),
            Some(("customers".into(), 1))
        );
        assert_eq!(
            s.key_for_symbol("Customer_AAAA02"),
            Some(("customers".into(), 2))
        );
        // A third entity with the same short code goes straight to 6.
        let c = s.symbol_for_with("Customer", "customers", 3, &derive);
        assert_eq!(c, "Customer_AAAA03");
        assert_eq!(s.key_for_symbol("Customer_AAAA"), None);
    }

    #[test]
    fn issued_symbols_are_the_live_ones() {
        let mut s = Session::new(1, ds("sales"), &keys(), 1000).unwrap();
        assert!(s.issued_symbols().is_empty());
        let derive = |w: &str, _t: &str, id: i64, len: usize| -> String {
            if len == 4 {
                format!("{w}_AAAA")
            } else {
                format!("{w}_AAAA{id:02}")
            }
        };
        s.symbol_for_with("Customer", "customers", 1, &derive);
        assert_eq!(s.issued_symbols(), vec!["Customer_AAAA".to_string()]);
        s.symbol_for_with("Customer", "customers", 2, &derive);
        // The collided short form is no longer issued.
        assert_eq!(
            s.issued_symbols(),
            vec!["Customer_AAAA01".to_string(), "Customer_AAAA02".to_string()]
        );
    }

    #[test]
    fn released_names_follow_live_turns() {
        let mut s = Session::new(1, ds("sales"), &keys(), 0).unwrap();
        s.push_turn(Turn {
            question: "q0".into(),
            symbols: vec![],
            released: vec!["Zed Zulu".into()],
        });
        s.push_turn(Turn {
            question: "q1".into(),
            symbols: vec![],
            released: vec!["Zed Zulu".into(), "Ada Moe".into()],
        });
        assert_eq!(
            s.released_names(),
            vec!["Zed Zulu".to_string(), "Ada Moe".to_string()]
        );
        for i in 2..12 {
            s.push_turn(Turn {
                question: format!("q{i}"),
                symbols: vec![],
                released: vec![],
            });
        }
        // Both turns dropped out of the context: their releases with them.
        assert!(s.released_names().is_empty());
    }

    #[test]
    fn sessions_are_per_uid_and_dataset() {
        let k = keys();
        let mut m = Sessions::new();
        let a = m
            .get_or_new(1, &ds("sales"), &k, 0, HALF_HOUR, false)
            .unwrap()
            .id;
        let a_again = m
            .get_or_new(1, &ds("sales"), &k, 60, HALF_HOUR, false)
            .unwrap()
            .id;
        let b = m
            .get_or_new(2, &ds("sales"), &k, 0, HALF_HOUR, false)
            .unwrap()
            .id;
        let c = m
            .get_or_new(1, &ds("hr"), &k, 0, HALF_HOUR, false)
            .unwrap()
            .id;
        assert_eq!(a, a_again);
        assert!(a != b && a != c && b != c);
        let sa = m
            .get_or_new(1, &ds("sales"), &k, 0, HALF_HOUR, false)
            .unwrap()
            .symbol_for("customer", "t", 1);
        let sb = m
            .get_or_new(2, &ds("sales"), &k, 0, HALF_HOUR, false)
            .unwrap()
            .symbol_for("customer", "t", 1);
        assert_ne!(sa, sb);
        m.drop_dataset(&ds("sales"));
        let a2 = m
            .get_or_new(1, &ds("sales"), &k, 0, HALF_HOUR, false)
            .unwrap()
            .id;
        assert_ne!(a, a2);
        let c2 = m
            .get_or_new(1, &ds("hr"), &k, 0, HALF_HOUR, false)
            .unwrap()
            .id;
        assert_eq!(c, c2);
    }

    #[test]
    fn expired_session_gets_a_new_key() {
        let k = keys();
        let mut m = Sessions::new();
        let s = m
            .get_or_new(1, &ds("sales"), &k, 0, HALF_HOUR, false)
            .unwrap();
        let (id, sym) = (s.id, s.symbol_for("customer", "customers", 7));
        let s = m
            .get_or_new(1, &ds("sales"), &k, 29 * 60, HALF_HOUR, false)
            .unwrap();
        assert_eq!(s.id, id);
        let s = m
            .get_or_new(1, &ds("sales"), &k, 31 * 60, HALF_HOUR, false)
            .unwrap();
        assert_ne!(s.id, id);
        assert_eq!(s.started_unix, 31 * 60);
        assert_ne!(s.symbol_for("customer", "customers", 7), sym);
        m.sweep(31 * 60 + 1801, HALF_HOUR);
        assert!(m.map.is_empty());
    }

    #[test]
    fn new_session_flag() {
        let k = keys();
        let mut m = Sessions::new();
        let id = m
            .get_or_new(1, &ds("sales"), &k, 0, HALF_HOUR, false)
            .unwrap()
            .id;
        let id2 = m
            .get_or_new(1, &ds("sales"), &k, 10, HALF_HOUR, true)
            .unwrap()
            .id;
        assert_ne!(id, id2);
        assert_eq!(
            m.get_or_new(1, &ds("sales"), &k, 20, HALF_HOUR, false)
                .unwrap()
                .id,
            id2
        );
    }

    #[test]
    fn turns_capped_at_ten() {
        let mut s = Session::new(1, ds("sales"), &keys(), 0).unwrap();
        for i in 0..15 {
            s.push_turn(Turn {
                question: format!("q{i}"),
                symbols: vec![],
                released: vec![],
            });
        }
        assert_eq!(s.turns.len(), 10);
        assert_eq!(s.turns.front().unwrap().question, "q5");
        assert_eq!(s.turns.back().unwrap().question, "q14");
    }

    #[test]
    fn debug_has_no_key_material() {
        let s = Session::new(1, ds("sales"), &keys(), 0).unwrap();
        let d = format!("{s:?}");
        let hex: String = s.key.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!d.contains(&hex) && !d.contains(&format!("{:?}", &s.key[..])));
    }
}
