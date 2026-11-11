//! The paired-device list: parse and write bytes only (file I/O is plan 29's).

use crate::{b64, frame::strict_json, WireError};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Pending,
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub label: String,
    pub owner_user: String,
    /// b64u of the 65 raw bytes.
    pub public_key: String,
    pub state: DeviceState,
    pub added_at: u64,
    /// saiife-touch credential ids (plan 31).
    #[serde(default)]
    pub touch_credentials: Vec<String>,
}

impl Device {
    pub fn public_raw(&self) -> Result<[u8; 65], WireError> {
        b64::dec_n::<65>(&self.public_key)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceList {
    pub v: u32,
    pub devices: Vec<Device>,
}

impl Default for DeviceList {
    fn default() -> Self {
        DeviceList {
            v: 1,
            devices: Vec::new(),
        }
    }
}

impl DeviceList {
    /// Strict parse (duplicate keys refused); `v` must be 1.
    pub fn parse(bytes: &[u8]) -> Result<DeviceList, WireError> {
        let val = strict_json(bytes)
            .ok_or_else(|| WireError::Store("not strict JSON (or duplicate keys)".into()))?;
        let list: DeviceList =
            serde_json::from_value(val).map_err(|e| WireError::Store(e.to_string()))?;
        if list.v != 1 {
            return Err(WireError::Store(format!(
                "unsupported device list version {}",
                list.v
            )));
        }
        let mut ids: Vec<&str> = list.devices.iter().map(|d| d.id.as_str()).collect();
        ids.sort_unstable();
        if let Some(w) = ids.windows(2).find(|w| w[0] == w[1]) {
            return Err(WireError::Store(format!("duplicate device id {}", w[0])));
        }
        Ok(list)
    }

    /// Pretty JSON, devices sorted by id.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut l = self.clone();
        l.devices.sort_by(|a, b| a.id.cmp(&b.id));
        let mut out = serde_json::to_vec_pretty(&l).expect("device list serializes");
        out.push(b'\n');
        out
    }

    pub fn get(&self, id: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.id == id)
    }

    /// Replaces the device with the same id, or appends.
    pub fn upsert(&mut self, d: Device) {
        match self.devices.iter_mut().find(|x| x.id == d.id) {
            Some(x) => *x = d,
            None => self.devices.push(d),
        }
    }

    /// Marks the device Revoked (the tombstone stays). True when a
    /// non-revoked device was changed.
    pub fn revoke(&mut self, id: &str) -> bool {
        match self.devices.iter_mut().find(|d| d.id == id) {
            Some(d) if d.state != DeviceState::Revoked => {
                d.state = DeviceState::Revoked;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(id: &str, state: DeviceState) -> Device {
        Device {
            id: id.into(),
            label: "phone".into(),
            owner_user: "u".into(),
            public_key: b64::enc(&[4u8; 65]),
            state,
            added_at: 5,
            touch_credentials: vec![],
        }
    }

    #[test]
    fn device_list_roundtrip_sorted() {
        let mut l = DeviceList::default();
        l.upsert(dev("d-b", DeviceState::Active));
        l.upsert(dev("d-a", DeviceState::Pending));
        let bytes = l.to_bytes();
        let back = DeviceList::parse(&bytes).unwrap();
        assert_eq!(back.devices.len(), 2);
        assert_eq!(back.devices[0].id, "d-a");
        assert_eq!(back.devices[1].id, "d-b");
        assert_eq!(back.get("d-b").unwrap().state, DeviceState::Active);
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.devices[0].public_raw().unwrap(), [4u8; 65]);
    }

    #[test]
    fn upsert_replaces_by_id() {
        let mut l = DeviceList::default();
        l.upsert(dev("d-a", DeviceState::Pending));
        l.upsert(dev("d-a", DeviceState::Active));
        assert_eq!(l.devices.len(), 1);
        assert_eq!(l.get("d-a").unwrap().state, DeviceState::Active);
    }

    #[test]
    fn revoked_stays_as_tombstone() {
        let mut l = DeviceList::default();
        l.upsert(dev("d-a", DeviceState::Active));
        assert!(l.revoke("d-a"));
        assert!(!l.revoke("d-a"));
        assert!(!l.revoke("d-none"));
        assert_eq!(l.get("d-a").unwrap().state, DeviceState::Revoked);
        assert_eq!(l.devices.len(), 1);
    }

    #[test]
    fn device_list_refuses_duplicate_keys() {
        let dup = br#"{"v":1,"v":1,"devices":[]}"#;
        assert!(matches!(DeviceList::parse(dup), Err(WireError::Store(_))));
    }

    #[test]
    fn device_list_refuses_duplicate_ids() {
        let mut l = DeviceList::default();
        l.devices.push(dev("d-a", DeviceState::Active));
        l.devices.push(dev("d-a", DeviceState::Revoked));
        let bytes = serde_json::to_vec(&l).unwrap();
        assert!(matches!(
            DeviceList::parse(&bytes),
            Err(WireError::Store(m)) if m.contains("duplicate device id d-a")
        ));
    }

    #[test]
    fn device_list_refuses_bad_version_and_unknown_fields() {
        assert!(DeviceList::parse(br#"{"v":2,"devices":[]}"#).is_err());
        assert!(DeviceList::parse(br#"{"v":0,"devices":[]}"#).is_err());
        assert!(DeviceList::parse(br#"{"v":1,"devices":[],"x":1}"#).is_err());
        assert!(DeviceList::parse(b"junk").is_err());
        assert!(DeviceList::parse(br#"{"v":1,"devices":[]}"#).is_ok());
    }
}
