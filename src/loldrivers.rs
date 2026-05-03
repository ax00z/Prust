// LOLDrivers JSON feed loaded into hash-keyed lookup tables.

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub enum LolDriversError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for LolDriversError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "loldrivers: io error: {e}"),
            Self::Json(e) => write!(f, "loldrivers: json parse error: {e}"),
        }
    }
}

impl std::error::Error for LolDriversError {}

impl From<std::io::Error> for LolDriversError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for LolDriversError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

#[derive(Deserialize, Debug)]
struct RawDriver {
    #[serde(default, rename = "Id")]
    id: String,
    #[serde(default, rename = "Category")]
    category: String,
    #[serde(default, rename = "MitreID")]
    mitre_id: Option<String>,
    #[serde(default, rename = "Tags")]
    tags: Vec<String>,
    #[serde(default, rename = "KnownVulnerableSamples")]
    samples: Vec<RawSample>,
}

#[derive(Deserialize, Debug)]
struct RawSample {
    #[serde(default, rename = "Filename")]
    filename: String,
    #[serde(default, rename = "SHA256")]
    sha256: Option<String>,
    #[serde(default, alias = "Imphash", alias = "ImpHash")]
    imphash: Option<String>,
    #[serde(default, rename = "Authentihash")]
    authentihash: Option<RawAuthentihash>,
}

#[derive(Deserialize, Debug)]
struct RawAuthentihash {
    #[serde(default, rename = "SHA256")]
    sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DriverEntry {
    pub id: String,
    pub filename: String,
    pub category: String,
    pub mitre_id: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Sha256,
    Authentihash,
    Imphash,
}

impl MatchKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Authentihash => "authentihash",
            Self::Imphash => "imphash",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DriverMatch {
    pub kind: MatchKind,
    pub entry: Arc<DriverEntry>,
}

#[derive(Debug, Default)]
pub struct LolDriversDb {
    entries: usize,
    by_sha256: HashMap<String, Arc<DriverEntry>>,
    by_authentihash: HashMap<String, Arc<DriverEntry>>,
    by_imphash: HashMap<String, Vec<Arc<DriverEntry>>>,
}

impl LolDriversDb {
    pub fn load_from_path(path: &Path) -> Result<Self, LolDriversError> {
        let bytes = fs::read(path)?;
        Self::load_from_bytes(&bytes)
    }

    pub fn load_from_bytes(bytes: &[u8]) -> Result<Self, LolDriversError> {
        let raw: Vec<RawDriver> = serde_json::from_slice(bytes)?;
        let mut db = LolDriversDb::default();

        for d in raw {
            for s in &d.samples {
                let sha256 = norm_hash(s.sha256.as_deref());
                let authentihash = s
                    .authentihash
                    .as_ref()
                    .and_then(|a| norm_hash(a.sha256.as_deref()));
                let imphash = norm_hash(s.imphash.as_deref());

                if sha256.is_none() && authentihash.is_none() && imphash.is_none() {
                    continue;
                }

                let entry = Arc::new(DriverEntry {
                    id: d.id.clone(),
                    filename: s.filename.clone(),
                    category: d.category.clone(),
                    mitre_id: d.mitre_id.clone(),
                    tags: d.tags.clone(),
                });

                if let Some(h) = sha256 {
                    db.by_sha256.insert(h, entry.clone());
                }
                if let Some(h) = authentihash {
                    db.by_authentihash.insert(h, entry.clone());
                }
                if let Some(h) = imphash {
                    db.by_imphash.entry(h).or_default().push(entry.clone());
                }

                db.entries += 1;
            }
        }

        Ok(db)
    }

    pub fn lookup(
        &self,
        sha256: &str,
        authentihash: Option<&str>,
        imphash: Option<&str>,
    ) -> Option<DriverMatch> {
        let s = sha256.to_ascii_lowercase();
        if let Some(e) = self.by_sha256.get(&s) {
            return Some(DriverMatch {
                kind: MatchKind::Sha256,
                entry: e.clone(),
            });
        }

        if let Some(a) = authentihash {
            let a = a.to_ascii_lowercase();
            if let Some(e) = self.by_authentihash.get(&a) {
                return Some(DriverMatch {
                    kind: MatchKind::Authentihash,
                    entry: e.clone(),
                });
            }
        }

        if let Some(h) = imphash {
            let h = h.to_ascii_lowercase();
            if let Some(list) = self.by_imphash.get(&h)
                && let Some(e) = list.first()
            {
                return Some(DriverMatch {
                    kind: MatchKind::Imphash,
                    entry: e.clone(),
                });
            }
        }

        None
    }

    pub fn len(&self) -> usize {
        self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}

fn norm_hash(h: Option<&str>) -> Option<String> {
    h.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = br#"[
        {
            "Id": "rtcore-id",
            "Category": "vulnerable",
            "MitreID": "T1068",
            "Tags": ["Vulnerable Driver"],
            "KnownVulnerableSamples": [
                {
                    "Filename": "RTCore64.sys",
                    "SHA256": "01AA278B07B58DC46C84BD0B1B5C8E9E01AA278B07B58DC46C84BD0B1B5C8E9E",
                    "Imphash": "ABCDEF0123456789ABCDEF0123456789",
                    "Authentihash": { "SHA256": "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF" }
                }
            ]
        },
        {
            "Id": "gdrv-id",
            "Category": "vulnerable",
            "MitreID": "T1068",
            "Tags": ["Vulnerable Driver"],
            "KnownVulnerableSamples": [
                {
                    "Filename": "gdrv.sys",
                    "SHA256": "1111111111111111111111111111111111111111111111111111111111111111",
                    "ImpHash": "2222222222222222222222222222222222"
                }
            ]
        }
    ]"#;

    #[test]
    fn parses_fixture_into_two_entries() {
        let db = LolDriversDb::load_from_bytes(FIXTURE).unwrap();
        assert_eq!(db.len(), 2);
        assert!(!db.is_empty());
    }

    #[test]
    fn sha256_lookup_is_case_insensitive() {
        let db = LolDriversDb::load_from_bytes(FIXTURE).unwrap();
        let lower = "01aa278b07b58dc46c84bd0b1b5c8e9e01aa278b07b58dc46c84bd0b1b5c8e9e";
        let m = db.lookup(lower, None, None).expect("should match");
        assert_eq!(m.kind, MatchKind::Sha256);
        assert_eq!(m.entry.filename, "RTCore64.sys");
        assert_eq!(m.entry.mitre_id.as_deref(), Some("T1068"));
    }

    #[test]
    fn sha256_beats_imphash_when_both_match() {
        let db = LolDriversDb::load_from_bytes(FIXTURE).unwrap();
        let m = db
            .lookup(
                "01aa278b07b58dc46c84bd0b1b5c8e9e01aa278b07b58dc46c84bd0b1b5c8e9e",
                None,
                Some("abcdef0123456789abcdef0123456789"),
            )
            .unwrap();
        assert_eq!(m.kind, MatchKind::Sha256);
    }

    #[test]
    fn imphash_matches_when_sha256_misses() {
        let db = LolDriversDb::load_from_bytes(FIXTURE).unwrap();
        let m = db
            .lookup(
                "0000000000000000000000000000000000000000000000000000000000000000",
                None,
                Some("abcdef0123456789abcdef0123456789"),
            )
            .unwrap();
        assert_eq!(m.kind, MatchKind::Imphash);
        assert_eq!(m.entry.filename, "RTCore64.sys");
    }

    #[test]
    fn authentihash_matches_when_sha256_misses() {
        let db = LolDriversDb::load_from_bytes(FIXTURE).unwrap();
        let m = db
            .lookup(
                "0000000000000000000000000000000000000000000000000000000000000000",
                Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
                None,
            )
            .unwrap();
        assert_eq!(m.kind, MatchKind::Authentihash);
    }

    #[test]
    fn miss_returns_none() {
        let db = LolDriversDb::load_from_bytes(FIXTURE).unwrap();
        assert!(
            db.lookup(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                None,
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn imphash_alias_field_name_works() {
        let db = LolDriversDb::load_from_bytes(FIXTURE).unwrap();
        let m = db
            .lookup(
                "0000000000000000000000000000000000000000000000000000000000000000",
                None,
                Some("2222222222222222222222222222222222"),
            )
            .unwrap();
        assert_eq!(m.kind, MatchKind::Imphash);
        assert_eq!(m.entry.filename, "gdrv.sys");
    }

    #[test]
    fn empty_or_whitespace_hashes_are_dropped() {
        let fixture = br#"[{
            "Id":"x","Category":"vulnerable","MitreID":null,
            "KnownVulnerableSamples":[
                {"Filename":"a.sys","SHA256":"","Imphash":"   "}
            ]
        }]"#;
        let db = LolDriversDb::load_from_bytes(fixture).unwrap();
        assert_eq!(db.len(), 0);
        assert!(db.lookup("", None, Some("")).is_none());
    }

    #[test]
    fn malformed_json_returns_typed_error() {
        let err = LolDriversDb::load_from_bytes(b"not json").unwrap_err();
        assert!(matches!(err, LolDriversError::Json(_)));
    }

    #[test]
    fn missing_optional_fields_default_cleanly() {
        let fixture = br#"[{
            "Id":"min","Category":"vulnerable",
            "KnownVulnerableSamples":[{"Filename":"x.sys","SHA256":"aa"}]
        }]"#;
        let db = LolDriversDb::load_from_bytes(fixture).unwrap();
        let m = db.lookup("aa", None, None).unwrap();
        assert_eq!(m.entry.mitre_id, None);
        assert!(m.entry.tags.is_empty());
    }
}
