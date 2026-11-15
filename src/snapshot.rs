//! A snapshot: the complete file list of one backup, with the chunks of every file.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Dir,
    File,
    Symlink,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Absolute path when it is valid UTF-8; otherwise empty and `raw` holds the bytes.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    pub kind: EntryKind,
    pub mode: u32,
    pub mtime: i64,
    pub mtime_nsec: i64,
    #[serde(default)]
    pub size: u64,
    /// Used to recognise unchanged files in the next backup (with size and times).
    #[serde(default)]
    pub ino: u64,
    #[serde(default)]
    pub ctime: i64,
    #[serde(default)]
    pub ctime_nsec: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<String>,
    /// Symlink target (as raw bytes in base64 when it is not UTF-8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl Entry {
    pub fn set_path(&mut self, p: &Path) {
        match p.to_str() {
            Some(s) => {
                self.path = s.to_string();
                self.raw = None;
            }
            None => {
                self.path = String::new();
                self.raw = Some(B64.encode(p.as_os_str().as_bytes()));
            }
        }
    }

    pub fn path(&self) -> Result<PathBuf> {
        match &self.raw {
            Some(b) => {
                let bytes = B64
                    .decode(b)
                    .map_err(|_| Error::Corrupt("bad raw path".into()))?;
                Ok(PathBuf::from(OsString::from_vec(bytes)))
            }
            None => Ok(PathBuf::from(&self.path)),
        }
    }

    /// The path made relative and checked: absolute, no `..`, no `.`: nothing that could
    /// point a restore outside its target directory.
    pub fn safe_relative(&self) -> Result<PathBuf> {
        let p = self.path()?;
        let mut out = PathBuf::new();
        let mut comps = p.components();
        if comps.next() != Some(Component::RootDir) {
            return Err(Error::Corrupt(format!(
                "snapshot path {:?} is not absolute",
                p
            )));
        }
        for c in comps {
            match c {
                Component::Normal(n) => out.push(n),
                _ => {
                    return Err(Error::Corrupt(format!(
                        "snapshot path {:?} is not clean",
                        p
                    )))
                }
            }
        }
        Ok(out)
    }

    pub fn display(&self) -> String {
        self.path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".into())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    /// Size of all files in the snapshot.
    pub bytes: u64,
    /// Files that were read (the rest were unchanged since the parent snapshot).
    pub files_read: u64,
    pub new_chunks: u64,
    /// Bytes added to the repository (compressed and encrypted).
    pub added_bytes: u64,
    pub skipped: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u32,
    pub name: String,
    pub time: String,
    pub host: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub parent: Option<String>,
    pub summary: Summary,
    /// What could not be read, e.g. "permission denied: /home/x/secret".
    #[serde(default)]
    pub warnings: Vec<String>,
    pub entries: Vec<Entry>,
}

impl Snapshot {
    /// "20261115T183000123Z-1a2b3c4d" (milliseconds): sortable by time, unique by the random tail.
    pub fn new_name(time: &chrono::DateTime<chrono::Utc>) -> Result<String> {
        let tail: [u8; 4] = crate::crypto::random()?;
        Ok(format!(
            "{}-{}",
            time.format("%Y%m%dT%H%M%S%3fZ"),
            tail.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }

    /// The set of backed-up roots, used to find the parent of the next backup.
    pub fn same_source(&self, host: &str, paths: &[String]) -> bool {
        let mut a = self.paths.clone();
        let mut b = paths.to_vec();
        a.sort();
        b.sort();
        self.host == host && a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(p: &str) -> Entry {
        Entry {
            path: p.into(),
            raw: None,
            kind: EntryKind::File,
            mode: 0o644,
            mtime: 0,
            mtime_nsec: 0,
            size: 0,
            ino: 0,
            ctime: 0,
            ctime_nsec: 0,
            chunks: vec![],
            target: None,
        }
    }

    #[test]
    fn safe_relative_rejects_escapes() {
        assert_eq!(
            entry("/home/user/a.txt").safe_relative().unwrap(),
            PathBuf::from("home/user/a.txt")
        );
        for bad in ["relative/a", "/home/../etc/passwd", ""] {
            assert!(entry(bad).safe_relative().is_err(), "{bad}");
        }
    }

    #[test]
    fn non_utf8_paths_roundtrip() {
        let p = PathBuf::from(OsString::from_vec(b"/tmp/caf\xe9.txt".to_vec()));
        let mut e = entry("");
        e.set_path(&p);
        assert!(e.raw.is_some() && e.path.is_empty());
        let json = serde_json::to_string(&e).unwrap();
        let back: Entry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path().unwrap(), p);
    }

    #[test]
    fn names_sort_by_time() {
        use chrono::TimeZone;
        let a = Snapshot::new_name(&chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap())
            .unwrap();
        let b = Snapshot::new_name(&chrono::Utc.with_ymd_and_hms(2026, 11, 2, 3, 4, 5).unwrap())
            .unwrap();
        assert!(a.starts_with("20260102T030405000Z-") && a < b && a.len() == 28);
    }
}
