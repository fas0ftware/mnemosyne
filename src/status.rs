//! A small JSON file with the outcome of the last backup and check of each repository,
//! for dashboards (Olympos) and scripts. It never contains file names or keys.
//!
//! Location: $MNEMOSYNE_STATUS, else $XDG_STATE_HOME/mnemosyne/status.json,
//! else ~/.local/state/mnemosyne/status.json.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Outcome {
    pub time: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    #[serde(default)]
    pub files: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub added_bytes: u64,
    #[serde(default)]
    pub warnings: u64,
    #[serde(default)]
    pub duration_ms: u64,
    /// For checks: "structure", "all" or "N%".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_data: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RepoStatus {
    #[serde(default)]
    pub last_backup: Option<Outcome>,
    /// Last backup that succeeded, kept when a later one fails.
    #[serde(default)]
    pub last_good_backup: Option<Outcome>,
    #[serde(default)]
    pub last_check: Option<Outcome>,
    #[serde(default)]
    pub snapshots: usize,
    #[serde(default)]
    pub repo_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub version: u32,
    pub repos: BTreeMap<String, RepoStatus>,
}

pub fn path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("MNEMOSYNE_STATUS") {
        return Some(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("mnemosyne/status.json"))
}

pub fn load() -> Status {
    path()
        .and_then(|p| fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Status {
            version: 1,
            repos: BTreeMap::new(),
        })
}

/// Read-modify-write; best effort, a status file must never fail a backup.
pub fn update(repo: &str, change: impl FnOnce(&mut RepoStatus)) {
    let Some(p) = path() else { return };
    let mut status = load();
    status.version = 1;
    change(status.repos.entry(repo.to_string()).or_default());
    let Ok(body) = serde_json::to_vec_pretty(&status) else {
        return;
    };
    if let Some(dir) = p.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let tmp = p.with_extension(format!("tmp{}", std::process::id()));
    let written = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&body).and_then(|_| f.sync_all()));
    if written.and_then(|_| fs::rename(&tmp, &p)).is_err() {
        let _ = fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_keeps_other_repos() {
        let d = tempfile::tempdir().unwrap();
        // Tests in this module are the only ones that set MNEMOSYNE_STATUS.
        unsafe { std::env::set_var("MNEMOSYNE_STATUS", d.path().join("s.json")) };
        update("/r1", |s| s.snapshots = 3);
        update("/r2", |s| {
            s.last_check = Some(Outcome {
                ok: true,
                ..Default::default()
            })
        });
        let st = load();
        assert_eq!(st.repos["/r1"].snapshots, 3);
        assert!(st.repos["/r2"].last_check.as_ref().unwrap().ok);
        unsafe { std::env::remove_var("MNEMOSYNE_STATUS") };
    }
}
