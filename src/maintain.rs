//! check, forget and prune.

use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Datelike, Local};
use serde::Serialize;

use crate::repo::{Lock, Repo};
use crate::snapshot::Snapshot;
use crate::{Error, Result};

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct CheckReport {
    pub snapshots: usize,
    pub chunks_referenced: usize,
    pub chunks_stored: usize,
    /// Stored chunks no snapshot uses any more (prune removes them).
    pub chunks_unused: usize,
    pub chunks_read: usize,
    pub bytes_read: u64,
    pub errors: Vec<String>,
}

impl CheckReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Which chunks to decrypt and verify.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReadData {
    None,
    /// Every chunk: a full restore drill without writing files.
    All,
    /// This percentage (1-100) of chunks, picked at random each run, so repeated runs
    /// cover everything over time.
    Percent(u8),
}

pub fn check(repo: &Repo, read: ReadData, progress: &mut dyn FnMut(&str)) -> Result<CheckReport> {
    let mut report = CheckReport::default();
    let stored = repo.chunk_ids()?;
    let mut referenced = BTreeSet::new();
    for name in repo.snapshot_names()? {
        match repo.load_snapshot(&name) {
            Ok(snap) => {
                report.snapshots += 1;
                for e in &snap.entries {
                    if let Err(err) = e.safe_relative() {
                        report.errors.push(format!("snapshot {name}: {err}"));
                    }
                    referenced.extend(e.chunks.iter().cloned());
                }
            }
            Err(err) => report.errors.push(format!("snapshot {name}: {err}")),
        }
    }
    report.chunks_referenced = referenced.len();
    report.chunks_stored = stored.len();
    report.chunks_unused = stored.iter().filter(|c| !referenced.contains(*c)).count();
    for id in &referenced {
        if !stored.contains(id) {
            report
                .errors
                .push(format!("chunk {id} is used by a snapshot but missing"));
        }
    }
    let to_read: Vec<&String> = match read {
        ReadData::None => vec![],
        ReadData::All => referenced.iter().filter(|c| stored.contains(*c)).collect(),
        ReadData::Percent(p) => {
            let p = p.clamp(1, 100) as u64;
            referenced
                .iter()
                .filter(|c| stored.contains(*c))
                .filter(|_| {
                    let r: [u8; 8] = crate::crypto::random().unwrap_or([0; 8]);
                    u64::from_le_bytes(r) % 100 < p
                })
                .collect()
        }
    };
    let total = to_read.len();
    for (i, id) in to_read.into_iter().enumerate() {
        match repo.get_chunk(id) {
            Ok(data) => {
                report.chunks_read += 1;
                report.bytes_read += data.len() as u64;
            }
            Err(err) => report.errors.push(err.to_string()),
        }
        if (i + 1) % 500 == 0 {
            progress(&format!("read {}/{total} chunks", i + 1));
        }
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub last: usize,
    pub daily: usize,
    pub weekly: usize,
    pub monthly: usize,
    pub yearly: usize,
}

impl Policy {
    pub fn is_empty(&self) -> bool {
        *self == Policy::default()
    }
}

/// Decide which snapshots to keep. Snapshots are grouped by host and paths; inside a group,
/// newest first, each rule keeps the newest snapshot of each of its last N periods.
pub fn plan(snaps: &[Snapshot], policy: Policy) -> (Vec<String>, Vec<String>) {
    let mut groups: Vec<(String, Vec<&Snapshot>)> = vec![];
    for s in snaps {
        let mut paths = s.paths.clone();
        paths.sort();
        let key = format!("{}\0{}", s.host, paths.join("\0"));
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, list)) => list.push(s),
            None => groups.push((key, vec![s])),
        }
    }
    let (mut keep, mut drop) = (vec![], vec![]);
    for (_, mut list) in groups {
        list.sort_by(|a, b| b.name.cmp(&a.name)); // newest first
        type Bucket = fn(&DateTime<Local>) -> String;
        let rules: [(usize, Bucket); 4] = [
            (policy.daily, |t| t.format("%Y-%m-%d").to_string()),
            (policy.weekly, |t| {
                format!("{}-W{}", t.iso_week().year(), t.iso_week().week())
            }),
            (policy.monthly, |t| t.format("%Y-%m").to_string()),
            (policy.yearly, |t| t.format("%Y").to_string()),
        ];
        let mut left: Vec<usize> = rules.iter().map(|r| r.0).collect();
        let mut last_bucket: Vec<Option<String>> = vec![None; rules.len()];
        for (i, s) in list.iter().enumerate() {
            let mut kept = i < policy.last;
            if let Ok(t) = DateTime::parse_from_rfc3339(&s.time) {
                let t = t.with_timezone(&Local);
                for (r, (_, bucket)) in rules.iter().enumerate() {
                    let b = bucket(&t);
                    if left[r] > 0 && last_bucket[r].as_deref() != Some(b.as_str()) {
                        last_bucket[r] = Some(b);
                        left[r] -= 1;
                        kept = true;
                    }
                }
            } else {
                kept = true; // unreadable time: never delete on a guess
            }
            if kept {
                keep.push(s.name.clone())
            } else {
                drop.push(s.name.clone())
            }
        }
    }
    keep.sort();
    drop.sort();
    (keep, drop)
}

pub fn forget(repo: &Repo, policy: Policy, dry_run: bool) -> Result<(Vec<String>, Vec<String>)> {
    if policy.is_empty() {
        return Err(Error::Usage(
            "say what to keep, e.g. --keep-daily 7 --keep-weekly 4 --keep-monthly 12".into(),
        ));
    }
    let _lock = if dry_run {
        None
    } else {
        Some(Lock::acquire(repo, "forget")?)
    };
    let snaps: Vec<Snapshot> = repo
        .snapshot_names()?
        .iter()
        .map(|n| repo.load_snapshot(n))
        .collect::<Result<_>>()?;
    let (keep, drop) = plan(&snaps, policy);
    if !dry_run {
        for name in &drop {
            repo.remove_snapshot(name)?;
        }
    }
    Ok((keep, drop))
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct PruneReport {
    pub chunks_removed: usize,
    pub bytes_freed: u64,
    pub tmp_removed: usize,
}

/// Delete chunks no snapshot uses. Refuses to run when any snapshot cannot be read,
/// because its chunks would look unused and be deleted.
pub fn prune(repo: &Repo, dry_run: bool) -> Result<PruneReport> {
    let _lock = if dry_run {
        None
    } else {
        Some(Lock::acquire(repo, "prune")?)
    };
    let mut used = HashSet::new();
    for name in repo.snapshot_names()? {
        let snap = repo.load_snapshot(&name).map_err(|e| {
            Error::Corrupt(format!(
                "snapshot {name} cannot be read ({e}); prune stops so its data is not deleted"
            ))
        })?;
        for e in snap.entries {
            used.extend(e.chunks);
        }
    }
    let mut report = PruneReport::default();
    for id in repo.chunk_ids()? {
        if !used.contains(&id) {
            report.chunks_removed += 1;
            report.bytes_freed += if dry_run {
                repo.chunk_size(&id)
            } else {
                repo.remove_chunk(&id)?
            };
        }
    }
    if !dry_run {
        report.tmp_removed = repo.clean_tmp()?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{self, Options};
    use crate::repo::tests::new_repo;
    use crate::snapshot::Summary;
    use std::fs;

    fn snap(name: &str, time: &str) -> Snapshot {
        Snapshot {
            version: 1,
            name: name.into(),
            time: time.into(),
            host: "h".into(),
            paths: vec!["/a".into()],
            excludes: vec![],
            tags: vec![],
            parent: None,
            summary: Summary::default(),
            warnings: vec![],
            entries: vec![],
        }
    }

    #[test]
    fn policy_plan() {
        // three snapshots a day for 10 days, at local noon-ish (UTC 09-11h is the same day in UTC+3)
        let mut snaps = vec![];
        for day in 1..=10 {
            for hour in [9, 10, 11] {
                snaps.push(snap(
                    &format!("202611{day:02}T{hour:02}0000Z-00000000"),
                    &format!("2026-11-{day:02}T{hour:02}:00:00Z"),
                ));
            }
        }
        let (keep, drop) = plan(
            &snaps,
            Policy {
                daily: 3,
                ..Default::default()
            },
        );
        assert_eq!(
            keep,
            vec![
                "20261108T110000Z-00000000",
                "20261109T110000Z-00000000",
                "20261110T110000Z-00000000"
            ]
        );
        assert_eq!(drop.len(), 27);
        let (keep, _) = plan(
            &snaps,
            Policy {
                last: 2,
                daily: 1,
                ..Default::default()
            },
        );
        assert_eq!(
            keep,
            vec!["20261110T100000Z-00000000", "20261110T110000Z-00000000"]
        );
        // another group is planned separately
        let mut other = snap("20261101T090000Z-ffffffff", "2026-11-01T09:00:00Z");
        other.paths = vec!["/b".into()];
        snaps.push(other);
        let (keep, _) = plan(
            &snaps,
            Policy {
                last: 1,
                ..Default::default()
            },
        );
        assert!(keep.contains(&"20261101T090000Z-ffffffff".to_string()) && keep.len() == 2);
    }

    #[test]
    fn forget_prune_check() {
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f"), b"version one").unwrap();
        let first = backup::backup(
            &repo,
            std::slice::from_ref(&src),
            &Options::default(),
            &mut |_| {},
        )
        .unwrap();
        fs::write(src.join("f"), b"version two!").unwrap();
        backup::backup(
            &repo,
            std::slice::from_ref(&src),
            &Options::default(),
            &mut |_| {},
        )
        .unwrap();

        let c = check(&repo, ReadData::All, &mut |_| {}).unwrap();
        assert!(c.ok(), "{:?}", c.errors);
        assert_eq!(
            (c.snapshots, c.chunks_stored, c.chunks_read, c.chunks_unused),
            (2, 2, 2, 0)
        );

        assert!(
            forget(&repo, Policy::default(), false).is_err(),
            "an empty policy deletes nothing"
        );
        let (_, gone) = forget(
            &repo,
            Policy {
                last: 1,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        assert_eq!(gone, vec![first.name.clone()]);
        assert_eq!(
            check(&repo, ReadData::None, &mut |_| {})
                .unwrap()
                .chunks_unused,
            1
        );
        assert_eq!(prune(&repo, true).unwrap().chunks_removed, 1);
        assert_eq!(
            repo.chunk_ids().unwrap().len(),
            2,
            "dry run deleted nothing"
        );
        assert_eq!(prune(&repo, false).unwrap().chunks_removed, 1);
        let c = check(&repo, ReadData::All, &mut |_| {}).unwrap();
        assert!(c.ok() && c.chunks_stored == 1);
    }

    #[test]
    fn check_finds_damage_and_prune_refuses_unreadable_snapshots() {
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f"), b"data").unwrap();
        let snap = backup::backup(&repo, &[src], &Options::default(), &mut |_| {}).unwrap();
        let id = &snap
            .entries
            .iter()
            .find(|e| !e.chunks.is_empty())
            .unwrap()
            .chunks[0];
        let path = d.path().join("repo/data").join(&id[..2]).join(id);
        let mut blob = fs::read(&path).unwrap();
        let n = blob.len();
        blob[n - 1] ^= 0xff;
        fs::write(&path, &blob).unwrap();
        assert!(
            check(&repo, ReadData::None, &mut |_| {}).unwrap().ok(),
            "structure is fine"
        );
        let c = check(&repo, ReadData::All, &mut |_| {}).unwrap();
        assert_eq!(c.errors.len(), 1, "{:?}", c.errors);
        fs::remove_file(&path).unwrap();
        assert!(
            !check(&repo, ReadData::None, &mut |_| {}).unwrap().ok(),
            "missing chunk"
        );

        fs::write(d.path().join("repo/snapshots").join(&snap.name), b"garbage").unwrap();
        assert!(prune(&repo, false).is_err());
    }
}
