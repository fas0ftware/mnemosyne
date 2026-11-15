//! What changed between two snapshots, from their file lists alone: content is compared
//! by chunk ids, so nothing is decrypted or read beyond the two snapshot files.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::snapshot::{Entry, EntryKind, Snapshot};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Added,
    Removed,
    /// Same path, different content (or a link pointing elsewhere).
    Modified,
    /// A file became a directory, a link became a file, ...
    Replaced,
    /// Same content; only mode or modification time differ.
    Metadata,
}

impl Kind {
    pub fn symbol(self) -> char {
        match self {
            Kind::Added => '+',
            Kind::Removed => '-',
            Kind::Modified => 'M',
            Kind::Replaced => 'T',
            Kind::Metadata => 'm',
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Change {
    pub kind: Kind,
    pub path: String,
    pub entry: &'static str,
    pub old_size: u64,
    pub new_size: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub replaced: usize,
    pub metadata: usize,
    /// Change in the total size of the files (can be negative).
    pub bytes_delta: i64,
}

fn key(e: &Entry) -> String {
    e.raw
        .clone()
        .map(|r| format!("\0{r}"))
        .unwrap_or_else(|| e.path.clone())
}

fn kind_name(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Dir => "dir",
        EntryKind::File => "file",
        EntryKind::Symlink => "link",
    }
}

/// Changes from `old` to `new`, sorted by path. Metadata-only changes are included only
/// when `metadata` is true (every backup touches directory times).
pub fn diff(old: &Snapshot, new: &Snapshot, metadata: bool) -> (Vec<Change>, Summary) {
    let before: BTreeMap<String, &Entry> = old.entries.iter().map(|e| (key(e), e)).collect();
    let after: BTreeMap<String, &Entry> = new.entries.iter().map(|e| (key(e), e)).collect();
    let mut changes = Vec::new();
    let mut summary = Summary::default();
    let total = |s: &Snapshot| {
        s.entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .map(|e| e.size as i64)
            .sum::<i64>()
    };
    summary.bytes_delta = total(new) - total(old);

    for (k, b) in &after {
        let change = match before.get(k) {
            None => Some(Kind::Added),
            Some(a) if a.kind != b.kind => Some(Kind::Replaced),
            Some(a) if a.chunks != b.chunks || a.size != b.size || a.target != b.target => {
                Some(Kind::Modified)
            }
            Some(a)
                if metadata
                    && (a.mode != b.mode || (a.mtime, a.mtime_nsec) != (b.mtime, b.mtime_nsec)) =>
            {
                Some(Kind::Metadata)
            }
            Some(_) => None,
        };
        if let Some(kind) = change {
            let old_size = before.get(k).map(|a| a.size).unwrap_or(0);
            changes.push(Change {
                kind,
                path: b.display(),
                entry: kind_name(b.kind),
                old_size,
                new_size: b.size,
            });
        }
    }
    for (k, a) in &before {
        if !after.contains_key(k) {
            changes.push(Change {
                kind: Kind::Removed,
                path: a.display(),
                entry: kind_name(a.kind),
                old_size: a.size,
                new_size: 0,
            });
        }
    }
    changes.sort_by(|x, y| x.path.cmp(&y.path).then(x.kind.cmp(&y.kind)));
    for c in &changes {
        match c.kind {
            Kind::Added => summary.added += 1,
            Kind::Removed => summary.removed += 1,
            Kind::Modified => summary.modified += 1,
            Kind::Replaced => summary.replaced += 1,
            Kind::Metadata => summary.metadata += 1,
        }
    }
    (changes, summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{self, Options};
    use crate::repo::tests::new_repo;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn added_removed_modified_replaced_metadata() {
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().join("src");
        fs::create_dir_all(src.join("dir")).unwrap();
        fs::write(src.join("same.txt"), "unchanged").unwrap();
        fs::write(src.join("edit.txt"), "version one").unwrap();
        fs::write(src.join("gone.txt"), "bye").unwrap();
        fs::write(src.join("becomes_dir"), "file").unwrap();
        fs::write(src.join("chmod.txt"), "mode").unwrap();
        let a = backup::backup(
            &repo,
            std::slice::from_ref(&src),
            &Options::default(),
            &mut |_| {},
        )
        .unwrap();

        fs::write(src.join("edit.txt"), "version two, longer").unwrap();
        fs::remove_file(src.join("gone.txt")).unwrap();
        fs::write(src.join("dir/new.txt"), "hello").unwrap();
        fs::remove_file(src.join("becomes_dir")).unwrap();
        fs::create_dir(src.join("becomes_dir")).unwrap();
        fs::set_permissions(src.join("chmod.txt"), fs::Permissions::from_mode(0o600)).unwrap();
        let b = backup::backup(
            &repo,
            std::slice::from_ref(&src),
            &Options::default(),
            &mut |_| {},
        )
        .unwrap();

        let (changes, s) = diff(&a, &b, false);
        let got: Vec<(char, String)> = changes
            .iter()
            .map(|c| {
                (
                    c.kind.symbol(),
                    c.path.rsplit('/').next().unwrap().to_string(),
                )
            })
            .collect();
        assert!(got.contains(&('M', "edit.txt".into())));
        assert!(got.contains(&('-', "gone.txt".into())));
        assert!(got.contains(&('+', "new.txt".into())));
        assert!(got.contains(&('T', "becomes_dir".into())));
        assert!(
            !got.iter().any(|(_, p)| p == "same.txt" || p == "chmod.txt"),
            "{got:?}"
        );
        assert_eq!((s.added, s.removed, s.modified, s.replaced), (1, 1, 1, 1));
        assert_eq!(
            s.bytes_delta,
            8 - 3 + 5 - 4,
            "edit grew by 8, gone -3, new +5, becomes_dir -4"
        );

        let (with_meta, _) = diff(&a, &b, true);
        assert!(with_meta
            .iter()
            .any(|c| c.kind == Kind::Metadata && c.path.ends_with("chmod.txt")));
        let (none, s0) = diff(&b, &b, true);
        assert!(none.is_empty() && s0 == Summary::default());
    }
}
