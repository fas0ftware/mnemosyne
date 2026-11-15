//! Backup: walk the paths, cut files into content-defined chunks, store new chunks,
//! write the snapshot.
//!
//! Files whose size, inode, modification and change times match the previous snapshot of
//! the same paths are not read again: their chunk list is copied. The rest are cut with
//! FastCDC, so an edit in the middle of a big file only changes the chunks around it.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::BufReader;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::repo::{Lock, Repo};
use crate::snapshot::{Entry, EntryKind, Snapshot, Summary};
use crate::{Error, Result};

const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

#[derive(Default, Clone)]
pub struct Options {
    /// Glob patterns. Without a `/` they match a file or directory name anywhere
    /// (`node_modules`, `*.pyc`); with one they match the whole path (`/home/*/Downloads`).
    pub excludes: Vec<String>,
    /// Skip the contents of directories tagged with a CACHEDIR.TAG file.
    pub exclude_caches: bool,
    pub tags: Vec<String>,
}

pub struct Excludes {
    names: GlobSet,
    paths: GlobSet,
    caches: bool,
    fixed: Vec<PathBuf>,
}

impl Excludes {
    pub fn new(opts: &Options, fixed: Vec<PathBuf>) -> Result<Excludes> {
        let (mut names, mut paths) = (GlobSetBuilder::new(), GlobSetBuilder::new());
        for p in &opts.excludes {
            let glob = GlobBuilder::new(p)
                .literal_separator(p.contains('/'))
                .build()
                .map_err(|e| Error::Usage(format!("bad exclude pattern {p:?}: {e}")))?;
            if p.contains('/') {
                paths.add(glob);
            } else {
                names.add(glob);
            }
        }
        let build = |b: GlobSetBuilder| b.build().map_err(|e| Error::Usage(e.to_string()));
        Ok(Excludes {
            names: build(names)?,
            paths: build(paths)?,
            caches: opts.exclude_caches,
            fixed,
        })
    }

    pub fn excluded(&self, path: &Path) -> bool {
        self.fixed.iter().any(|f| path.starts_with(f))
            || path.file_name().is_some_and(|n| self.names.is_match(n))
            || self.paths.is_match(path)
    }

    fn is_cache_dir(&self, dir: &Path) -> bool {
        self.caches
            && fs::read(dir.join("CACHEDIR.TAG")).is_ok_and(|b| b.starts_with(CACHEDIR_SIGNATURE))
    }
}

fn key(e: &Entry) -> String {
    e.raw
        .clone()
        .map(|r| format!("\0{r}"))
        .unwrap_or_else(|| e.path.clone())
}

struct Walker<'a> {
    repo: &'a Repo,
    excludes: Excludes,
    parent: HashMap<String, Entry>,
    known: HashSet<String>,
    entries: Vec<Entry>,
    warnings: Vec<String>,
    summary: Summary,
    progress: &'a mut dyn FnMut(&str),
}

impl Walker<'_> {
    fn base_entry(path: &Path, meta: &fs::Metadata, kind: EntryKind) -> Entry {
        let mut e = Entry {
            path: String::new(),
            raw: None,
            kind,
            mode: meta.permissions().mode() & 0o7777,
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            size: if kind == EntryKind::File {
                meta.len()
            } else {
                0
            },
            ino: meta.ino(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            chunks: vec![],
            target: None,
        };
        e.set_path(path);
        e
    }

    fn warn(&mut self, msg: String) {
        (self.progress)(&format!("warning: {msg}"));
        self.warnings.push(msg);
        self.summary.skipped += 1;
    }

    fn visit(&mut self, path: &Path, is_root: bool) -> Result<()> {
        if !is_root && self.excludes.excluded(path) {
            return Ok(());
        }
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                self.warn(format!("{}: {e}", path.display()));
                return Ok(());
            }
        };
        let ft = meta.file_type();
        if ft.is_dir() {
            self.entries
                .push(Walker::base_entry(path, &meta, EntryKind::Dir));
            self.summary.dirs += 1;
            if self.excludes.is_cache_dir(path) {
                return Ok(());
            }
            let mut children: Vec<PathBuf> = match fs::read_dir(path) {
                Ok(d) => d.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
                Err(e) => {
                    self.warn(format!("{}: {e}", path.display()));
                    return Ok(());
                }
            };
            children.sort();
            for c in children {
                self.visit(&c, false)?;
            }
        } else if ft.is_symlink() {
            let mut e = Walker::base_entry(path, &meta, EntryKind::Symlink);
            match fs::read_link(path) {
                Ok(t) => {
                    let mut probe = e.clone();
                    probe.set_path(&t);
                    e.target = Some(probe.raw.map(|r| format!("\0{r}")).unwrap_or(probe.path));
                    self.entries.push(e);
                    self.summary.symlinks += 1;
                }
                Err(err) => self.warn(format!("{}: {err}", path.display())),
            }
        } else if ft.is_file() {
            let mut e = Walker::base_entry(path, &meta, EntryKind::File);
            if let Some(old) = self.parent.get(&key(&e)) {
                let same = old.kind == EntryKind::File
                    && (
                        old.size,
                        old.mtime,
                        old.mtime_nsec,
                        old.ino,
                        old.ctime,
                        old.ctime_nsec,
                    ) == (e.size, e.mtime, e.mtime_nsec, e.ino, e.ctime, e.ctime_nsec)
                    && old.chunks.iter().all(|c| self.known.contains(c));
                if same {
                    e.chunks = old.chunks.clone();
                    self.summary.files += 1;
                    self.summary.bytes += e.size;
                    self.entries.push(e);
                    return Ok(());
                }
            }
            match self.store_file(path, &mut e) {
                Ok(()) => {
                    self.summary.files += 1;
                    self.summary.files_read += 1;
                    self.summary.bytes += e.size;
                    self.entries.push(e);
                }
                Err(Error::Io(err)) => self.warn(format!("{}: {err}", path.display())),
                Err(other) => return Err(other),
            }
        } else {
            self.warn(format!(
                "{}: special file (socket, pipe or device) skipped",
                path.display()
            ));
        }
        Ok(())
    }

    fn store_file(&mut self, path: &Path, e: &mut Entry) -> Result<()> {
        let file = File::open(path)?;
        let c = self.repo.chunker;
        let mut size = 0u64;
        for chunk in fastcdc::v2020::StreamCDC::new(BufReader::new(file), c.min, c.avg, c.max) {
            let chunk = chunk.map_err(|err| match err {
                fastcdc::v2020::Error::IoError(io) => Error::Io(io),
                other => Error::Io(std::io::Error::other(other.to_string())),
            })?;
            let id = self.repo.keys().chunk_id(&chunk.data);
            let written = self.repo.put_chunk(&id, &chunk.data, &mut self.known)?;
            if written > 0 {
                self.summary.new_chunks += 1;
                self.summary.added_bytes += written;
            }
            size += chunk.length as u64;
            e.chunks.push(id);
        }
        e.size = size; // what was actually read, if the file changed meanwhile
        (self.progress)(&format!("+ {}", path.display()));
        Ok(())
    }
}

/// Back up `paths` into the repository and return the saved snapshot.
pub fn backup(
    repo: &Repo,
    paths: &[PathBuf],
    opts: &Options,
    progress: &mut dyn FnMut(&str),
) -> Result<Snapshot> {
    if paths.is_empty() {
        return Err(Error::Usage(
            "nothing to back up: give at least one path".into(),
        ));
    }
    let started = Instant::now();
    let started_at = chrono::Utc::now();
    let _lock = Lock::acquire(repo, "backup")?;
    let mut roots = Vec::new();
    for p in paths {
        let abs = fs::canonicalize(p).map_err(|e| Error::Usage(format!("{}: {e}", p.display())))?;
        if !roots.contains(&abs) {
            roots.push(abs);
        }
    }
    roots.sort();
    let root_names: Vec<String> = roots.iter().map(|r| r.display().to_string()).collect();
    let host = crate::hostname();

    // The newest snapshot of the same paths on this machine is the parent.
    let mut parent_name = None;
    let mut parent = HashMap::new();
    for name in repo.snapshot_names()?.iter().rev() {
        let snap = repo.load_snapshot(name)?;
        if snap.same_source(&host, &root_names) {
            parent = snap.entries.into_iter().map(|e| (key(&e), e)).collect();
            parent_name = Some(snap.name);
            break;
        }
    }

    // Never back up the repository into itself.
    let repo_root = fs::canonicalize(&repo.root)?;
    let excludes = Excludes::new(opts, vec![repo_root])?;
    let mut w = Walker {
        repo,
        excludes,
        parent,
        known: repo.chunk_ids()?,
        entries: vec![],
        warnings: vec![],
        summary: Summary::default(),
        progress,
    };
    for r in &roots {
        w.visit(r, true)?;
    }
    let now = started_at;
    w.summary.duration_ms = started.elapsed().as_millis() as u64;
    let snap = Snapshot {
        version: 1,
        name: Snapshot::new_name(&now)?,
        time: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        host,
        paths: root_names,
        excludes: opts.excludes.clone(),
        tags: opts.tags.clone(),
        parent: parent_name,
        summary: w.summary,
        warnings: w.warnings,
        entries: w.entries,
    };
    repo.save_snapshot(&snap)?;
    Ok(snap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::tests::new_repo;

    fn quiet() -> impl FnMut(&str) {
        |_: &str| {}
    }

    #[test]
    fn excludes_by_name_and_path() {
        let opts = Options {
            excludes: vec![
                "node_modules".into(),
                "*.pyc".into(),
                "/data/*/cache".into(),
            ],
            ..Default::default()
        };
        let ex = Excludes::new(&opts, vec![PathBuf::from("/data/repo")]).unwrap();
        assert!(ex.excluded(Path::new("/a/b/node_modules")));
        assert!(ex.excluded(Path::new("/a/x.pyc")));
        assert!(ex.excluded(Path::new("/data/u/cache")));
        assert!(
            !ex.excluded(Path::new("/data/u/v/cache")),
            "* does not cross /"
        );
        assert!(ex.excluded(Path::new("/data/repo/data/ab")));
        assert!(!ex.excluded(Path::new("/a/node_modules_notes.txt")));
        assert!(Excludes::new(
            &Options {
                excludes: vec!["[".into()],
                ..Default::default()
            },
            vec![]
        )
        .is_err());
    }

    #[test]
    fn backup_dedups_and_reuses_unchanged_files() {
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        let big: Vec<u8> = (0..3_000_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        fs::write(src.join("big.bin"), &big).unwrap();
        fs::write(src.join("copy.bin"), &big).unwrap(); // same content: no new chunks
        fs::write(src.join("sub/small.txt"), b"hello").unwrap();
        fs::write(src.join("empty"), b"").unwrap();
        std::os::unix::fs::symlink("sub/small.txt", src.join("link")).unwrap();

        let first = backup(
            &repo,
            std::slice::from_ref(&src),
            &Options::default(),
            &mut quiet(),
        )
        .unwrap();
        assert_eq!(
            (
                first.summary.files,
                first.summary.dirs,
                first.summary.symlinks
            ),
            (4, 2, 1)
        );
        let big_entry = first
            .entries
            .iter()
            .find(|e| e.path.ends_with("big.bin"))
            .unwrap();
        let copy_entry = first
            .entries
            .iter()
            .find(|e| e.path.ends_with("copy.bin"))
            .unwrap();
        assert!(big_entry.chunks.len() > 3, "content-defined chunks");
        assert_eq!(big_entry.chunks, copy_entry.chunks);
        let unique: HashSet<&String> = big_entry.chunks.iter().collect();
        assert_eq!(first.summary.new_chunks as usize, unique.len() + 1); // + small.txt; the empty file has none

        let second = backup(
            &repo,
            std::slice::from_ref(&src),
            &Options::default(),
            &mut quiet(),
        )
        .unwrap();
        assert_eq!(second.parent.as_deref(), Some(first.name.as_str()));
        assert_eq!(
            (second.summary.files_read, second.summary.new_chunks),
            (0, 0)
        );

        // change 10 bytes in the middle: only the chunks around them are new
        let mut edited = big.clone();
        edited[1_500_000..1_500_010].copy_from_slice(b"0123456789");
        fs::write(src.join("big.bin"), &edited).unwrap();
        let third = backup(
            &repo,
            std::slice::from_ref(&src),
            &Options::default(),
            &mut quiet(),
        )
        .unwrap();
        assert_eq!(third.summary.files_read, 1);
        assert!(
            third.summary.new_chunks <= 2,
            "{} new chunks",
            third.summary.new_chunks
        );
    }

    #[test]
    fn excluded_paths_cache_dirs_and_the_repo_itself() {
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().to_path_buf(); // contains the repository
        fs::create_dir_all(src.join("app/node_modules/x")).unwrap();
        fs::write(src.join("app/node_modules/x/i.js"), b"x").unwrap();
        fs::write(src.join("app/main.py"), b"print()").unwrap();
        fs::create_dir_all(src.join("cache")).unwrap();
        fs::write(
            src.join("cache/CACHEDIR.TAG"),
            [CACHEDIR_SIGNATURE, b"\n"].concat(),
        )
        .unwrap();
        fs::write(src.join("cache/blob"), b"x").unwrap();
        let opts = Options {
            excludes: vec!["node_modules".into()],
            exclude_caches: true,
            ..Default::default()
        };
        let snap = backup(&repo, &[src], &opts, &mut quiet()).unwrap();
        let paths: Vec<&str> = snap.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with("app/main.py")));
        assert!(
            paths.iter().any(|p| p.ends_with("/cache")),
            "the cache dir itself is kept"
        );
        assert!(!paths.iter().any(|p| p.contains("node_modules")
            || p.ends_with("cache/blob")
            || p.contains("/repo/")));
    }

    #[test]
    fn unreadable_files_are_warnings_not_failures() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads everything
        }
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("ok"), b"fine").unwrap();
        fs::write(src.join("secret"), b"no").unwrap();
        fs::set_permissions(src.join("secret"), fs::Permissions::from_mode(0o000)).unwrap();
        let snap = backup(&repo, &[src], &Options::default(), &mut quiet()).unwrap();
        assert_eq!((snap.summary.files, snap.summary.skipped), (1, 1));
        assert!(snap.warnings[0].contains("secret"));
    }
}
