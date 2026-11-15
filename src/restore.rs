//! Restore a snapshot (or part of it) into a target directory.
//!
//! A snapshot is treated as untrusted input: every path must be absolute and clean, files
//! are opened with O_NOFOLLOW, no parent directory may be a symlink, and symlinks are
//! created last, so a crafted snapshot cannot make the restore write outside the target.
//! Every chunk is verified against its id as it is read.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::repo::Repo;
use crate::snapshot::{Entry, EntryKind, Snapshot};
use crate::{Error, Result};

#[derive(Default, Clone)]
pub struct Options {
    /// Restore only entries at or below these absolute paths.
    pub include: Vec<PathBuf>,
    /// Replace files that already exist in the target.
    pub overwrite: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
    pub skipped_existing: u64,
}

fn wanted(e: &Entry, include: &[PathBuf]) -> Result<bool> {
    if include.is_empty() {
        return Ok(true);
    }
    let p = e.path()?;
    Ok(include
        .iter()
        .any(|i| p.starts_with(i) || i.starts_with(&p) && e.kind == EntryKind::Dir))
}

/// Refuse to go through a symlink on the way from `target` to `dest`.
fn check_no_symlink_parents(target: &Path, rel: &Path) -> Result<()> {
    let mut cur = target.to_path_buf();
    if let Some(parent) = rel.parent() {
        for c in parent.components() {
            cur.push(c);
            if let Ok(m) = fs::symlink_metadata(&cur) {
                if m.file_type().is_symlink() {
                    return Err(Error::Corrupt(format!(
                        "{} is a symlink; refusing to restore through it",
                        cur.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn set_times(path: &Path, e: &Entry) {
    let ts = [
        libc::timespec {
            tv_sec: e.mtime as libc::time_t,
            tv_nsec: e.mtime_nsec as libc::c_long,
        },
        libc::timespec {
            tv_sec: e.mtime as libc::time_t,
            tv_nsec: e.mtime_nsec as libc::c_long,
        },
    ];
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        // AT_SYMLINK_NOFOLLOW: set the link's own time, never its target's.
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c.as_ptr(),
                ts.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
    }
}

fn decode_target(t: &str) -> Result<PathBuf> {
    match t.strip_prefix('\0') {
        Some(b) => Ok(PathBuf::from(OsString::from_vec(
            B64.decode(b)
                .map_err(|_| Error::Corrupt("bad link target".into()))?,
        ))),
        None => Ok(PathBuf::from(t)),
    }
}

pub fn restore(
    repo: &Repo,
    snap: &Snapshot,
    target: &Path,
    opts: &Options,
    progress: &mut dyn FnMut(&str),
) -> Result<Report> {
    fs::create_dir_all(target)?;
    let target = fs::canonicalize(target)?;
    let mut report = Report::default();
    let mut dirs = Vec::new();
    let mut links = Vec::new();

    for e in &snap.entries {
        if !wanted(e, &opts.include)? {
            continue;
        }
        let rel = e.safe_relative()?;
        check_no_symlink_parents(&target, &rel)?;
        let dest = target.join(&rel);
        match e.kind {
            EntryKind::Dir => {
                match fs::symlink_metadata(&dest) {
                    Ok(m) if m.is_dir() => {}
                    Ok(_) => {
                        return Err(Error::Usage(format!(
                            "{} exists and is not a directory",
                            dest.display()
                        )))
                    }
                    Err(_) => fs::create_dir_all(&dest)?,
                }
                dirs.push((dest, e));
                report.dirs += 1;
            }
            EntryKind::File => {
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                if let Ok(m) = fs::symlink_metadata(&dest) {
                    if !opts.overwrite || !m.is_file() {
                        report.skipped_existing += 1;
                        progress(&format!("exists, skipped: {}", dest.display()));
                        continue;
                    }
                }
                let mut f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&dest)?;
                let mut written = 0u64;
                for id in &e.chunks {
                    let data = repo.get_chunk(id)?;
                    f.write_all(&data)?;
                    written += data.len() as u64;
                }
                drop(f);
                if written != e.size {
                    return Err(Error::Corrupt(format!(
                        "{}: restored {written} bytes, expected {}",
                        e.display(),
                        e.size
                    )));
                }
                fs::set_permissions(&dest, fs::Permissions::from_mode(e.mode & 0o7777))?;
                set_times(&dest, e);
                report.files += 1;
                report.bytes += written;
            }
            EntryKind::Symlink => links.push((dest, e)),
        }
    }
    // Links last: nothing is ever written through one of them.
    for (dest, e) in links {
        if fs::symlink_metadata(&dest).is_ok() {
            if !opts.overwrite {
                report.skipped_existing += 1;
                continue;
            }
            fs::remove_file(&dest)?;
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let t = decode_target(e.target.as_deref().unwrap_or(""))?;
        std::os::unix::fs::symlink(&t, &dest)?;
        set_times(&dest, e);
        report.symlinks += 1;
    }
    // Directory modes and times last, deepest first, so creating files does not undo them.
    for (dest, e) in dirs.into_iter().rev() {
        let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(e.mode & 0o7777));
        set_times(&dest, e);
    }
    // One flush for the whole restore instead of one per file.
    {
        use std::os::fd::AsRawFd;
        let dir = fs::File::open(&target)?;
        if unsafe { libc::syncfs(dir.as_raw_fd()) } != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{self, Options as BackupOptions};
    use crate::repo::tests::new_repo;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn roundtrip_contents_modes_times_links() {
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().join("src");
        fs::create_dir_all(src.join("a/b")).unwrap();
        let big: Vec<u8> = (0..2_000_000u32).map(|i| (i ^ (i >> 7)) as u8).collect();
        fs::write(src.join("a/big"), &big).unwrap();
        fs::write(src.join("a/b/script.sh"), b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(src.join("a/b/script.sh"), fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(src.join("empty"), b"").unwrap();
        std::os::unix::fs::symlink("a/big", src.join("link")).unwrap();
        let snap = backup::backup(
            &repo,
            std::slice::from_ref(&src),
            &BackupOptions::default(),
            &mut |_| {},
        )
        .unwrap();

        let out = d.path().join("out");
        let r = restore(&repo, &snap, &out, &Options::default(), &mut |_| {}).unwrap();
        assert_eq!(
            (r.files, r.symlinks, r.bytes),
            (3, 1, big.len() as u64 + 18)
        );
        let base = out.join(src.strip_prefix("/").unwrap());
        assert_eq!(fs::read(base.join("a/big")).unwrap(), big);
        let m = fs::metadata(base.join("a/b/script.sh")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o750);
        assert_eq!(
            m.mtime(),
            fs::metadata(src.join("a/b/script.sh")).unwrap().mtime()
        );
        assert_eq!(
            fs::read_link(base.join("link")).unwrap(),
            PathBuf::from("a/big")
        );
        assert_eq!(fs::read(base.join("empty")).unwrap(), b"");

        // second restore: existing files are kept unless --overwrite
        fs::write(base.join("empty"), b"changed").unwrap();
        let again = restore(&repo, &snap, &out, &Options::default(), &mut |_| {}).unwrap();
        assert_eq!(again.files, 0);
        assert_eq!(fs::read(base.join("empty")).unwrap(), b"changed");
        restore(
            &repo,
            &snap,
            &out,
            &Options {
                overwrite: true,
                ..Default::default()
            },
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(fs::read(base.join("empty")).unwrap(), b"");
    }

    #[test]
    fn partial_restore() {
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().join("src");
        fs::create_dir_all(src.join("keep")).unwrap();
        fs::create_dir_all(src.join("other")).unwrap();
        fs::write(src.join("keep/x"), b"x").unwrap();
        fs::write(src.join("other/y"), b"y").unwrap();
        let snap = backup::backup(
            &repo,
            std::slice::from_ref(&src),
            &BackupOptions::default(),
            &mut |_| {},
        )
        .unwrap();
        let out = d.path().join("out");
        let src = fs::canonicalize(src).unwrap();
        let r = restore(
            &repo,
            &snap,
            &out,
            &Options {
                include: vec![src.join("keep")],
                ..Default::default()
            },
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(r.files, 1);
        let base = out.join(src.strip_prefix("/").unwrap());
        assert!(base.join("keep/x").exists() && !base.join("other/y").exists());
    }

    #[test]
    fn hostile_snapshot_cannot_escape() {
        let d = tempfile::tempdir().unwrap();
        let repo = new_repo(d.path());
        let src = d.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f"), b"payload").unwrap();
        let good = backup::backup(
            &repo,
            std::slice::from_ref(&src),
            &BackupOptions::default(),
            &mut |_| {},
        )
        .unwrap();
        let file = good
            .entries
            .iter()
            .find(|e| e.kind == EntryKind::File)
            .unwrap()
            .clone();
        let out = d.path().join("out");

        // 1. ".." in a path
        let mut evil = good.clone();
        let mut e = file.clone();
        e.path = "/x/../../escaped".into();
        evil.entries = vec![e];
        assert!(restore(&repo, &evil, &out, &Options::default(), &mut |_| {}).is_err());

        // 2. a symlink to outside, then a file "inside" it
        let outside = d.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let mut link = file.clone();
        link.kind = EntryKind::Symlink;
        link.path = "/evil".into();
        link.target = Some(outside.display().to_string());
        link.chunks.clear();
        let mut through = file.clone();
        through.path = "/evil/pwned".into();
        evil.entries = vec![link.clone(), through.clone()];
        // links are made last, so the file lands in a real directory "evil" inside out/
        restore(&repo, &evil, &out, &Options::default(), &mut |_| {}).unwrap();
        assert!(!outside.join("pwned").exists());
        // and when the link already exists from an earlier restore, the write is refused
        let out2 = d.path().join("out2");
        fs::create_dir_all(&out2).unwrap();
        std::os::unix::fs::symlink(&outside, out2.join("evil")).unwrap();
        evil.entries = vec![through];
        assert!(restore(&repo, &evil, &out2, &Options::default(), &mut |_| {}).is_err());
        assert!(!outside.join("pwned").exists());
    }
}
