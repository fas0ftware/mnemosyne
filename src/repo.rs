//! The repository on disk.
//!
//! ```text
//! <repo>/config.json            format, repository id, KDF settings, wrapped master key
//! <repo>/data/ab/ab12…(64 hex)  encrypted chunks, named by their keyed hash
//! <repo>/snapshots/<name>       encrypted snapshots (the file list of one backup)
//! <repo>/locks/lock             present while a backup, forget or prune runs
//! <repo>/tmp/                   files being written; renamed into place when complete
//! ```
//!
//! Every file is written to tmp/, flushed to disk and then renamed, so an interrupted
//! backup leaves either a complete file or none: never half of one.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{self, KdfCost, Keys, Kind, KEY_LEN, SALT_LEN};
use crate::snapshot::Snapshot;
use crate::{Error, Result};

pub const FORMAT: u32 = 1;
/// Largest chunk the chunker produces is 4 MiB; anything bigger in a repository is damage.
pub const MAX_CHUNK: usize = 16 << 20;
pub const MAX_SNAPSHOT: usize = 1 << 30;
pub const MIN_PASSWORD: usize = 10;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Chunker {
    pub min: u32,
    pub avg: u32,
    pub max: u32,
}

impl Chunker {
    pub const DEFAULT: Chunker = Chunker {
        min: 256 << 10,
        avg: 1 << 20,
        max: 4 << 20,
    };
}

#[derive(Serialize, Deserialize)]
struct Kdf {
    algorithm: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct Config {
    format: u32,
    id: String,
    created: String,
    chunker: Chunker,
    kdf: Kdf,
    key_nonce: String,
    key: String,
    /// Optional second key slot, unlocked by a recovery code printed on paper.
    /// Older versions ignore the field, so adding it keeps the repository readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<Slot>,
}

#[derive(Serialize, Deserialize)]
struct Slot {
    kdf: Kdf,
    key_nonce: String,
    key: String,
}

/// Crockford base32: no I, L, O or U, so a code copied from paper is hard to misread.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_BYTES: usize = 20; // 160 bits, 32 characters

/// "abcd-efgh..." typed back in any case, with or without dashes and spaces, O for 0 and
/// I or L for 1: the canonical 32 characters, or None when it cannot be a recovery code.
pub fn normalize_recovery_code(code: &str) -> Option<String> {
    let out: String = code
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    (out.len() == 32 && out.bytes().all(|b| CODE_ALPHABET.contains(&b))).then_some(out)
}

fn new_recovery_code() -> Result<String> {
    let bytes: [u8; CODE_BYTES] = crypto::random()?;
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = String::new();
    for b in bytes {
        bits = (bits << 8) | u32::from(b);
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(CODE_ALPHABET[((bits >> n) & 31) as usize] as char);
        }
    }
    Ok(out)
}

/// "ABCD-EFGH-..." for printing.
pub fn format_recovery_code(code: &str) -> String {
    code.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

impl Config {
    /// Everything except the wrapped key itself is bound to it as associated data,
    /// so editing the header (weaker KDF, other chunker, other id) breaks the unlock.
    fn aad(&self) -> Vec<u8> {
        format!(
            "mnemosyne-config|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.format,
            self.id,
            self.created,
            self.chunker.min,
            self.chunker.avg,
            self.chunker.max,
            self.kdf.algorithm,
            self.kdf.m_cost,
            self.kdf.t_cost,
            self.kdf.p_cost
        )
        .into_bytes()
        .into_iter()
        .chain(self.kdf.salt.bytes())
        .collect()
    }

    /// The recovery slot's associated data: the fixed header and its own KDF settings, but not
    /// the password slot's salt, so changing the password keeps the recovery code valid.
    fn recovery_aad(&self, kdf: &Kdf) -> Vec<u8> {
        format!(
            "mnemosyne-recovery|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.format,
            self.id,
            self.created,
            self.chunker.min,
            self.chunker.avg,
            self.chunker.max,
            kdf.algorithm,
            kdf.m_cost,
            kdf.t_cost,
            kdf.p_cost,
            kdf.salt
        )
        .into_bytes()
    }

    fn cost(&self) -> KdfCost {
        KdfCost {
            m: self.kdf.m_cost,
            t: self.kdf.t_cost,
            p: self.kdf.p_cost,
        }
    }
}

pub struct Repo {
    pub root: PathBuf,
    pub id: String,
    pub chunker: Chunker,
    keys: Keys,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn check_password_strength(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(Error::Usage(format!(
            "the password needs at least {MIN_PASSWORD} characters"
        )));
    }
    Ok(())
}

impl Repo {
    pub fn init(root: &Path, password: &str) -> Result<Repo> {
        Repo::init_with(root, password, KdfCost::DEFAULT, Chunker::DEFAULT)
    }

    pub fn init_with(root: &Path, password: &str, cost: KdfCost, chunker: Chunker) -> Result<Repo> {
        check_password_strength(password)?;
        if root.join("config.json").exists() {
            return Err(Error::Usage(format!(
                "{} is already a Mnemosyne repository",
                root.display()
            )));
        }
        if root.exists() && fs::read_dir(root)?.next().is_some() {
            return Err(Error::Usage(format!(
                "{} exists and is not empty",
                root.display()
            )));
        }
        for dir in ["", "data", "snapshots", "locks", "tmp"] {
            make_private_dir(&root.join(dir))?;
        }
        let keys = Keys::generate()?;
        let id = hex(&crypto::random::<16>()?);
        let mut config = Config {
            format: FORMAT,
            id: id.clone(),
            created: crate::now_rfc3339(),
            chunker,
            kdf: Kdf {
                algorithm: "argon2id".into(),
                m_cost: cost.m,
                t_cost: cost.t,
                p_cost: cost.p,
                salt: String::new(),
            },
            key_nonce: String::new(),
            key: String::new(),
            recovery: None,
        };
        let repo = Repo {
            root: root.to_path_buf(),
            id,
            chunker,
            keys,
        };
        repo.write_config(&mut config, password)?;
        Ok(repo)
    }

    fn write_config(&self, config: &mut Config, password: &str) -> Result<()> {
        let salt: [u8; SALT_LEN] = crypto::random()?;
        config.kdf.salt = B64.encode(salt);
        let mut wrapping = crypto::derive(password, &salt, config.cost())?;
        let wrapped = crypto::wrap(&wrapping, &self.keys, &config.aad());
        wrapping.zeroize();
        let (nonce, sealed) = wrapped?;
        config.key_nonce = B64.encode(nonce);
        config.key = B64.encode(sealed);
        let text = serde_json::to_vec_pretty(config).map_err(|e| Error::Corrupt(e.to_string()))?;
        self.write_atomic(&self.root.join("config.json"), &text)
    }

    pub fn open(root: &Path, password: &str) -> Result<Repo> {
        let config = Repo::read_config(root)?;
        let salt = B64
            .decode(&config.kdf.salt)
            .map_err(|_| Error::Corrupt("bad salt".into()))?;
        if !(16..=64).contains(&salt.len()) {
            return Err(Error::Corrupt("bad salt length".into()));
        }
        let nonce = B64
            .decode(&config.key_nonce)
            .map_err(|_| Error::Corrupt("bad key nonce".into()))?;
        let sealed = B64
            .decode(&config.key)
            .map_err(|_| Error::Corrupt("bad wrapped key".into()))?;
        let mut wrapping: [u8; KEY_LEN] = crypto::derive(password, &salt, config.cost())?;
        let keys = crypto::unwrap(&wrapping, &nonce, &sealed, &config.aad());
        wrapping.zeroize();
        Ok(Repo {
            root: root.to_path_buf(),
            id: config.id,
            chunker: config.chunker,
            keys: keys?,
        })
    }

    /// Open with the recovery code instead of the password (to set a new password).
    pub fn open_with_recovery(root: &Path, code: &str) -> Result<Repo> {
        let code = normalize_recovery_code(code).ok_or_else(|| {
            Error::Usage("that is not a recovery code (32 letters and digits)".into())
        })?;
        let config = Repo::read_config(root)?;
        let slot = config
            .recovery
            .as_ref()
            .ok_or_else(|| Error::Usage("this repository has no recovery key".into()))?;
        let cost = KdfCost {
            m: slot.kdf.m_cost,
            t: slot.kdf.t_cost,
            p: slot.kdf.p_cost,
        };
        if slot.kdf.algorithm != "argon2id" {
            return Err(Error::Corrupt(
                "unknown key derivation in the recovery slot".into(),
            ));
        }
        let salt = B64
            .decode(&slot.kdf.salt)
            .map_err(|_| Error::Corrupt("bad recovery salt".into()))?;
        if !(16..=64).contains(&salt.len()) {
            return Err(Error::Corrupt("bad recovery salt length".into()));
        }
        let nonce = B64
            .decode(&slot.key_nonce)
            .map_err(|_| Error::Corrupt("bad recovery nonce".into()))?;
        let sealed = B64
            .decode(&slot.key)
            .map_err(|_| Error::Corrupt("bad recovery key".into()))?;
        let mut wrapping: [u8; KEY_LEN] = crypto::derive(&code, &salt, cost)?;
        let keys = crypto::unwrap(&wrapping, &nonce, &sealed, &config.recovery_aad(&slot.kdf));
        wrapping.zeroize();
        Ok(Repo {
            root: root.to_path_buf(),
            id: config.id,
            chunker: config.chunker,
            keys: keys?,
        })
    }

    pub fn has_recovery(&self) -> bool {
        Repo::read_config(&self.root)
            .map(|c| c.recovery.is_some())
            .unwrap_or(false)
    }

    /// Create (or replace) the recovery slot. Returns the code, formatted for printing.
    /// It exists only here and on the owner's paper: it is never stored.
    pub fn create_recovery_code(&self) -> Result<String> {
        let mut config = Repo::read_config(&self.root)?;
        let code = new_recovery_code()?;
        let salt: [u8; SALT_LEN] = crypto::random()?;
        let main = config.cost();
        let kdf = Kdf {
            algorithm: "argon2id".into(),
            m_cost: main.m,
            t_cost: main.t,
            p_cost: main.p,
            salt: B64.encode(salt),
        };
        let mut wrapping = crypto::derive(
            &code,
            &salt,
            KdfCost {
                m: kdf.m_cost,
                t: kdf.t_cost,
                p: kdf.p_cost,
            },
        )?;
        let wrapped = crypto::wrap(&wrapping, &self.keys, &config.recovery_aad(&kdf));
        wrapping.zeroize();
        let (nonce, sealed) = wrapped?;
        config.recovery = Some(Slot {
            kdf,
            key_nonce: B64.encode(nonce),
            key: B64.encode(sealed),
        });
        let text = serde_json::to_vec_pretty(&config).map_err(|e| Error::Corrupt(e.to_string()))?;
        self.write_atomic(&self.root.join("config.json"), &text)?;
        Ok(format_recovery_code(&code))
    }

    pub fn remove_recovery(&self) -> Result<bool> {
        let mut config = Repo::read_config(&self.root)?;
        let had = config.recovery.take().is_some();
        let text = serde_json::to_vec_pretty(&config).map_err(|e| Error::Corrupt(e.to_string()))?;
        self.write_atomic(&self.root.join("config.json"), &text)?;
        Ok(had)
    }

    fn read_config(root: &Path) -> Result<Config> {
        let path = root.join("config.json");
        let text = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::Usage(format!("{} is not a Mnemosyne repository", root.display()))
            }
            _ => Error::Io(e),
        })?;
        if text.len() > 64 << 10 {
            return Err(Error::Corrupt("config.json is too large".into()));
        }
        let config: Config = serde_json::from_slice(&text)
            .map_err(|e| Error::Corrupt(format!("config.json: {e}")))?;
        if config.format != FORMAT {
            return Err(Error::Corrupt(format!(
                "repository format {} is not supported",
                config.format
            )));
        }
        if config.kdf.algorithm != "argon2id" {
            return Err(Error::Corrupt(format!(
                "unknown key derivation {}",
                config.kdf.algorithm
            )));
        }
        if config.id.len() != 32 || !config.id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Corrupt("bad repository id".into()));
        }
        let c = config.chunker;
        if !(64 << 10..=c.avg).contains(&c.min) || c.avg > c.max || c.max > (MAX_CHUNK as u32) / 2 {
            return Err(Error::Corrupt("bad chunker settings".into()));
        }
        Ok(config)
    }

    /// Re-wrap the master key with a new password. Data and snapshots stay as they are.
    pub fn change_password(&self, new_password: &str) -> Result<()> {
        check_password_strength(new_password)?;
        let text = fs::read(self.root.join("config.json"))?;
        let mut config: Config =
            serde_json::from_slice(&text).map_err(|e| Error::Corrupt(e.to_string()))?;
        self.write_config(&mut config, new_password)
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    // --- files ---------------------------------------------------------------------------

    pub fn write_atomic(&self, dest: &Path, bytes: &[u8]) -> Result<()> {
        self.write_file(dest, bytes, true)
    }

    /// Write via tmp/ and rename. With `durable`, the file and the rename are flushed to
    /// disk before returning; without it, `sync()` must run before anything refers to it.
    fn write_file(&self, dest: &Path, bytes: &[u8], durable: bool) -> Result<()> {
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{}.tmp", hex(&crypto::random::<12>()?)));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let written = f
            .write_all(bytes)
            .and_then(|_| if durable { f.sync_all() } else { Ok(()) });
        drop(f);
        if let Err(e) = written.and_then(|_| fs::rename(&tmp, dest)) {
            let _ = fs::remove_file(&tmp);
            return Err(Error::Io(e));
        }
        if durable {
            if let Some(dir) = dest.parent() {
                // Make the rename itself durable. Some filesystems refuse fsync on a directory.
                let _ = File::open(dir).and_then(|d| d.sync_all());
            }
        }
        Ok(())
    }

    /// Flush everything written to the repository's filesystem (one syncfs instead of an
    /// fsync per chunk: thousands of times faster on a big first backup).
    pub fn sync(&self) -> Result<()> {
        use std::os::fd::AsRawFd;
        let dir = File::open(&self.root)?;
        if unsafe { libc::syncfs(dir.as_raw_fd()) } != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn chunk_path(&self, id: &str) -> PathBuf {
        self.root.join("data").join(&id[..2]).join(id)
    }

    fn check_id(id: &str) -> Result<()> {
        if id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(())
        } else {
            Err(Error::Corrupt(format!("bad chunk id {id:?}")))
        }
    }

    /// Ids of every chunk stored, from the directory listing.
    pub fn chunk_ids(&self) -> Result<HashSet<String>> {
        let mut out = HashSet::new();
        let data = self.root.join("data");
        for dir in fs::read_dir(&data)? {
            let dir = dir?;
            if !dir.file_type()?.is_dir() {
                continue;
            }
            for f in fs::read_dir(dir.path())? {
                let name = f?.file_name().to_string_lossy().into_owned();
                if Repo::check_id(&name).is_ok() {
                    out.insert(name);
                }
            }
        }
        Ok(out)
    }

    /// Store a chunk unless it is already there. Returns the bytes written (0 if deduplicated).
    pub fn put_chunk(&self, id: &str, data: &[u8], known: &mut HashSet<String>) -> Result<u64> {
        Repo::check_id(id)?;
        if known.contains(id) {
            return Ok(0);
        }
        let path = self.chunk_path(id);
        if path.exists() {
            known.insert(id.to_string());
            return Ok(0);
        }
        make_private_dir(path.parent().expect("chunk has a parent"))?;
        let blob = self.keys.seal(Kind::Chunk, &self.id, id, data)?;
        self.write_file(&path, &blob, false)?;
        known.insert(id.to_string());
        Ok(blob.len() as u64)
    }

    /// Read, decrypt and verify a chunk: its plaintext must hash back to its id.
    pub fn get_chunk(&self, id: &str) -> Result<Vec<u8>> {
        Repo::check_id(id)?;
        let blob =
            read_capped(&self.chunk_path(id), MAX_CHUNK as u64 + 1024).map_err(|e| match e {
                Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                    Error::Corrupt(format!("chunk {id} is missing"))
                }
                other => other,
            })?;
        let data = self
            .keys
            .open(Kind::Chunk, &self.id, id, &blob, MAX_CHUNK)?;
        if self.keys.chunk_id(&data) != id {
            return Err(Error::Corrupt(format!("chunk {id} does not match its id")));
        }
        Ok(data)
    }

    pub fn remove_chunk(&self, id: &str) -> Result<u64> {
        Repo::check_id(id)?;
        let path = self.chunk_path(id);
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        fs::remove_file(path)?;
        Ok(size)
    }

    pub fn chunk_size(&self, id: &str) -> u64 {
        fs::metadata(self.chunk_path(id))
            .map(|m| m.len())
            .unwrap_or(0)
    }

    // --- snapshots -----------------------------------------------------------------------

    fn snapshot_path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Error::Corrupt(format!("bad snapshot name {name:?}")));
        }
        Ok(self.root.join("snapshots").join(name))
    }

    pub fn save_snapshot(&self, snap: &Snapshot) -> Result<()> {
        // Every chunk the snapshot names must be on disk before the snapshot is.
        self.sync()?;
        let json = serde_json::to_vec(snap).map_err(|e| Error::Corrupt(e.to_string()))?;
        let blob = self
            .keys
            .seal(Kind::Snapshot, &self.id, &snap.name, &json)?;
        self.write_atomic(&self.snapshot_path(&snap.name)?, &blob)
    }

    pub fn load_snapshot(&self, name: &str) -> Result<Snapshot> {
        let blob =
            read_capped(&self.snapshot_path(name)?, MAX_SNAPSHOT as u64).map_err(|e| match e {
                Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                    Error::Usage(format!("no snapshot {name}"))
                }
                other => other,
            })?;
        let json = self
            .keys
            .open(Kind::Snapshot, &self.id, name, &blob, MAX_SNAPSHOT)?;
        let snap: Snapshot = serde_json::from_slice(&json)
            .map_err(|e| Error::Corrupt(format!("snapshot {name}: {e}")))?;
        if snap.name != name {
            return Err(Error::Corrupt(format!(
                "snapshot {name} claims to be {}",
                snap.name
            )));
        }
        Ok(snap)
    }

    /// Snapshot names, oldest first (names start with the UTC time).
    pub fn snapshot_names(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = fs::read_dir(self.root.join("snapshots"))?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| self.snapshot_path(n).is_ok())
            .collect();
        names.sort();
        Ok(names)
    }

    pub fn remove_snapshot(&self, name: &str) -> Result<()> {
        fs::remove_file(self.snapshot_path(name)?)?;
        Ok(())
    }

    /// "latest", a full name, or an unambiguous prefix of one.
    pub fn resolve(&self, wanted: &str) -> Result<String> {
        let names = self.snapshot_names()?;
        if wanted == "latest" {
            return names
                .last()
                .cloned()
                .ok_or_else(|| Error::Usage("the repository has no snapshots".into()));
        }
        let hits: Vec<&String> = names
            .iter()
            .filter(|n| n.starts_with(wanted) || n.ends_with(wanted))
            .collect();
        match hits.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(Error::Usage(format!("no snapshot matches {wanted:?}"))),
            _ => Err(Error::Usage(format!(
                "{wanted:?} matches {} snapshots; give more of the name",
                hits.len()
            ))),
        }
    }

    /// Bytes used by the repository on disk.
    pub fn disk_usage(&self) -> u64 {
        fn walk(p: &Path) -> u64 {
            match fs::symlink_metadata(p) {
                Ok(m) if m.is_dir() => fs::read_dir(p)
                    .map(|d| d.filter_map(|e| e.ok()).map(|e| walk(&e.path())).sum())
                    .unwrap_or(0),
                Ok(m) => m.len(),
                Err(_) => 0,
            }
        }
        walk(&self.root)
    }

    /// Leftovers of interrupted writes.
    pub fn clean_tmp(&self) -> Result<usize> {
        let mut n = 0;
        for e in fs::read_dir(self.root.join("tmp"))? {
            fs::remove_file(e?.path())?;
            n += 1;
        }
        Ok(n)
    }
}

/// Read a repository file, refusing one larger than `cap` before reading it: a planted
/// multi-gigabyte "chunk" must not exhaust memory during a check or restore.
fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = File::open(path)?;
    let len = f.metadata()?.len();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if len > cap {
        return Err(Error::Corrupt(format!(
            "{name}: {len} bytes, more than any valid file"
        )));
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.take(cap + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(Error::Corrupt(format!("{name}: grew while being read")));
    }
    Ok(buf)
}

pub fn make_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        // Not every filesystem keeps Unix modes (NTFS mounts ignore them); that is fine.
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

// --- lock --------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub struct LockInfo {
    pub host: String,
    pub pid: u32,
    pub time: String,
    pub operation: String,
}

/// Exclusive lock for operations that write. Removed when dropped.
pub struct Lock {
    path: PathBuf,
}

impl Lock {
    pub fn acquire(repo: &Repo, operation: &str) -> Result<Lock> {
        let path = repo.root.join("locks").join("lock");
        let info = LockInfo {
            host: crate::hostname(),
            pid: std::process::id(),
            time: crate::now_rfc3339(),
            operation: operation.into(),
        };
        let body = serde_json::to_vec(&info).map_err(|e| Error::Corrupt(e.to_string()))?;
        for _ in 0..2 {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut f) => {
                    f.write_all(&body)?;
                    f.sync_all()?;
                    return Ok(Lock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let other: Option<LockInfo> = fs::read(&path)
                        .ok()
                        .and_then(|b| serde_json::from_slice(&b).ok());
                    match other {
                        Some(o) if o.host == info.host && !Path::new(&format!("/proc/{}", o.pid)).exists() => {
                            fs::remove_file(&path)?; // the process that held it is gone
                        }
                        Some(o) => {
                            return Err(Error::Locked(format!(
                                "{} (pid {} on {}) since {}; if it is no longer running: mnemosyne unlock",
                                o.operation, o.pid, o.host, o.time
                            )))
                        }
                        None => return Err(Error::Locked("unreadable lock file; check it, then: mnemosyne unlock".into())),
                    }
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
        Err(Error::Locked("could not take the lock".into()))
    }

    pub fn force_remove(repo: &Repo) -> Result<bool> {
        let path = repo.root.join("locks").join("lock");
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const FAST: KdfCost = KdfCost { m: 8, t: 1, p: 1 };
    pub const SMALL: Chunker = Chunker {
        min: 64 << 10,
        avg: 128 << 10,
        max: 512 << 10,
    };

    pub fn new_repo(dir: &Path) -> Repo {
        Repo::init_with(&dir.join("repo"), "test password 123", FAST, SMALL).unwrap()
    }

    #[test]
    fn init_open_and_password() {
        let d = tempfile::tempdir().unwrap();
        let r = new_repo(d.path());
        let root = d.path().join("repo");
        assert!(matches!(
            Repo::open(&root, "wrong password!!"),
            Err(Error::WrongPassword)
        ));
        let again = Repo::open(&root, "test password 123").unwrap();
        assert_eq!(again.id, r.id);
        assert_eq!(again.keys().to_bytes(), r.keys().to_bytes());
        r.change_password("a new password 456").unwrap();
        assert!(Repo::open(&root, "test password 123").is_err());
        assert_eq!(
            Repo::open(&root, "a new password 456")
                .unwrap()
                .keys()
                .to_bytes(),
            r.keys().to_bytes()
        );
        assert!(
            Repo::init_with(&root, "test password 123", FAST, SMALL).is_err(),
            "no second init"
        );
        assert!(Repo::init_with(&d.path().join("x"), "short", FAST, SMALL).is_err());
    }

    #[test]
    fn recovery_code_opens_and_survives_a_password_change() {
        let d = tempfile::tempdir().unwrap();
        let r = new_repo(d.path());
        let root = d.path().join("repo");
        assert!(!r.has_recovery());
        assert!(matches!(
            Repo::open_with_recovery(&root, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"),
            Err(Error::Usage(_))
        ));
        let code = r.create_recovery_code().unwrap();
        assert!(r.has_recovery());
        assert_eq!(code.len(), 39, "8 groups of 4 with dashes: {code}");
        // typed back carelessly: lower case, spaces, O for 0, I for 1
        let sloppy = code
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "i");
        assert_eq!(
            Repo::open_with_recovery(&root, &sloppy)
                .unwrap()
                .keys()
                .to_bytes(),
            r.keys().to_bytes()
        );
        // a different code of the right shape fails like a wrong password
        let mut other = code.clone();
        let last = if other.ends_with('A') { 'B' } else { 'A' };
        other.pop();
        other.push(last);
        assert!(matches!(
            Repo::open_with_recovery(&root, &other),
            Err(Error::WrongPassword)
        ));
        assert!(matches!(
            Repo::open_with_recovery(&root, "not a code"),
            Err(Error::Usage(_))
        ));
        // the password slot keeps working, and changing the password keeps the code valid
        r.change_password("a new password 456").unwrap();
        assert!(Repo::open(&root, "a new password 456").is_ok());
        let via_code = Repo::open_with_recovery(&root, &code).unwrap();
        via_code.change_password("set from the code 789").unwrap();
        assert!(Repo::open(&root, "set from the code 789").is_ok());
        // a new code replaces the old one
        let second = r.create_recovery_code().unwrap();
        assert!(
            Repo::open_with_recovery(&root, &code).is_err()
                && Repo::open_with_recovery(&root, &second).is_ok()
        );
        assert!(r.remove_recovery().unwrap() && !r.has_recovery());
    }

    #[test]
    fn tampered_recovery_slot_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let r = new_repo(d.path());
        let code = r.create_recovery_code().unwrap();
        let path = d.path().join("repo/config.json");
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        v["recovery"]["kdf"]["t_cost"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(Repo::open_with_recovery(&d.path().join("repo"), &code).is_err());
        v["recovery"]["kdf"]["m_cost"] = serde_json::json!(4_000_000);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(
            Repo::open_with_recovery(&d.path().join("repo"), &code).is_err(),
            "KDF limits apply here too"
        );
        assert!(
            Repo::open(&d.path().join("repo"), "test password 123").is_ok(),
            "the password slot is untouched"
        );
    }

    #[test]
    fn codes_are_random_and_well_formed() {
        let a = new_recovery_code().unwrap();
        let b = new_recovery_code().unwrap();
        assert_ne!(a, b);
        assert!(normalize_recovery_code(&a).is_some() && a.len() == 32);
        assert_eq!(
            normalize_recovery_code("0123-4567-89ab-cdef-ghjk-mnpq-rstv-wxyz").as_deref(),
            Some("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        );
        assert!(
            normalize_recovery_code("UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU").is_none(),
            "U is not in the alphabet"
        );
        assert!(normalize_recovery_code("ABCD").is_none());
    }

    #[test]
    fn non_empty_dir_is_refused() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("file"), b"x").unwrap();
        assert!(Repo::init_with(d.path(), "test password 123", FAST, SMALL).is_err());
    }

    #[test]
    fn tampered_header_is_refused() {
        let d = tempfile::tempdir().unwrap();
        new_repo(d.path());
        let path = d.path().join("repo/config.json");
        let text = fs::read_to_string(&path).unwrap();
        for (from, to) in [
            ("\"t_cost\": 1", "\"t_cost\": 2"),
            ("\"m_cost\": 8", "\"m_cost\": 2000000"),
        ] {
            fs::write(&path, text.replace(from, to)).unwrap();
            assert!(
                Repo::open(&d.path().join("repo"), "test password 123").is_err(),
                "{from}"
            );
        }
    }

    #[test]
    fn chunks_dedup_verify_and_detect_damage() {
        let d = tempfile::tempdir().unwrap();
        let r = new_repo(d.path());
        let mut known = r.chunk_ids().unwrap();
        let id = r.keys().chunk_id(b"some data");
        assert!(r.put_chunk(&id, b"some data", &mut known).unwrap() > 0);
        assert_eq!(r.put_chunk(&id, b"some data", &mut known).unwrap(), 0);
        assert_eq!(r.get_chunk(&id).unwrap(), b"some data");
        assert_eq!(r.chunk_ids().unwrap(), HashSet::from([id.clone()]));
        // swap in another chunk's blob under this name: authentication fails
        let other = r.keys().chunk_id(b"other");
        r.put_chunk(&other, b"other", &mut known).unwrap();
        fs::copy(r.chunk_path(&other), r.chunk_path(&id)).unwrap();
        assert!(r.get_chunk(&id).is_err());
        assert!(r.get_chunk("../../config.json").is_err());
        assert!(
            fs::read_dir(d.path().join("repo/tmp"))
                .unwrap()
                .next()
                .is_none(),
            "tmp is clean"
        );
    }

    #[test]
    fn oversized_files_are_refused_without_reading_them() {
        let d = tempfile::tempdir().unwrap();
        let r = new_repo(d.path());
        let mut known = HashSet::new();
        let id = r.keys().chunk_id(b"x");
        r.put_chunk(&id, b"x", &mut known).unwrap();
        // a sparse 64 GiB file: reading it would take the whole machine down
        let f = OpenOptions::new()
            .write(true)
            .open(r.chunk_path(&id))
            .unwrap();
        f.set_len(64 << 30).unwrap();
        match r.get_chunk(&id) {
            Err(Error::Corrupt(msg)) => assert!(msg.contains("more than any valid file"), "{msg}"),
            other => panic!("expected a refusal, got {:?}", other.map(|v| v.len())),
        }
    }

    #[test]
    fn lock_is_exclusive_and_stale_locks_clear() {
        let d = tempfile::tempdir().unwrap();
        let r = new_repo(d.path());
        let l = Lock::acquire(&r, "backup").unwrap();
        assert!(matches!(Lock::acquire(&r, "prune"), Err(Error::Locked(_))));
        drop(l);
        let _l = Lock::acquire(&r, "prune").unwrap();
        drop(_l);
        // a lock left by a process that no longer exists
        let dead = LockInfo {
            host: crate::hostname(),
            pid: 4_000_000,
            time: "x".into(),
            operation: "backup".into(),
        };
        fs::write(
            d.path().join("repo/locks/lock"),
            serde_json::to_vec(&dead).unwrap(),
        )
        .unwrap();
        assert!(Lock::acquire(&r, "backup").is_ok());
        // another machine's lock is respected
        let remote = LockInfo {
            host: "elsewhere".into(),
            pid: 1,
            time: "x".into(),
            operation: "backup".into(),
        };
        fs::write(
            d.path().join("repo/locks/lock"),
            serde_json::to_vec(&remote).unwrap(),
        )
        .unwrap();
        assert!(Lock::acquire(&r, "backup").is_err());
        assert!(Lock::force_remove(&r).unwrap());
    }
}
