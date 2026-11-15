//! Mnemosyne: encrypted, deduplicating backups that test their own restores.
//!
//! - Files are cut into content-defined chunks (FastCDC), so an edit inside a big file
//!   stores only the chunks around it, and equal data is stored once.
//! - Chunks and snapshots are compressed (zstd) and encrypted (XChaCha20-Poly1305) with a
//!   random master key; the password only unlocks that key (Argon2id).
//! - `check --read-data` decrypts and verifies every chunk: a restore drill without
//!   writing files. Status goes to a small JSON file for dashboards.
//! - No network code at all: a repository is a directory (another disk, a USB stick,
//!   a mounted share).

pub mod backup;
pub mod crypto;
pub mod maintain;
pub mod repo;
pub mod restore;
pub mod snapshot;
pub mod status;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("wrong password (or the repository's key file is damaged)")]
    WrongPassword,
    #[error("repository data is damaged: {0}")]
    Corrupt(String),
    #[error("{0}")]
    Usage(String),
    #[error("the repository is locked by {0}")]
    Locked(String),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("encryption failed")]
    Crypto,
    #[error("the system random number generator failed")]
    Random,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// "1.4 GiB"
pub fn human_bytes(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", units[u])
    }
}
