//! Keys and sealed blobs.
//!
//! - Password -> Argon2id -> wrapping key. It encrypts the repository's random master key
//!   material (64 bytes: an encryption key and an id key), so changing the password only
//!   re-wraps those 64 bytes and never touches the data.
//! - Every blob (chunk or snapshot) is compressed with zstd and sealed with
//!   XChaCha20-Poly1305 under a fresh random 24-byte nonce. The associated data binds the
//!   repository id, the blob kind and the blob's name, so a blob cannot be swapped for
//!   another one or moved between repositories without failing to open.
//! - Chunk ids are keyed BLAKE3 hashes of the plaintext: equal data is stored once, and the
//!   ids reveal nothing about the content to someone without the key.
//! - No custom cryptography: only audited RustCrypto crates and BLAKE3.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305,
};
use std::io::Read;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;
const MAGIC: &[u8; 4] = b"MNEM";
const BLOB_VERSION: u8 = 1;
const ZSTD_LEVEL: i32 = 3;

/// Argon2id defaults: 64 MiB, 3 passes, 1 lane (the same as Sphinx).
pub const DEFAULT_M_COST: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;
/// Limits for parameters read from a repository: a hostile config must not be able to
/// ask for terabytes of memory before the password is even checked.
pub const MAX_M_COST: u32 = 1024 * 1024;
pub const MAX_T_COST: u32 = 16;
pub const MAX_P_COST: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Chunk = 1,
    Snapshot = 2,
}

/// The repository's master key material. Wiped from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    enc: [u8; KEY_LEN],
    id: [u8; KEY_LEN],
}

impl Keys {
    pub fn generate() -> Result<Keys> {
        Ok(Keys {
            enc: random()?,
            id: random()?,
        })
    }

    pub fn to_bytes(&self) -> [u8; 2 * KEY_LEN] {
        let mut out = [0u8; 2 * KEY_LEN];
        out[..KEY_LEN].copy_from_slice(&self.enc);
        out[KEY_LEN..].copy_from_slice(&self.id);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Keys> {
        if bytes.len() != 2 * KEY_LEN {
            return Err(Error::Corrupt("master key has the wrong length".into()));
        }
        let mut keys = Keys {
            enc: [0; KEY_LEN],
            id: [0; KEY_LEN],
        };
        keys.enc.copy_from_slice(&bytes[..KEY_LEN]);
        keys.id.copy_from_slice(&bytes[KEY_LEN..]);
        Ok(keys)
    }

    /// Content address of a chunk: keyed BLAKE3 of its plaintext, as 64 hex characters.
    pub fn chunk_id(&self, data: &[u8]) -> String {
        blake3::keyed_hash(&self.id, data).to_hex().to_string()
    }

    /// Compress and encrypt. Layout: "MNEM" | version | kind | nonce (24) | ciphertext.
    pub fn seal(&self, kind: Kind, repo_id: &str, name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut compressed = zstd::bulk::compress(plaintext, ZSTD_LEVEL).map_err(Error::Io)?;
        let nonce: [u8; NONCE_LEN] = random()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&self.enc).map_err(|_| Error::Crypto)?;
        let aad = blob_aad(kind, repo_id, name);
        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &compressed,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        compressed.zeroize();
        let mut out = Vec::with_capacity(6 + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.push(BLOB_VERSION);
        out.push(kind as u8);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt and decompress, refusing more than `limit` bytes of plaintext.
    pub fn open(
        &self,
        kind: Kind,
        repo_id: &str,
        name: &str,
        blob: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>> {
        let what = || format!("{name}: not a Mnemosyne blob");
        if blob.len() < 6 + NONCE_LEN + 16 || &blob[..4] != MAGIC {
            return Err(Error::Corrupt(what()));
        }
        if blob[4] != BLOB_VERSION {
            return Err(Error::Corrupt(format!(
                "{name}: blob version {} is not supported",
                blob[4]
            )));
        }
        if blob[5] != kind as u8 {
            return Err(Error::Corrupt(format!("{name}: wrong blob kind")));
        }
        let nonce: [u8; NONCE_LEN] = blob[6..6 + NONCE_LEN]
            .try_into()
            .map_err(|_| Error::Corrupt(what()))?;
        let cipher = XChaCha20Poly1305::new_from_slice(&self.enc).map_err(|_| Error::Crypto)?;
        let aad = blob_aad(kind, repo_id, name);
        let mut compressed = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &blob[6 + NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                Error::Corrupt(format!(
                    "{name}: authentication failed (damaged or tampered)"
                ))
            })?;
        let result = decompress(&compressed, limit, name);
        compressed.zeroize();
        result
    }
}

fn decompress(data: &[u8], limit: usize, name: &str) -> Result<Vec<u8>> {
    let decoder = zstd::stream::read::Decoder::new(data).map_err(Error::Io)?;
    let mut out = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::Corrupt(format!("{name}: {e}")))?;
    if out.len() > limit {
        return Err(Error::Corrupt(format!(
            "{name}: larger than {limit} bytes when unpacked"
        )));
    }
    Ok(out)
}

fn blob_aad(kind: Kind, repo_id: &str, name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + repo_id.len() + name.len());
    aad.extend_from_slice(b"mnemosyne");
    aad.push(BLOB_VERSION);
    aad.push(kind as u8);
    aad.extend_from_slice(repo_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    aad
}

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| Error::Random)?;
    Ok(buf)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfCost {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfCost {
    pub const DEFAULT: KdfCost = KdfCost {
        m: DEFAULT_M_COST,
        t: DEFAULT_T_COST,
        p: DEFAULT_P_COST,
    };

    pub fn check(&self) -> Result<()> {
        if self.m > MAX_M_COST
            || self.t > MAX_T_COST
            || self.p > MAX_P_COST
            || self.t == 0
            || self.p == 0
        {
            return Err(Error::Corrupt(format!(
                "refusing key-derivation settings m={} KiB t={} p={} (outside the safe range)",
                self.m, self.t, self.p
            )));
        }
        Ok(())
    }
}

/// Password -> 32-byte wrapping key.
pub fn derive(password: &str, salt: &[u8], cost: KdfCost) -> Result<[u8; KEY_LEN]> {
    cost.check()?;
    let params = Params::new(cost.m, cost.t, cost.p, Some(KEY_LEN))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let mut key = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(key)
}

/// Encrypt the master key material with the wrapping key. `aad` binds the config header.
pub fn wrap(
    wrapping: &[u8; KEY_LEN],
    keys: &Keys,
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping).map_err(|_| Error::Crypto)?;
    let mut plain = keys.to_bytes();
    let sealed = cipher
        .encrypt(&nonce.into(), Payload { msg: &plain, aad })
        .map_err(|_| Error::Crypto);
    plain.zeroize();
    Ok((nonce, sealed?))
}

pub fn unwrap(wrapping: &[u8; KEY_LEN], nonce: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Keys> {
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| Error::Corrupt("bad key nonce".into()))?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping).map_err(|_| Error::Crypto)?;
    let mut plain = cipher
        .decrypt(&nonce.into(), Payload { msg: sealed, aad })
        .map_err(|_| Error::WrongPassword)?;
    let keys = Keys::from_bytes(&plain);
    plain.zeroize();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys::generate().unwrap()
    }

    #[test]
    fn seal_open_roundtrip_and_binding() {
        let k = keys();
        let data = b"hello hello hello hello".repeat(100);
        let blob = k.seal(Kind::Chunk, "repo1", "abc", &data).unwrap();
        assert!(blob.len() < data.len(), "compressed");
        assert_eq!(
            k.open(Kind::Chunk, "repo1", "abc", &blob, 1 << 20).unwrap(),
            data
        );
        // name, kind, repository and key are all bound
        assert!(k.open(Kind::Chunk, "repo1", "abd", &blob, 1 << 20).is_err());
        assert!(k
            .open(Kind::Snapshot, "repo1", "abc", &blob, 1 << 20)
            .is_err());
        assert!(k.open(Kind::Chunk, "repo2", "abc", &blob, 1 << 20).is_err());
        assert!(keys()
            .open(Kind::Chunk, "repo1", "abc", &blob, 1 << 20)
            .is_err());
        // any flipped bit fails
        for i in [0, 5, 10, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[i] ^= 1;
            assert!(
                k.open(Kind::Chunk, "repo1", "abc", &bad, 1 << 20).is_err(),
                "byte {i}"
            );
        }
        assert!(k
            .open(Kind::Chunk, "repo1", "abc", &blob[..20], 1 << 20)
            .is_err());
    }

    #[test]
    fn decompression_limit() {
        let k = keys();
        let blob = k
            .seal(Kind::Snapshot, "r", "s", &vec![0u8; 100_000])
            .unwrap();
        assert!(k.open(Kind::Snapshot, "r", "s", &blob, 99_999).is_err());
        assert_eq!(
            k.open(Kind::Snapshot, "r", "s", &blob, 100_000)
                .unwrap()
                .len(),
            100_000
        );
    }

    #[test]
    fn fresh_nonce_every_time() {
        let k = keys();
        assert_ne!(
            k.seal(Kind::Chunk, "r", "n", b"x").unwrap(),
            k.seal(Kind::Chunk, "r", "n", b"x").unwrap()
        );
    }

    #[test]
    fn chunk_ids_are_keyed() {
        let (a, b) = (keys(), keys());
        assert_eq!(a.chunk_id(b"data"), a.chunk_id(b"data"));
        assert_ne!(a.chunk_id(b"data"), b.chunk_id(b"data"));
        assert_ne!(
            a.chunk_id(b"data"),
            blake3::hash(b"data").to_hex().to_string()
        );
        assert_eq!(a.chunk_id(b"").len(), 64);
    }

    #[test]
    fn wrap_unwrap() {
        let cost = KdfCost { m: 8, t: 1, p: 1 };
        let w = derive("correct horse", b"0123456789abcdef", cost).unwrap();
        let k = keys();
        let (nonce, sealed) = wrap(&w, &k, b"hdr").unwrap();
        assert_eq!(
            unwrap(&w, &nonce, &sealed, b"hdr").unwrap().to_bytes(),
            k.to_bytes()
        );
        let wrong = derive("wrong horse", b"0123456789abcdef", cost).unwrap();
        assert!(matches!(
            unwrap(&wrong, &nonce, &sealed, b"hdr"),
            Err(Error::WrongPassword)
        ));
        assert!(unwrap(&w, &nonce, &sealed, b"other header").is_err());
    }

    #[test]
    fn kdf_limits() {
        assert!(KdfCost {
            m: MAX_M_COST + 1,
            t: 1,
            p: 1
        }
        .check()
        .is_err());
        assert!(KdfCost { m: 8, t: 0, p: 1 }.check().is_err());
        assert!(KdfCost::DEFAULT.check().is_ok());
    }
}
