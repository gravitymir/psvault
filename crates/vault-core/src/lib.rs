//! `vault-core` — the portable, self-contained encrypted vault format.
//!
//! One master password protects one file. The file is fully self-describing:
//! it carries the KDF parameters and random salt/nonce in a header, so the same
//! bytes open on any machine (native binary or WASM in a browser) with nothing
//! but the password.
//!
//! ```text
//! master password ──Argon2id(salt)──▶ 32-byte key ──XChaCha20-Poly1305(nonce)──▶ ciphertext
//! ```
//!
//! The header (magic, version, KDF params, salt, nonce) is authenticated as
//! associated data, so tampering with the parameters is detected on decrypt.

mod error;
mod model;
pub mod totp;

pub use error::{Result, VaultError};
pub use model::{Entry, Totp, Vault};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"PSV1";
const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20 uses a 192-bit nonce
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // = 57

/// Argon2id cost parameters recorded in the file header.
///
/// Kept explicit (not just "defaults") so an old file always re-derives with the
/// exact costs it was written with, even if our recommended defaults change.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub m_cost: u32, // memory in KiB
    pub t_cost: u32, // iterations
    pub p_cost: u32, // parallelism (lanes)
}

impl Default for KdfParams {
    /// OWASP-recommended Argon2id baseline: 19 MiB, 2 passes, 1 lane.
    fn default() -> Self {
        KdfParams {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| VaultError::Random(e.to_string()))
}

/// Derive the 32-byte encryption key from the password and salt.
fn derive_key(password: &[u8], salt: &[u8], p: &KdfParams) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(KEY_LEN))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Serialize the header. These exact bytes are also fed to the AEAD as
/// associated data, binding the ciphertext to its KDF parameters.
fn write_header(params: &KdfParams, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.push(FORMAT_VERSION);
    h.extend_from_slice(&params.m_cost.to_le_bytes());
    h.extend_from_slice(&params.t_cost.to_le_bytes());
    h.extend_from_slice(&params.p_cost.to_le_bytes());
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce);
    debug_assert_eq!(h.len(), HEADER_LEN);
    h
}

struct ParsedHeader {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader> {
    if bytes.len() < HEADER_LEN {
        return Err(VaultError::Truncated);
    }
    if &bytes[0..4] != MAGIC {
        return Err(VaultError::BadMagic);
    }
    let version = bytes[4];
    if version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let m_cost = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
    let t_cost = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
    let p_cost = u32::from_le_bytes(bytes[13..17].try_into().unwrap());
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[17..17 + SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[17 + SALT_LEN..HEADER_LEN]);
    Ok(ParsedHeader {
        params: KdfParams {
            m_cost,
            t_cost,
            p_cost,
        },
        salt,
        nonce,
    })
}

/// Encrypt a vault into a single self-contained file, using the default KDF cost.
pub fn encrypt(vault: &Vault, password: &str) -> Result<Vec<u8>> {
    encrypt_with(vault, password, &KdfParams::default())
}

/// Encrypt a vault with explicit KDF parameters (useful for tests or tuning).
pub fn encrypt_with(vault: &Vault, password: &str, params: &KdfParams) -> Result<Vec<u8>> {
    let mut plaintext = vault.to_plaintext()?;
    let out = seal_bytes(&plaintext, password, params);
    plaintext.zeroize();
    out
}

/// Decrypt a vault file with the master password.
///
/// Returns [`VaultError::Decrypt`] for a wrong password *or* any tampering —
/// the two are deliberately indistinguishable.
pub fn decrypt(file: &[u8], password: &str) -> Result<Vault> {
    let mut plaintext = open_bytes(file, password)?;
    let vault = Vault::from_plaintext(&plaintext);
    plaintext.zeroize();
    Ok(vault?)
}

/// Encrypt arbitrary bytes into a self-contained file (the "file locker").
///
/// Same format and guarantees as a vault file — only the payload is opaque
/// bytes (e.g. a `.pfx`, a document) instead of vault JSON. The caller owns
/// `plaintext` and is responsible for wiping it afterwards if it is sensitive.
pub fn seal_bytes(plaintext: &[u8], password: &str, params: &KdfParams) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;

    let mut key = derive_key(password.as_bytes(), &salt, params)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();

    let header = write_header(params, &salt, &nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Decrypt)?;

    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a sealed file back into its raw bytes.
pub fn open_bytes(file: &[u8], password: &str) -> Result<Vec<u8>> {
    let ParsedHeader {
        params,
        salt,
        nonce,
    } = parse_header(file)?;
    let header = &file[..HEADER_LEN];
    let ciphertext = &file[HEADER_LEN..];

    let mut key = derive_key(password.as_bytes(), &salt, &params)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();

    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| VaultError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap KDF so tests stay fast; real files use the default cost.
    fn fast() -> KdfParams {
        KdfParams {
            m_cost: 512,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn sample() -> Vault {
        let mut v = Vault::new();
        v.entries.push(Entry {
            id: "1".into(),
            title: "GitHub".into(),
            username: "gravitymir".into(),
            password: "s3cr3t-p@ss".into(),
            url: "https://github.com".into(),
            notes: "personal".into(),
            totp: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        });
        v
    }

    #[test]
    fn roundtrip_recovers_contents() {
        let v = sample();
        let file = encrypt_with(&v, "correct horse battery staple", &fast()).unwrap();
        let out = decrypt(&file, "correct horse battery staple").unwrap();
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].password, "s3cr3t-p@ss");
        assert_eq!(out.entries[0].title, "GitHub");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let file = encrypt_with(&sample(), "right", &fast()).unwrap();
        assert!(matches!(decrypt(&file, "wrong"), Err(VaultError::Decrypt)));
    }

    #[test]
    fn ciphertext_does_not_leak_plaintext() {
        let file = encrypt_with(&sample(), "pw", &fast()).unwrap();
        let hay = &file[HEADER_LEN..];
        assert!(!hay.windows(11).any(|w| w == b"s3cr3t-p@ss"));
        assert!(!hay.windows(6).any(|w| w == b"GitHub"));
    }

    #[test]
    fn tampering_with_kdf_params_is_detected() {
        let mut file = encrypt_with(&sample(), "pw", &fast()).unwrap();
        file[5] ^= 0x01; // flip a bit in m_cost inside the header (AAD)
        assert!(decrypt(&file, "pw").is_err());
    }

    #[test]
    fn flipping_a_ciphertext_bit_is_detected() {
        let mut file = encrypt_with(&sample(), "pw", &fast()).unwrap();
        let last = file.len() - 1;
        file[last] ^= 0x01;
        assert!(matches!(decrypt(&file, "pw"), Err(VaultError::Decrypt)));
    }

    #[test]
    fn rejects_foreign_files() {
        // Full-length buffer with wrong magic -> BadMagic.
        let foreign = vec![b'X'; HEADER_LEN + 8];
        assert!(matches!(decrypt(&foreign, "pw"), Err(VaultError::BadMagic)));
        // Too short to even hold a header -> Truncated (checked before magic).
        assert!(matches!(decrypt(b"PS", "pw"), Err(VaultError::Truncated)));
    }

    #[test]
    fn file_locker_roundtrips_arbitrary_bytes() {
        // Simulate a small binary file (e.g. a .pfx): all byte values, incl. 0x00.
        let data: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        let sealed = seal_bytes(&data, "pw", &fast()).unwrap();
        assert_ne!(&sealed[HEADER_LEN..], &data[..], "payload must be encrypted");
        let opened = open_bytes(&sealed, "pw").unwrap();
        assert_eq!(opened, data);
        assert!(matches!(open_bytes(&sealed, "nope"), Err(VaultError::Decrypt)));
    }

    #[test]
    fn salt_and_nonce_are_random_per_write() {
        let v = sample();
        let a = encrypt_with(&v, "pw", &fast()).unwrap();
        let b = encrypt_with(&v, "pw", &fast()).unwrap();
        assert_ne!(a, b, "two encryptions must differ (fresh salt+nonce)");
    }
}
