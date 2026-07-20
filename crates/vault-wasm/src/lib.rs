//! WASM boundary for the vault.
//!
//! JavaScript owns the entry list and the UI; Rust owns crypto only. The two
//! talk in bytes (the encrypted file) and JSON (the decrypted vault).

use vault_core::{decrypt, encrypt, open_bytes, seal_bytes, KdfParams, Vault};
use wasm_bindgen::prelude::*;

/// Better panic messages in the browser console during development.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console")]
    console_error_panic_hook::set_once();
}

/// Decrypt a vault file into its JSON contents.
///
/// Returns the vault as a JSON string, or throws with a human-readable reason
/// (wrong password, not a vault file, corrupted, ...).
#[wasm_bindgen]
pub fn unlock(file: &[u8], password: &str) -> Result<String, JsValue> {
    let vault = decrypt(file, password).map_err(js_err)?;
    serde_vault_to_json(&vault)
}

/// Encrypt JSON vault contents back into a self-contained file (bytes).
#[wasm_bindgen]
pub fn lock(vault_json: &str, password: &str) -> Result<Vec<u8>, JsValue> {
    let vault: Vault = serde_json::from_str(vault_json)
        .map_err(|e| JsValue::from_str(&format!("invalid vault JSON: {e}")))?;
    encrypt(&vault, password).map_err(js_err)
}

/// JSON for a fresh, empty vault — so the UI can start a new file.
#[wasm_bindgen]
pub fn empty_vault_json() -> Result<String, JsValue> {
    serde_vault_to_json(&Vault::new())
}

/// Encrypt an arbitrary file's bytes under the password (the "file locker").
/// Returns the sealed `.psv` bytes to download.
#[wasm_bindgen]
pub fn lock_file(data: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
    seal_bytes(data, password, &KdfParams::default()).map_err(js_err)
}

/// Decrypt a sealed file back into its original bytes.
#[wasm_bindgen]
pub fn unlock_file(file: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
    open_bytes(file, password).map_err(js_err)
}

/// Generate a random password using cryptographically secure randomness.
///
/// `len` characters drawn from lowercase+uppercase+digits, plus symbols when
/// `symbols` is true. Uses rejection sampling to avoid modulo bias.
#[wasm_bindgen]
pub fn generate_password(len: usize, symbols: bool) -> Result<String, JsValue> {
    const BASE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const SYM: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

    let mut alphabet: Vec<u8> = BASE.to_vec();
    if symbols {
        alphabet.extend_from_slice(SYM);
    }
    let n = alphabet.len() as u8;
    // Largest multiple of n that fits in a byte; bytes >= this are rejected.
    let limit = 256u16 - (256u16 % n as u16);

    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        getrandom::getrandom(&mut buf).map_err(|e| JsValue::from_str(&e.to_string()))?;
        for &b in buf.iter() {
            if (b as u16) < limit {
                out.push(alphabet[(b % n) as usize] as char);
                if out.len() == len {
                    break;
                }
            }
        }
    }
    Ok(out)
}

fn serde_vault_to_json(v: &Vault) -> Result<String, JsValue> {
    serde_json::to_string(v).map_err(|e| JsValue::from_str(&e.to_string()))
}

fn js_err(e: vault_core::VaultError) -> JsValue {
    JsValue::from_str(&e.to_string())
}
