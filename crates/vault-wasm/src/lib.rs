//! WASM boundary for the vault.
//!
//! JavaScript owns the entry list and the UI; Rust owns crypto only. The two
//! talk in bytes (the encrypted file) and JSON (the decrypted vault).

use vault_core::totp::{self, Algorithm};
use vault_core::{decrypt, encrypt, open_bytes, seal_bytes, KdfParams, Totp, Vault};
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

// ---------------------------------------------------------------------------
// TOTP (2FA authenticator) — decode a setup QR, parse otpauth, generate codes.
// ---------------------------------------------------------------------------

/// Decode a QR code from raw RGBA pixels (as produced by a `<canvas>`
/// `getImageData`). Returns the encoded text — for 2FA setup that is an
/// `otpauth://...` URI. Throws if no QR is found.
///
/// `rgba` must be exactly `width * height * 4` bytes.
#[wasm_bindgen]
pub fn decode_qr(rgba: &[u8], width: u32, height: u32) -> Result<String, JsValue> {
    let (w, h) = (width as usize, height as usize);
    if rgba.len() != w * h * 4 {
        return Err(JsValue::from_str(
            "pixel buffer size does not match width×height",
        ));
    }
    // Luma from RGBA (Rec. 601-ish integer weights), what rqrr wants.
    let mut luma = vec![0u8; w * h];
    for (i, px) in rgba.chunks_exact(4).enumerate() {
        luma[i] = ((px[0] as u32 * 77 + px[1] as u32 * 150 + px[2] as u32 * 29) >> 8) as u8;
    }
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| luma[y * w + x]);
    let grids = img.detect_grids();
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            return Ok(content);
        }
    }
    Err(JsValue::from_str("no QR code found in the image"))
}

/// Parse an `otpauth://totp/...` URI into a JSON object the UI can drop straight
/// into an entry: `{ secret, issuer, account, algorithm, digits, period }`.
#[wasm_bindgen]
pub fn parse_otpauth(uri: &str) -> Result<String, JsValue> {
    let t = totp::parse_otpauth(uri).map_err(js_err)?;
    serde_json::to_string(&t).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Parse a Google Authenticator export QR payload (`otpauth-migration://...`)
/// into a JSON array of TOTP objects — one per account in the migration.
#[wasm_bindgen]
pub fn parse_migration(uri: &str) -> Result<String, JsValue> {
    let list = totp::parse_migration(uri).map_err(js_err)?;
    serde_json::to_string(&list).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Current TOTP code for a stored secret at `unix_seconds` (seconds since the
/// epoch — pass `Date.now()/1000`). Returns the zero-padded digit string.
#[wasm_bindgen]
pub fn totp_code(
    secret: &str,
    algorithm: &str,
    digits: u8,
    period: u32,
    unix_seconds: f64,
) -> Result<String, JsValue> {
    let secs = if unix_seconds < 0.0 {
        0
    } else {
        unix_seconds as u64
    };
    totp::totp_code(secret, secs, digits, period, Algorithm::parse(algorithm)).map_err(js_err)
}

/// Build an SVG QR code for a stored TOTP (the "export / move to another device"
/// direction). `totp_json` is the same shape `parse_otpauth` returns.
#[wasm_bindgen]
pub fn totp_qr_svg(totp_json: &str) -> Result<String, JsValue> {
    let t: Totp = serde_json::from_str(totp_json)
        .map_err(|e| JsValue::from_str(&format!("invalid TOTP JSON: {e}")))?;
    let uri = totp::build_otpauth(&t);
    let code = qrcode::QrCode::new(uri.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("cannot build QR: {e}")))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .build();
    Ok(svg)
}

fn serde_vault_to_json(v: &Vault) -> Result<String, JsValue> {
    serde_json::to_string(v).map_err(|e| JsValue::from_str(&e.to_string()))
}

fn js_err(e: vault_core::VaultError) -> JsValue {
    JsValue::from_str(&e.to_string())
}
