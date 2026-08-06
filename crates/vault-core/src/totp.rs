//! One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238), plus the
//! `otpauth://` URI format that 2FA QR codes use.
//!
//! This is what lets the vault stand in for a phone authenticator app: import a
//! service's `otpauth://totp/...` secret (from its setup QR or the typed key)
//! and regenerate the same rotating codes locally, offline.
//!
//! Only the arithmetic lives here; the current time is supplied by the caller
//! (`unix_seconds`) so this stays a pure, testable function with no clock.

use crate::error::{Result, VaultError};
use crate::model::Totp;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Hash function underlying the HMAC. TOTP defaults to SHA-1; some services use
/// the SHA-2 variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// Parse a case-insensitive name; unknown values fall back to SHA-1, which
    /// is the otpauth default and what almost every service uses.
    pub fn parse(name: &str) -> Algorithm {
        match name.trim().to_ascii_uppercase().as_str() {
            "SHA256" => Algorithm::Sha256,
            "SHA512" => Algorithm::Sha512,
            _ => Algorithm::Sha1,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

fn totp_err(msg: impl Into<String>) -> VaultError {
    VaultError::Totp(msg.into())
}

/// Decode a Base32 (RFC 4648) secret. Tolerant of the ways services present
/// keys: lowercase, spaces, and dashes between groups, and `=` padding are all
/// ignored. Rejects any other character.
pub fn base32_decode(input: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);
    for ch in input.chars() {
        if ch == ' ' || ch == '-' || ch == '=' {
            continue;
        }
        let up = ch.to_ascii_uppercase() as u8;
        let val =
            ALPHABET.iter().position(|&a| a == up).ok_or_else(|| {
                totp_err(format!("secret is not valid Base32 (bad character '{ch}')"))
            })? as u32;
        acc = (acc << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if out.is_empty() {
        return Err(totp_err("secret is empty"));
    }
    Ok(out)
}

/// Encode bytes as unpadded, uppercase Base32 — used when we rebuild an
/// `otpauth://` URI for the "export as QR" direction.
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// HMAC-based one-time password (RFC 4226) for an explicit counter.
fn hotp(key: &[u8], counter: u64, digits: u8, alg: Algorithm) -> String {
    let msg = counter.to_be_bytes();
    let mac: Vec<u8> = match alg {
        Algorithm::Sha1 => {
            let mut m = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut m = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut m = <Hmac<Sha512>>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
    };
    // Dynamic truncation (RFC 4226 §5.3): low nibble of the last byte picks a
    // 4-byte window, masked to 31 bits.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    let modulo = 10u32.pow(digits as u32);
    format!("{:0width$}", bin % modulo, width = digits as usize)
}

/// The current TOTP (RFC 6238) code for a Base32 secret at `unix_seconds`.
///
/// `digits` is clamped to 1..=9 (the truncation yields a 31-bit value, so 10+
/// digits cannot be represented) and `period` must be non-zero.
pub fn totp_code(
    secret_b32: &str,
    unix_seconds: u64,
    digits: u8,
    period: u32,
    alg: Algorithm,
) -> Result<String> {
    if period == 0 {
        return Err(totp_err("period must be greater than zero"));
    }
    let digits = digits.clamp(1, 9);
    let key = base32_decode(secret_b32)?;
    let counter = unix_seconds / period as u64;
    Ok(hotp(&key, counter, digits, alg))
}

/// Convenience: compute the code straight from a stored [`Totp`].
pub fn code_for(t: &Totp, unix_seconds: u64) -> Result<String> {
    totp_code(
        &t.secret,
        unix_seconds,
        t.digits,
        t.period,
        Algorithm::parse(&t.algorithm),
    )
}

/// Parse an `otpauth://totp/...` URI (the payload of a 2FA setup QR code) into a
/// stored [`Totp`]. Only the TOTP type is supported (HOTP uses a counter, not a
/// clock, and is essentially unused for website 2FA).
pub fn parse_otpauth(uri: &str) -> Result<Totp> {
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| totp_err("not an otpauth:// URI"))?;
    let (kind, rest) = rest
        .split_once('/')
        .ok_or_else(|| totp_err("otpauth URI is missing its type/label"))?;
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(totp_err(format!(
            "unsupported otpauth type '{kind}' (only totp is supported)"
        )));
    }

    let (label_raw, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };

    // The label is usually "Issuer:Account" (either part may be percent-encoded
    // and the separator may be "%3A"); a bare "Account" is also valid.
    let label = percent_decode(label_raw);
    let (mut issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };

    let mut secret = String::new();
    let mut algorithm = "SHA1".to_string();
    let mut digits: u8 = 6;
    let mut period: u32 = 30;

    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = v.split_whitespace().collect(),
            "issuer" => {
                if !v.trim().is_empty() {
                    issuer = v.trim().to_string();
                }
            }
            "algorithm" => algorithm = Algorithm::parse(&v).name().to_string(),
            "digits" => digits = v.trim().parse().unwrap_or(6),
            "period" => period = v.trim().parse().unwrap_or(30),
            _ => {}
        }
    }

    if secret.is_empty() {
        return Err(totp_err("otpauth URI has no secret"));
    }
    // Validate the secret decodes now, so a bad QR fails at import, not later.
    base32_decode(&secret)?;

    Ok(Totp {
        secret,
        issuer,
        account,
        algorithm,
        digits: digits.clamp(1, 9),
        period: if period == 0 { 30 } else { period },
    })
}

/// Rebuild a canonical `otpauth://totp/...` URI from a stored [`Totp`], for the
/// "export as QR" direction (move the secret to a phone or another app).
pub fn build_otpauth(t: &Totp) -> String {
    let label = if t.issuer.is_empty() {
        percent_encode(&t.account)
    } else {
        format!(
            "{}:{}",
            percent_encode(&t.issuer),
            percent_encode(&t.account)
        )
    };
    let mut uri = format!(
        "otpauth://totp/{label}?secret={}",
        // The secret is already Base32; keep it verbatim (uppercased, no spaces).
        t.secret
            .split_whitespace()
            .collect::<String>()
            .to_uppercase()
    );
    if !t.issuer.is_empty() {
        uri.push_str(&format!("&issuer={}", percent_encode(&t.issuer)));
    }
    uri.push_str(&format!(
        "&algorithm={}&digits={}&period={}",
        Algorithm::parse(&t.algorithm).name(),
        t.digits,
        t.period
    ));
    uri
}

/// Percent-decode a URI component (`%3A` -> `:`, `+` is left as-is, since 2FA
/// labels are path/label components, not form fields).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode everything that isn't an unreserved character, so labels with
/// spaces, `:` or `@` survive a round trip through the URI.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        for sample in [&b"Hello!"[..], b"", b"1234567890", b"\x00\xff\x10"] {
            let enc = base32_encode(sample);
            if sample.is_empty() {
                assert!(base32_decode(&enc).is_err()); // empty -> rejected
            } else {
                assert_eq!(base32_decode(&enc).unwrap(), sample);
            }
        }
    }

    #[test]
    fn base32_ignores_spaces_dashes_case() {
        let a = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        let b = base32_decode("jbsw y3dp ehpk 3pxp").unwrap();
        let c = base32_decode("JBSW-Y3DP-EHPK-3PXP").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    // RFC 6238 Appendix B test vectors. The SHA-1 seed is the ASCII of
    // "12345678901234567890" (20 bytes), given there in hex/Base32.
    fn rfc_secret() -> String {
        base32_encode(b"12345678901234567890")
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = rfc_secret();
        // (unix time, expected 8-digit code)
        let cases = [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (t, expected) in cases {
            let code = totp_code(&secret, t, 8, 30, Algorithm::Sha1).unwrap();
            assert_eq!(code, expected, "TOTP mismatch at t={t}");
        }
    }

    #[test]
    fn rfc6238_sha256_and_sha512() {
        // SHA-256 seed is 32 bytes, SHA-512 seed 64 bytes (repeats of the ASCII
        // digits per the RFC), checked at t=59.
        let seed256: Vec<u8> = b"12345678901234567890123456789012".to_vec();
        let seed512: Vec<u8> =
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
        assert_eq!(
            totp_code(&base32_encode(&seed256), 59, 8, 30, Algorithm::Sha256).unwrap(),
            "46119246"
        );
        assert_eq!(
            totp_code(&base32_encode(&seed512), 59, 8, 30, Algorithm::Sha512).unwrap(),
            "90693936"
        );
    }

    #[test]
    fn parse_full_otpauth() {
        let uri = "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
        let t = parse_otpauth(uri).unwrap();
        assert_eq!(t.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(t.issuer, "GitHub");
        assert_eq!(t.account, "me@example.com");
        assert_eq!(t.digits, 6);
        assert_eq!(t.period, 30);
    }

    #[test]
    fn parse_percent_encoded_label_and_defaults() {
        let uri = "otpauth://totp/Big%20Co%3Ajane%40corp.com?secret=JBSWY3DPEHPK3PXP";
        let t = parse_otpauth(uri).unwrap();
        assert_eq!(t.issuer, "Big Co");
        assert_eq!(t.account, "jane@corp.com");
        assert_eq!(t.algorithm, "SHA1"); // defaulted
        assert_eq!(t.digits, 6);
        assert_eq!(t.period, 30);
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse_otpauth("https://example.com").is_err());
        assert!(parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(parse_otpauth("otpauth://totp/x?issuer=NoSecret").is_err());
        assert!(parse_otpauth("otpauth://totp/x?secret=not!base32!").is_err());
    }

    #[test]
    fn build_then_parse_roundtrips() {
        let orig = Totp {
            secret: "JBSWY3DPEHPK3PXP".into(),
            issuer: "Acme Inc".into(),
            account: "user@acme.io".into(),
            algorithm: "SHA256".into(),
            digits: 8,
            period: 60,
        };
        let uri = build_otpauth(&orig);
        let back = parse_otpauth(&uri).unwrap();
        assert_eq!(back.secret, orig.secret);
        assert_eq!(back.issuer, orig.issuer);
        assert_eq!(back.account, orig.account);
        assert_eq!(back.algorithm, orig.algorithm);
        assert_eq!(back.digits, orig.digits);
        assert_eq!(back.period, orig.period);
    }
}
