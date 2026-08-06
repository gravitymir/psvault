use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// A single stored secret (a login, card, note, etc.).
///
/// `password` is wiped from memory on drop. The rest are treated as
/// metadata — searchable, not especially secret.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Entry {
    /// Stable identifier, unique within a vault (e.g. a UUID string).
    #[zeroize(skip)]
    pub id: String,
    #[zeroize(skip)]
    pub title: String,
    #[zeroize(skip)]
    pub username: String,
    pub password: String,
    #[zeroize(skip)]
    pub url: String,
    #[zeroize(skip)]
    pub notes: String,
    /// Optional two-factor (TOTP) secret attached to this login. `None` for the
    /// vast majority of entries; present once a 2FA QR/secret is imported.
    ///
    /// Skipped by this struct's `Zeroize` (it is an `Option`, not a `String`);
    /// the inner [`Totp`] wipes its own secret via its own `ZeroizeOnDrop`.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<Totp>,
    /// Unix seconds; 0 if unknown.
    #[zeroize(skip)]
    pub created: u64,
    #[zeroize(skip)]
    pub updated: u64,
}

/// A stored TOTP (RFC 6238) configuration — everything needed to regenerate the
/// rotating 6-digit codes an authenticator app would show, so a phone isn't
/// required. Imported from an `otpauth://` QR code or typed in by hand.
///
/// `secret` is the sensitive part (the shared key, Base32) and is wiped on drop.
/// The rest are non-secret display/tuning metadata.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Totp {
    /// Shared secret, Base32 (RFC 4648) as issued by the service.
    pub secret: String,
    /// Service name (e.g. "GitHub"); from the otpauth `issuer`. May be empty.
    #[zeroize(skip)]
    #[serde(default)]
    pub issuer: String,
    /// Account label (e.g. "you@example.com"); from the otpauth label. May be empty.
    #[zeroize(skip)]
    #[serde(default)]
    pub account: String,
    /// "SHA1" (default), "SHA256", or "SHA512".
    #[zeroize(skip)]
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Code length, usually 6.
    #[zeroize(skip)]
    #[serde(default = "default_digits")]
    pub digits: u8,
    /// Rotation period in seconds, usually 30.
    #[zeroize(skip)]
    #[serde(default = "default_period")]
    pub period: u32,
}

fn default_algorithm() -> String {
    "SHA1".to_string()
}
fn default_digits() -> u8 {
    6
}
fn default_period() -> u32 {
    30
}

/// The full decrypted contents of a vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Vault {
    /// Format revision of the *contents* (independent of the file crypto format).
    #[serde(default = "default_schema")]
    pub schema: u32,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

fn default_schema() -> u32 {
    1
}

impl Vault {
    pub fn new() -> Self {
        Vault {
            schema: 1,
            entries: Vec::new(),
        }
    }

    /// Serialize contents to the JSON that will be encrypted.
    pub(crate) fn to_plaintext(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Parse decrypted JSON back into a vault.
    pub(crate) fn from_plaintext(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}
