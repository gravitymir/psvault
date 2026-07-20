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
    /// Unix seconds; 0 if unknown.
    #[zeroize(skip)]
    pub created: u64,
    #[zeroize(skip)]
    pub updated: u64,
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
