//! SLH-DSA ACVP registration models.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Lossless SLH-DSA ACVP registration document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    /// Vector-set identifier.
    pub vs_id: u64,

    /// Algorithm identifier.
    pub algorithm: String,

    /// Operation mode.
    pub mode: String,

    /// Revision identifier.
    pub revision: String,

    /// Whether the registration is a sample.
    #[serde(default)]
    pub is_sample: bool,

    /// Operation-specific registration fields.
    #[serde(flatten)]
    pub capabilities: Map<String, Value>,
}
