//! SLH-DSA ACVP validation-response models.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// SLH-DSA ACVP validation document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Validation {
    /// Vector-set identifier.
    pub vs_id: u64,

    /// Overall validation disposition.
    pub disposition: String,

    /// Per-test validation details.
    #[serde(default)]
    pub tests: Vec<Value>,
}
