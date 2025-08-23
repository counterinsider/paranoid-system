// SPDX-License-Identifier: MIT OR Apache-2.0
//! Structs for Attestation Server Communication
//!
//! A client talks to server using JSON messages. Common JSON response includes:
//! ```json
//!  {
//!      "success": "<true-if-no-error-otherwise-false>",
//!      "error": "<error-message-or-not-present>",
//!      "data": "<data-object-or-not-present>",
//!      "action_required": ["<required-actions-or-not-present>"]
//!  }
//! ```

use serde::{Deserialize, Serialize};

/// Common response with generic optional data
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Response<D> {
    pub success: bool,
    pub error: Option<String>,
    pub data: Option<D>,
    pub action_required: Option<Vec<String>>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestEmpty;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseEmpty;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestEnroll {
    pub ak: String,
    pub ek_pub: String,
    pub ek_cert: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseEnroll {
    pub jwt_token: String,
    // Client identifier - RFC-9562 UUID Version 8
    pub uuid: String,
    pub totp_secret: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RequestPush {
    /// Current state of given PCRs set
    pub pcr_digest: Vec<u8>,
    /// Boot aggregate values and corresponding timestamps (separated with newline)
    pub ba: String,
    /// IMA log (for pre-configured set of files only)
    pub ima_log: String,
    /// SHA256 hash of concatenated in given order [`RequestPush::ima_log`], [`RequestPush::ba`], [`RequestPush::pcr_digest`], [`RequestEnroll::client_binary`]
    pub system_state_hash: Vec<u8>,
    pub tpm_log: Vec<u8>,
    /// TPM restart (boot) counter
    pub bc: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponsePush {
    pub baseline_nonce: String,
    pub session_nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RequestPushComplete {
    pub baseline_nonce: String,
    pub session_nonce: Option<String>,
    pub totp: Option<String>,
    pub payloads: Option<Vec<Vec<u8>>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ResponsePushComplete {
    pub session_nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ResponseAttestNonce {
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RequestAttest {
    pub quote: String,
    pub tpm_log: Vec<u8>,
    pub ima_log: String,
    pub ba: String,
    pub bc: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseAttest {
    pub session_nonce: Option<String>,
    pub bc_diff: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RequestAttestComplete {
    pub session_nonce: Option<String>,
    pub totp: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ResponseAttestComplete {
    pub session_nonce: Option<String>,
    pub payloads: Option<Vec<Vec<u8>>>,
}
