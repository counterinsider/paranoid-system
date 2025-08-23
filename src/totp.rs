// SPDX-License-Identifier: MIT OR Apache-2.0
//! Implementation of RFC 6238 TOTP two-factor authentication interface

use anyhow::{Context, Result, anyhow};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

/// RFC-6238 TOTP authenticator interface
pub struct TOTPInterface(TOTP);

impl TOTPInterface {
    /// Initializes TOTP authenticator
    pub fn new(secret_base32: &str) -> Result<Self> {
        let secret = Secret::Encoded(secret_base32.to_string());
        let totp = TOTP::new(
            // According to RFC-6238
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().context("Invalid Base32 TOTP secret")?,
        )?;
        Ok(Self(totp))
    }

    /// Authenticates with One-Time-Password
    pub fn auth(&self, input_code: &str) -> Result<()> {
        // Verify the code
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time is before UNIX EPOCH")?
            .as_secs();

        if self.0.check(input_code, current_timestamp) {
            Ok(())
        } else {
            Err(anyhow!(
                "TOTP verification failed. Please check the code and system time."
            ))
        }
    }

    /// Generate One-Time-Password from the current system time
    pub fn generate(&self) -> Result<String> {
        Ok(self.0.generate_current()?)
    }
}
