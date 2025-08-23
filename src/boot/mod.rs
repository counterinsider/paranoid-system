// SPDX-License-Identifier: MIT OR Apache-2.0
//! `paranoid-boot` actions and helpers

use crate::server::dto::*;
use crate::tpm::Quote;
use crate::{
    boot::ima::*,
    common::*,
    env::{Env, ParamsIntegrtyBoot, constants::*},
    log::*,
    totp::TOTPInterface,
    tpm::Tpm,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use flate2::{Compression, write::GzEncoder};
use glob::glob;
use qrcode::{QrCode, render::unicode};
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    io::{Write, stdin, stdout},
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    fs::{
        self, File, create_dir, read_to_string, remove_dir_all, remove_file,
        rename,
    },
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
};
use tss_esapi::structures::Digest;
use zeroize::{Zeroize, Zeroizing};

pub mod ima;

#[cfg(test)]
mod tests;
#[cfg(test)]
use crate::env::GLOBAL_VAR_TOTP_GENERATOR;

// ---- actions

/// Enrolls new client
pub async fn enroll(env: Arc<Env<ParamsIntegrtyBoot>>) -> Result<()> {
    info!("Starting client enrollment process ...");
    let data_dir = PathBuf::from(&env.params.data_dir);
    let identity_dir = data_dir.join("identity");
    let payload_filenames_map_file_path =
        data_dir.join(CONF_CLIENT_SECURED_PAYLOAD_FILENAMES_MAP_FILE);

    fs::create_dir_all(&identity_dir).await.context(format!(
        "Failed to create {} directory",
        identity_dir.display()
    ))?;

    let ekpub_pem_path = identity_dir.join("ekpub.pem");
    let ek_cert_path = identity_dir.join("ek.crt");
    let ak_pem_path = identity_dir.join("ak.pem");
    let jwt_path = identity_dir.join(CONF_CLIENT_JWT_FILE);
    let uuid_path = identity_dir.join("uuid.dat");

    if ak_pem_path.exists() {
        let err_msg =
            "Existing AK found. Launch `cleanup` action first, then repeat";
        error!("{}", err_msg);
        bail!(err_msg);
    }

    // Initialize TPM state
    info!("Creating TPM keys ...");
    let mut tpm = Tpm::new()?;
    let ek = tpm.ek(None)?;
    let ek_cert = ek.cert_pem();
    let ek_pub = ek.pub_pem()?;
    let ak = tpm.ak_create(ek)?;
    let ak_pem = ak.to_pem()?;

    fs::write(&ak_pem_path, ak_pem.as_str())
        .await
        .context(format!(
            "Failed to save AK PEM to {}",
            ak_pem_path.display()
        ))?;
    fs::write(&ekpub_pem_path, &ek_pub).await.context(format!(
        "Failed to save EK Public Key PEM to {}",
        ekpub_pem_path.display()
    ))?;
    if let Some(ref ek_cert_pem) = ek_cert {
        fs::write(&ek_cert_path, ek_cert_pem)
            .await
            .context(format!(
                "Failed to save EK Cert to {}",
                ek_cert_path.display()
            ))?;
    }
    info!("TPM keys have been generated");

    if env.params.attest_remote {
        info!("Enrolling in attestation server ...");
        let q = RequestEnroll {
            ak: ak_pem,
            ek_pub,
            ek_cert,
        };
        let r: Response<ResponseEnroll> =
            server_request(env.clone(), "enroll", Some(q))
                .await
                .context("Failed to enroll in attestation server")?;
        ensure!(
            r.success,
            "Attestation server refused enrollment request. Error: {}",
            r.error.unwrap_or("unknown".to_string())
        );
        let data = r
            .data
            .ok_or(anyhow!("Attestation server returned no data"))?;

        if let Some(ref actions) = r.action_required {
            if actions.iter().any(|v| v == "totp_record_secret") {
                // TOTP secret provided
                // Display QR-code and secret itself
                // Ensure that user properly configured TOTP generator
                if data.totp_secret.is_none() {
                    bail!(
                        "Attestation server did not provide totp_secret while requesting such action"
                    );
                }
                let totp_secret = data.totp_secret.unwrap().clone();

                let totp = TOTPInterface::new(totp_secret.as_str())?;

                warn!(
                    "[x] Two-factor TOTP authentication required to interact with the attestation server."
                );
                warn!(
                    "[x] You can use any RFC-6238 compliant time-based one-time password generator (e.g. Google Authenticator)."
                );
                warn!(
                    "[x] Please, save the secret or scan QR-code with your chosen TOTP generator:"
                );
                let otp_uri = format!(
                    // TODO: include server name
                    "otpauth://totp/{}:enrollment?secret={}&issuer=AttestationServer",
                    data.uuid, totp_secret
                );
                let code = QrCode::new(otp_uri.as_bytes())?;
                let image = code
                    .render::<unicode::Dense1x2>()
                    .dark_color(unicode::Dense1x2::Dark)
                    .light_color(unicode::Dense1x2::Light)
                    .build();
                println!("{}", image);
                warn!("[x] TOTP SECRET: {}", totp_secret.as_str());
                warn!(
                    "[x] To complete enrollment you have to be authenticated with TOTP password now"
                );
                confirm_totp_secret(&totp)?;
                #[cfg(test)]
                {
                    GLOBAL_VAR_TOTP_GENERATOR.set(totp).map_err(|_| {
                        anyhow!("Could not set GLOBAL_VAR_TOTP_GENERATOR")
                    })?;
                }
            }
        }

        fs::write(&jwt_path, &data.jwt_token)
            .await
            .context(format!(
                "Failed to save server authentication credentials to {}",
                jwt_path.display()
            ))?;
        fs::write(&uuid_path, &data.uuid).await.context(format!(
            "Failed to save UUID to {}",
            uuid_path.display()
        ))?;
        if payload_filenames_map_file_path.exists() {
            remove_file(payload_filenames_map_file_path).await?;
        }
        info!("Successfully enrolled in attestation server");
        info!("The server assigned UUID is {}", data.uuid);
    }

    info!("Completed");
    Ok(())
}

/// Establishes new integrity baseline
pub async fn fix(env: Arc<Env<ParamsIntegrtyBoot>>) -> Result<()> {
    info!("Establishing new boot integrity baseline ...");
    let data_dir = PathBuf::from(&env.params.data_dir);
    let mut q = RequestPush::default();

    info!("Reading TPM (UEFI) log ...");

    #[cfg(not(test))]
    let tpm_log_path = CONF_CLIENT_TPM_LOG_FILE;
    #[cfg(test)]
    let tpm_log_path = "/tmp/binary_bios_measurements";

    let mut tpm_log_file = File::open(tpm_log_path)
        .await
        .context("Could not read tpm log kernel file")?;
    let mut tpm_log = Vec::new();
    tpm_log_file.read(&mut tpm_log).await?;
    let tpm_logs_dir = data_dir.join("tpm-logs");
    if !tpm_logs_dir.exists() {
        create_dir(&tpm_logs_dir).await?;
    }
    let tpm_logs_glob = format!("{}/*.bin.gz", tpm_logs_dir.display());

    // Rotate previous TPM logs and save current one
    if !env.params.attest_remote {
        let tpm_log_current = tpm_logs_dir.join("current.bin.gz");
        if tpm_log_current.exists() {
            let tpm_log_paths: Vec<_> = glob(tpm_logs_glob.as_str())
                .context(format!("Could not read by glob: {}", tpm_logs_glob))?
                .filter_map(Result::ok)
                .collect();
            let tpm_log_count = tpm_log_paths.len() - 1;
            rename(
                &tpm_log_current,
                tpm_logs_dir.join(format!("{}.bin.gz", tpm_log_count)),
            )
            .await?;

            if tpm_log_paths.len() + 1
                > env.common_params.max_system_states as usize
            {
                info!("[x] Rotating {} tpm logs ...", tpm_log_paths.len());
                // Rotating previous logs and deleting the oldest.
                for tpm_log_count in 0..tpm_log_paths.len() {
                    if tpm_log_count == 0 {
                        remove_file(
                            tpm_logs_dir
                                .join(format!("{}.bin.gz", tpm_log_count)),
                        )
                        .await?;
                    } else {
                        rename(
                            tpm_logs_dir
                                .join(format!("{}.bin.gz", tpm_log_count)),
                            tpm_logs_dir
                                .join(format!("{}.bin.gz", tpm_log_count - 1)),
                        )
                        .await?;
                    }
                }
            }
        }
        // TODO: encryption via TPM with make/activate credential functionality
        let output_file = std::fs::File::create(tpm_log_current)?;
        let mut encoder = GzEncoder::new(output_file, Compression::default());
        encoder.write_all(&tpm_log)?;
    }
    q.tpm_log = tpm_log;

    info!("Reading IMA log ...");
    let (ba, ima_log) = read_ima_log().await?;
    if !env.params.attest_remote {
        let mut output_file =
            File::create(data_dir.join("ima-log.dat")).await?;
        output_file.write_all(ima_log.as_bytes()).await?;
    }
    q.ba = collect_boot_aggregates(env.clone(), ba).await?;
    q.ima_log = ima_log;

    info!("Reading TPM restart count ...");
    let mut tpm = Tpm::new()?;
    let restart_count = tpm.restart_count(None)?;
    if !env.params.attest_remote {
        let mut output_file = File::create(data_dir.join("bc.dat")).await?;
        output_file
            .write_all(restart_count.to_string().as_bytes())
            .await?;
    }
    q.bc = restart_count;

    let pcr_selection = Tpm::pcr_selection_from_str(&env.params.pcr_selection)
        .context(format!(
            "Could not parse PCR selection --pcr-selection option: {}",
            env.params.pcr_selection
        ))?;
    info!("Reading TPM PCRs ...");
    q.pcr_digest = tpm.pcr_digest(&pcr_selection)?.value().into();

    q.system_state_hash = system_state_hash(&q.ima_log, &q.ba, &q.pcr_digest)?;

    info!("Computed system state hash");

    info!("TPM policy enforcement ...");
    let tpm_policy_dir = data_dir.join("tpm-policy");
    if !tpm_policy_dir.exists() {
        create_dir(&tpm_policy_dir).await?;
    }
    let policy: Vec<u8> = tpm.policy(pcr_selection)?.value().into();
    let policies = tpm_policies(&tpm_policy_dir, Some(policy)).await?;

    let hmac_key = Zeroizing::new(gen_bytes(128)?);
    let mut policy_count: u32 = 0;
    for policy in policies {
        let policy = Digest::try_from(policy.as_slice()).map_err(|e| {
            anyhow!("Invalid policy value ({}): {}", hex_encode(&policy), e)
        })?;
        tpm.seal(
            &hmac_key,
            CONF_TPM_HMAC_KEY_PERSISTENT_HANDLE_START + policy_count,
            policy,
        )
        .map_err(|e| anyhow!("Could not seal HMAC key: {}", e))?;
        policy_count += 1;
    }
    info!("Sealed HMAC key with the policies authorization requirement");
    info!("Saving system state hash and boot counter HMAC ...");
    let system_state_hash_hmac =
        hmac(&hmac_key, Zeroizing::new(q.system_state_hash.clone()))?;
    let mut system_state_hash_hmac_file =
        File::create(data_dir.join("state.hmac.dat")).await?;
    system_state_hash_hmac_file
        .write_all(&system_state_hash_hmac)
        .await?;

    let bc_hmac = hmac(
        &hmac_key,
        Zeroizing::new(q.bc.to_string().as_bytes().to_vec()),
    )?;
    let mut bc_hmac_file = File::create(data_dir.join("bc.hmac.dat")).await?;
    bc_hmac_file.write_all(&bc_hmac).await?;

    /* TODO:
     * compound policy (TPM policyor)
     * save `bc` onto TPM persistent handle
     * save compound policy value SHA256 hash or concatenated policy values SHA256 hash onto TPM persistent handle.
     * consider this data encryption in TPM with make/activate credential functionality
     */

    if env.params.attest_remote {
        info!("Pushing new integrity baseline to attestation server ...");
        let r: Response<ResponsePush> =
            server_request(env.clone(), "push", Some(q)).await.context(
                "Failed to push new integrity baseline to attestation server",
            )?;
        ensure!(
            r.success,
            "Attestation server refused push request. Error: {}",
            r.error.unwrap_or("unknown".to_string())
        );
        let data = r
            .data
            .ok_or(anyhow!("Attestation server returned no data"))?;

        // Multi-factor auth and secured payloads upload
        let mut q = RequestPushComplete::default();
        q.baseline_nonce = data.baseline_nonce;
        let (payloads, payload_filenames_map) =
            read_and_encrypt_payloads(env.clone()).await?;
        if let Some(ref actions) = r.action_required {
            if actions.iter().any(|v| v == "totp_auth") {
                if data.session_nonce.is_none() {
                    bail!(
                        "Attestation server did not provide session_nonce while requesting action"
                    );
                }
                q.session_nonce = data.session_nonce;
            }
        }

        if q.session_nonce.is_some() || payloads.len() > 0 {
            if payloads.len() > 0 {
                info!("Uploading {} secured payloads ...", payloads.len());
                q.payloads = Some(payloads);
            }
            if q.session_nonce.is_some() {
                auth_2fa(async |input_code| {
                    q.totp = Some(input_code);
                    let r: Response<ResponsePushComplete> = server_request(
                        env.clone(),
                        "push/complete",
                        Some(q.clone()),
                    )
                    .await
                    .context("Failed to complete push request")?;
                    ensure!(
                        r.success,
                        "Attestation server refused to complete push request. Error: {}",
                        r.error.unwrap_or("unknown".to_string())
                    );
                    let data = r.data.ok_or(anyhow!(
                        "Attestation server returned no data"
                    ))?;
                    if let Some(ref actions) = r.action_required {
                        if actions.iter().any(|v| v == "totp_auth") {
                            if data.session_nonce.is_none() {
                                bail!(
                                    "Attestation server did not provide session_nonce while requesting action"
                                );
                            }
                            q.session_nonce = data.session_nonce;
                            return Err(anyhow!("Incorrect TOTP code! Try again"));
                        }
                    }

                    Ok(())
                }).await?;

                info!("Completed two-factor authentication");
                if q.payloads.is_some() {
                    info!("Uploaded secured payloads");
                }
            } else if q.payloads.is_some() {
                // Only uploading payloads
                let r: Response<ResponsePushComplete> = server_request(
                    env.clone(),
                    "push/complete",
                    Some(q.clone()),
                )
                .await
                .context("Failed to complete push request")?;
                ensure!(
                    r.success,
                    "Attestation server refused to complete push request. Error: {}",
                    r.error.unwrap_or("unknown".to_string())
                );
                info!("Uploaded secured payloads");
            }

            if q.payloads.is_some() {
                let payload_filenames_map_path = data_dir
                    .join(CONF_CLIENT_SECURED_PAYLOAD_FILENAMES_MAP_FILE);
                let mut payload_filenames_map_file =
                    File::create(payload_filenames_map_path).await?;
                payload_filenames_map_file
                    .write_all(payload_filenames_map.as_bytes())
                    .await?;
            }
        }
    }

    info!("Integrity baseline has been established");

    Ok(())
}

/// Asserts system launch state against previously established integrity baselines
pub async fn attest(env: Arc<Env<ParamsIntegrtyBoot>>) -> Result<()> {
    info!(
        "Begin system launch integrity assertion against previosly established integrity baselines..."
    );

    let data_dir = PathBuf::from(&env.params.data_dir);
    let mut q = RequestAttest::default();

    info!("Reading TPM (UEFI) log ...");

    #[cfg(not(test))]
    let tpm_log_path = CONF_CLIENT_TPM_LOG_FILE;
    #[cfg(test)]
    let tpm_log_path = "/tmp/binary_bios_measurements";

    let mut tpm_log_file = File::open(tpm_log_path).await.context(format!(
        "Could not read tpm log file: {}",
        CONF_CLIENT_TPM_LOG_FILE
    ))?;
    let mut tpm_log = Vec::new();
    tpm_log_file.read(&mut tpm_log).await?;

    info!("Reading IMA log ...");
    let (ba, ima_log) = read_ima_log().await?;
    q.ba = collect_boot_aggregates(env.clone(), ba).await?;
    q.ima_log = ima_log;

    info!("Connecting to TPM...");
    let mut tpm = Tpm::new()?;
    let (ak_handle, _) = tpm.ak_load().context("Could not load AK")?;
    if !env.params.attest_remote {
        info!("Reading TPM restart count ...");
        // Otherwise, aquire boot counter from quote
        q.bc = tpm.restart_count(Some(ak_handle))?;
    }

    let pcr_selection = Tpm::pcr_selection_from_str(&env.params.pcr_selection)
        .context(format!(
            "Could not parse PCR selection --pcr-selection option: {}",
            env.params.pcr_selection
        ))?;

    info!("Reading TPM PCRs ...");
    let pcr_digest: Vec<u8> = tpm.pcr_digest(&pcr_selection)?.value().into();

    info!("Begin local attestation...");
    let tpm_policy_dir = data_dir.join("tpm-policy");
    let policies = tpm_policies(&tpm_policy_dir, None).await?;
    debug!(
        "Trying unseal with {} authorization policies ...",
        policies.len()
    );

    let mut hmac_key: Option<Zeroizing<Vec<u8>>> = None;
    let local_assertion_err_msg =
        "HMAC key unsealing failed! The machine is in unexpected state!";
    for policy_count in 0..policies.len() as u32 {
        if let Ok(hmac_key_data) = tpm.unseal(
            CONF_TPM_HMAC_KEY_PERSISTENT_HANDLE_START + policy_count,
            pcr_selection.clone(),
        ) {
            hmac_key =
                Some(Zeroizing::new(Vec::from(hmac_key_data.as_slice())));
            debug!("Unsealed HMAC key with policy {}", policy_count);
            break;
        }
    }

    let current_system_state_hash =
        system_state_hash(&q.ima_log, &q.ba, &pcr_digest)?;
    info!("Computed current system state hash");

    let mut serv_bc_diff = 0;
    if env.params.attest_remote {
        info!("Opening remote attestation session ...");
        let r: Response<ResponseAttestNonce> =
            server_request(env.clone(), "attest/nonce", None::<RequestEmpty>)
                .await
                .context(
                    "Failed to request attestation server for opening attestation session",
                )?;
        ensure!(
            r.success,
            "Attestation server refused opening attestation session. Error: {}",
            r.error.unwrap_or("unknown".to_string())
        );
        let data = r
            .data
            .ok_or(anyhow!("Attestation server returned no data"))?;

        // Now it is time for issuing TPM quote, before HMAC key unsealing assertion.
        // Remote attestation is executed regardless of local success
        if hmac_key.is_none() {
            warn!("{}", local_assertion_err_msg);
        }

        info!("Issuing TPM quote ...");
        let mut qualifying_data = data.nonce.as_bytes().to_owned();
        qualifying_data.extend_from_slice(&current_system_state_hash);
        let qualifying_data = calculate_sha256(&qualifying_data)?;

        q.quote = tpm
            .quote(&qualifying_data, pcr_selection.clone(), ak_handle)?
            .marshall()?;
        let quote = Quote::unmarshall(&q.quote)?;
        q.bc = quote.att.clock_info().reset_count();

        info!("Remote attestation started ...");
        let r: Response<ResponseAttest> =
            server_request(env.clone(), "attest", Some(q.clone()))
                .await
                .context("Remote attestation request failed")?;
        // TODO: notify user with detailed error message as it contains attestation failure description
        ensure!(
            r.success,
            "Remote attestation failed. Error: {}",
            r.error.unwrap_or("unknown".to_string())
        );
        let data = r
            .data
            .ok_or(anyhow!("Attestation server returned no data"))?;

        serv_bc_diff = data.bc_diff;

        info!("Remote attestation completed successfully");

        if let Some(ref actions) = r.action_required {
            if actions.iter().any(|v| v == "download_payloads") {
                info!("Downloading secured payloads ...");
                let mut payloads: Option<Vec<Vec<u8>>> = None;
                let mut qc = RequestAttestComplete::default();
                qc.session_nonce = data.session_nonce;

                if actions.iter().any(|v| v == "totp_auth") {
                    auth_2fa(async |input_code| {
                        qc.totp = Some(input_code);
                        let r: Response<ResponseAttestComplete> = server_request(
                            env.clone(),
                            "attest/complete",
                            Some(qc.clone()),
                        ).await.context("Failed to complete push request")?;
                        ensure!(
                            r.success,
                            "Attestation server refused to complete attestation request. Error: {}",
                            r.error.unwrap_or("unknown".to_string())
                        );

                        let data = r.data.ok_or(anyhow!(
                            "Attestation server returned no data"
                        ))?;

                        if let Some(ref actions) = r.action_required {
                            if actions.iter().any(|v| v == "totp_auth") {
                                if data.session_nonce.is_none() {
                                    bail!(
                                        "Attestation server did not provide session_nonce while requesting action"
                                    );
                                }
                                qc.session_nonce = data.session_nonce;
                                bail!("Incorrect TOTP code! Try again");
                            }
                        }

                        payloads = data.payloads;

                        Ok(())
                    }).await?;
                } else {
                    let r: Response<ResponseAttestComplete> = server_request(
                        env.clone(),
                        "attest/complete",
                        Some(qc.clone()),
                    )
                    .await
                    .context("Failed to complete push request")?;
                    ensure!(
                        r.success,
                        "Attestation server refused to complete attestation request. Error: {}",
                        r.error.unwrap_or("unknown".to_string())
                    );
                    let data = r.data.ok_or(anyhow!(
                        "Attestation server returned no data"
                    ))?;

                    payloads = data.payloads;
                }

                if payloads.is_none() {
                    bail!("Attestation server did not return any payloads");
                }

                let payloads_num = payloads.as_ref().unwrap().len();
                save_and_decrypt_payloads(env.clone(), payloads.unwrap())
                    .await?;
                info!(
                    "Saved {} payloads in memory-backed filesystem folder: {}",
                    payloads_num, CONF_CLIENT_SECURED_PAYLOADS_STORE
                );
            }
        }
    }

    if hmac_key.is_none() {
        if env.params.attest_remote {
            // Unreachable, except if
            let err_msg = "Remote attestation succeded, but local attestation did not. Ensure, remote attestation server is not compromised";
            error!("{}", err_msg);
            bail!(err_msg);
        } else {
            error!("{}", local_assertion_err_msg);
        }

        describe_assertion_failure(
            env.clone(),
            &q.tpm_log,
            &q.ima_log,
            &q.ba,
            q.bc,
        )
        .await?;
        bail!(local_assertion_err_msg);
    }
    let hmac_key = hmac_key.unwrap();

    let current_system_state_hash_hmac =
        hmac(&hmac_key, Zeroizing::new(current_system_state_hash.clone()))?;
    let mut system_state_hash_hmac_file =
        File::open(data_dir.join("state.hmac.dat")).await?;
    let mut system_state_hash_hmac = vec![];
    system_state_hash_hmac_file
        .read_to_end(&mut system_state_hash_hmac)
        .await?;
    if current_system_state_hash_hmac != system_state_hash_hmac {
        let common_err_msg = "Local attestation failed! System state hash mismatch! Integrity has been compromised!";
        error!("{}", common_err_msg);
        describe_assertion_failure(
            env.clone(),
            &q.tpm_log,
            &q.ima_log,
            &q.ba,
            q.bc,
        )
        .await?;
        return Err(anyhow!(common_err_msg));
    }
    info!("Local attestation completed successfully");

    let current_bc_hmac = hmac(
        &hmac_key,
        Zeroizing::new(q.bc.to_string().as_bytes().to_vec()),
    )?;
    let bc_hmac_file_path = data_dir.join("bc.hmac.dat");
    let mut bc_hmac_file = File::open(&bc_hmac_file_path).await?;
    let mut bc_hmac = vec![];
    bc_hmac_file.read_to_end(&mut bc_hmac).await?;

    if current_bc_hmac != bc_hmac || serv_bc_diff > 1 {
        let bc_diff = if !env.params.attest_remote {
            let mut bc_file = File::open(data_dir.join("bc.dat")).await?;
            let mut prev_bc = String::new();
            bc_file.read_to_string(&mut prev_bc).await?;
            let prev_bc = prev_bc.parse::<u32>().unwrap_or(0);
            q.bc.saturating_sub(prev_bc)
        } else {
            serv_bc_diff
        };
        if bc_diff > 1 {
            warn!(
                "[x] Machine has been powered on besides normal boot {} times",
                bc_diff - 1
            );
        }
        // TODO: desktop notification that machine has been powered on besides normal boot.
    }

    if !env.params.attest_remote {
        let mut bc_file = File::create(data_dir.join("bc.dat")).await?;
        bc_file.write_all(&q.bc.to_string().as_bytes()).await?;
    }
    let mut bc_hmac_file =
        File::create(data_dir.join(&bc_hmac_file_path)).await?;
    bc_hmac_file.write_all(&current_bc_hmac).await?;

    info!("Completed attestation");

    Ok(())
}

/// Cleanup client data
pub async fn cleanup(env: Arc<Env<ParamsIntegrtyBoot>>) -> Result<()> {
    info!("Cleaning up client data directories ...");
    let data_dir = PathBuf::from(&env.params.data_dir);
    let payloads_store = PathBuf::from(CONF_CLIENT_SECURED_PAYLOADS_STORE);
    if data_dir.exists() {
        remove_dir_all(&data_dir).await?;
    }
    if payloads_store.exists() {
        remove_dir_all(&payloads_store).await?;
    }
    info!("Completed. You can enroll in attestation server again");
    Ok(())
}

// ---- End actions

/// Read and save TPM policies
async fn tpm_policies(
    tpm_policy_dir: &PathBuf,
    current_policy: Option<Vec<u8>>,
) -> Result<Vec<Vec<u8>>> {
    // TODO: assess necessity to keep policy digests on disk
    let mut policies = Vec::<Vec<u8>>::new();
    let tpm_policy_glob = format!("{}/*.policy.dat", tpm_policy_dir.display());
    let tpm_policy_paths: Vec<PathBuf> = glob(tpm_policy_glob.as_str())
        .context(format!("Could not read by glob: {}", tpm_policy_glob))?
        .filter_map(Result::ok)
        .collect();

    for policy_path in tpm_policy_paths {
        let mut policy_file = File::open(policy_path).await?;
        let mut policy_value = vec![];
        policy_file.read_to_end(&mut policy_value).await?;
        policies.push(policy_value);
    }
    if let Some(policy) = current_policy {
        if !policies.iter().any(|v| v == &policy) {
            let policy_path =
                tpm_policy_dir.join(format!("{}.policy.dat", timestamp()));
            let mut policy_file = File::create(policy_path).await?;
            policy_file.write_all(&policy).await?;
            policies.push(policy);
            info!("Added new TPM policy");
        }
    }
    // ensure order
    policies.sort();
    Ok(policies)
}

/// Wait until user provided correct TOTP in terminal
fn confirm_totp_secret(totp: &TOTPInterface) -> Result<()> {
    let totp_regex = Regex::new(r"^[0-9]{6}$")?;
    loop {
        print!("[x] Enter 6-digit code: ");
        stdout().flush()?;
        let mut input_code = String::new();
        if cfg!(test) {
            input_code = totp.generate()?;
            println!("{}", &input_code);
        } else {
            let _ = stdin()
                .read_line(&mut input_code)
                .context("Failed to read TOTP")?;
        }
        input_code = input_code.trim().into();
        if !totp_regex.is_match(&input_code) {
            warn!("[x] Invalid input. Try again");
            continue;
        }
        if totp.auth(&input_code).is_err() {
            warn!("[x] Provided code is incorrect. Try again");
            trace!("Correct code is: {}", totp.generate()?);
            continue;
        }
        break;
    }
    info!("Two-factor authentication completed successfully");

    Ok(())
}

/// Execute two-factor authentication, asking user to provide TOTP.
/// Callback must be provided, which completes authentication.
async fn auth_2fa<F>(mut callback: F) -> Result<()>
where
    F: AsyncFnMut(String) -> Result<()>,
{
    warn!("[x] Two-factor TOTP authentication required");
    let totp_regex = Regex::new(r"^[0-9]{6}$")?;
    loop {
        // Trying until valid TOTP provided
        print!("[x] Enter 6-digit code: ");
        stdout().flush()?;
        #[allow(unused_assignments)]
        let mut input_code = String::new();
        #[cfg(test)]
        {
            let totp = GLOBAL_VAR_TOTP_GENERATOR
                .get()
                .ok_or(anyhow!("Could not get GLOBAL_VAR_TOTP_GENERATOR"))?;
            input_code = totp.generate()?;
            println!("{}", &input_code);
        }
        #[cfg(not(test))]
        {
            let _ = stdin()
                .read_line(&mut input_code)
                .context("Failed to read TOTP")?;
        }
        input_code = input_code.trim().into();
        if !totp_regex.is_match(&input_code) {
            warn!("[x] Invalid input. Try again");
            continue;
        }

        if let Err(e) = callback(input_code.into()).await {
            warn!("[x] {}", e);
            continue;
        }

        break;
    }

    Ok(())
}

/// Read secured payloads, but ensures that it is first upload. Then encrypts them.
async fn read_and_encrypt_payloads(
    env: Arc<Env<ParamsIntegrtyBoot>>,
) -> Result<(Vec<Vec<u8>>, String)> {
    let data_dir = PathBuf::from(&env.params.data_dir);
    let payload_filenames_map_file =
        data_dir.join(CONF_CLIENT_SECURED_PAYLOAD_FILENAMES_MAP_FILE);
    let uuid_path = data_dir.join("identity/uuid.dat");
    let client_uuid = read_to_string(uuid_path)
        .await
        .context("Could not read UUID from disk")?;

    let mut payloads = vec![];
    let mut payload_filenames_map = String::new();
    if !payload_filenames_map_file.exists() {
        let mut payload_names = HashSet::<String>::new();
        if let Some(ref payload_paths) = env.params.secured_payloads {
            for p in payload_paths {
                let p = PathBuf::from(p);
                let p_basename = p
                    .as_path()
                    .file_name()
                    .ok_or_else(|| OsStr::new(""))
                    .map_err(|e| anyhow!("Could not get basename: {:?}", e))?
                    .to_string_lossy()
                    .to_string()
                    .replace(":", "");
                if !payload_names.insert(p_basename.clone()) {
                    warn!(
                        "Non-unique names encountered in provided secured payload list: {}",
                        payload_paths.join(", ")
                    );
                    warn!("Skipping file: {}", p_basename);
                    continue;
                }
                let mut payload = Vec::<u8>::new();
                let mut payload_file = File::open(&p).await.context(
                    format!("Payload {} is inaccessible", p.display()),
                )?;
                payload_file.read_to_end(&mut payload).await?;

                /*
                 * TODO: payload encryption
                 * With TPM MakeCredential or symmetric key provided in configuration option
                 */

                let mut hash_filename_data = client_uuid.as_bytes().to_owned();
                hash_filename_data.extend_from_slice(&payload);
                let hash_filename =
                    hex_encode(&calculate_sha512(&hash_filename_data)?);
                payload_filenames_map.push_str(&p_basename);
                payload_filenames_map.push_str(":");
                payload_filenames_map.push_str(&hash_filename);
                payload_filenames_map.push_str("\n");

                payloads.push(payload);
            }
        }
    }

    Ok((payloads, payload_filenames_map))
}

/// Save payloads in memory-backed filesystem and check their integrity
async fn save_and_decrypt_payloads(
    env: Arc<Env<ParamsIntegrtyBoot>>,
    payloads: Vec<Vec<u8>>,
) -> Result<()> {
    #[cfg(not(test))]
    let store_dir = PathBuf::from(CONF_CLIENT_SECURED_PAYLOADS_STORE);
    #[cfg(test)]
    let store_dir = PathBuf::from(&env.params.data_dir).join("saved-payloads");
    if !store_dir.exists() {
        bail!("{} was not created", CONF_CLIENT_SECURED_PAYLOADS_STORE);
    }
    let data_dir = PathBuf::from(&env.params.data_dir);
    let payload_filenames_map_file_path =
        data_dir.join(CONF_CLIENT_SECURED_PAYLOAD_FILENAMES_MAP_FILE);
    let uuid_path = data_dir.join("identity/uuid.dat");
    let client_uuid = read_to_string(uuid_path)
        .await
        .context("Could not read UUID from disk")?;
    let mut filenames_map_lines =
        BufReader::new(File::open(payload_filenames_map_file_path).await?)
            .lines();
    let mut filenames_map = HashMap::new();
    while let Some(map_row) = filenames_map_lines.next_line().await? {
        let s = map_row.split(":");
        if let Some(hash) = s.clone().nth(1) {
            if let Some(name) = s.clone().nth(0) {
                filenames_map.insert(hash.to_string(), name.to_string());
            } else {
                warn!(
                    "Could not read payload filenames map row: {}. Skipping",
                    &map_row[0..20]
                );
            }
        } else {
            warn!(
                "Could not read payload filenames map row: {}. Skipping",
                &map_row[0..20]
            );
        }
    }

    for mut payload in payloads.into_iter() {
        let mut hash_filename_data = client_uuid.as_bytes().to_owned();
        hash_filename_data.extend_from_slice(&payload);
        let hash = hex_encode(&calculate_sha512(&hash_filename_data)?);
        if let Some(name) = filenames_map.get(&hash) {
            let mut payload_file =
                File::create(store_dir.join(name)).await.context(format!(
                    "Could not open payload file {} for writing",
                    name
                ))?;
            payload_file.write_all(&payload).await?;
        } else {
            warn!("Server returned some unknown payload. Skipping");
        }
        payload.zeroize();
    }

    Ok(())
}

/// Gives details on integrity assertion failure
async fn describe_assertion_failure(
    _env: Arc<Env<ParamsIntegrtyBoot>>,
    _current_tpm_log: &Vec<u8>,
    _current_ima_log: &str,
    _current_collected_ba: &str,
    _current_bc: u32,
) -> Result<()> {
    // TODO: more information on why the integrity has been compromised using difference
    // for tpm_log, ima_log, boot_aggregate and considering seal-glob option
    Ok(())
}
