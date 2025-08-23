// SPDX-License-Identifier: MIT OR Apache-2.0
//! Common functionality and utilities

use crate::{
    env::{
        Env, Params,
        constants::{
            CONF_CLIENT_IMA_LOG_FILE, CONF_CLIENT_JWT_AUTH_ROUTES,
            CONF_CLIENT_JWT_FILE, CONF_CLIENT_SECURED_PAYLOADS_STORE,
            CONF_CLIENT_TPM_LOG_FILE,
        },
    },
    log::*,
    server::dto::Response,
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose};
pub use hex::encode as hex_encode;
use nix::{
    fcntl::AT_FDCWD,
    sys::stat::{FchmodatFlags, Mode, fchmodat, stat},
    unistd::{Gid, Uid, User, chown, geteuid, setgid, setuid},
};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::{Hasher, MessageDigest},
    pkey::PKey,
    rand::rand_bytes,
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
            SubjectKeyIdentifier,
        },
    },
};
use reqwest::{ClientBuilder, Url, tls::TlsInfo};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    hash::Hash,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::{File, create_dir_all, read_to_string},
    io::AsyncReadExt,
};
use zeroize::Zeroizing;

/// Calculates the SHA1 hash of the given data.
fn calculate_sha1(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Hasher::new(MessageDigest::sha1())?;
    hasher.update(data)?;
    Ok(hasher.finish()?.to_vec())
}

/// Calculates the SHA256 hash of the given data.
pub fn calculate_sha256(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(data)?;
    Ok(hasher.finish()?.to_vec())
}

/// Calculates the SHA512 hash of the given data.
pub fn calculate_sha512(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Hasher::new(MessageDigest::sha512())?;
    hasher.update(data)?;
    Ok(hasher.finish()?.to_vec())
}

/// Reads the current executable's content SHA256 hash
pub async fn read_current_exe_sha256() -> Result<Vec<u8>> {
    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?;
    let mut file = File::open(&exe_path).await.with_context(|| {
        format!("Failed to open executable at {:?}", exe_path)
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await.with_context(|| {
        format!("Failed to read executable content from {:?}", exe_path)
    })?;
    Ok(calculate_sha256(&buffer)?)
}

/// Verifies the SHA1 fingerprint of a DER-encoded certificate against an expected fingerprint string.
/// The expected format is uppercase hex bytes separated by colons (e.g., "AB:CD:EF:...") as given by `openssl` tool
pub fn expect_fingerprint(
    cert_der: &[u8],
    expected_fingerprint_str: &str,
) -> Result<()> {
    let calculated_hash = calculate_sha1(cert_der)?;
    let calculated_fingerprint = calculated_hash
        .iter()
        .map(|byte| format!("{:02X}", byte)) // Format each byte as 2-digit uppercase hex
        .collect::<Vec<String>>()
        .join(":"); // Join with colons

    // Extract only hash
    let expected_fingerprint = expected_fingerprint_str
        .split("=")
        .last()
        .ok_or(anyhow!("Expected fingerprint is empty"))?;
    let expected_fingerprint = expected_fingerprint.to_string();

    // Compare (case-insensitive just to be safe, though openssl output is usually uppercase)
    if calculated_fingerprint.eq_ignore_ascii_case(expected_fingerprint.trim())
    {
        Ok(()) // Fingerprints match
    } else {
        Err(anyhow!(
            "Server certificate fingerprint mismatch! Expected: '{}', Calculated: '{}'",
            expected_fingerprint_str,
            calculated_fingerprint
        ))
    }
}

/// Execute server request with generic Request (Rq) and Response (Rs) data transfer objects
pub async fn server_request<Rq, Rs, P>(
    env: Arc<Env<P>>,
    route: &str,
    data: Option<Rq>,
) -> Result<Response<Rs>>
where
    Rq: Clone + Serialize,
    for<'de> Rs: Clone + Deserialize<'de>,
    P: Params,
{
    let server_url = env.get("server_url")?;
    let server_cert_fingerprint = env.try_get("server_cert_fingerprint")?;
    let mut server_insecure = env.get("server_insecure")?.parse::<bool>()?;

    let url = Url::parse(&server_url).context("Could not parse server_url")?;
    let url = url
        .join(route)
        .context("Could not join route with base URL")?;
    debug!("Requesting {}...", url);

    let mut client = ClientBuilder::new().timeout(Duration::from_secs(30));

    if !env.common_params.no_https {
        client = client.https_only(true);
        if url.scheme() == "http" {
            bail!(
                "Plain text attestation server URL configured but <no-https> flag is not provided. Plain text connection might expose boot logs to MiTM"
            );
        }
    } else if server_cert_fingerprint.is_some() {
        bail!(
            "<no-https> is enabled while server certificate fingerprint match enforced with <server_cert_fingerprint> option. Check configuration."
        )
    }

    if url.scheme() == "https" {
        client = client.tls_info(true);
    }

    if server_cert_fingerprint.is_some() {
        server_insecure = true;
    }

    if server_insecure {
        client = client.danger_accept_invalid_certs(true);
    }

    let client = client.build()?;

    // Authorization: Bearer header with JWT
    let mut auth_token = "".to_string();
    if CONF_CLIENT_JWT_AUTH_ROUTES.contains(&route) {
        let data_dir = env.get("data_dir")?;
        let auth_token_file = PathBuf::from(&data_dir)
            .join("identity")
            .join(CONF_CLIENT_JWT_FILE);
        auth_token = read_to_string(auth_token_file)
            .await
            .context("Could not read server authentication credentials")?;
    }

    let response = if let Some(data) = data {
        client
            .post(url.as_str())
            .bearer_auth(auth_token)
            .json(&data)
            .send()
            .await
            .context(format!(
                "Failed to send POST request to attestation server: {}",
                url.as_str()
            ))?
    } else {
        client
            .get(url.as_str())
            .bearer_auth(auth_token)
            .send()
            .await
            .context(format!(
                "Failed to send GET request to attestation server: {}",
                url.as_str()
            ))?
    };

    // Verify server TLS certificate fingerprint
    if let Some(fingerprint) = server_cert_fingerprint {
        if url.scheme() == "https" {
            debug!("Verifying sever certificate fingerprint ...");
            let peer_cert_der = response.extensions().get::<TlsInfo>().ok_or(anyhow!("Could not get TlsInfo from response"))?
                    .peer_certificate()
                    .ok_or(anyhow!("Could not get peer certificate from response (required for verification)"))?;
            expect_fingerprint(peer_cert_der, &fingerprint)?;
        }
    }

    if !response.status().is_success() {
        let status = response.status();
        bail!(
            "Attestation server request failed with HTTP status: {}",
            status
        );
    }

    Ok(response.json().await.context(
        "Could not deserialize HTTP server response into requested type",
    )?)
}

/// Generates random bytes
pub fn gen_bytes(size: usize) -> Result<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![0u8; size];
    rand_bytes(&mut buffer)?;
    Ok(buffer)
}

/// Generates base64-encoded secret of given byte size
pub fn gen_encoded_secret(size: usize) -> Result<String> {
    let secret = general_purpose::STANDARD.encode(&gen_bytes(size)?);
    Ok(secret)
}

/// Computes SHA256 HMAC value of given data with given HMAC key
pub fn hmac(
    key: &Zeroizing<Vec<u8>>,
    data: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut data = data.clone();
    data.extend_from_slice(b":");
    data.extend_from_slice(key);
    calculate_sha256(&data)
}

/// Generate self-signed certificate
pub fn generate_self_signed_cert() -> Result<(String, String)> {
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", "US")?;
    name_builder.append_entry_by_text("ST", "California")?;
    name_builder.append_entry_by_text("L", "San Francisco")?;
    name_builder.append_entry_by_text("O", "Paranoid")?;
    name_builder.append_entry_by_text("CN", "localhost")?;
    let name = name_builder.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?; // X509 v3

    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    builder.set_serial_number(serial.to_asn1_integer()?.as_ref())?;

    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;

    builder.set_pubkey(&pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?; // Valid 1 year
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    let basic_constraints = BasicConstraints::new().ca().pathlen(0).build()?;
    builder.append_extension(basic_constraints)?;

    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .key_cert_sign()
        .crl_sign()
        .build()?;
    builder.append_extension(key_usage)?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(auth_key_identifier)?;

    builder.sign(&pkey, MessageDigest::sha256())?;

    let certificate = builder.build();

    let key_pem =
        String::from_utf8_lossy(&pkey.private_key_to_pem_pkcs8()?).to_string();
    let cert_pem = String::from_utf8_lossy(&certificate.to_pem()?).to_string();

    Ok((key_pem, cert_pem))
}

/// Drops privileges having adjusted permissions for essential files first.
pub async fn privileges_adjust<P>(
    username: &str,
    env: Arc<Env<P>>,
) -> Result<()>
where
    P: Params,
{
    if !geteuid().is_root() {
        return Err(anyhow!("Not running as root"));
    }

    debug!("Adjusting permissions and dropping privileges ...");

    let target_user = User::from_name(username)
        .context(format!("Failed for user lookup: {}", username))?
        .ok_or(anyhow!("User {} does not exist", username))?;

    let target_uid = target_user.uid;
    let target_gid = target_user.gid;
    // To discard special and full permissions (ANDing 0o100644 with 0o000777 (permission_mask) results in 0o000644, cleaned permission mask)
    let clean_permissions_mask = Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO; // 0o777
    let target_mode_root_readonly = Mode::S_IRUSR | Mode::S_IRGRP; // 0o440
    let target_mode_user = Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP; // 0o640
    let target_mode_user_dir = Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP; // 0o750

    let data_dir = env.get("data_dir")?;

    if !PathBuf::from(&data_dir).exists() {
        create_dir_all(&data_dir).await.context(format!(
            "Failed to create data directory: {}",
            data_dir
        ))?;
    }

    // user-owned files
    for file_path in [data_dir.as_str()] {
        let file_stat = stat(file_path).context(format!(
            "Could not get metadata for file: {}",
            file_path
        ))?;

        let current_uid = Uid::from_raw(file_stat.st_uid);
        let current_gid = Gid::from_raw(file_stat.st_gid);

        // Check and set owner/group
        if current_uid != target_uid || current_gid != target_gid {
            chown(file_path, Some(target_uid), Some(target_gid)).context(
                format!(
                    "Could not change owner to {} of file: {}",
                    username, file_path
                ),
            )?;
        }

        let current_mode = Mode::from_bits_truncate(file_stat.st_mode)
            & clean_permissions_mask;

        if PathBuf::from(file_path).is_dir() {
            if current_mode != target_mode_user_dir {
                fchmodat(
                    AT_FDCWD,
                    &PathBuf::from(file_path),
                    target_mode_user_dir,
                    FchmodatFlags::FollowSymlink,
                )
                .context(format!(
                    "Could not change mode of file: {}",
                    file_path
                ))?;
            }
        } else {
            if current_mode != target_mode_user {
                fchmodat(
                    AT_FDCWD,
                    &PathBuf::from(file_path),
                    target_mode_user,
                    FchmodatFlags::FollowSymlink,
                )
                .context(format!(
                    "Could not change mode of file: {}",
                    file_path
                ))?;
            }
        };
    }

    let mut root_owned_files = vec![];
    if PathBuf::from(CONF_CLIENT_IMA_LOG_FILE).exists() {
        root_owned_files.push(CONF_CLIENT_IMA_LOG_FILE);
    }
    if PathBuf::from(CONF_CLIENT_TPM_LOG_FILE).exists() {
        root_owned_files.push(CONF_CLIENT_TPM_LOG_FILE);
    }

    for file_path in root_owned_files {
        let file_stat = stat(file_path).context(format!(
            "Could not get metadata for file: {}",
            file_path
        ))?;
        let current_mode = Mode::from_bits_truncate(file_stat.st_mode)
            & clean_permissions_mask;
        if current_mode != target_mode_root_readonly {
            fchmodat(
                AT_FDCWD,
                &PathBuf::from(file_path),
                target_mode_root_readonly,
                FchmodatFlags::FollowSymlink,
            )
            .context(format!("Could not change mode of file: {}", file_path))?;
        }
    }

    if !PathBuf::from(CONF_CLIENT_SECURED_PAYLOADS_STORE).exists() {
        create_dir_all(CONF_CLIENT_SECURED_PAYLOADS_STORE).await?;
    }
    chown(
        CONF_CLIENT_SECURED_PAYLOADS_STORE,
        Some(target_uid),
        Some(target_gid),
    )
    .context(format!(
        "Could not change owner to {} of file: {}",
        username, CONF_CLIENT_SECURED_PAYLOADS_STORE
    ))?;

    setgid(target_gid)
        .context(format!("Could not drop privileges to group: {}", username))?;
    setuid(target_uid)
        .context(format!("Could not drop privileges to user: {}", username))?;

    debug!("Dropped privileges to user: {}", username);

    Ok(())
}

/// Returns a new vector containing only the unique values from the input vector.
pub fn get_unique_values<T>(vec: &Vec<T>) -> Vec<T>
where
    T: Eq + Hash + Clone,
{
    let unique_set: HashSet<_> = vec.iter().cloned().collect();
    unique_set.into_iter().collect()
}

/// Normalizes a file name in the same way as the Linux kernel's IMA subsystem
/// for the 'ima-ng' template.
pub fn normalize_ima_ng_filename(filename: &String) -> String {
    let mut normalized = String::new();
    for c in filename.chars() {
        if c == '\\' {
            normalized.push_str("\\\\");
        } else if c < ' ' || c >= '\x7f' {
            normalized.push_str(&format!("\\{:03o}", c as u32));
        } else {
            normalized.push(c);
        }
    }
    normalized
}

/// Get current system Unix timestamp
pub fn timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    now.as_secs()
}

/// Compute system state hash
pub fn system_state_hash(
    ima_log: &str,
    ba: &str,
    pcr_digest: &[u8],
) -> Result<Vec<u8>> {
    let mut system_state = String::new();
    system_state.push_str(ima_log);
    system_state.push_str(ba);
    system_state.push_str(hex_encode(pcr_digest).as_str());
    calculate_sha256(system_state.as_bytes())
}
