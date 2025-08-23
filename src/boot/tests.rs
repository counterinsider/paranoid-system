// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unit tests for integrity-boot, integrity-srv binaries

use super::tpm_policies;
use crate::{
    boot::{attest, enroll, fix},
    common::{gen_encoded_secret, normalize_ima_ng_filename, timestamp},
    env::{
        Env, GLOBAL_VAR_IMA_EXTENDED_LOG_2, Params, ParamsIntegrtyBoot,
        ParamsIntegrtySrv,
    },
    server::launcher::server_launch,
};
use anyhow::Result;
use clap::CommandFactory;
use config::Config;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tempfile::{TempDir, tempdir};
use tokio::{
    fs::{self, File, OpenOptions, create_dir_all},
    io::AsyncWriteExt,
    task::spawn,
    time::sleep,
};

// --- Begin Tests

#[tokio::test]
async fn test_tpm_policies() {
    let temp_dir = tempdir().unwrap();
    let tpm_policy_dir = temp_dir.path().to_path_buf();
    let p1 = vec![0x01, 0x02, 0x03];
    let p2 = vec![0x00, 0x00, 0x00];
    let p3 = vec![0x04, 0x05, 0x06];
    let policies = tpm_policies(&tpm_policy_dir, None)
        .await
        .expect("Could not invoke tpm_policies under mock environment");
    assert!(policies.is_empty(), "Empty policies assertion failed!");

    let policies = tpm_policies(&tpm_policy_dir, Some(p1)).await.unwrap();
    assert!(policies.len() == 1);

    fs::write(
        tpm_policy_dir.join(format!("{}.policy.dat", timestamp() + 111)),
        &p2,
    )
    .await
    .unwrap();

    let policies = tpm_policies(&tpm_policy_dir, Some(p2)).await.unwrap();
    assert!(policies.len() == 2);

    sleep(Duration::from_secs(1)).await;
    let policies = tpm_policies(&tpm_policy_dir, Some(p3))
        .await
        .expect("Could not invoke tpm_policies under mock environment");
    assert!(policies.len() == 3);
}

#[tokio::test]
async fn test_actions_routes_all() {
    // Testing all routes in sequence, so in single test

    println!("##############################");
    println!(
        "# Testing with attestation server but without two-factor auth and payloads ..."
    );
    println!("##############################");

    // 1. Setup: mock server and client environment
    // Environment variant: remote attestation without two-factor auth and payloads (remote)
    let data_dir_server = tempdir().unwrap();
    let conf_dir_server = tempdir().unwrap();
    let data_dir_client = tempdir().unwrap();
    let conf_dir_client = tempdir().unwrap();
    let (env_client, env_server) = mock_environemt(
        &data_dir_server,
        &conf_dir_server,
        &data_dir_client,
        &conf_dir_client,
        "remote",
    )
    .await
    .unwrap();

    // 2. (remote): Launch server
    spawn(async move {
        server_launch(env_server)
            .await
            .expect("Could not launch server");
    });
    sleep(Duration::from_secs(2)).await;

    // 3. (remote): Test `enroll` route
    enroll(env_client.clone())
        .await
        .expect("Could not enroll in attestation server");

    // 4. (remote) Test `fix` route
    mock_ima_and_tpm_eventlog().await.unwrap();
    fix(env_client.clone())
        .await
        .expect("Could not establish integrity baseline");

    // 5. (remote) Test `attest` route
    attest(env_client.clone())
        .await
        .expect("Could not attest against established integrity baseline");

    println!("##############################");
    println!("# Testing without attestation server ...");
    println!("##############################");

    // Environment variant: without remote attestation (local)
    let data_dir_server = tempdir().unwrap();
    let conf_dir_server = tempdir().unwrap();
    let data_dir_client = tempdir().unwrap();
    let conf_dir_client = tempdir().unwrap();
    let (env_client, _) = mock_environemt(
        &data_dir_server,
        &conf_dir_server,
        &data_dir_client,
        &conf_dir_client,
        "local",
    )
    .await
    .unwrap();

    // 6. (local): Test `enroll` route
    enroll(env_client.clone())
        .await
        .expect("Could not enroll in attestation server");

    // 7. (local): Test `fix` route
    fix(env_client.clone())
        .await
        .expect("Could not establish integrity baseline");

    // 8. (local) Test `attest` route
    attest(env_client.clone())
        .await
        .expect("Could not attest against established integrity baseline");

    println!("##############################");
    println!(
        "# Testing with attestation server, with two-factor auth and payloads ..."
    );
    println!("##############################");

    // Environment variant: with attestation server, with two-factor auth and payloads (remote_full)
    let data_dir_server = tempdir().unwrap();
    let conf_dir_server = tempdir().unwrap();
    let data_dir_client = tempdir().unwrap();
    let conf_dir_client = tempdir().unwrap();
    let (env_client, env_server) = mock_environemt(
        &data_dir_server,
        &conf_dir_server,
        &data_dir_client,
        &conf_dir_client,
        "remote_full",
    )
    .await
    .unwrap();

    // 9. (remote_full): Launch server
    spawn(async move {
        server_launch(env_server)
            .await
            .expect("Could not launch server");
    });
    sleep(Duration::from_secs(2)).await;

    // 10. (remote_full): Test `enroll` route
    enroll(env_client.clone())
        .await
        .expect("Could not enroll in attestation server");

    // 11. (remote_full): Test `fix` route
    fix(env_client.clone())
        .await
        .expect("Could not establish integrity baseline");

    // 12. (remote_full) Test `attest` route
    attest(env_client.clone())
        .await
        .expect("Could not attest against established integrity baseline");
}

// --- Test helpers

async fn create_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).await?;
    }
    let mut file = File::create(path).await?;
    file.write_all(content.as_bytes()).await?;
    Ok(())
}

async fn mock_ima_and_tpm_eventlog() -> Result<()> {
    let ima_log_path = "/tmp/ascii_runtime_measurements_sha256";
    let tpm_log_path = PathBuf::from("/tmp/binary_bios_measurements");

    // just touch ima_log_path as it created in test_read_ima_log, then wait for test_read_ima_log completion
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(ima_log_path)
        .await?;
    drop(file);
    sleep(Duration::from_secs(1)).await;

    // ensure mock ima log written and GLOBAL_VAR_IMA_EXTENDED_LOG_2 is set (in case if test_read_ima_log is not launched)
    if GLOBAL_VAR_IMA_EXTENDED_LOG_2.get().is_none() {
        let test_ima_log_location =
            "/tmp/ascii_runtime_measurements_sha256".to_string();

        let ima_log_content = "\
            10 any ima-ng sha256:37406d190e1257cb5b61c7789ba3718599b9045d16698412bd191cd0348c452d boot_aggregate\n\
            10 any ima-ng sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /path/to/whitelisted/file1\n\
            10 any ima-ng sha256:0000000000000000000000000000000000000000000000000000000000000000 /path/to/another/file\n\
            10 any ima-ng sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 /path/to/whitelisted/file2\n\
            10 any ima-ng sha256:b5a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 /path/to/non/whitelisted/file\n\
            10 any unknown-template sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef /path/to/unknown/template\n\
        ";

        let mut file = File::create(&test_ima_log_location).await.unwrap();
        file.write_all(ima_log_content.as_bytes()).await.unwrap();
        file.sync_data().await.unwrap();

        let mut whitelisted_set = Vec::new();
        whitelisted_set.push(normalize_ima_ng_filename(
            &"/path/to/whitelisted/file1".to_string(),
        ));
        whitelisted_set.push(normalize_ima_ng_filename(
            &"/path/to/whitelisted/file2".to_string(),
        ));
        whitelisted_set.push(normalize_ima_ng_filename(
            &"/path/to/another/file".to_string(),
        ));
        whitelisted_set.push(normalize_ima_ng_filename(
            &"/path/to/unknown/template".to_string(),
        ));
        GLOBAL_VAR_IMA_EXTENDED_LOG_2
            .set(whitelisted_set)
            .expect("Failed to set GLOBAL_VAR_IMA_EXTENDED_LOG");
    }

    create_file(&tpm_log_path, "").await?;

    Ok(())
}

// Mock environment
async fn mock_environemt(
    data_dir_server: &TempDir,
    conf_dir_server: &TempDir,
    data_dir_client: &TempDir,
    conf_dir_client: &TempDir,
    variant: &str,
) -> Result<(Arc<Env<ParamsIntegrtyBoot>>, Arc<Env<ParamsIntegrtySrv>>)> {
    let conf_file_server =
        conf_dir_server.path().to_path_buf().join("config.toml");
    create_file(&conf_file_server, "").await.unwrap();

    let payload_store_dir =
        data_dir_client.path().to_path_buf().join("saved-payloads");
    if !payload_store_dir.exists() {
        create_dir_all(payload_store_dir).await?;
    }

    let mut env_server = ParamsIntegrtySrv::new().unwrap();
    if variant != "local" {
        env_server.common_params.config_file = conf_file_server;
        env_server.params.data_dir = data_dir_server
            .path()
            .to_path_buf()
            .to_string_lossy()
            .to_string();
        env_server.params.address = "127.0.0.1".into();
        env_server.params.port = 8443;
        if variant == "remote_full" {
            env_server.params.port = 8444;
        }
        env_server.params.tls_certfile =
            conf_dir_server.path().to_path_buf().join("server.cert");
        env_server.params.tls_keyfile = conf_dir_server
            .path()
            .to_path_buf()
            .join("server-privkey.pem");

        if variant == "remote_full" {
            env_server.params.totp_auth = true;
        }
    }

    let conf_file_client =
        conf_dir_client.path().to_path_buf().join("config.toml");
    let mut env_client = ParamsIntegrtyBoot::new().unwrap();
    env_client.common_params.config_file = conf_file_client;
    env_client.params.data_dir =
        data_dir_client.path().to_string_lossy().to_string();

    let mut options = vec![
        "integrity-boot",
        "--log-level",
        "trace",
        "--data-dir",
        &env_client.params.data_dir,
    ];

    if variant != "local" {
        let mut server_url = "https://127.0.0.1:8443";
        if variant == "remote_full" {
            server_url = "https://127.0.0.1:8444";
        }
        options.extend(&vec![
            "--attest-remote",
            "--server-url",
            server_url,
            "--server-insecure",
        ]);
        env_client.params.attest_remote = true;
        env_client.params.server_url = Some(server_url.into());
        env_client.params.server_insecure = true;

        if variant == "remote_full" {
            let secure_payloads_folder =
                data_dir_client.path().join(".payloads");
            let mut secure_payloads = vec![];
            for f in 0..3 {
                let secure_payload_file =
                    secure_payloads_folder.join(f.to_string());
                create_file(
                    secure_payload_file.as_path(),
                    gen_encoded_secret(512)?.as_str(),
                )
                .await?;
                secure_payloads
                    .push(secure_payload_file.to_string_lossy().to_string());
            }
            env_client.params.secured_payloads = Some(secure_payloads);
        }
    }

    let matches = ParamsIntegrtyBoot::command().get_matches_from(&options);
    env_client.common_matches = env_client
        .params
        .populate_configuration(&matches, &Config::builder().build()?)?;

    let env_server = Arc::new(env_server);
    let env_client = Arc::new(env_client);

    Ok((env_client, env_server))
}
