// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux IMA subsystem related functionality: IMA log parsing, boot aggregates collection

#[cfg(test)]
use crate::env::GLOBAL_VAR_IMA_EXTENDED_LOG_2;
use crate::{
    common::*,
    env::{Env, GLOBAL_VAR_IMA_EXTENDED_LOG, ParamsIntegrtyBoot, constants::*},
    log::*,
};
use anyhow::{Context, Result, anyhow, ensure};
use glob::glob;
use regex::Regex;
use std::{path::PathBuf, sync::Arc};
use tokio::{
    fs::{self, File},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
};
use zeroize::Zeroize;

/// Read pre-configured file set to add them to IMA measurement log.
/// The function must be invoked before privileges drop.
pub async fn extend_ima_log(env: Arc<Env<ParamsIntegrtyBoot>>) -> Result<()> {
    let data_dir = PathBuf::from(&env.params.data_dir);
    // Important static files
    let static_files = [
        #[cfg(not(test))]
        "/etc/ima/ima-policy",
        //TODO: Ensure config file is located on partition for which IMA measurement in /etc/ima/ima-policy is configured
        &env.common_params.config_file.to_string_lossy().to_string(),
        &data_dir
            .join("identity/uuid.data")
            .to_string_lossy()
            .to_string(),
        &data_dir
            .join("identity/".to_string() + CONF_CLIENT_JWT_FILE)
            .to_string_lossy()
            .to_string(),
        &data_dir
            .join("identity/ak.pem")
            .to_string_lossy()
            .to_string(),
        &data_dir
            .join("identity/ekpub.pem")
            .to_string_lossy()
            .to_string(),
    ];

    async fn process_files<I>(paths: I) -> Result<usize>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut added_count = 0;
        for path in paths {
            if path.as_path().exists() && path.is_file() {
                if let Ok(mut file) = fs::File::open(path).await {
                    let mut buffer = vec![0; 8];
                    file.read_to_end(&mut buffer).await?;
                    buffer.zeroize();
                    added_count += 1;
                }
            }
        }
        Ok(added_count)
    }

    let mut all_files = static_files
        .iter()
        .map(|v| PathBuf::from(v))
        .collect::<Vec<PathBuf>>();

    let mut added_count = process_files(all_files.clone()).await?;

    debug!("Added {} static files to IMA log", added_count);

    let boot_files_conf_dir =
        PathBuf::from(env.common_params.config_file.as_path().parent().ok_or(
            anyhow!("Could not derive boot-files.d location from config file"),
        )?);
    let boot_files_conf_glob =
        format!("{}/boot-files.d/*.list", boot_files_conf_dir.display());

    let mut boot_file_conf_paths: Vec<_> = glob(&boot_files_conf_glob)
        .context(format!("Could not read by glob: {}", boot_files_conf_glob))?
        .filter_map(Result::ok) // Filter out glob errors for individual paths
        .collect();
    boot_file_conf_paths.sort(); // Sort by name

    added_count = boot_file_conf_paths.len();
    all_files.extend_from_slice(&boot_file_conf_paths);
    process_files(boot_file_conf_paths.clone()).await?;

    debug!(
        "Added {} boot files configuration (boot-files.d/*.list files) to IMA log",
        added_count
    );

    let mut seal_glob_files: Vec<_> = vec![];
    if let Some(ref seal_globs) = env.params.seal_glob {
        for seal_glob in seal_globs {
            let file_paths: Vec<_> = glob(seal_glob)
                .context(format!(
                    "Could not read by glob: {}. Check seal-glob option.",
                    seal_glob
                ))?
                .filter_map(Result::ok)
                .collect();
            seal_glob_files.extend(file_paths);
        }
    }

    seal_glob_files.sort();

    added_count = seal_glob_files.len();
    all_files.extend_from_slice(&seal_glob_files);
    process_files(seal_glob_files).await?;
    debug!(
        "Added {} files read by globs given in seal-glob option to IMA log",
        added_count
    );

    for boot_file_conf_file in boot_file_conf_paths.iter() {
        let file = File::open(boot_file_conf_file).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        while let Some(boot_file_conf_glob) = lines.next_line().await? {
            let boot_file_conf_glob = boot_file_conf_glob.trim();
            if boot_file_conf_glob.len() > 0 {
                let mut file_paths: Vec<_> = glob(boot_file_conf_glob)
                    .context(format!(
                        "Could not read by glob: {}. Check {} boot files list configuration file.",
                        boot_file_conf_glob,
                        boot_file_conf_file.display()
                    ))?
                    .filter_map(Result::ok)
                    .collect();
                if file_paths.len() > 0 {
                    file_paths.sort();
                    added_count = file_paths.len();
                    all_files.extend_from_slice(&file_paths);
                    process_files(file_paths).await?;
                    debug!(
                        "Added {} boot files read by glob {} given in {} configuration file to IMA log",
                        added_count,
                        boot_file_conf_glob,
                        boot_file_conf_file.display()
                    );
                }
            }
        }
    }

    GLOBAL_VAR_IMA_EXTENDED_LOG
        .set(get_unique_values(
            &all_files
                .into_iter()
                .map(|v| v.to_string_lossy().to_string())
                .collect::<Vec<String>>(),
        ))
        .map_err(|_| {
            anyhow!("Could not set GLOBAL_VAR_IMA_EXTENDED_LOG global variable")
        })?;

    Ok(())
}

// Extract boot aggregate and whitelisted file names form IMA log
pub(super) async fn read_ima_log() -> Result<(String, String)> {
    #[cfg(not(test))]
    let ima_log_path = CONF_CLIENT_IMA_LOG_FILE;
    #[cfg(test)]
    let ima_log_path = "/tmp/ascii_runtime_measurements_sha256";

    let mut ima_log_file = File::open(ima_log_path)
        .await
        .context("Could not read IMA log kernel file")?;
    let mut ima_log = String::new();
    ima_log_file.read_to_string(&mut ima_log).await?;

    // Extract boot aggregate value
    let mut ba = ima_log
        .lines()
        .nth(0)
        .ok_or(anyhow!("Could not extract boot aggregate from IMA log"))?
        .split(" ");
    ensure!(
        ba.clone()
            .last()
            .ok_or(anyhow!("Could not extract boot aggregate from IMA log"))?
            == "boot_aggregate",
        "Could not extract boot aggregate from IMA log"
    );
    let ba = ba
        .nth(3)
        .ok_or(anyhow!("Could not extract boot aggregate from IMA log"))?
        .split(":");
    ensure!(
        ba.clone().nth(0).ok_or(anyhow!(
            "Could not extract boot aggregate hash function from IMA log"
        ))? == "sha256",
        "Expected SHA256 boot aggregate hash function"
    );
    let ba = ba
        .last()
        .ok_or(anyhow!(
            "Could not extract boot aggregate value from IMA log"
        ))?
        .to_string();

    // Extract only whitelisted IMA log entries
    #[cfg(not(test))]
    let whitelisted_filenames = GLOBAL_VAR_IMA_EXTENDED_LOG
        .get()
        .ok_or(anyhow!("Could not get GLOBAL_VAR_IMA_EXTENDED_LOG"))?
        .to_owned()
        .iter()
        .map(normalize_ima_ng_filename)
        .collect::<Vec<String>>();
    #[cfg(test)]
    let whitelisted_filenames = GLOBAL_VAR_IMA_EXTENDED_LOG_2
        .get()
        .ok_or(anyhow!("Could not get GLOBAL_VAR_IMA_EXTENDED_LOG_2"))?
        .to_owned()
        .iter()
        .map(normalize_ima_ng_filename)
        .collect::<Vec<String>>();

    let ima_log = ima_log.lines().filter(|v| {
        let mut f = v.split(" ");
        if let Some(template) = f.clone().nth(2) {
            if template == "ima-ng" {
                if let Some(hash) = f.clone().nth(3) {
                    if let Some(hash_func) = hash.split(":").nth(0) {
                        if hash_func == "sha256" {
                            if let Some(hash_val) = hash.split(":").nth(1) {
                                let sha256_regex = Regex::new(r"^[a-fA-F0-9]{64}$").unwrap();
                                if hash_val != "0000000000000000000000000000000000000000000000000000000000000000" && sha256_regex.is_match(hash_val) {
                                    if let Some(file_name) = f.nth(4) {
                                        let file_name = normalize_ima_ng_filename(&file_name.to_string());
                                        return whitelisted_filenames.iter().any(|v| v == &file_name)
                                    }
                                }
                            }
                        } else {
                            warn!("Expected SHA256 hash function in ima-ng IMA log template, got: {}", hash_func);
                        }
                    }
                }
            }
        }
        return false;
    })
    .map(|v| v.to_string())
    .collect::<Vec<String>>();
    let mut ima_log = get_unique_values(&ima_log);
    ima_log.sort();
    let ima_log = ima_log.join("\n");

    Ok((ba, ima_log))
}

/// Read and write collected boot aggregates in format `<current-timestamp>:<boot-aggregate>`
pub(super) async fn collect_boot_aggregates(
    env: Arc<Env<ParamsIntegrtyBoot>>,
    current_ba: String,
) -> Result<String> {
    let data_dir = PathBuf::from(&env.params.data_dir);
    let ba_file_path = data_dir.join("ba.dat");
    let mut ba_vals = Vec::<(String, String)>::new();
    let mut ba_vals_str = String::new();
    if ba_file_path.exists() {
        let mut file = File::open(&ba_file_path).await?;
        file.read_to_string(&mut ba_vals_str).await?;
        ba_vals = ba_vals_str
            .lines()
            .map(|v| v.split(":"))
            .filter(|v| v.clone().count() > 1)
            .map(|v| {
                (
                    v.clone().nth(0).unwrap().to_string(),
                    v.clone().nth(1).unwrap().to_string(),
                )
            })
            .collect::<Vec<(String, String)>>();
    }
    if !ba_vals.iter().any(|v| v.1 == current_ba) {
        ba_vals.push((timestamp().to_string(), current_ba));
        ba_vals.sort_by(|a, b| {
            b.0.parse::<u64>()
                .unwrap()
                .cmp(&a.0.parse::<u64>().unwrap())
        });
        while ba_vals.len() > env.common_params.max_system_states as usize {
            ba_vals.pop();
        }
        let mut file = File::create(&ba_file_path).await?;
        ba_vals_str = ba_vals
            .into_iter()
            .map(|v| (v.0 + ":").to_string() + &v.1)
            .collect::<Vec<String>>()
            .join("\n");
        file.write_all(ba_vals_str.as_bytes()).await?;
        info!("Added boot aggregate value to system states");
    }

    Ok(ba_vals_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Params;
    use std::path::Path;
    use tempfile::{TempDir, tempdir};
    use tokio::fs::create_dir_all;

    async fn create_dummy_file(path: &Path, content: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).await?;
        }
        let mut file = File::create(path).await?;
        file.write_all(content.as_bytes()).await?;
        Ok(())
    }

    async fn create_mock_env(
        tmp_data_dir: &TempDir,
        tmp_config_dir: &TempDir,
    ) -> Result<Arc<Env<ParamsIntegrtyBoot>>> {
        let data_dir = tmp_data_dir.path().to_path_buf();
        let config_dir = tmp_config_dir.path().to_path_buf();
        let config_file = config_dir.join("config.toml");

        create_dummy_file(&config_file, "").await?;
        create_dummy_file(&data_dir.join("identity/uuid.data"), "uuid_data")
            .await?;
        create_dummy_file(
            &data_dir.join("identity/".to_string() + CONF_CLIENT_JWT_FILE),
            "jwt_data",
        )
        .await?;
        create_dummy_file(&data_dir.join("identity/ak.pem"), "ak_content")
            .await?;
        create_dummy_file(
            &data_dir.join("identity/ekpub.pem"),
            "ekpub_content",
        )
        .await?;

        // Setup boot-files.d structure and content
        let boot_files_d_dir = config_dir.join("boot-files.d");
        create_dir_all(&boot_files_d_dir).await?;
        create_dummy_file(
            &boot_files_d_dir.join("defaults.list"),
            "/etc/default/*\n/sbin/*",
        )
        .await?;
        create_dummy_file(
            &boot_files_d_dir.join("libs.list"),
            "/usr/lib/*\n/nonexistent",
        )
        .await?;

        let mut env = ParamsIntegrtyBoot::new()?;
        env.common_params.config_file = config_file;
        env.params.data_dir = data_dir.to_string_lossy().to_string();
        env.params.seal_glob =
            Some(vec!["/project/*".to_string(), "/nonexistent".to_string()]);

        Ok(Arc::new(env))
    }

    #[tokio::test]
    async fn test_extend_ima_log() {
        let tmp_data_dir = tempdir().unwrap();
        let tmp_config_dir = tempdir().unwrap();
        let env = create_mock_env(&tmp_data_dir, &tmp_config_dir)
            .await
            .expect("Could not build environment object");

        extend_ima_log(env)
            .await
            .expect("Could not extend IMA log under mock environment");

        let whitelisted_filenames = GLOBAL_VAR_IMA_EXTENDED_LOG
            .get()
            .ok_or(anyhow!("Could not get GLOBAL_VAR_IMA_EXTENDED_LOG"))
            .unwrap()
            .to_owned()
            .iter()
            .map(normalize_ima_ng_filename)
            .collect::<Vec<String>>();

        let mut glob_files: Vec<_> = vec![];
        for glob_val in [
            "/etc/default/*",
            "/sbin/*",
            "/usr/lib/*",
            "/nonexistent",
            "/project/*",
        ] {
            let file_paths: Vec<_> = glob(glob_val)
                .context(format!(
                    "Could not read by glob: {}. Check seal-glob option.",
                    glob_val
                ))
                .unwrap()
                .filter_map(Result::ok)
                .collect();
            glob_files.extend(file_paths);
        }

        glob_files = get_unique_values(&glob_files);
        glob_files.sort();

        const PREDEFINED_EXISTING_COUNT: usize = 7;
        assert_eq!(
            whitelisted_filenames.len(),
            PREDEFINED_EXISTING_COUNT + glob_files.len(),
            "Read files count mismatch!"
        );
    }

    #[tokio::test]
    async fn test_read_ima_log() {
        // Setup: Create a temporary IMA log file with controlled content
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

        // Initialize GLOBAL_VAR_IMA_EXTENDED_LOG
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

        let (boot_aggregate, ima_log) = read_ima_log()
            .await
            .expect("Could not execute read_ima_log under mocked environment");

        // Verify: Assert the expected outcomes
        assert_eq!(
            boot_aggregate,
            "37406d190e1257cb5b61c7789ba3718599b9045d16698412bd191cd0348c452d"
        );

        let expected_ima_log_lines: Vec<String> = vec![
            "10 any ima-ng sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 /path/to/whitelisted/file2".to_string(),
            "10 any ima-ng sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /path/to/whitelisted/file1".to_string(),
        ];
        let mut expected_ima_log_lines_sorted = expected_ima_log_lines;
        expected_ima_log_lines_sorted.sort();
        let expected_ima_log = expected_ima_log_lines_sorted.join("\n");

        assert_eq!(ima_log, expected_ima_log);
    }

    #[tokio::test]
    async fn test_collect_boot_aggregates() {
        let tmp_data_dir = tempdir().unwrap();
        let tmp_config_dir = tempdir().unwrap();
        let env = create_mock_env(&tmp_data_dir, &tmp_config_dir)
            .await
            .expect("Could not build environment object");

        let ba_file_path = tmp_data_dir.path().to_path_buf().join("ba.dat");

        // Setup: Create an initial `ba.dat` file with some content
        // Using realistic-looking timestamps and SHA256-like hashes.
        // Timestamps are chosen to be older than what `timestamp()` will generate.
        let initial_content = "\
            1678886400:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\n\
            1678972800:f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2\n\
        ".to_string();
        create_dummy_file(&ba_file_path, &initial_content)
            .await
            .unwrap();
        let current_ba =
            "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
                .to_string();
        let current_timestatmp = timestamp();

        // Execution: Call the function under test and expect an error
        let ba = collect_boot_aggregates(env.clone(), current_ba.clone()).await.expect("Could not execute collect_boot_aggregates under mocked environment");
        let expected_ba = format!(
            "\
            {}:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b\n\
            1678972800:f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2\n\
            1678886400:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\
        ",
            current_timestatmp
        );
        assert_eq!(expected_ba, ba, "Collected incorrectly!");
    }
}
