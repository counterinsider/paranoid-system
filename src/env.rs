// SPDX-License-Identifier: MIT OR Apache-2.0
//! Execution environment helpers:
//! 1. Argument parser
//! 2. Configuration initialization

use crate::log::*;
#[cfg(test)]
use crate::totp::TOTPInterface;
use crate::tpm::Tpm;
use anyhow::{Result, anyhow, bail};
use clap::ArgMatches;
#[allow(unused)]
use clap::{
    Args, CommandFactory, Parser, Subcommand, builder::PossibleValuesParser,
    parser::ValueSource, value_parser,
};
use config::{Config, Environment, File as ConfigFile, FileFormat};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, OnceLock, atomic::AtomicBool},
};

/// Process environment: cli parameters, configuration and global runtime state
pub struct Env<P>
where
    P: Params,
{
    /// Binary name being run
    pub name: String,
    /// Command line parameters
    pub params: P,
    /// Common command line parameters
    pub common_params: CommonParams,
    /// Signal for every thread and task to terminate immediately
    /// before process exits
    pub do_shutdown: Arc<AtomicBool>,
    /// Common argument values for access from generic implementations
    // Using map of pre-defined stringified argument values instead of clap ArgMatches
    // for passing to functions with parameterized environment as ArgMatches is immutable and manual
    // tampering with its private fields is prone errors due to possibility of clap API change
    pub common_matches: HashMap<String, Option<String>>,
}

/// Temp placeholder
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecuredPayload {
    filename: String,
    content: Vec<u8>,
}

impl<P> Env<P>
where
    P: Params,
{
    /// new execution environment instance.
    /// `name` parameter is required indicating which binary is executed
    pub fn new(name: &str) -> Result<Env<P>> {
        #[cfg(not(test))]
        let mut args = P::parse();
        #[cfg(test)]
        let mut args = P::parse_from(vec![name, "--log-level", "trace"]);

        #[cfg(not(test))]
        let matches = P::command().get_matches();
        #[cfg(test)]
        let matches =
            P::command().get_matches_from(vec![name, "--log-level", "trace"]);

        let mut common_matches = HashMap::new();
        let mut conf_loaded_msg = String::new();
        if !cfg!(test) {
            // initialize and populate configuration
            let config_builder = Config::builder();
            let config_file = matches
                .get_one::<PathBuf>("config_file")
                .ok_or(anyhow!("config_file option error"))?;

            let config_builder = if config_file.exists() {
                conf_loaded_msg = format!(
                    "Loaded configuration from file {}",
                    config_file.display()
                );
                config_builder.add_source(ConfigFile::new(
                    &config_file.to_string_lossy(),
                    FileFormat::Toml,
                ))
            } else {
                config_builder
            };

            // environment variables override file config
            let config_builder = config_builder.add_source(
                Environment::with_prefix(name)
                    .keep_prefix(false)
                    .prefix_separator("_")
                    .try_parsing(true)
                    .ignore_empty(true),
            );
            let config = config_builder.build()?;

            common_matches = args.populate_configuration(&matches, &config)?;
        }

        // shutdown signal
        let do_shutdown = Arc::new(AtomicBool::new(false));

        let env = Env {
            name: name.to_string(),
            common_params: args.common(),
            params: args,
            do_shutdown,
            common_matches,
        };

        init_logging(&env, name)?;

        if conf_loaded_msg.len() > 0 {
            debug!("{}", conf_loaded_msg);
        }

        Ok(env)
    }

    /// Get argument value for parameterized implementations
    pub fn get(&self, common_match_id: &str) -> Result<String> {
        self.common_matches
            .get(common_match_id)
            .ok_or(anyhow!("option error: {}", common_match_id))?
            .clone()
            .ok_or(anyhow!("option error: {}", common_match_id))
    }

    /// Get optional argument value for parameterized implementations
    pub fn try_get(&self, common_match_id: &str) -> Result<Option<String>> {
        Ok(self
            .common_matches
            .get(common_match_id)
            .ok_or(anyhow!("option error: {}", common_match_id))?
            .clone())
    }
}

// ----------------------------------------------------------------------------
// |                            CONSTANTS                                     |
// ----------------------------------------------------------------------------
/// Crate-wide constants definitions
pub mod constants {
    pub const CONF_GLOBAL_SHUTDOWN_TIMEOUT_SEC: u64 = 3;

    pub const CONF_TPM_EK_HANDLE: u32 = 0x81010092;
    pub const CONF_TPM_AK_PERSISTENT_HANDLE: u32 = 0x81010093;
    pub const CONF_TPM_HMAC_BOOT_COUNTER_PERSISTENT_HANDLE: u32 = 0x81010094;
    pub const CONF_TPM_HMAC_COMPOUND_POLICY_HASH_PERSISTENT_HANDLE: u32 =
        0x81010095;
    pub const CONF_TPM_HMAC_KEY_PERSISTENT_HANDLE_START: u32 = 0x81010096;

    pub const CONF_SERVER_HANDLER_TIMEOUT_SEC: u64 = 15;
    pub const CONF_SERVER_SQLITE_DATABASE_FILE: &str = "server.db";
    pub const CONF_SERVER_IDENTITY_SIZE: usize = 256;
    pub const CONF_SERVER_JWT_SECRET_FILE: &str = "jwt-key.dat";
    pub const CONF_SERVER_SECURED_PAYLOADS_STORE: &str = "secured-payloads";
    pub const CONF_SERVER_EPHEMERAL_SECRET_LEN: usize = 48;

    pub const CONF_CLIENT_JWT_FILE: &str = "server-auth.dat";
    pub const CONF_CLIENT_JWT_AUTH_ROUTES: [&str; 5] = [
        "push",
        "push/complete",
        "attest/nonce",
        "attest",
        "attest/complete",
    ];
    pub const CONF_CLIENT_TPM_LOG_FILE: &str =
        "/sys/kernel/security/tpm0/binary_bios_measurements";
    pub const CONF_CLIENT_IMA_LOG_FILE: &str =
        "/sys/kernel/security/ima/ascii_runtime_measurements";
    pub const CONF_CLIENT_SECURED_PAYLOADS_STORE: &str =
        "/run/tss/secured-payloads";
    pub const CONF_CLIENT_SECURED_PAYLOAD_FILENAMES_MAP_FILE: &str =
        "secured-payloads.list";
}

pub static GLOBAL_VAR_IMA_EXTENDED_LOG: OnceLock<Vec<String>> = OnceLock::new();
#[cfg(test)]
// Required for [`crate::boot::ima::read_ima_log`] unit test
pub static GLOBAL_VAR_IMA_EXTENDED_LOG_2: OnceLock<Vec<String>> =
    OnceLock::new();
#[cfg(test)]
// Required for [`crate::boot::tests::test_actions_routes_all`] unit test
pub static GLOBAL_VAR_TOTP_GENERATOR: OnceLock<TOTPInterface> = OnceLock::new();

// ----------------------------------------------------------------------------
// |                    CONFIGURATION AND CLI PARAMETERS                      |
// ----------------------------------------------------------------------------

/// Uniting type
pub trait Params: Clone + Sized + Parser {
    fn new() -> Result<Env<Self>>;

    /// Populate non-default CLI parameters with values loaded
    /// from configuration file or environment variables
    fn populate_configuration(
        &mut self,
        matches: &ArgMatches,
        config: &Config,
    ) -> Result<HashMap<String, Option<String>>>;

    fn common(&self) -> CommonParams;
}

/// paranoid-boot - system launch integrity measurement with TPM and Linux IMA
///
/// Program runs on every system startup and asserts boot integrity against previously established baselines
#[derive(Parser, Default, Clone, Debug)]
#[command(
    name = "paranoid-boot - system launch integrity measurement with TPM and Linux IMA",
    version
)]
pub struct ParamsIntegrtyBoot {
    //---- paranoid-boot specific options
    /// Data directory
    #[arg(short, long, default_value = "/var/lib/paranoid-system/client/boot")]
    pub data_dir: String,

    /// Additional files for measurement as list of glob patterns
    ///
    /// Integrity of these files will be measured and included in boot integrity baseline
    #[arg(long)]
    pub seal_glob: Option<Vec<String>>,

    // /// Use authenticated communication with TPM
    // #[arg(long, action)]
    // pub tpm_auth: bool,
    /// Asserted TPM PCR (Platform Configuration Register) set
    #[arg(long, default_value_t = String::from("sha256:0,1,2,3,4,5,6,7"))]
    pub pcr_selection: String,

    /// Enable remote attestation
    #[arg(long, action)]
    pub attest_remote: bool,

    /// Remote attestation server URL
    #[arg(long)]
    pub server_url: Option<String>,

    /// Remote attestation server TLS certificate fingerprint
    ///
    /// Calculated as `openssl s_client -connect <host>:<port> </dev/null 2>/dev/null | openssl x509 -fingerprint -noout -in /dev/stdin`
    /// Example: SHA1 Fingerprint=41:97:CB:04:97:77:C5:B5:A8:E4:0B:89:2F:46:49:28:96:0C:78:13
    #[arg(long)]
    pub server_cert_fingerprint: Option<String>,

    /// Do not verify server TLS certificate
    ///
    /// Implied as set if `server_cert_fingerprint` is given
    #[arg(long, action)]
    pub server_insecure: bool,

    /// Secured payloads
    ///
    /// These files will be secured by server and returned only when attestation passed.
    /// The payloads are uploaded only once, when integrity baseline had been established (with `paranoid-boot fix` action).
    /// The payloads are encrypted with key stored in TPM before sending to the server and decrypted when downloaded.
    /// Note again that for updating payloads new enrollment required.
    /// Ensure that the files are accessible by the `user` (see --user option) and have unique names.
    /// After upload the files can be manually deleted. When downloaded the files are stored in `/run/tss/secured-payloads` folder.
    #[arg(long)]
    pub secured_payloads: Option<Vec<String>>,

    /// Use secured payloads encryption passphrase instead key stored in TPM.
    ///
    /// Payloads will be encrypted with the passphrase.
    #[arg(long)]
    pub secured_payloads_psk: Option<String>,

    //---- end paranoid-boot specific options
    #[command(flatten, next_help_heading = "Common options")]
    pub config: CommonParams,

    #[command(subcommand)]
    pub action: Option<ParamsIntegrtyBootAction>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ParamsIntegrtyBootAction {
    Enroll,
    Fix,
    Attest,
    Cleanup,
}

impl Params for ParamsIntegrtyBoot {
    fn new() -> Result<Env<Self>> {
        Env::new("paranoid-boot")
    }

    fn populate_configuration(
        &mut self,
        matches: &ArgMatches,
        config: &Config,
    ) -> Result<HashMap<String, Option<String>>> {
        #[allow(unused_mut)]
        let mut updated_options = self.clone();
        let mut updated_common_options = self.config.clone();
        let mut common_matches = HashMap::new();

        let option_ids = [
            "data_dir",
            "seal_glob",
            "pcr_selection",
            "attest_remote",
            "server_url",
            "server_cert_fingerprint",
            "server_insecure",
            "secured_payloads",
            "secured_payloads_psk",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>();

        for option_id in option_ids.iter() {
            // overwrite only default values as CLI parameters take precedence over
            // configuration and environment
            let option_config_id = &option_id.replace("_", "-");
            let mut is_default_val = false;
            if let Some(ValueSource::DefaultValue) =
                matches.value_source(option_id)
            {
                is_default_val = true;
            }
            if is_default_val || !matches.try_contains_id(option_id)? {
                trace!("Trying to read config for {} option", option_id);

                if option_id == "data_dir" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.data_dir = v;
                    }
                } else if option_id == "seal_glob" {
                    if let Ok(v) = config.get_array(option_config_id) {
                        updated_options.seal_glob = Some(
                            v.into_iter()
                                .map(|v| v.to_string())
                                .collect::<Vec<String>>(),
                        );
                    }
                // } else if option_id == "tpm_auth" {
                //     if let Ok(v) = config.get(option_config_id) {
                //         updated_options.tpm_auth = v;
                //     }
                } else if option_id == "pcr_selection" {
                    if let Ok(v) = config.get::<String>(option_config_id) {
                        Tpm::pcr_selection_from_str(v.as_str()).map_err(
                            |e| anyhow!("Invalid PCR selection ({}): {}", v, e),
                        )?;
                        updated_options.pcr_selection = v;
                    }
                } else if option_id == "attest_remote" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.attest_remote = v;
                    }
                } else if option_id == "server_url" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.server_url = Some(v);
                    }
                } else if option_id == "server_cert_fingerprint" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.server_cert_fingerprint = Some(v);
                    }
                } else if option_id == "server_insecure" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.server_insecure = v;
                    }
                } else if option_id == "secured_payloads_psk" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.secured_payloads_psk = Some(v);
                    }
                } else if option_id == "secured_payloads" {
                    if self.secured_payloads.is_some()
                        && self.secured_payloads.as_ref().unwrap().len() == 0
                    {
                        let conf_v: Result<Vec<SecuredPayload>> = config
                            .get(option_config_id)
                            .map_err(|e| anyhow!("{:?}", e));
                        match conf_v {
                            Ok(v) => {
                                let mut vnew = Vec::<String>::new();
                                for v0 in v {
                                    vnew.push(serde_json::to_string(&v0)?)
                                }
                                self.secured_payloads = Some(vnew);
                            }
                            Err(e) => {
                                if !cfg!(test) {
                                    bail!(
                                        "Could not parse <secured_payloads> configuration values: {}",
                                        e
                                    );
                                }
                            }
                        };
                    } else {
                        // just ensure syntax is correct
                        if self.secured_payloads.is_some() {
                            for v0 in
                                self.secured_payloads.as_ref().unwrap().iter()
                            {
                                if let Err(e) =
                                    serde_json::from_str::<SecuredPayload>(
                                        v0.as_str(),
                                    )
                                {
                                    if !cfg!(test) {
                                        bail!(
                                            "Could not parse --secured_payloads [`crate::env::SecuredPayload`] value\n{}\n{}",
                                            v0,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        common_matches
            .insert("data_dir".into(), Some(updated_options.data_dir.clone()));
        common_matches
            .insert("server_url".into(), updated_options.server_url.clone());
        common_matches.insert(
            "server_cert_fingerprint".into(),
            updated_options.server_cert_fingerprint.clone(),
        );
        common_matches.insert(
            "server_insecure".into(),
            Some(updated_options.server_insecure.to_string()),
        );

        common_matches.extend(
            updated_common_options.populate_configuration(matches, config)?,
        );

        // Update existing argument values
        *self = updated_options;
        (*self).config = updated_common_options;

        Ok(common_matches)
    }

    fn common(&self) -> CommonParams {
        self.config.clone()
    }
}

/// paranoid-srv - attestation server checking client system integrity and TPM quotes.
///
/// HTTP server with TLS support which asserts client system integrity against previously established baselines.
#[derive(Parser, Default, Clone)]
#[command(
    name = "paranoid-srv - attestation server checking client system integrity and TPM quotes",
    version
)]
pub struct ParamsIntegrtySrv {
    //---- paranoid-srv specific options
    /// Data directory
    #[arg(short, long, default_value = "/var/lib/paranoid-system/server")]
    pub data_dir: String,

    /// Listen to address
    #[arg(short, long, default_value_t = String::from("0.0.0.0"))]
    pub address: String,

    /// Listen on port
    #[arg(short, long, default_value_t = 443 as u32)]
    pub port: u32,

    /// Server TLS certificate path
    #[arg(long, default_value = "<data_dir>/certs/server.cert")]
    pub tls_certfile: PathBuf,

    /// Server TLS private key path
    #[arg(long, default_value = "<data_dir>/certs/server-privkey.pem")]
    pub tls_keyfile: PathBuf,

    /// Disallow client enrollment
    ///
    /// If this option is given, new clients could not be added
    #[arg(long, default_value_t = false)]
    pub disallow_enroll: bool,

    /// Enable RFC 6238 Time-Based One-Time Password (TOTP) authentication
    ///
    /// If enabled, client will be required to provide TOTP during baseline insertion and secured payload download
    #[arg(long, default_value_t = false)]
    pub totp_auth: bool,

    /// Maximum payloads client can upload to the server
    #[arg(long, default_value_t = 32 as u32)]
    pub max_client_payloads: u32,

    /// Uploaded client payload size limit, bytes
    #[arg(long, default_value_t = 1024 * 8 as u32)]
    pub max_payload_size: u32,

    /// Maximum allowed duration for remote attestation to be completed, seconds
    #[arg(long, default_value_t = 60 * 5 as u32)]
    pub attestation_within: u32,

    //---- end paranoid-srv specific options
    #[command(flatten, next_help_heading = "Common options")]
    pub config: CommonParams,

    #[command(subcommand)]
    pub action: Option<ParamsIntegrtySrvAction>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ParamsIntegrtySrvAction {
    Serve,
    Cleanup,
}

impl Params for ParamsIntegrtySrv {
    fn new() -> Result<Env<Self>> {
        Env::new("paranoid-srv")
    }

    fn populate_configuration(
        &mut self,
        matches: &ArgMatches,
        config: &Config,
    ) -> Result<HashMap<String, Option<String>>> {
        #[allow(unused_mut)]
        let mut updated_options = self.clone();
        let mut updated_common_options = self.config.clone();
        let mut common_matches = HashMap::new();

        let option_ids = [
            "data_dir",
            "address",
            "port",
            "tls_certfile",
            "tls_keyfile",
            "disallow_enroll",
            "totp_auth",
            "max_client_payloads",
            "max_payload_size",
            "attestation_within",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>();

        for option_id in option_ids.iter() {
            // overwrite only default values as CLI parameters take precedence over
            // configuration and environment
            let option_config_id = &option_id.replace("_", "-");
            let mut is_default_val = false;
            if let Some(ValueSource::DefaultValue) =
                matches.value_source(option_id)
            {
                is_default_val = true;
            }
            if is_default_val || !matches.try_contains_id(option_id)? {
                if option_id == "data_dir" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.data_dir = v;
                    }
                } else if option_id == "address" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.address = v;
                    }
                } else if option_id == "port" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.port = v;
                    }
                } else if option_id == "tls_certfile" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.tls_certfile = v;
                    }
                } else if option_id == "tls_keyfile" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.tls_keyfile = v;
                    }
                } else if option_id == "disallow_enroll" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.disallow_enroll = v;
                    }
                } else if option_id == "totp_auth" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.totp_auth = v;
                    }
                } else if option_id == "max_client_payloads" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.max_client_payloads = v;
                    }
                } else if option_id == "max_payload_size" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.max_payload_size = v;
                    }
                } else if option_id == "attestation_within" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.attestation_within = v;
                    }
                }
            }
        }

        common_matches
            .insert("data_dir".into(), Some(updated_options.data_dir.clone()));

        common_matches.extend(
            updated_common_options.populate_configuration(matches, config)?,
        );

        // data directories settings
        updated_options.tls_keyfile = PathBuf::from(
            updated_options
                .tls_keyfile
                .to_string_lossy()
                .to_string()
                .replace("<data_dir>", &self.data_dir),
        );
        updated_options.tls_certfile = PathBuf::from(
            updated_options
                .tls_certfile
                .to_string_lossy()
                .to_string()
                .replace("<data_dir>", &self.data_dir),
        );

        // just update existing values
        *self = updated_options;
        (*self).config = updated_common_options;

        Ok(common_matches)
    }

    fn common(&self) -> CommonParams {
        self.config.clone()
    }
}

/// paranoid-rt - daemon which measures run-time system integrity
#[derive(Parser, Default, Clone)]
#[command(
    name = "paranoid-rt - measure run-time system integrity using IMA",
    version
)]
pub struct ParamsIntegrtyRt {
    //---- paranoid-rt specific options
    /// Data directory
    #[arg(
        short,
        long,
        default_value = "/var/lib/paranoid-system/client/runtime"
    )]
    pub data_dir: String,

    //---- end paranoid-rt specific options
    #[command(flatten, next_help_heading = "Common options")]
    pub config: CommonParams,

    #[command(subcommand)]
    pub action: Option<ParamsIntegrtyRtAction>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ParamsIntegrtyRtAction {
    Daemon,
    Reset,
}

impl Params for ParamsIntegrtyRt {
    fn new() -> Result<Env<Self>> {
        Env::new("paranoid-rt")
    }

    fn populate_configuration(
        &mut self,
        matches: &ArgMatches,
        config: &Config,
    ) -> Result<HashMap<String, Option<String>>> {
        #[allow(unused_mut)]
        let mut updated_options = self.clone();
        let mut updated_common_options = self.config.clone();
        let mut common_matches = HashMap::new();
        let option_ids = ["data_dir"]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<String>>();

        for option_id in option_ids.iter() {
            // overwrite only default values as CLI parameters take precedence over
            // configuration and environment
            let option_config_id = &option_id.replace("_", "-");
            let mut is_default_val = false;
            if let Some(ValueSource::DefaultValue) =
                matches.value_source(option_id)
            {
                is_default_val = true;
            }
            if is_default_val || !matches.try_contains_id(option_id)? {
                if option_id == "data_dir" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.data_dir = v;
                    }
                }
            }
        }

        common_matches
            .insert("data_dir".into(), Some(updated_options.data_dir.clone()));

        common_matches.extend(
            updated_common_options.populate_configuration(matches, config)?,
        );

        // just update existing values
        *self = updated_options;
        (*self).config = updated_common_options;

        Ok(common_matches)
    }

    fn common(&self) -> CommonParams {
        self.config.clone()
    }
}

/// Common parameters for all binaries
#[derive(Args, Clone, Debug, Default)]
pub struct CommonParams {
    //---- system wide configuration - primary configuration options
    /// Path to TOML configuration file
    ///
    /// The file contains corresponding to listed options.
    #[arg(short, long, default_value = "/etc/paranoid-system/config.toml")]
    pub config_file: PathBuf,

    /// Drop privileges to this user
    #[arg(long, short, default_value_t = String::from("tss"))]
    pub user: String,

    /// Log location
    #[arg(long, default_value = "/var/log/paranoid-system")]
    pub log_dir: String,

    /// Logging level
    #[arg(long, default_value = "info", value_parser = PossibleValuesParser::new(["trace", "debug", "info", "warn", "error"]))]
    pub log_level: String,

    /// Rotate logs as files with specified size in bytes
    #[arg(long, default_value_t = 1024 * 1024 * 8 as u32)]
    pub log_rotate_size: u32,

    /// Rotate logs with specified maximum number of files
    #[arg(long, default_value_t = 16 as u32)]
    pub log_rotate_limit: u32,

    /// Maximum system states
    #[arg(long, default_value_t = 5 as u32)]
    pub max_system_states: u32,

    /// Do not use HTTPS. Plain text connection might expose boot logs to MiTM
    #[arg(long, default_value_t = false)]
    pub no_https: bool,
}

// NOTE: configuration population logic below
impl CommonParams {
    /// Populate non-default CLI parameters with values loaded
    /// from configuration file or environment variables
    pub fn populate_configuration(
        &mut self,
        matches: &ArgMatches,
        config: &Config,
    ) -> Result<HashMap<String, Option<String>>> {
        let mut updated_options = self.clone();
        let mut common_matches = HashMap::new();

        let option_ids = [
            "user",
            "log_dir",
            "log_level",
            "log_rotate_size",
            "log_rotate_limit",
            "max_system_states",
            "no_https",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>();

        for option_id in option_ids.iter() {
            // overwrite only default values as CLI parameters take precedence over
            // configuration and environment
            let option_config_id = &option_id.replace("_", "-");
            let mut is_default_val = false;
            if let Some(ValueSource::DefaultValue) =
                matches.value_source(option_id)
            {
                is_default_val = true;
            }
            if is_default_val || !matches.try_contains_id(option_id)? {
                if option_id == "log_level" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.log_level = v;
                    }
                } else if option_id == "log_dir" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.log_dir = v;
                    }
                } else if option_id == "user" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.user = v;
                    }
                } else if option_id == "log_rotate_size" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.log_rotate_size = v;
                    }
                } else if option_id == "log_rotate_limit" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.log_rotate_limit = v;
                    }
                } else if option_id == "max_system_states" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.max_system_states = v;
                    }
                } else if option_id == "no_https" {
                    if let Ok(v) = config.get(option_config_id) {
                        updated_options.no_https = v;
                    }
                }
            }
        }

        common_matches.insert(
            "log_level".into(),
            Some(updated_options.log_level.clone()),
        );
        common_matches
            .insert("log_dir".into(), Some(updated_options.log_dir.clone()));
        common_matches.insert(
            "log_rotate_limit".into(),
            Some(updated_options.log_rotate_limit.to_string()),
        );
        common_matches.insert(
            "log_rotate_size".into(),
            Some(updated_options.log_rotate_size.to_string()),
        );

        // data directories settings
        // updated_options.some_dir = updated_options
        //     .some_dir
        //     .replace("<data_dir>", self.some_dir.as_str());

        // just update existing values
        *self = updated_options;

        Ok(common_matches)
    }
}
