// SPDX-License-Identifier: MIT OR Apache-2.0
//! Logging wrappers extending logging functionality

#[cfg(not(test))]
pub use log::{debug, error, info, trace, warn};
#[cfg(test)]
pub use std::println as error;
#[cfg(test)]
pub use std::println as warn;
#[cfg(test)]
pub use std::println as info;
#[cfg(test)]
pub use std::println as debug;
#[cfg(test)]
pub use std::println as trace;

use crate::env::{Env, Params};
use anyhow::Result;
use file_rotate::{
    ContentLimit, FileRotate,
    compression::Compression,
    suffix::{AppendTimestamp, FileLimit},
};
use log::{LevelFilter, Log};
use simple_logger::SimpleLogger;
use simplelog::{
    CombinedLogger, Config as LoggerConfig, ConfigBuilder, SharedLogger,
    WriteLogger,
};
use std::{
    env::var as get_env_var,
    fs::{create_dir_all, exists},
    path::PathBuf,
    process,
};
use syslog::{BasicLogger, Facility, Formatter3164};

/// Initialize logging subsystem
pub fn init_logging<P>(env: &Env<P>, name: &str) -> Result<()>
where
    P: Params,
{
    if cfg!(test) {
        return Ok(());
    }

    let log_dir = env.get("log_dir")?;
    let log_rotate_size = env.get("log_rotate_size")?.parse::<u32>()?;
    let log_rotate_limit = env.get("log_rotate_limit")?.parse::<u32>()?;
    let log_level = env.get("log_level")?;

    let mut log_file_path = PathBuf::from(log_dir);
    if !exists(&log_file_path)? {
        // FIXME: clarify error context
        create_dir_all(&log_file_path)?;
    }
    log_file_path.push(String::from(name) + ".log");

    let log_file_rotate = FileRotate::new(
        log_file_path.clone(),
        AppendTimestamp::default(FileLimit::MaxFiles(
            log_rotate_limit as usize,
        )),
        ContentLimit::BytesSurpassed(log_rotate_size as usize),
        Compression::OnRotate(0),
        None,
    );

    let arg_log_level = log_level.clone();

    let log_level = match arg_log_level.as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Error,
    };

    let mut log_config = ConfigBuilder::new();
    log_config.set_max_level(log_level);
    if log_level != LevelFilter::Trace {
        log_config.add_filter_ignore("sea_orm".into());
        log_config.add_filter_ignore("tss_esapi".into()); //TODO: does not work
    }
    log_config.set_time_format_rfc3339();
    let log_config = log_config.build();

    let mut loggers: Vec<Box<(dyn SharedLogger + 'static)>> =
        vec![WriteLogger::new(
            log_level,
            log_config.clone(),
            log_file_rotate,
        )];

    let mut syslog_initialized = false;
    if get_env_var("JOURNAL_STREAM").is_ok_and(|v| v.len() > 0) {
        // if running under systemd use [`syslog`] logger, otherwise use [`simplelogger`]
        let formatter = Formatter3164 {
            facility: Facility::LOG_DAEMON,
            hostname: None,
            process: name.into(),
            pid: process::id(),
        };
        if let Ok(logger) = syslog::unix(formatter) {
            loggers.push(Box::new(SyslogLoggerWrapper(
                BasicLogger::new(logger),
                log_level.clone(),
                log_config.clone(),
            )));
            syslog_initialized = true;
        }
    }
    if !syslog_initialized {
        loggers.push(Box::new(SimpleLoggerWrapper(
            SimpleLogger::new().with_level(log_level),
            log_config.clone(),
        )));
    }
    CombinedLogger::init(loggers)?;

    Ok(())
}

struct SimpleLoggerWrapper(SimpleLogger, LoggerConfig);

impl Log for SimpleLoggerWrapper {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.0.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        self.0.log(record);
    }

    fn flush(&self) {
        self.0.flush();
    }
}

impl SharedLogger for SimpleLoggerWrapper {
    fn level(&self) -> LevelFilter {
        self.0.max_level()
    }

    fn config(&self) -> Option<&LoggerConfig> {
        Some(&self.1)
    }

    fn as_log(self: Box<Self>) -> Box<dyn log::Log> {
        Box::new(self.0)
    }
}

struct SyslogLoggerWrapper(BasicLogger, LevelFilter, LoggerConfig);

impl Log for SyslogLoggerWrapper {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.0.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        self.0.log(record);
    }

    fn flush(&self) {
        self.0.flush();
    }
}

impl SharedLogger for SyslogLoggerWrapper {
    fn level(&self) -> LevelFilter {
        self.1
    }

    fn config(&self) -> Option<&LoggerConfig> {
        Some(&self.2)
    }

    fn as_log(self: Box<Self>) -> Box<dyn log::Log> {
        Box::new(self.0)
    }
}
