// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{Context, Result};
use paranoid_system::{
    common::privileges_adjust,
    env::{
        Env, Params, ParamsIntegritySrv, ParamsIntegritySrvAction, constants::*,
    },
    log::*,
    server::launcher::{server_launch, shutdown_signal_future},
};
use std::{
    path::PathBuf,
    process::exit,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    fs::remove_dir_all,
    select, spawn,
    sync::oneshot::{self, Receiver},
    time::sleep,
};

#[tokio::main]
async fn main() -> Result<()> {
    let env = Arc::new(ParamsIntegritySrv::new()?);

    if &env.common_params.user != "tss" {
        // if only non-default value is set, drop privileges
        privileges_adjust(&env.common_params.user, env.clone())
            .await
            .context("Could not adjust process privileges")?;
    }

    let (shutdown_trigger_tx, shutdown_trigger_rx) = oneshot::channel();
    shutdown_signal_hook(env.clone(), shutdown_trigger_rx);

    if let Some(ParamsIntegritySrvAction::Serve) = env.params.action {
        server_launch(env).await?;
    } else if let Some(ParamsIntegritySrvAction::Cleanup) = env.params.action {
        cleanup(env).await?;
    } else {
        // default
        server_launch(env).await?;
    }

    let _ = shutdown_trigger_tx.send(true);

    Ok(())
}

fn shutdown_signal_hook(env: Arc<Env<ParamsIntegritySrv>>, rx: Receiver<bool>) {
    spawn(async move {
        trace!("Setting up signal handler...");
        shutdown_signal_future().await;
        debug!("Shutting down ...");
        env.do_shutdown.store(true, Ordering::SeqCst);
        select! {
            _ =  async {
                sleep(Duration::from_secs(CONF_GLOBAL_SHUTDOWN_TIMEOUT_SEC)).await;
            } => {
                info!("Killing all threads on {}s timeout. Exit", CONF_GLOBAL_SHUTDOWN_TIMEOUT_SEC);
                exit(0);
            }
            _ = async {
                match rx.await {
                    Ok(_) => {},
                    Err(_) => error!("Error when waiting for threads termination. Exit"),
                }
            } => {
                trace!("Exit");
                exit(0);
            }
        };
    });
}

/// Cleanup server data
async fn cleanup(env: Arc<Env<ParamsIntegritySrv>>) -> Result<()> {
    info!("Cleaning up server data directories ...");
    let data_dir = PathBuf::from(&env.params.data_dir);
    if data_dir.exists() {
        remove_dir_all(&data_dir).await?;
    }
    info!("Completed");
    Ok(())
}
