// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{Context, Result, anyhow};
use nix::sys::stat::{Mode, umask};
use paranoid_system::{
    boot::{self, ima::extend_ima_log},
    common::privileges_adjust,
    env::{Params, ParamsIntegrtyBoot, ParamsIntegrtyBootAction},
    log::*,
};
use std::{process::exit, sync::Arc};
use tokio::{select, signal::ctrl_c, spawn};

#[tokio::main]
async fn main() -> Result<()> {
    umask(
        Mode::from_bits(0o0027)
            .ok_or(anyhow!("Failed to set up process umask"))?,
    );

    let env = Arc::new(ParamsIntegrtyBoot::new()?);

    if let Some(
        ParamsIntegrtyBootAction::Fix | ParamsIntegrtyBootAction::Attest,
    ) = env.params.action
    {
        /*
         * TODO: system configuration:
         *
         * 1. checking kernel configuration /boot/config-* for CONFIG_IMA=y parameter;
         * 2. adding ima=on ima_policy=tcb (ima_template=ima-ng) to kernel parameters;
         * 3. checking /etc/ima/ima-policy IMA policy.
         */

        // Read boot process critical files early as root
        info!("Extending IMA log with pre-configured files list ...");
        extend_ima_log(env.clone()).await?;
    }

    if let Some(
        ParamsIntegrtyBootAction::Enroll
        | ParamsIntegrtyBootAction::Fix
        | ParamsIntegrtyBootAction::Attest,
    ) = env.params.action
    {
        privileges_adjust(&env.common_params.user, env.clone())
            .await
            .context("Could not adjust process priviliges")?;
    }

    spawn(async move {
        trace!("Setting up signal handler...");
        if let Err(e) = ctrl_c().await {
            error!("Could not complete SIGINT signal hook: {:?}", e);
            exit(1);
        }
        trace!("Shutting down ...");
        select! {
            _ =  async {
                // Immediately
                warn!("\n[x] Aborted");
            } => {
                exit(0);
            }
        };
    });

    if let Some(ParamsIntegrtyBootAction::Enroll) = env.params.action {
        boot::enroll(env.clone()).await?;
    } else if let Some(ParamsIntegrtyBootAction::Fix) = env.params.action {
        boot::fix(env.clone()).await?;
    } else if let Some(ParamsIntegrtyBootAction::Attest) = env.params.action {
        boot::attest(env.clone()).await?;
    } else if let Some(ParamsIntegrtyBootAction::Cleanup) = env.params.action {
        boot::cleanup(env.clone()).await?;
    } else {
        unimplemented!();
    }

    Ok(())
}
