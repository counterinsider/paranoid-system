// SPDX-License-Identifier: MIT OR Apache-2.0
//! Server launcher and shutdown handler

use crate::{
    common::{gen_encoded_secret, generate_self_signed_cert},
    env::constants::*,
    log::*,
    server::{Env, app_init, db::db_connect_sqlite},
};
use anyhow::{Context, Result, bail};
use axum::{extract::Request, serve};
use futures_util::pin_mut;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use nix::sys::stat::{Mode, fchmod};
use std::{
    convert::From,
    os::fd::AsFd,
    path::PathBuf,
    process::exit,
    sync::{Arc, atomic::Ordering},
};
use tokio::{
    fs::{File, create_dir_all, read_to_string},
    io::AsyncWriteExt,
    net::TcpListener,
    signal::ctrl_c,
    spawn,
};
use tokio_native_tls::{
    TlsAcceptor,
    native_tls::{Identity, Protocol, TlsAcceptor as NativeTlsAcceptor},
};
use tower_service::Service;

/// Shutdown signal handler
pub async fn shutdown_signal_future() {
    if let Err(e) = ctrl_c().await {
        error!("Could not complete SIGINT signal hook: {:?}", e);
        exit(1);
    }
}

/// Server launcher
pub async fn server_launch(env: Env) -> Result<()> {
    let address =
        env.params.address.clone() + ":" + env.params.port.to_string().as_str();

    debug!("Connecting to database ...");
    // TODO: parameterize database backend: PostgreSQL, MySQL, SQLite
    let mut db_path = PathBuf::from(&env.params.data_dir);
    db_path.push("db");
    if !db_path.exists() {
        create_dir_all(&db_path).await.context(format!(
            "Could not create SQLite database directory: {}",
            db_path.display()
        ))?;
    } else if db_path.is_file() {
        bail!("SQLite database directory {} is a file", db_path.display());
    }
    db_path.push(CONF_SERVER_SQLITE_DATABASE_FILE);
    let db = Arc::new(db_connect_sqlite(&db_path).await?);

    debug!(
        "Starting {} server on {} ...",
        if env.common_params.no_https {
            "HTTP"
        } else {
            "HTTPS"
        },
        address
    );

    let listener = TcpListener::bind(address.as_str())
        .await
        .context(format!("Could not listen on {}", address))?;
    let router = app_init(env.clone(), db.clone());

    let secret_file_mode = Mode::S_IRUSR; // 0o400
    let mut jwt_secret_filename = PathBuf::from(&env.params.data_dir);
    jwt_secret_filename.push(CONF_SERVER_JWT_SECRET_FILE);
    if !PathBuf::from(&jwt_secret_filename).exists() {
        // Generate JWT secret
        info!("Generating JWT secret ...");
        let jwt_secret = gen_encoded_secret(512)?;
        let mut jwt_secret_file = File::create(&jwt_secret_filename).await?;
        fchmod(jwt_secret_file.as_fd(), secret_file_mode)
            .context("Could not change JWT secret file permissions")?;
        jwt_secret_file.write_all(jwt_secret.as_bytes()).await?;
    }

    if env.common_params.no_https {
        info!("Begin serving requests ...");
        serve(listener, router)
            .with_graceful_shutdown(shutdown_signal_future())
            .await
            .context("Could not start web server")?;
    } else {
        if !PathBuf::from(&env.params.tls_keyfile).exists() {
            // Generate self-signed TLS certificate
            info!("Generating self-signed TLS certificate ...");
            let tls_keyfile_dir = PathBuf::from(&env.params.tls_keyfile);
            if let Some(tls_keyfile_dir) = tls_keyfile_dir.parent() {
                if !tls_keyfile_dir.exists() {
                    create_dir_all(tls_keyfile_dir).await.context(
                        "Could not create directory for TLS keyfile",
                    )?;
                }
            }
            let tls_certfile_dir = PathBuf::from(&env.params.tls_certfile);
            if let Some(tls_certfile_dir) = tls_certfile_dir.parent() {
                if !tls_certfile_dir.exists() {
                    create_dir_all(tls_certfile_dir).await.context(
                        "Could not create directory for TLS certfile",
                    )?;
                }
            }

            let (key_pem, cert_pem) = generate_self_signed_cert()?;
            let mut key_pem_file =
                File::create(&env.params.tls_keyfile).await?;
            fchmod(key_pem_file.as_fd(), secret_file_mode)
                .context("Could not change TLS private key file permissions")?;
            key_pem_file.write_all(key_pem.as_bytes()).await?;
            let mut cert_pem_file =
                File::create(&env.params.tls_certfile).await?;
            cert_pem_file.write_all(cert_pem.as_bytes()).await?;
        }

        let key_pem =
            read_to_string(&env.params.tls_keyfile)
                .await
                .context(format!(
                    "Error in reading TLS private key file {}",
                    env.params.tls_keyfile.display()
                ))?;
        let cert_pem =
            read_to_string(&env.params.tls_certfile)
                .await
                .context(format!(
                    "Error in reading TLS certificate file {}",
                    env.params.tls_certfile.display()
                ))?;

        let tls_identity =
            Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes())
                .context(
                    "Could not parse server TLS certificate and key file",
                )?;
        let tls_acceptor = TlsAcceptor::from(
            NativeTlsAcceptor::builder(tls_identity)
                .min_protocol_version(Some(Protocol::Tlsv12))
                .build()
                .context("Could not initialize TLS backend")?,
        );

        pin_mut!(listener);

        info!("Begin serving requests ...");

        loop {
            if env.do_shutdown.load(Ordering::Relaxed) {
                break;
            }

            let router = router.clone();
            let tls_acceptor = tls_acceptor.clone();

            let (stream, sock_addr) = listener
                .accept()
                .await
                .context("Could not accept new TCP connection")?;

            spawn(async move {
                let Ok(stream) = tls_acceptor.accept(stream).await else {
                    error!(
                        "Could not complete TLS handshake with {}",
                        sock_addr
                    );
                    return;
                };

                let stream = TokioIo::new(stream);

                let hyper_service =
                    service_fn(move |request: Request<Incoming>| {
                        router.clone().call(request)
                    });

                let ret = Builder::new(TokioExecutor::new())
                    .serve_connection(stream, hyper_service)
                    .await;

                if let Err(err) = ret {
                    error!("Request from {sock_addr} processing error: {err}");
                }
            });
        }
    }

    Ok(())
}
