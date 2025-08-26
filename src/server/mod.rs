// SPDX-License-Identifier: MIT OR Apache-2.0
//! `paranoid-srv` server routes handlers and data transfer objects

use crate::{
    common::{
        calculate_sha256, calculate_sha512, gen_encoded_secret,
        get_unique_values, system_state_hash, timestamp,
    },
    env::{Env as AppEnv, ParamsIntegritySrv, constants::*},
    log::*,
    totp::TOTPInterface,
    tpm::{Quote, Tpm},
};
use anyhow::{Context, Error, Result, anyhow, bail};
use axum::{
    BoxError, Json, RequestPartsExt, Router,
    error_handling::HandleErrorLayer,
    extract::{FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response as AxumResponse},
    routing::{get, post},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use chrono::Utc;
use db::entities::{self, *};
use dto::*;
use hex::encode as hex_encode;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use regex::Regex;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, DatabaseConnection, entity::*,
    query::*, sea_query,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryInto},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs::{File, create_dir_all, read_to_string},
    io::{AsyncReadExt, AsyncWriteExt},
};
use totp_rs::Secret;
use tower::{ServiceBuilder, timeout::error::Elapsed};
use tower_http::{
    compression::CompressionLayer, decompression::RequestDecompressionLayer,
};
use uuid::Uuid;

pub mod db;
pub mod dto;
pub mod launcher;

/// Type representing request handler error response
pub struct ServerError(Error);
/// Type representing request handler result response
pub type ServerResult<T> = Result<Json<Response<T>>, ServerError>;

pub type DB = Arc<DatabaseConnection>;
pub type Env = Arc<AppEnv<ParamsIntegritySrv>>;
pub type ST = State<AppState>;

/// Web application shared state
#[derive(Clone)]
pub struct AppState {
    env: Env,
    db: DB,
}

/// Web server routes
pub fn app_init(env: Env, db: DB) -> Router {
    let router = Router::new()
        .route("/", get(handler_default))
        .route("/enroll", post(route_enroll))
        .route("/push", post(route_push))
        .route("/push/complete", post(route_push_complete))
        .route("/attest/nonce", get(route_attest_nonce))
        .route("/attest", post(route_attest))
        .route("/attest/complete", post(route_attest_complete))
        .fallback(handler_404)
        .layer(
            ServiceBuilder::new()
                .layer(RequestDecompressionLayer::new())
                .layer(CompressionLayer::new()),
        )
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(server_error_handler))
                .timeout(Duration::from_secs(CONF_SERVER_HANDLER_TIMEOUT_SEC)),
        )
        .with_state(AppState { env, db });
    debug!("Initialized routes and middleware");
    router
}

/// Default page
pub async fn handler_default() -> &'static str {
    "Operational"
}

/// 404 page
pub async fn handler_404() -> &'static str {
    "Not found"
}

// ---- Routes handlers ----

/// Process client enrollment
pub async fn route_enroll(
    State(state): ST,
    Json(req): Json<RequestEnroll>,
) -> ServerResult<ResponseEnroll> {
    if state.env.params.disallow_enroll {
        return Err(ServerError(anyhow!("Forbidden")));
    }

    let mut data = Vec::<u8>::new();
    data.extend_from_slice(req.ak.as_bytes());
    data.extend_from_slice(req.ek_pub.as_bytes());
    if let Some(ref ek_cert_pem) = req.ek_cert {
        data.extend_from_slice(ek_cert_pem.as_bytes());
    }

    let uuid = Uuid::new_v8(calculate_sha256(&data)?[0..16].try_into()?);

    let mut action_required = None;
    let mut totp_secret = None;
    if state.env.params.totp_auth {
        action_required = Some(vec!["totp_record_secret".into()]);
        totp_secret =
            Some(format!("{}", Secret::generate_secret().to_encoded()));
    }

    let client = clients::ActiveModel {
        uuid: Set(uuid.into()),
        ek_pub: Set(req.ek_pub.clone()),
        ek_cert: Set(if let Some(ek_cert) = &req.ek_cert {
            ek_cert.to_owned()
        } else {
            String::new()
        }),
        ak: Set(req.ak.clone()),
        totp_secret: if let Some(totp_secret) = &totp_secret {
            Set(totp_secret.to_owned())
        } else {
            Set(String::new())
        },
        name: Set(String::new()),
        ..Default::default()
    };

    let claims = JwtClaims {
        uuid: uuid.into(),
        client: None,
        // exp presence required but not validated
        exp: timestamp() + 86400 * 30 * 12 * 7,
    };
    let jwt_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(
            read_jwt_secret(state.env.clone()).await?.as_bytes(),
        ),
    )
    .context("Could not encode JWT token")?;

    client
        .insert(&*state.db)
        .await
        .context("Could not insert new client row")?;

    ok(
        Some(ResponseEnroll {
            jwt_token,
            uuid: uuid.into(),
            totp_secret,
        }),
        action_required,
    )
}

/// Establish client integrity baseline
pub async fn route_push(
    State(state): ST,
    auth: JwtClaims,
    Json(req): Json<RequestPush>,
) -> ServerResult<ResponsePush> {
    let (client, client_name) = get_client(auth);

    info!(
        "Establishing new integrity baseline for client: {}",
        client_name
    );

    // Verify system state hash
    let system_state_hash =
        system_state_hash(&req.ima_log, &req.ba, &req.pcr_digest)?;

    if system_state_hash != req.system_state_hash {
        return Err(ServerError(anyhow!("System state verification failed")));
    }

    baseline::Entity::delete_many()
        .filter(baseline::Column::IsAccepted.eq(Value::Bool(Some(false))))
        .filter(baseline::Column::Uuid.eq(client.uuid.clone()))
        .exec(&*state.db)
        .await?;

    let baseline_nonce = gen_encoded_secret(CONF_SERVER_EPHEMERAL_SECRET_LEN)?;
    let mut session_nonce = None;
    let mut action_required = None;

    let baseline = baseline::ActiveModel {
        uuid: Set(client.uuid.clone()),
        pcr_digest: Set(req.pcr_digest),
        ba: Set(req.ba),
        ima_log: Set(req.ima_log),
        tpm_log: Set(req.tpm_log),
        nonce: Set(baseline_nonce.clone()),
        is_accepted: Set(if state.env.params.totp_auth {
            false
        } else {
            true
        }),
        ..Default::default()
    };

    let baseline_id = baseline::Entity::insert(baseline)
        .exec(&*state.db)
        .await?
        .last_insert_id;

    let poweron_row = poweron::ActiveModel {
        uuid: Set(client.uuid.clone()),
        counter: Set(req.bc as i32),
        ..Default::default()
    };
    poweron::Entity::insert(poweron_row)
        .on_conflict(
            sea_query::OnConflict::column(poweron::Column::Uuid)
                .update_column(poweron::Column::Counter)
                .to_owned(),
        )
        .exec(&*state.db)
        .await?;

    if state.env.params.totp_auth {
        push_session::Entity::delete_many()
            .filter(push_session::Column::Uuid.eq(client.uuid.clone()))
            .exec(&*state.db)
            .await?;
        session_nonce =
            Some(gen_encoded_secret(CONF_SERVER_EPHEMERAL_SECRET_LEN)?);
        action_required = Some(vec!["totp_auth".into()]);
        let push_session = push_session::ActiveModel {
            uuid: Set(client.uuid.clone()),
            baseline_id: Set(baseline_id),
            session_nonce: Set(session_nonce.as_ref().unwrap().to_owned()),
            ..Default::default()
        };
        push_session::Entity::insert(push_session)
            .exec(&*state.db)
            .await?;
        info!(
            "Expecting TOTP authentication of new integrity baseline for client: {}",
            client_name
        );
    } else {
        info!("Established integrity baseline for client: {}", client_name);
    }

    // Ensure complaince with `max_system_states` parameter
    let mut baselines = baseline::Entity::find()
        .columns([baseline::Column::Id])
        .filter(baseline::Column::Uuid.eq(client.uuid.clone()))
        .order_by_desc(baseline::Column::EstablishedAt)
        .all(&*state.db)
        .await?;

    if baselines.len() > state.env.common_params.max_system_states as usize
        && state.env.common_params.max_system_states > 0
    {
        debug!(
            "[x] Removing older baselines for client {} as current number of baselines {} more than configured limit {}",
            client_name,
            baselines.len(),
            state.env.common_params.max_system_states
        );
        let mut baseline_ids = vec![];
        while baselines.len()
            > state.env.common_params.max_system_states as usize
        {
            baseline_ids.push(baselines.pop().unwrap().id);
        }
        baseline::Entity::delete_many()
            .filter(baseline::Column::Id.is_in(baseline_ids))
            .exec(&*state.db)
            .await?;
    }

    ok(
        Some(ResponsePush {
            baseline_nonce,
            session_nonce,
        }),
        action_required,
    )
}

/// Establish client integrity baseline
pub async fn route_push_complete(
    State(state): ST,
    auth: JwtClaims,
    Json(req): Json<RequestPushComplete>,
) -> ServerResult<ResponsePushComplete> {
    let (client, client_name) = get_client(auth);

    info!(
        "Completing setting up integrity baseline for client: {}",
        client_name
    );

    let mut session_nonce = None;
    let mut action_required = None;
    let baseline = baseline::Entity::find()
        .filter(baseline::Column::Uuid.eq(client.uuid.clone()))
        .filter(baseline::Column::IsAccepted.eq(Value::Bool(Some(false))))
        .filter(
            baseline::Column::Nonce
                .eq(Value::String(Some(Box::new(req.baseline_nonce.clone())))),
        )
        .one(&*state.db)
        .await
        .context("Could not fetch baseline")?
        .ok_or(anyhow!(
            "No baseline found with given nonce, which requires acceptance"
        ))?;

    if state.env.params.totp_auth {
        info!(
            "Verifying two-factor authentication code for client: {} ...",
            client_name
        );
        // TODO: rate limiting
        let req_session_nonce = req
            .session_nonce
            .ok_or(anyhow!("Session nonce is not provided"))?
            .clone();
        let req_totp = req
            .totp
            .ok_or(anyhow!("TOTP code is not provided"))?
            .clone();

        let session = push_session::Entity::find()
            .filter(push_session::Column::Uuid.eq(client.uuid.clone()))
            .filter(push_session::Column::BaselineId.eq(baseline.id))
            .one(&*state.db)
            .await
            .context("Could not fetch push session")?
            .ok_or(anyhow!("No push session found for given baseline"))?;
        if session.session_nonce != req_session_nonce {
            return Err(ServerError(anyhow!("Invalid session nonce")));
        }
        if Utc::now().naive_utc().and_utc().timestamp()
            - session.opened_at.naive_utc().and_utc().timestamp()
            > state.env.params.attestation_within as i64
        {
            return Err(ServerError(anyhow!(
                "Session expired. Only {} seconds given to complete two-factor authentication",
                state.env.params.attestation_within
            )));
        }
        auth_2fa(
            async || {
                session_nonce =
                    Some(gen_encoded_secret(CONF_SERVER_EPHEMERAL_SECRET_LEN)?);
                let mut session: push_session::ActiveModel = session.into();
                session.session_nonce = Set(session_nonce.clone().unwrap());
                session
                    .update(&*state.db)
                    .await
                    .context("Could not update session nonce")?;
                action_required = Some(vec!["totp_auth".into()]);
                Ok(())
            },
            &client,
            &req_totp,
            &client_name,
        )
        .await?;
    }

    // Process payloads, process only when TOTP auth succeeded
    if action_required.is_none()
        && req.payloads.is_some()
        && req.payloads.as_ref().unwrap().len() > 0
    {
        let payload_dir = PathBuf::from(&state.env.params.data_dir)
            .join(CONF_SERVER_SECURED_PAYLOADS_STORE);
        // Ensure it is first upload
        let uploaded_payloads = secured_payload::Entity::find()
            .filter(secured_payload::Column::Uuid.eq(client.uuid.clone()))
            .all(&*state.db)
            .await?;
        if uploaded_payloads.len() > 0 {
            let msg = format!(
                "Rejecting payloads upload as they have been already uploaded once for given client: {}",
                client_name
            );
            warn!("{}", msg);
            return Err(ServerError(anyhow!(msg)));
        }

        if req.payloads.as_ref().unwrap().len()
            > state.env.params.max_client_payloads as usize
        {
            let msg = format!(
                "Rejecting upload of {} payloads for client {} as it exceeds configured limit {}",
                req.payloads.as_ref().unwrap().len(),
                client_name,
                state.env.params.max_client_payloads
            );
            warn!("{}", msg);
            return Err(ServerError(anyhow!(msg)));
        }

        info!(
            "Saving uploaded {} payloads for client: {}",
            req.payloads.as_ref().unwrap().len(),
            client_name
        );

        for payload in req.payloads.as_ref().unwrap().iter() {
            if payload.len() > state.env.params.max_payload_size as usize {
                let msg = format!(
                    "Rejecting payload upload for client {} as it exceeds configured size limit {}b",
                    client_name, state.env.params.max_payload_size
                );
                warn!("{}", msg);
                return Err(ServerError(anyhow!(msg)));
            }
            let mut hash_filename_data = client.uuid.as_bytes().to_owned();
            hash_filename_data.extend_from_slice(&payload);
            let name_chunks =
                hex_encode(&calculate_sha512(&hash_filename_data)?)
                    .chars()
                    .collect::<Vec<_>>()
                    .chunks(2)
                    .map(|chunk| chunk.iter().collect::<String>()) // Convert each chunk back to a String
                    .collect::<Vec<String>>();
            // Using two-level depth for filesystem performance
            let mut hash_filename = PathBuf::from("./");
            for i in 0..2 as usize {
                hash_filename = hash_filename.join(name_chunks.get(i).unwrap());
            }
            create_dir_all(payload_dir.join(&hash_filename)).await?;

            hash_filename = hash_filename.join(name_chunks.join(""));
            let mut payload_file =
                File::create(payload_dir.join(&hash_filename)).await?;
            payload_file.write_all(payload).await?;

            let payload_record = secured_payload::ActiveModel {
                uuid: Set(client.uuid.clone()),
                filename_hash: Set(hash_filename.to_string_lossy().to_string()),
                ..Default::default()
            };
            payload_record
                .insert(&*state.db)
                .await
                .context("Could not insert new payload row")?;

            debug!(
                "Saved payload {} for client {}",
                hash_filename.display(),
                client_name
            );
        }
    }

    // Mark the baseline as accepted
    if action_required.is_none() {
        let mut baseline: baseline::ActiveModel = baseline.into();
        baseline.is_accepted = Set(true);
        baseline
            .update(&*state.db)
            .await
            .context("Could not mark baseline as accepted")?;
    }

    ok(
        Some(ResponsePushComplete { session_nonce }),
        action_required,
    )
}

/// Open attestation session giving nonce to a client, which will be used in qualifying data of TPM quote
pub async fn route_attest_nonce(
    State(state): ST,
    auth: JwtClaims,
) -> ServerResult<ResponseAttestNonce> {
    let (client, client_name) = get_client(auth);

    info!("Opening attestation session for client: {}", client_name);

    let delete_result = attestation_nonce::Entity::delete_many()
        .filter(attestation_nonce::Column::Uuid.eq(client.uuid.clone()))
        .exec(&*state.db)
        .await?;
    if delete_result.rows_affected > 0 {
        warn!(
            "Previous attestation nonce exists for client {}",
            client_name
        );
    }

    let nonce = gen_encoded_secret(CONF_SERVER_EPHEMERAL_SECRET_LEN)?;
    let attestation_nonce_record = attestation_nonce::ActiveModel {
        uuid: Set(client.uuid.clone()),
        attestation_nonce: Set(nonce.clone()),
        ..Default::default()
    };
    attestation_nonce_record
        .insert(&*state.db)
        .await
        .context("Could not insert new attestation_nonce row")?;

    ok(Some(ResponseAttestNonce { nonce }), None)
}

/// Attest client machine remotely
pub async fn route_attest(
    State(state): ST,
    auth: JwtClaims,
    Json(req): Json<RequestAttest>,
) -> ServerResult<ResponseAttest> {
    let (client, client_name) = get_client(auth);

    info!("Executing attestation of client: {}", client_name);

    let mut session_nonce = None;
    let mut action_required = vec![];

    debug!("Fetching attestation nonce for client: {}", client_name);
    let attestation_nonce = attestation_nonce::Entity::find()
        .filter(attestation_nonce::Column::Uuid.eq(client.uuid.clone()))
        .one(&*state.db)
        .await?
        .ok_or(anyhow!(
            "Could not fetch active attestation nonce for client: {}",
            client_name
        ))?;

    if Utc::now().naive_utc().and_utc().timestamp()
        - attestation_nonce
            .created_at
            .naive_utc()
            .and_utc()
            .timestamp()
        > state.env.params.attestation_within as i64
    {
        return Err(ServerError(anyhow!(
            "Session expired. Only {} seconds given to complete attestation",
            state.env.params.attestation_within
        )));
    }

    debug!("Fetching established baselines for client: {}", client_name);

    let baselines = baseline::Entity::find()
        .filter(baseline::Column::Uuid.eq(client.uuid.clone()))
        .order_by_desc(baseline::Column::EstablishedAt)
        .all(&*state.db)
        .await?;

    debug!(
        "Verifying client {} TPM quote against {} baselines ...",
        client_name,
        baselines.len()
    );

    // Collect boot aggregates in format `<current-timestamp>:<boot-aggregate>`
    let mut ba_vals_str = String::new();
    for baseline in baselines.iter() {
        if ba_vals_str.len() > 0 {
            ba_vals_str.push_str("\n");
        }
        ba_vals_str.push_str(&baseline.ba);
    }
    let mut ba_vals = ba_vals_str
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
    ba_vals = get_unique_values(&ba_vals);
    ba_vals
        .iter()
        .try_for_each(|v| -> Result<()> {
            v.0.parse::<u64>()?;
            Ok(())
        })
        .context(
            "Error parsing timestamp value in boot aggregates collection item",
        )?;
    ba_vals.sort_by(|a, b| {
        b.0.parse::<u64>()
            .unwrap()
            .cmp(&a.0.parse::<u64>().unwrap())
    });
    let ba_vals_str_for_msg = ba_vals
        .iter()
        .map(|v| (v.0.clone() + ":").to_string() + &v.1)
        .collect::<Vec<String>>()
        .join("\n");

    let mut verified_baseline = None;
    let quote = Quote::unmarshall(&req.quote)
        .context("Could not unmarshall TPM quote")?;
    for baseline in baselines.iter() {
        // Pick up appropriate collection of boot aggregate values as boot aggregate can differ
        // from one boot to another, regardless of `ima-log`, `pcr_digest` values in qualifying data.
        // So trying to reduce `ba_vals` from top until TPM quote expected_nonce is found.
        let qualifying_data = loop {
            if ba_vals.len() == 0 {
                warn!(
                    "Qualifying data calculation failure as boot aggregates collection or IMA log difference for client: {}",
                    client_name
                );
                warn!("Remote attestation failed for client: {}", client_name);
                return Err(ServerError(anyhow!(
                    describe_attestation_failure(
                        &req,
                        &baselines,
                        &ba_vals_str_for_msg
                    )?
                )));
            }
            let mut expected_nonce =
                attestation_nonce.attestation_nonce.as_bytes().to_owned();
            let ba = ba_vals
                .iter()
                .map(|v| (v.0.clone() + ":").to_string() + &v.1)
                .collect::<Vec<String>>()
                .join("\n");
            let current_system_state_hash = system_state_hash(
                &baseline.ima_log,
                &ba,
                &baseline.pcr_digest,
            )?;
            expected_nonce.extend_from_slice(&current_system_state_hash);
            let expected_nonce = calculate_sha256(&expected_nonce)?;
            if quote.att.extra_data().as_slice() == expected_nonce.as_slice() {
                break expected_nonce;
            }
            ba_vals.remove(0);
        };

        if let Ok(_) = Tpm::check_quote(
            client.ak.clone(),
            req.quote.clone(),
            &qualifying_data,
            &baseline.pcr_digest,
        ) {
            verified_baseline = Some(baseline.to_owned());
            break;
        }
    }

    if verified_baseline.is_none() {
        warn!("Remote attestation failed for client: {}", client_name);

        return Err(ServerError(anyhow!(describe_attestation_failure(
            &req,
            &baselines,
            &ba_vals_str_for_msg
        )?)));
    }

    let baseline = verified_baseline.unwrap();
    let quote = Quote::unmarshall(&req.quote)?;
    info!(
        "Verified client {} TPM quote against existing baseline established at {}",
        client_name, baseline.established_at
    );

    if quote.att.clock_info().reset_count() != req.bc {
        return Err(ServerError(anyhow!(
            "TPM quote boot counter does not match one provided in request"
        )));
    }

    let poweron = poweron::Entity::find()
        .filter(poweron::Column::Uuid.eq(client.uuid.clone()))
        .one(&*state.db)
        .await?
        .ok_or(anyhow!("Could not fetch boot counter"))?;

    let bc_diff = req.bc.saturating_sub(poweron.counter as u32);
    if bc_diff > 1 {
        warn!(
            "Client {} machine has been powered on besides normal boot {} times",
            client_name,
            bc_diff - 1
        );
    }
    let mut poweron: poweron::ActiveModel = poweron.into();
    poweron.counter = Set(req.bc as i32);
    poweron
        .update(&*state.db)
        .await
        .context("Could not update boot counter")?;

    let payloads = secured_payload::Entity::find()
        .columns([secured_payload::Column::Id])
        .filter(secured_payload::Column::Uuid.eq(client.uuid.clone()))
        .all(&*state.db)
        .await?;

    if payloads.len() > 0 {
        session_nonce =
            Some(gen_encoded_secret(CONF_SERVER_EPHEMERAL_SECRET_LEN)?);
        action_required.push("download_payloads".to_string());
        if state.env.params.totp_auth {
            action_required.push("totp_auth".to_string());
        }

        let delete_result = attestation_session::Entity::delete_many()
            .filter(attestation_session::Column::Uuid.eq(client.uuid.clone()))
            .exec(&*state.db)
            .await?;
        if delete_result.rows_affected > 0 {
            warn!(
                "Previous attestation session removed just now for client: {}",
                client_name
            );
        }

        let attestation_session = attestation_session::ActiveModel {
            uuid: Set(client.uuid.clone()),
            session_nonce: Set(session_nonce.as_ref().unwrap().to_owned()),
            // Set timestamp of actual attestation start moment
            opened_at: Set(attestation_nonce.created_at),
            ..Default::default()
        };
        attestation_session
            .insert(&*state.db)
            .await
            .context("Could not insert attestation session row")?;

        info!(
            "Attestation completed but expecting {} payloads to be downloaded by client: {}",
            payloads.len(),
            client_name
        );
    } else {
        info!("Attestation completed for client: {}", client_name);
    }

    let attestation_nonce: attestation_nonce::ActiveModel =
        attestation_nonce.into();
    attestation_nonce
        .delete(&*state.db)
        .await
        .context("Could not delete attestation nonce")?;

    ok(
        Some(ResponseAttest {
            session_nonce: session_nonce,
            bc_diff,
        }),
        Some(action_required),
    )
}

/// Complete attestation: implement access to payloads with 2FA authentication (if enabled)
pub async fn route_attest_complete(
    State(state): ST,
    auth: JwtClaims,
    Json(req): Json<RequestAttestComplete>,
) -> ServerResult<ResponseAttestComplete> {
    let (client, client_name) = get_client(auth);

    info!("Completing attestation of client: {}", client_name);

    let mut session_nonce = None;
    let mut action_required = vec![];
    let mut payloads: Option<Vec<Vec<u8>>> = None;

    let attestation_session = attestation_session::Entity::find()
        .filter(attestation_session::Column::Uuid.eq(client.uuid.clone()))
        .one(&*state.db)
        .await?
        .ok_or(anyhow!("Could not fetch attestation session"))?;
    if req.session_nonce.is_none() {
        return Err(ServerError(anyhow!(
            "Session nonce was not provided in request"
        )));
    }
    if req.session_nonce.unwrap() != attestation_session.session_nonce {
        return Err(ServerError(anyhow!("Invalid session nonce")));
    }

    if Utc::now().naive_utc().and_utc().timestamp()
        - attestation_session
            .opened_at
            .naive_utc()
            .and_utc()
            .timestamp()
        > state.env.params.attestation_within as i64
    {
        return Err(ServerError(anyhow!(
            "Session expired. Only {} seconds given to complete attestation",
            state.env.params.attestation_within
        )));
    }

    let mut access_granted = true;
    if state.env.params.totp_auth {
        if req.totp.is_none() {
            return Err(ServerError(anyhow!(
                "2FA TOTP was not provided in request"
            )));
        }
        auth_2fa(
            async || {
                session_nonce =
                    Some(gen_encoded_secret(CONF_SERVER_EPHEMERAL_SECRET_LEN)?);
                let mut attestation_session: attestation_session::ActiveModel =
                    attestation_session.into();
                attestation_session.session_nonce =
                    Set(session_nonce.clone().unwrap());
                attestation_session
                    .update(&*state.db)
                    .await
                    .context("Could not update attestation session nonce")?;
                action_required.push("totp_auth".into());
                access_granted = false;
                Ok(())
            },
            &client,
            req.totp.as_ref().unwrap(),
            &client_name,
        )
        .await?;
    }

    if access_granted {
        let payload_dir = PathBuf::from(&state.env.params.data_dir)
            .join(CONF_SERVER_SECURED_PAYLOADS_STORE);
        let fetched_payloads = secured_payload::Entity::find()
            .filter(secured_payload::Column::Uuid.eq(client.uuid.clone()))
            .all(&*state.db)
            .await?;
        if fetched_payloads.len() == 0 {
            return Err(ServerError(anyhow!(
                "No payloads for download. The request is not necessary"
            )));
        }
        for fetched_payload in fetched_payloads.iter() {
            let payload_path = payload_dir.join(&fetched_payload.filename_hash);
            debug!(
                "Reading payload {} for client: {}",
                fetched_payload.filename_hash, client_name
            );
            let mut payload_file = File::open(payload_path)
                .await
                .context("Could not read one of payloads")?;
            let mut payload = vec![];
            payload_file.read_to_end(&mut payload).await?;
            if payloads.is_none() {
                payloads = Some(vec![]);
            }
            payloads.as_mut().unwrap().push(payload);
        }
        info!(
            "Returning {} secured payloads to client: {}",
            payloads.as_ref().unwrap().len(),
            client_name
        );
    }

    ok(
        Some(ResponseAttestComplete {
            session_nonce,
            payloads,
        }),
        Some(action_required),
    )
}

// ---- End Routes handlers ----

/// Common successfull response
fn ok<T>(
    data: Option<T>,
    action_required: Option<Vec<String>>,
) -> ServerResult<T> {
    Ok(Json(Response {
        success: true,
        error: None,
        data,
        action_required,
    }))
}

/// Handle request processing errors within handlers
impl IntoResponse for ServerError {
    fn into_response(self) -> AxumResponse {
        (
            StatusCode::OK,
            Json(Response::<ResponseEmpty> {
                success: false,
                error: Some(format!("{}", self.0)),
                data: None,
                action_required: None,
            }),
        )
            .into_response()
    }
}

impl<E> From<E> for ServerError
where
    E: Into<Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

/// Handle server internal errors
async fn server_error_handler(
    err: BoxError,
) -> (StatusCode, Json<Response<ResponseEmpty>>) {
    let mut status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut error = "Internal server error".to_string();

    if err.is::<Elapsed>() {
        status = StatusCode::REQUEST_TIMEOUT;
        error = "Request took too long".into();
    } else {
        if cfg!(debug_assertions) {
            error = format!("Internal server error: {err}")
        }
    }

    (
        status,
        Json(Response::<ResponseEmpty> {
            success: false,
            error: Some(error),
            data: None,
            action_required: None,
        }),
    )
}

// --- Authentication ----

#[derive(Serialize, Deserialize, Clone, Debug)]
/// Authentication JWT token data
pub struct JwtClaims {
    pub uuid: String,
    pub client: Option<entities::clients::Model>,
    pub exp: u64,
}

async fn read_jwt_secret(env: Env) -> Result<String> {
    let mut jwt_secret_file = PathBuf::from(&env.params.data_dir);
    jwt_secret_file.push(CONF_SERVER_JWT_SECRET_FILE);
    Ok(read_to_string(jwt_secret_file)
        .await
        .context("Could not read JWT secret")?)
}

impl FromRequestParts<AppState> for JwtClaims {
    type Rejection = ServerError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .context("Valid JWT token required")?;

        // Decode and validate JWT token
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        let token_data = decode::<JwtClaims>(
            bearer.token(),
            &DecodingKey::from_secret(
                read_jwt_secret(state.env.clone()).await?.as_bytes(),
            ),
            &validation,
        )
        .context("Could not validate JWT token")?;

        // Ensure UUID exists in DB and client binary hash is equivalent to one stored
        let client =
            db_fetch_client(state, token_data.claims.uuid.as_str()).await?;

        let mut claims = token_data.claims;
        claims.client = Some(client);

        Ok(claims)
    }
}

/// Fetches client from database
async fn db_fetch_client(
    state: &AppState,
    uuid: &str,
) -> Result<clients::Model> {
    let client = clients::Entity::find()
        .filter(clients::Column::Uuid.eq(uuid))
        .one(&*state.db)
        .await?;

    Ok(client.ok_or(anyhow!("Client does not exist"))?)
}

/// Get client from JWT auth claims
fn get_client(mut auth: JwtClaims) -> (clients::Model, String) {
    let client = auth.client.take().unwrap();
    let client_name = if client.name.len() > 0 {
        client.name.clone()
    } else {
        client.uuid.clone()
    };
    (client, client_name)
}

/// Gives details on attestation failure
fn describe_attestation_failure(
    _req: &RequestAttest,
    _baselines: &Vec<baseline::Model>,
    _ba_vals_str: &str,
) -> Result<String> {
    // TODO: more information on why the attestation failed using difference
    // for tpm_log, ima_log, boot_aggregate in request against every baseline
    // Failure of qualifying data calculation on difference of:
    // boot aggregates collection, IMA log, PCR digest
    let mut _failure_reason = (true, true, true);

    Ok("Remote attestation failure".into())
}

/// Execute two-factor authentication, checking TOTP from request.
/// Callback must be provided, which is invoked once, if authentication failed.
async fn auth_2fa<F>(
    failure_callback: F,
    client: &clients::Model,
    req_totp: &str,
    client_name: &str,
) -> Result<()>
where
    F: AsyncFnOnce() -> Result<()>,
{
    let totp = TOTPInterface::new(client.totp_secret.as_str())?;
    let totp_regex = Regex::new(r"^[0-9]{6}$")?;
    if !totp_regex.is_match(req_totp) {
        bail!("Incorrect two-factor authentication TOTP code");
    }

    if totp.auth(&req_totp).is_err() {
        debug!(
            "Invalid two-factor authentication TOTP code for client {}",
            client_name
        );

        failure_callback().await?;
    } else {
        debug!(
            "Completed two-factor authentication for client: {}",
            client_name
        );
    }
    Ok(())
}
