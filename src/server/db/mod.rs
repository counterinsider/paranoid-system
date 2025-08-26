// SPDX-License-Identifier: MIT OR Apache-2.0
//! Server database backend abstract model based on SeaORM
//!
//! ```not_rust
//!
//! # 1. Migrate to existing database (SQLite only currently supported)
//! sqlite3 migration/sqlite3/integrity-linux.db < migration/sqlite3/20250505_01.schema.sql
//! # 2. List created tables
//! # sqlite3 integrity-linux.db
//! # sqlite> .schema
//! # sqlite> .exit
//!
//! # 2. Generate entities
//! sea-orm-cli generate entity \
//!   -u sqlite://integrity-linux.db \
//!   -o entities \
//!   --with-serde both
//!
//! # 4. Cleanup
//! rm -rf "${CARGO_TARGET_DIR:-target}" migration/sqlite3/integrity-linux.db
//! ```

use anyhow::{Context, Result, anyhow};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sqlx::{query, sqlite::SqlitePoolOptions};
use std::path::PathBuf;

use crate::log::*;

pub mod entities;

/// SQLite database initialization and connection opening
pub async fn db_connect_sqlite(
    db_path: &PathBuf,
) -> Result<DatabaseConnection> {
    let mut db_url = "sqlite://".to_string()
        + db_path
            .to_str()
            .ok_or(anyhow!("Could not convert db path to db URL"))?;
    db_url = db_url + "?mode=rwc";

    if !db_path.exists() {
        let schema_sql =
            include_str!("migration/sqlite/20250803_01.schema.sql").to_string()
                + "\n";

        warn!("[x] DATABASE DOES NOT EXIST");
        info!("Initializing database in: {}", db_path.display());

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await?;

        debug!("Migrating database tables ...");
        query(&schema_sql)
            .execute(&pool)
            .await
            .context("Could not perform DB migration")?;

        pool.close().await;

        info!("Database has been initialized");
    }

    let mut conn_opts = ConnectOptions::new(db_url);
    conn_opts.sqlx_logging(false);
    Ok(Database::connect(conn_opts)
        .await
        .context("Could not open database")?)
}
