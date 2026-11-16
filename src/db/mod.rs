//! SQLite database initialization, WAL configuration, and repository exports.
//!
//! # Persistence Invariants
//! - Write-Ahead Logging (`journal_mode = WAL`) is enabled at connection pool creation so
//!   concurrent Axum readers and the background scanner/webhook writers do not block each
//!   other unnecessarily.
//! - Foreign key enforcement (`PRAGMA foreign_keys = ON`) and a 5-second busy timeout are
//!   applied to every pooled connection.
//! - For in-memory SQLite databases (`sqlite::memory:`), pool size is pinned to `1` so all
//!   queries share the exact same ephemeral memory database.

pub mod repository;

use std::{path::Path, str::FromStr, time::Duration};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::error::{GatewayError, GatewayResult};

/// Initializes a SQLite connection pool in WAL mode and runs embedded migrations.
///
/// If `database_url` points to a filesystem path (e.g. `sqlite://data/xmr_gateway.db`),
/// its parent directory is created automatically if missing.
///
/// # Errors
/// Returns [`GatewayError::Config`] if `database_url` cannot be parsed or directory creation
/// fails, [`GatewayError::Database`] if connecting fails, or [`GatewayError::Migration`] if
/// schema migrations fail.
pub async fn init_sqlite_pool(database_url: &str) -> GatewayResult<SqlitePool> {
    ensure_sqlite_parent_dir(database_url)?;

    let is_in_memory = database_url == "sqlite::memory:" || database_url.contains("mode=memory");

    let connect_options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));

    let max_connections = if is_in_memory { 1 } else { 8 };

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(connect_options)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}

/// Ensures the parent directory of a file-backed SQLite URI exists before opening it.
fn ensure_sqlite_parent_dir(database_url: &str) -> GatewayResult<()> {
    if database_url == "sqlite::memory:" || database_url.contains("mode=memory") {
        return Ok(());
    }

    let path_part = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .unwrap_or(database_url);

    let file_path_str = path_part.split('?').next().unwrap_or(path_part);
    if file_path_str.is_empty() || file_path_str == ":memory:" {
        return Ok(());
    }

    let path = Path::new(file_path_str);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            GatewayError::Config(format!(
                "failed to create SQLite directory '{}': {err}",
                parent.display()
            ))
        })?;
    }

    Ok(())
}
