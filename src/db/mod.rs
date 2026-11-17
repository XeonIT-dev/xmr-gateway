//! SQLite database initialization, WAL configuration, and repository exports.
//!
//! # Persistence Invariants
//! - Write-Ahead Logging (`journal_mode = WAL`) with full synchronous durability
//!   (`synchronous = FULL`) is enabled at connection pool creation so concurrent Axum
//!   readers and background scanner/webhook writers never roll back committed financial
//!   transitions on abrupt OS crashes or power loss.
//! - Foreign key enforcement (`PRAGMA foreign_keys = ON`) and a 5-second busy timeout are
//!   applied to every pooled connection.
//! - For in-memory SQLite databases (`sqlite::memory:`), pool size is pinned to `1` so all
//!   queries share the exact same ephemeral memory database.

pub mod repository;

use std::{
    fs::{File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::error::{GatewayError, GatewayResult};

/// Exclusive OS advisory process lock preventing multiple `xmr-gateway` instances from
/// concurrently sharing the same SQLite database and `monero-wallet-rpc` wallet (`P1-3`).
///
/// Holding this guard keeps the underlying file descriptor open; dropping it releases the
/// advisory lock automatically upon process exit or clean shutdown.
#[derive(Debug)]
pub struct DatabaseProcessLock {
    _file: Option<File>,
    lock_path: Option<PathBuf>,
}

impl DatabaseProcessLock {
    /// Returns the filesystem path of the active process lockfile (`None` for in-memory DBs).
    #[must_use]
    pub fn lock_path(&self) -> Option<&Path> {
        self.lock_path.as_deref()
    }
}

/// Acquires an exclusive non-blocking OS advisory lock (`<db_path>.lock`) enforcing the
/// single-instance deployment invariant for file-backed SQLite databases (`P1-3`).
///
/// For in-memory SQLite URLs (`sqlite::memory:` / `mode=memory`), returns a no-op guard.
///
/// # Errors
/// Returns [`GatewayError::Config`] if directory creation or lockfile I/O fails, or if
/// another `xmr-gateway` process already holds the lock (`TryLockError::WouldBlock`).
pub fn acquire_database_lock(database_url: &str) -> GatewayResult<DatabaseProcessLock> {
    let Some(db_path) = sqlite_file_path(database_url) else {
        return Ok(DatabaseProcessLock {
            _file: None,
            lock_path: None,
        });
    };

    ensure_sqlite_parent_dir(database_url)?;

    let lock_path = PathBuf::from(format!("{}.lock", db_path.display()));
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    opts.mode(0o600);

    let file = opts.open(&lock_path).map_err(|err| {
        GatewayError::Config(format!(
            "failed to open singleton process lock '{}': {err}",
            lock_path.display()
        ))
    })?;

    match file.try_lock() {
        Ok(()) => Ok(DatabaseProcessLock {
            _file: Some(file),
            lock_path: Some(lock_path),
        }),
        Err(TryLockError::WouldBlock) => Err(GatewayError::Config(format!(
            "singleton process lock '{}' is already held by another running xmr-gateway instance",
            lock_path.display()
        ))),
        Err(TryLockError::Error(err)) => Err(GatewayError::Config(format!(
            "failed to acquire singleton process lock '{}': {err}",
            lock_path.display()
        ))),
    }
}

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
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));

    let max_connections = if is_in_memory { 1 } else { 8 };

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(connect_options)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    enforce_sqlite_file_permissions(database_url)?;

    Ok(pool)
}

/// Extracts the filesystem path of a file-backed SQLite URI (`None` for in-memory DBs).
fn sqlite_file_path(database_url: &str) -> Option<PathBuf> {
    if database_url == "sqlite::memory:" || database_url.contains("mode=memory") {
        return None;
    }

    let path_part = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .unwrap_or(database_url);

    let file_path_str = path_part.split('?').next().unwrap_or(path_part);
    if file_path_str.is_empty() || file_path_str == ":memory:" {
        return None;
    }

    Some(PathBuf::from(file_path_str))
}

/// Ensures the parent directory of a file-backed SQLite URI exists before opening it.
fn ensure_sqlite_parent_dir(database_url: &str) -> GatewayResult<()> {
    let Some(path) = sqlite_file_path(database_url) else {
        return Ok(());
    };

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            GatewayError::Config(format!(
                "failed to create SQLite directory '{}': {err}",
                parent.display()
            ))
        })?;
        #[cfg(unix)]
        if parent != Path::new("/")
            && parent != Path::new("/tmp")
            && parent != Path::new("/var/tmp")
        {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |err| {
                    GatewayError::Config(format!(
                        "failed to enforce 0700 permissions on SQLite directory '{}': {err}",
                        parent.display()
                    ))
                },
            )?;
        }
    }

    Ok(())
}

/// Enforces restrictive `0600` owner-only permissions on `.db`, `-wal`, and `-shm` files (`XMR-040`).
fn enforce_sqlite_file_permissions(database_url: &str) -> GatewayResult<()> {
    #[cfg(unix)]
    if let Some(db_path) = sqlite_file_path(database_url) {
        let candidates = [
            db_path.clone(),
            PathBuf::from(format!("{}-wal", db_path.display())),
            PathBuf::from(format!("{}-shm", db_path.display())),
        ];
        for file_path in candidates {
            if file_path.exists() {
                std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|err| {
                        GatewayError::Config(format!(
                            "failed to enforce 0600 permissions on SQLite file '{}': {err}",
                            file_path.display()
                        ))
                    })?;
            }
        }
    }

    #[cfg(not(unix))]
    let _ = database_url;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sqlite_pool_enforces_full_synchronous_and_foreign_keys() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let db_path = tmp_dir.path().join("durability.db");
        let db_url = format!("sqlite://{}", db_path.display());

        let pool = init_sqlite_pool(&db_url).await.unwrap();

        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous;")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(synchronous, 2, "PRAGMA synchronous must be 2 (FULL)");

        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys;")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(foreign_keys, 1, "PRAGMA foreign_keys must be 1 (ON)");

        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");

        let bundled_sqlite_ver: String = sqlx::query_scalar("SELECT sqlite_version();")
            .fetch_one(&pool)
            .await
            .unwrap();
        eprintln!("bundled_sqlite_version={bundled_sqlite_ver}");
        assert!(
            !bundled_sqlite_ver.trim().is_empty(),
            "bundled SQLite runtime version must be non-empty"
        );

        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "SQLite DB file must enforce 0600 permissions");
            let dir_mode = std::fs::metadata(tmp_dir.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                dir_mode, 0o700,
                "SQLite directory must enforce 0700 permissions"
            );
        }
    }

    #[test]
    fn singleton_database_lock_rejects_second_concurrent_process_and_releases_on_drop() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let db_path = tmp_dir.path().join("singleton.db");
        let db_url = format!("sqlite://{}", db_path.display());

        let first_lock = acquire_database_lock(&db_url).unwrap();
        assert_eq!(
            first_lock.lock_path().unwrap(),
            tmp_dir.path().join("singleton.db.lock")
        );

        let second_err = acquire_database_lock(&db_url).unwrap_err();
        assert!(matches!(second_err, GatewayError::Config(_)));

        drop(first_lock);

        let reacquired = acquire_database_lock(&db_url);
        assert!(reacquired.is_ok());

        // In-memory URLs remain permitted as no-op locks
        assert!(acquire_database_lock("sqlite::memory:").is_ok());
    }
}
