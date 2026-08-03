use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::report::{Outcome, ProbeReport, REPORT_SCHEMA_VERSION};

const DATABASE_SCHEMA_VERSION: i64 = 1;
pub const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_HISTORY_LIST: usize = 1_000;
const MAX_OBSERVATIONS: usize = 1_024;
const MAX_TARGET_BYTES: usize = 16 * 1024;

pub struct History {
    connection: Connection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub id: i64,
    pub generated_at_unix: u64,
    pub target_url: String,
    pub observation_count: usize,
    /// All outcomes other than success, including challenges and rate limits.
    pub error_count: usize,
}

impl History {
    pub fn open(path: &Path) -> Result<Self> {
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            bail!("history requires a database file path");
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).context("creating history directory")?;
        }
        private_file(path)?;
        let connection = Connection::open(path).context("opening history database")?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA trusted_schema = OFF; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY;",
        )?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => {
                let tables: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                    [],
                    |row| row.get(0),
                )?;
                ensure!(
                    tables == 0,
                    "unsupported unversioned history database; existing objects were left unchanged"
                );
                let transaction = connection.unchecked_transaction()?;
                transaction.execute_batch(
                    "CREATE TABLE reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        generated_at_unix INTEGER NOT NULL CHECK (generated_at_unix >= 0),
                        target_url TEXT NOT NULL,
                        observation_count INTEGER NOT NULL CHECK (observation_count >= 0),
                        error_count INTEGER NOT NULL CHECK (error_count >= 0 AND error_count <= observation_count),
                        report_schema_version INTEGER NOT NULL,
                        report_json TEXT NOT NULL
                    );
                    CREATE INDEX reports_timestamp ON reports(generated_at_unix DESC, id DESC);
                    CREATE INDEX reports_target ON reports(target_url, generated_at_unix DESC);
                    PRAGMA user_version = 1;",
                )?;
                transaction.commit()?;
            }
            DATABASE_SCHEMA_VERSION => {
                // Check required columns immediately rather than failing later on first use.
                connection.prepare("SELECT id, generated_at_unix, target_url, observation_count, error_count, report_schema_version, report_json FROM reports LIMIT 0")?;
            }
            _ => bail!(
                "unsupported history database schema version {version}; supported version is {DATABASE_SCHEMA_VERSION}"
            ),
        }
        // DELETE mode avoids persistent WAL files. SQLite gives its rollback journal
        // the database's private file mode; secure_delete clears deleted payloads.
        connection.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA secure_delete = ON;")?;
        Ok(Self { connection })
    }

    pub fn save(&self, report: &ProbeReport) -> Result<i64> {
        report.validate_schema()?;
        ensure!(
            report.observations.len() <= MAX_OBSERVATIONS,
            "report exceeds the {MAX_OBSERVATIONS} observation history limit"
        );
        let report = report.sanitized();
        ensure!(
            report.target_url.len() <= MAX_TARGET_BYTES,
            "target URL exceeds the {MAX_TARGET_BYTES} byte history limit"
        );
        let json = report.to_json()?;
        ensure!(
            json.len() <= MAX_REPORT_BYTES,
            "report exceeds the {MAX_REPORT_BYTES} byte history limit"
        );
        let generated_at = i64::try_from(report.generated_at_unix)
            .context("report timestamp is outside the SQLite integer range")?;
        let observation_count = report.observations.len() as i64;
        let error_count = report
            .observations
            .iter()
            .filter(|observation| observation.outcome != Outcome::Success)
            .count() as i64;
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO reports (generated_at_unix, target_url, observation_count, error_count, report_schema_version, report_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![generated_at, report.target_url, observation_count, error_count, REPORT_SCHEMA_VERSION, json],
        )?;
        let id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(id)
    }

    pub fn list(&self, limit: usize) -> Result<Vec<HistoryEntry>> {
        ensure!(
            limit <= MAX_HISTORY_LIST,
            "history list limit cannot exceed {MAX_HISTORY_LIST}"
        );
        let mut statement = self.connection.prepare(
            "SELECT id, generated_at_unix, CASE WHEN length(CAST(target_url AS BLOB)) <= 16384 THEN target_url ELSE NULL END, observation_count, error_count, report_schema_version FROM reports ORDER BY generated_at_unix DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (id, generated_at, target_url, observations, errors, version) = row?;
            let target_url = target_url.with_context(|| {
                format!("history entry {id} has an oversized or missing target URL")
            })?;
            ensure!(
                version == i64::from(REPORT_SCHEMA_VERSION),
                "history entry {id} uses unsupported report schema version {version}"
            );
            ensure!(
                generated_at >= 0
                    && observations >= 0
                    && observations <= MAX_OBSERVATIONS as i64
                    && errors >= 0
                    && errors <= observations,
                "history entry {id} has malformed metadata"
            );
            entries.push(HistoryEntry {
                id,
                generated_at_unix: generated_at as u64,
                target_url: crate::report::redact_url(&target_url),
                observation_count: observations as usize,
                error_count: errors as usize,
            });
        }
        Ok(entries)
    }

    pub fn delete(&self, id: i64) -> Result<bool> {
        ensure!(id > 0, "history entry ID must be positive");
        let transaction = self.connection.unchecked_transaction()?;
        let deleted = transaction.execute("DELETE FROM reports WHERE id = ?1", [id])?;
        transaction.commit()?;
        Ok(deleted != 0)
    }

    pub fn load(&self, id: i64) -> Result<ProbeReport> {
        // Query size first: an oversized row never gets materialized into a String.
        let metadata = self.connection.query_row(
            "SELECT length(CAST(report_json AS BLOB)), report_schema_version, generated_at_unix, CASE WHEN length(CAST(target_url AS BLOB)) <= 16384 THEN target_url ELSE NULL END, observation_count, error_count FROM reports WHERE id = ?1",
            [id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?)),
        ).optional()?.with_context(|| format!("history entry {id} does not exist"))?;
        let (length, version, generated_at, target_url, observations, errors) = metadata;
        let target_url = target_url.with_context(|| {
            format!("history entry {id} has an oversized or missing target URL")
        })?;
        ensure!(
            length >= 0 && length <= MAX_REPORT_BYTES as i64,
            "history entry {id} exceeds the {MAX_REPORT_BYTES} byte load limit"
        );
        ensure!(
            version == i64::from(REPORT_SCHEMA_VERSION),
            "history entry {id} uses unsupported report schema version {version}"
        );
        ensure!(
            observations >= 0 && observations <= MAX_OBSERVATIONS as i64,
            "history entry {id} has invalid observation metadata"
        );
        // The length predicate also bounds the second read if another connection
        // changes the row between the metadata query and payload query.
        let json: String = self.connection.query_row(
            "SELECT report_json FROM reports WHERE id = ?1 AND length(CAST(report_json AS BLOB)) <= ?2",
            params![id, MAX_REPORT_BYTES as i64],
            |row| row.get(0),
        ).optional()?.with_context(|| format!("history entry {id} changed during loading or exceeds the load limit"))?;
        let report: ProbeReport = serde_json::from_str(&json).map_err(|error| {
            anyhow::anyhow!(
                "history entry {id} contains malformed report JSON at line {}, column {}",
                error.line(),
                error.column()
            )
        })?;
        report
            .validate_schema()
            .with_context(|| format!("history entry {id} cannot be loaded"))?;
        let actual_errors = report
            .observations
            .iter()
            .filter(|observation| observation.outcome != Outcome::Success)
            .count();
        ensure!(
            report.generated_at_unix <= i64::MAX as u64
                && report.generated_at_unix as i64 == generated_at
                && report.target_url == target_url
                && report.observations.len() == observations as usize
                && actual_errors as i64 == errors,
            "history entry {id} metadata does not match its report"
        );
        Ok(report.sanitized())
    }
}

fn private_file(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "history path must be a regular file, not a directory or symbolic link"
        );
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .context("creating private history file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("setting private history file permissions")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Observation, ResponseSnapshot};
    use std::collections::BTreeMap;

    fn report() -> ProbeReport {
        ProbeReport::new(
            "https://example.com/?token=TARGET-SECRET&q=safe".into(),
            vec![Observation::from_response(
                "wreq",
                Some("chrome_149".into()),
                ResponseSnapshot {
                    status: 200,
                    http_version: "HTTP/2".into(),
                    final_url: "https://example.com/?api_key=FINAL-SECRET&q=safe".into(),
                    headers: BTreeMap::from([("set-cookie".into(), "COOKIE-SECRET".into())]),
                    body: Vec::new(),
                    duration_ms: 30,
                },
            )],
        )
    }

    #[test]
    fn history_round_trip_preserves_sanitized_report_and_private_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.sqlite");
        let history = History::open(&path).unwrap();
        let report = report();
        let id = history.save(&report).unwrap();
        assert_eq!(
            history.load(id).unwrap().to_json().unwrap(),
            report.to_json().unwrap()
        );
        let entries = history.list(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        assert_eq!(entries[0].observation_count, 1);
        assert_eq!(entries[0].error_count, 0);
        let stored: String = history
            .connection
            .query_row(
                "SELECT report_json FROM reports WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stored.contains("SECRET"));
        assert!(stored.contains("q=safe"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn unknown_database_and_old_report_schemas_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("future.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        drop(connection);
        assert!(
            History::open(&path)
                .err()
                .unwrap()
                .to_string()
                .contains("unsupported history database schema")
        );
        let history = History::open(&directory.path().join("current.sqlite")).unwrap();
        let mut old = report();
        old.schema_version = 0;
        assert!(history.save(&old).is_err());
        let id = history.save(&report()).unwrap();
        history
            .connection
            .execute(
                "UPDATE reports SET report_json = ?1 WHERE id = ?2",
                params![serde_json::to_string(&old).unwrap(), id],
            )
            .unwrap();
        assert!(
            format!("{:#}", history.load(id).unwrap_err())
                .contains("unsupported report schema version 0")
        );
    }

    #[test]
    fn malformed_and_oversized_rows_fail_without_echoing_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let history = History::open(&directory.path().join("history.sqlite")).unwrap();
        let id = history.save(&report()).unwrap();
        history
            .connection
            .execute(
                "UPDATE reports SET report_json = ?1 WHERE id = ?2",
                params!["MALFORMED-PRIVATE-PAYLOAD", id],
            )
            .unwrap();
        let error = format!("{:#}", history.load(id).unwrap_err());
        assert!(error.contains("malformed report JSON"));
        assert!(!error.contains("PRIVATE-PAYLOAD"));
        history
            .connection
            .execute(
                "UPDATE reports SET report_json = zeroblob(?1) WHERE id = ?2",
                params![MAX_REPORT_BYTES as i64 + 1, id],
            )
            .unwrap();
        assert!(
            history
                .load(id)
                .unwrap_err()
                .to_string()
                .contains("load limit")
        );
        assert!(
            history
                .load(id + 1)
                .unwrap_err()
                .to_string()
                .contains("does not exist")
        );
        assert!(history.list(MAX_HISTORY_LIST + 1).is_err());
    }

    #[test]
    fn existing_unversioned_data_is_not_modified() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("old.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES ('keep');",
            )
            .unwrap();
        drop(connection);
        assert!(History::open(&path).is_err());
        let connection = Connection::open(path).unwrap();
        let value: String = connection
            .query_row("SELECT value FROM unrelated", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "keep");
    }

    #[test]
    fn deletion_removes_only_the_selected_entry() {
        let directory = tempfile::tempdir().unwrap();
        let history = History::open(&directory.path().join("history.sqlite")).unwrap();
        let kept_report = report();
        let kept_id = history.save(&kept_report).unwrap();
        let removed_id = history.save(&report()).unwrap();
        assert!(history.delete(removed_id).unwrap());
        assert!(history.load(removed_id).is_err());
        assert_eq!(
            history.load(kept_id).unwrap().to_json().unwrap(),
            kept_report.to_json().unwrap()
        );
        assert_eq!(
            history
                .list(10)
                .unwrap()
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            vec![kept_id]
        );
        assert!(!history.delete(removed_id).unwrap());
        assert!(history.delete(0).is_err());
        assert!(history.delete(-1).is_err());
        let secure_delete: i64 = history
            .connection
            .pragma_query_value(None, "secure_delete", |row| row.get(0))
            .unwrap();
        assert_eq!(secure_delete, 1);
    }
}
