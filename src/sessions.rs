//! Durable, origin-scoped proxy cookie jars. Session and credential data is private.

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use cookie_store::CookieStore;
use http::{HeaderValue, Uri, Version};
use rusqlite::{Connection, OptionalExtension, params};
use url::Url;
use uuid::Uuid;
use wreq::cookie::Cookies;

const SCHEMA_VERSION: i64 = 1;
const MAX_SERIALIZED_JAR: usize = 4 * 1024 * 1024;
const MAX_COOKIES: usize = 256;
const MAX_COOKIE_BYTES: usize = 8192;

pub struct SessionDb {
    connection: Mutex<Connection>,
    _process_lock: Option<std::fs::File>,
}

impl SessionDb {
    pub fn open(path: &Path) -> Result<Arc<Self>> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            && !parent.exists()
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .context("opening private session database")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        drop(file);
        let lock_path = path.with_extension("sqlite.lock");
        let lock_file = options
            .open(lock_path)
            .context("opening session database process lock")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            lock_file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        fs2::FileExt::try_lock_exclusive(&lock_file)
            .context("another proxy already uses this session database")?;
        Self::initialize(
            Connection::open(path).context("opening session SQLite database")?,
            Some(lock_file),
        )
    }

    pub fn in_memory() -> Result<Arc<Self>> {
        Self::initialize(Connection::open_in_memory()?, None)
    }

    fn initialize(
        mut connection: Connection,
        process_lock: Option<std::fs::File>,
    ) -> Result<Arc<Self>> {
        connection.busy_timeout(Duration::from_secs(3))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if !matches!(version, 0 | SCHEMA_VERSION) {
            bail!("unsupported session database schema {version}");
        }
        if version == 0 {
            let objects: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if objects != 0 {
                bail!("existing unversioned database is not a proxy session database");
            }
        } else {
            connection.prepare("SELECT scope,id,touched,cookies FROM proxy_sessions LIMIT 0")?;
        }
        connection.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA secure_delete=ON; PRAGMA journal_mode=DELETE;",
        )?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS proxy_sessions (
                scope TEXT NOT NULL,
                id TEXT NOT NULL,
                touched INTEGER NOT NULL,
                cookies TEXT NOT NULL,
                PRIMARY KEY(scope, id)
             );
             CREATE INDEX IF NOT EXISTS proxy_sessions_age ON proxy_sessions(scope, touched);",
        )?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(Arc::new(Self {
            connection: Mutex::new(connection),
            _process_lock: process_lock,
        }))
    }

    pub fn load(
        self: &Arc<Self>,
        scope: &str,
        id: Uuid,
        idle_limit: Duration,
    ) -> Result<Option<Arc<PersistentJar>>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("session database lock poisoned"))?;
        let stored: Option<(i64, String)> = connection
            .query_row(
                "SELECT touched, cookies FROM proxy_sessions WHERE scope=?1 AND id=?2",
                params![scope, id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((touched, cookies)) = stored else {
            return Ok(None);
        };
        if touched < 0 {
            bail!("invalid stored session timestamp");
        }
        if now().saturating_sub(touched)
            >= i64::try_from(idle_limit.as_secs())
                .context("session lifetime is outside SQLite range")?
        {
            connection.execute(
                "DELETE FROM proxy_sessions WHERE scope=?1 AND id=?2",
                params![scope, id.to_string()],
            )?;
            return Ok(None);
        }
        if cookies.len() > MAX_SERIALIZED_JAR {
            bail!("stored session cookie data exceeds its size limit");
        }
        let store = cookie_store::serde::json::load(cookies.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid stored session cookie data"))?;
        if store.iter_unexpired().count() > MAX_COOKIES {
            bail!("stored session contains too many cookies");
        }
        if store
            .iter_unexpired()
            .any(|cookie| cookie.to_string().len() > MAX_COOKIE_BYTES)
        {
            bail!("stored session cookie exceeds its size limit");
        }
        connection.execute(
            "UPDATE proxy_sessions SET touched=?3 WHERE scope=?1 AND id=?2",
            params![scope, id.to_string(), now()],
        )?;
        Ok(Some(Arc::new(PersistentJar::new(
            self.clone(),
            scope.into(),
            id,
            store,
        ))))
    }

    pub fn create(
        self: &Arc<Self>,
        scope: &str,
        id: Uuid,
        idle_limit: Duration,
        limit: usize,
    ) -> Result<Arc<PersistentJar>> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("session database lock poisoned"))?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM proxy_sessions WHERE scope=?1 AND touched<=?2",
            params![
                scope,
                now().saturating_sub(
                    i64::try_from(idle_limit.as_secs())
                        .context("session lifetime is outside SQLite range")?
                )
            ],
        )?;
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM proxy_sessions WHERE scope=?1",
            [scope],
            |row| row.get(0),
        )?;
        if usize::try_from(count).context("invalid stored session count")? >= limit {
            bail!("proxy session capacity reached; active sessions are preserved");
        }
        transaction.execute(
            "INSERT INTO proxy_sessions(scope,id,touched,cookies) VALUES(?1,?2,?3,'[]')",
            params![scope, id.to_string(), now()],
        )?;
        transaction.commit()?;
        Ok(Arc::new(PersistentJar::new(
            self.clone(),
            scope.into(),
            id,
            CookieStore::default(),
        )))
    }

    pub fn touch(&self, scope: &str, id: Uuid) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("session database lock poisoned"))?;
        let updated = connection.execute(
            "UPDATE proxy_sessions SET touched=?3 WHERE scope=?1 AND id=?2",
            params![scope, id.to_string(), now()],
        )?;
        if updated == 0 {
            bail!("proxy session no longer exists");
        }
        Ok(())
    }

    fn store(&self, scope: &str, id: Uuid, data: &str) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("session database lock poisoned"))?;
        let updated = connection.execute(
            "UPDATE proxy_sessions SET cookies=?3,touched=?4 WHERE scope=?1 AND id=?2",
            params![scope, id.to_string(), data, now()],
        )?;
        if updated == 0 {
            bail!("cannot save an expired proxy session");
        }
        Ok(())
    }
}

pub struct PersistentJar {
    db: Arc<SessionDb>,
    scope: String,
    id: Uuid,
    store: Mutex<CookieStore>,
    error: Mutex<Option<String>>,
}

impl PersistentJar {
    fn new(db: Arc<SessionDb>, scope: String, id: Uuid, store: CookieStore) -> Self {
        Self {
            db,
            scope,
            id,
            store: Mutex::new(store),
            error: Mutex::new(None),
        }
    }

    pub fn persistence_error(&self) -> Option<String> {
        self.error.lock().ok().and_then(|error| error.clone())
    }

    fn remember_error(&self, error: String) {
        tracing::error!(%error, "proxy cookie storage failed");
        if let Ok(mut previous) = self.error.lock() {
            *previous = Some(error);
        }
    }
}

fn cookie_url(uri: &Uri) -> Option<Url> {
    let mut url = Url::parse(&uri.to_string()).ok()?;
    if url.scheme() == "ws" {
        url.set_scheme("http").ok()?;
    } else if url.scheme() == "wss" {
        url.set_scheme("https").ok()?;
    }
    Some(url)
}

impl wreq::cookie::CookieStore for PersistentJar {
    fn set_cookies(&self, headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
        let Some(url) = cookie_url(uri) else {
            return;
        };
        let Ok(mut store) = self.store.lock() else {
            self.remember_error("cookie jar lock poisoned".into());
            return;
        };
        for header in headers {
            if header.as_bytes().len() > MAX_COOKIE_BYTES {
                self.remember_error("upstream cookie exceeds 8192 bytes".into());
                continue;
            }
            if let Ok(cookie) = header.to_str() {
                let mut candidate = store.clone();
                if candidate.parse(cookie, &url).is_ok() {
                    if candidate.iter_unexpired().count() > MAX_COOKIES {
                        self.remember_error("upstream cookie count exceeds 256".into());
                        continue;
                    }
                    *store = candidate;
                }
            }
        }
        let mut data = Vec::new();
        *store = CookieStore::from_cookies(
            store
                .iter_unexpired()
                .cloned()
                .map(Ok::<_, std::convert::Infallible>),
            false,
        )
        .expect("copying parsed cookies cannot fail");
        if let Err(error) =
            cookie_store::serde::json::save_incl_expired_and_nonpersistent(&store, &mut data)
        {
            self.remember_error(format!("serializing proxy cookies: {error}"));
            return;
        }
        if data.len() > MAX_SERIALIZED_JAR {
            self.remember_error("proxy cookie snapshot exceeds size limit".into());
            return;
        }
        if let Err(error) = self
            .db
            .store(&self.scope, self.id, &String::from_utf8_lossy(&data))
        {
            self.remember_error(format!("persisting proxy cookies: {error}"));
        }
    }

    fn cookies(&self, uri: &Uri, version: Version) -> Cookies {
        let Some(url) = cookie_url(uri) else {
            return Cookies::Empty;
        };
        let Ok(store) = self.store.lock() else {
            return Cookies::Empty;
        };
        let mut matching = store.matches(&url);
        matching.sort_by_key(|cookie| std::cmp::Reverse(cookie.path.len()));
        let cookies: Vec<String> = matching
            .into_iter()
            .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
            .collect();
        if cookies.is_empty() {
            return Cookies::Empty;
        }
        if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
            Cookies::Uncompressed(
                cookies
                    .iter()
                    .filter_map(|cookie| HeaderValue::from_str(cookie).ok())
                    .collect(),
            )
        } else {
            HeaderValue::from_str(&cookies.join("; "))
                .map(Cookies::Compressed)
                .unwrap_or(Cookies::Empty)
        }
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| i64::try_from(time.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wreq::cookie::CookieStore as _;

    fn value(jar: &PersistentJar, uri: &str) -> String {
        match jar.cookies(&uri.parse().unwrap(), Version::HTTP_11) {
            Cookies::Compressed(value) => value.to_str().unwrap().to_owned(),
            _ => String::new(),
        }
    }

    #[test]
    fn cookies_survive_reopening_and_remain_origin_path_and_secure_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sessions.sqlite");
        let id = Uuid::new_v4();
        let lifetime = Duration::from_secs(1800);
        {
            let db = SessionDb::open(&path).unwrap();
            let jar = db.create("origin-a", id, lifetime, 10).unwrap();
            let header =
                HeaderValue::from_static("session=secret; Path=/private; Secure; HttpOnly");
            jar.set_cookies(
                &mut std::iter::once(&header),
                &"https://example.com/private/login".parse().unwrap(),
            );
            assert!(jar.persistence_error().is_none());
        }
        let db = SessionDb::open(&path).unwrap();
        let jar = db.load("origin-a", id, lifetime).unwrap().unwrap();
        assert_eq!(
            value(&jar, "https://example.com/private/check"),
            "session=secret"
        );
        assert_eq!(
            value(&jar, "wss://example.com/private/socket"),
            "session=secret"
        );
        assert!(value(&jar, "http://example.com/private/check").is_empty());
        assert!(value(&jar, "https://example.com/public").is_empty());
        assert!(value(&jar, "https://other.example/private/check").is_empty());
        assert!(db.load("origin-b", id, lifetime).unwrap().is_none());
    }

    #[test]
    fn capacity_does_not_evict_active_sessions_and_expired_sessions_are_removed() {
        let db = SessionDb::in_memory().unwrap();
        let id = Uuid::new_v4();
        let lifetime = Duration::from_secs(1800);
        db.create("scope", id, lifetime, 1).unwrap();
        assert!(db.create("scope", Uuid::new_v4(), lifetime, 1).is_err());
        assert!(db.load("scope", id, lifetime).unwrap().is_some());
        db.connection
            .lock()
            .unwrap()
            .execute("UPDATE proxy_sessions SET touched=0", [])
            .unwrap();
        assert!(db.load("scope", id, lifetime).unwrap().is_none());
        assert!(db.create("scope", Uuid::new_v4(), lifetime, 1).is_ok());
    }

    #[test]
    fn corrupt_cookie_data_is_reported_instead_of_overwritten() {
        let db = SessionDb::in_memory().unwrap();
        let id = Uuid::new_v4();
        let lifetime = Duration::from_secs(1800);
        db.create("scope", id, lifetime, 1).unwrap();
        db.connection
            .lock()
            .unwrap()
            .execute("UPDATE proxy_sessions SET cookies='invalid json'", [])
            .unwrap();
        assert!(db.load("scope", id, lifetime).is_err());
    }

    #[test]
    fn duplicate_cookie_names_put_the_most_specific_path_first() {
        let db = SessionDb::in_memory().unwrap();
        let jar = db
            .create("scope", Uuid::new_v4(), Duration::from_secs(1800), 1)
            .unwrap();
        let headers = [
            HeaderValue::from_static("name=root; Path=/"),
            HeaderValue::from_static("name=private; Path=/private"),
        ];
        jar.set_cookies(
            &mut headers.iter(),
            &"https://example.com/private/login".parse().unwrap(),
        );
        assert_eq!(
            value(&jar, "https://example.com/private/check"),
            "name=private; name=root"
        );
    }

    #[test]
    fn second_proxy_cannot_open_the_same_persistent_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.sqlite");
        let first = SessionDb::open(&path).unwrap();
        assert!(SessionDb::open(&path).is_err());
        drop(first);
        assert!(SessionDb::open(&path).is_ok());
    }

    #[test]
    fn unrelated_databases_are_rejected_without_changing_their_schema() {
        let directory = tempfile::tempdir().unwrap();
        for version in [0, 1, 2] {
            let path = directory.path().join(format!("unrelated-{version}.sqlite"));
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch("CREATE TABLE unrelated (value TEXT); INSERT INTO unrelated VALUES ('retained');")
                .unwrap();
            connection
                .pragma_update(None, "user_version", version)
                .unwrap();
            drop(connection);
            assert!(SessionDb::open(&path).is_err());
            let connection = Connection::open(&path).unwrap();
            let value: String = connection
                .query_row("SELECT value FROM unrelated", [], |row| row.get(0))
                .unwrap();
            assert_eq!(value, "retained");
            let tables: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(tables, 1);
            let stored_version: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            assert_eq!(stored_version, version);
        }
    }
}
