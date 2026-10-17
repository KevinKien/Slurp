/// Traffic storage using SQLite.
///
/// Stores all captured HTTP request/response pairs and provides
/// a broadcast channel for real-time notification to Web UI / MCP.
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension,params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use uuid::Uuid;

/// A captured HTTP request/response pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    #[serde(default)]
    pub bookmarked: bool,
    #[serde(default)]
    pub notes: String,
    pub id: String,
    pub timestamp: DateTime<Utc>,
    /// HTTP method: GET, POST, etc.
    pub method: String,
    /// Full URL: https://example.com/api/data?q=1
    pub url: String,
    /// Just the host: example.com
    pub host: String,
    /// URL path: /api/data
    pub path: String,
    /// HTTP or HTTPS
    pub scheme: String,
    /// Request headers as JSON
    pub request_headers: String,
    /// Request body (may be empty, truncated for large bodies)
    pub request_body: Vec<u8>,
    /// Content-Type of request
    pub request_content_type: Option<String>,
    /// Response status code (0 if no response yet)
    pub status_code: u16,
    /// Response headers as JSON
    pub response_headers: String,
    /// Response body
    pub response_body: Vec<u8>,
    /// Content-Type of response
    pub response_content_type: Option<String>,
    /// Time taken in milliseconds
    pub duration_ms: u64,
    /// Size of request body in bytes
    pub request_size: u64,
    /// Size of response body in bytes
    pub response_size: u64,
    /// Error message if the request failed
    pub error: Option<String>,
    /// Workspace this entry belongs to (assigned by storage on first insert)
    #[serde(default = "default_workspace_id")]
    pub workspace_id: String,
    /// Where the request came from: "proxy" (captured traffic) or "replay" (sent from the Replay tool)
    #[serde(default = "default_source")]
    pub source: String,
}

/// Id of the built-in workspace that always exists and cannot be deleted.
pub const DEFAULT_WORKSPACE_ID: &str = "default";

fn default_workspace_id() -> String {
    DEFAULT_WORKSPACE_ID.to_string()
}

fn default_source() -> String {
    "proxy".to_string()
}

/// Pseudo-workspace for traffic that is kept in memory only. It is never written to disk and
/// disappears when the tool exits. It is not a row in `workspaces`, so it cannot be renamed or deleted.
pub const TEMP_WORKSPACE_ID: &str = "temporary";

/// Where newly captured traffic goes. Every launch starts as `Unchosen`; until the user picks
/// something, traffic is held in memory exactly as for `Temporary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Unchosen,
    Temporary,
    Workspace(String),
}

/// Session state shown to the UI so it can ask the user to pick a workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// "unchosen", "temporary" or "workspace"
    pub target: String,
    /// The workspace receiving traffic, when `target` is "workspace"
    pub workspace_id: Option<String>,
    /// Number of requests currently held in memory only
    pub temporary_count: u64,
}

/// Serialize header pairs to the JSON shape stored in history: `{"name": ["value", ...]}`.
pub fn pairs_to_json(headers: &[(String, String)]) -> String {
    let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (name, value) in headers {
        map.entry(name.to_ascii_lowercase()).or_default().push(value.clone());
    }
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
}

impl TrafficEntry {
    /// Create a new entry with just the request info (response pending).
    pub fn new_request(
        method: &str,
        url: &str,
        host: &str,
        path: &str,
        scheme: &str,
        headers: &str,
        body: Vec<u8>,
        content_type: Option<String>,
    ) -> Self {
        let request_size = body.len() as u64;
        Self {
            bookmarked: false,
            notes: String::new(),
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            method: method.to_string(),
            url: url.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            scheme: scheme.to_string(),
            request_headers: headers.to_string(),
            request_body: body,
            request_content_type: content_type,
            status_code: 0,
            response_headers: String::new(),
            response_body: Vec::new(),
            response_content_type: None,
            duration_ms: 0,
            request_size,
            response_size: 0,
            error: None,
            workspace_id: default_workspace_id(),
            source: default_source(),
        }
    }
}

/// Real-time traffic event sent to subscribers (Web UI, MCP, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TrafficEvent {
    #[serde(rename = "entry_deleted")]
    EntryDeleted { id: String },
    AnnotationChanged { id: String, bookmarked: bool, notes: String },
    /// A new request/response has been captured
    #[serde(rename = "new_entry")]
    NewEntry { entry: TrafficEntry },
    /// An existing entry has been updated (e.g., response received)
    #[serde(rename = "entry_updated")]
    EntryUpdated { entry: TrafficEntry },
    /// All entries have been cleared
    #[serde(rename = "cleared")]
    Cleared,
    /// All entries of one workspace have been cleared
    #[serde(rename = "workspace_cleared")]
    WorkspaceCleared { workspace_id: String },
    /// A workspace was created, renamed, deleted or the capture target changed
    #[serde(rename = "workspaces_changed")]
    WorkspacesChanged,
    #[serde(rename = "replay_changed")]
    ReplayChanged { workspace_id: String, document: serde_json::Value },
    #[serde(rename = "replay_result")]
    ReplayResult { workspace_id: String, tab_id: u64, entry: TrafficEntry },
    /// A request or response is being held by the interceptor
    #[serde(rename = "intercept_queued")]
    InterceptQueued { item: crate::intercept::HeldItem },
    /// A held item was forwarded, dropped, timed out, or its client went away
    #[serde(rename = "intercept_resolved")]
    InterceptResolved { id: String },
    #[serde(rename = "scope_changed")]
    ScopeChanged { scope: crate::intercept::ScopeSettings },
    /// Interception was switched on or off
    #[serde(rename = "intercept_settings")]
    InterceptSettings { requests: bool, responses: bool },
}

/// A named group of captured traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub request_count: u64,
    /// True for the workspace that receives newly captured traffic.
    pub active: bool,
}

/// Why a workspace operation failed; maps to HTTP statuses in the API layer.
#[derive(Debug)]
pub enum WorkspaceError {
    InvalidName,
    NameTaken,
    NotFound,
    /// The default workspace cannot be deleted.
    Protected,
    Other(anyhow::Error),
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName => write!(f, "workspace name must be 1-60 characters"),
            Self::NameTaken => write!(f, "a workspace with this name already exists"),
            Self::NotFound => write!(f, "workspace not found"),
            Self::Protected => write!(f, "the default workspace cannot be deleted"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

impl From<rusqlite::Error> for WorkspaceError {
    fn from(e: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(err, _) = &e {
            if err.code == rusqlite::ErrorCode::ConstraintViolation {
                return Self::NameTaken;
            }
        }
        Self::Other(e.into())
    }
}

/// Optional filters shared by listing, counting and stats. `None` means "any".
#[derive(Debug, Default, Clone)]
pub struct TrafficFilter<'a> {
    pub host: Option<&'a str>,
    pub method: Option<&'a str>,
    pub status: Option<u16>,
    pub search: Option<&'a str>,
    pub workspace: Option<&'a str>,
}

impl TrafficFilter<'_> {
    /// Build the WHERE clause (starting with " WHERE 1=1") and its parameters.
    fn to_sql(&self) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
        let mut sql = String::from(" WHERE 1=1");
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(host) = self.host {
            sql.push_str(" AND host LIKE ?");
            params.push(Box::new(format!("%{}%", host)));
        }
        if let Some(method) = self.method {
            sql.push_str(" AND method = ?");
            params.push(Box::new(method.to_string()));
        }
        if let Some(status) = self.status {
            sql.push_str(" AND status_code = ?");
            params.push(Box::new(status));
        }
        if let Some(q) = self.search {
            sql.push_str(" AND (url LIKE ? OR request_headers LIKE ? OR response_headers LIKE ? OR notes LIKE ?)");
            let pattern = format!("%{}%", q);
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern));
        }
        if let Some(ws) = self.workspace {
            sql.push_str(" AND workspace_id = ?");
            params.push(Box::new(ws.to_string()));
        }
        (sql, params)
    }
}

const ENTRY_COLUMNS: &str = "id, timestamp, method, url, host, path, scheme,
    request_headers, request_body, request_content_type,
    status_code, response_headers, response_body, response_content_type,
    duration_ms, request_size, response_size, error, workspace_id, source, bookmarked, notes";

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<TrafficEntry> {
    Ok(TrafficEntry {
        id: row.get(0)?,
        timestamp: row
            .get::<_, String>(1)?
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now()),
        method: row.get(2)?,
        url: row.get(3)?,
        host: row.get(4)?,
        path: row.get(5)?,
        scheme: row.get(6)?,
        request_headers: row.get(7)?,
        request_body: row.get(8)?,
        request_content_type: row.get(9)?,
        status_code: row.get(10)?,
        response_headers: row.get(11)?,
        response_body: row.get(12)?,
        response_content_type: row.get(13)?,
        duration_ms: row.get(14)?,
        request_size: row.get(15)?,
        response_size: row.get(16)?,
        error: row.get(17)?,
        workspace_id: row.get(18)?,
        source: row.get(19)?,
        bookmarked: row.get(20)?,
        notes: row.get(21)?,
    })
}

const TRAFFIC_TABLE: &str = "CREATE TABLE IF NOT EXISTS traffic (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    scheme TEXT NOT NULL DEFAULT 'http',
    request_headers TEXT NOT NULL DEFAULT '{}',
    request_body BLOB NOT NULL DEFAULT x'',
    request_content_type TEXT,
    status_code INTEGER NOT NULL DEFAULT 0,
    response_headers TEXT NOT NULL DEFAULT '{}',
    response_body BLOB NOT NULL DEFAULT x'',
    response_content_type TEXT,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    request_size INTEGER NOT NULL DEFAULT 0,
    response_size INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    workspace_id TEXT NOT NULL DEFAULT 'default',
    bookmarked INTEGER NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'proxy'
);";

/// Add a column to databases created before it existed.
fn ensure_column(conn: &Connection, name: &str, definition: &str) -> Result<()> {
    let exists = conn
        .prepare("SELECT 1 FROM pragma_table_info('traffic') WHERE name = ?1")?
        .exists(params![name])?;
    if !exists {
        conn.execute_batch(&format!("ALTER TABLE traffic ADD COLUMN {name} {definition};"))?;
    }
    Ok(())
}

fn write_entry(conn: &Connection, entry: &TrafficEntry) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO traffic (
            id, timestamp, method, url, host, path, scheme,
            request_headers, request_body, request_content_type,
            status_code, response_headers, response_body, response_content_type,
            duration_ms, request_size, response_size, error, workspace_id, source
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20) ON CONFLICT(id) DO UPDATE SET timestamp=excluded.timestamp, method=excluded.method, url=excluded.url, host=excluded.host, path=excluded.path, scheme=excluded.scheme, request_headers=excluded.request_headers, request_body=excluded.request_body, request_content_type=excluded.request_content_type, status_code=excluded.status_code, response_headers=excluded.response_headers, response_body=excluded.response_body, response_content_type=excluded.response_content_type, duration_ms=excluded.duration_ms, request_size=excluded.request_size, response_size=excluded.response_size, error=excluded.error, workspace_id=excluded.workspace_id, source=excluded.source",
        params![
            entry.id,
            entry.timestamp.to_rfc3339(),
            entry.method,
            entry.url,
            entry.host,
            entry.path,
            entry.scheme,
            entry.request_headers,
            entry.request_body,
            entry.request_content_type,
            entry.status_code,
            entry.response_headers,
            entry.response_body,
            entry.response_content_type,
            entry.duration_ms,
            entry.request_size,
            entry.response_size,
            entry.error,
            entry.workspace_id,
            entry.source,
        ],
    )
}

/// Manages traffic storage and real-time broadcasting.
///
/// Saved workspaces live in SQLite on disk. Traffic captured without a workspace lives in a
/// second, in-memory SQLite database that is never written to disk and is gone on exit.
pub struct TrafficStorage {
    db: Mutex<Connection>,
    /// In-memory database for the temporary session
    mem: Mutex<Connection>,
    /// Broadcast channel for real-time events
    tx: broadcast::Sender<TrafficEvent>,
    /// Maximum body size to store (bytes). Larger bodies are truncated.
    max_body_size: usize,
    /// Where new traffic goes. Deliberately not persisted: every launch asks again.
    target: Mutex<Target>,
}

impl TrafficStorage {
    /// Create a new storage. Pass ":memory:" for in-memory or a file path.
    pub fn new(db_path: &str, max_body_size: usize) -> Result<Arc<Self>> {
        let conn = if db_path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            // Ensure parent directory exists
            if let Some(parent) = Path::new(db_path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            Connection::open(db_path)?
        };

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        conn.execute_batch(TRAFFIC_TABLE)?;
        conn.execute_batch(crate::websocket::SCHEMA)?;
        conn.execute("UPDATE websocket_connections SET closed_at=?1,error='Slurp restarted' WHERE closed_at IS NULL", params![Utc::now().to_rfc3339()])?;
        // Migrations: databases created before these columns existed.
        ensure_column(&conn, "workspace_id", &format!("TEXT NOT NULL DEFAULT '{DEFAULT_WORKSPACE_ID}'"))?;
        ensure_column(&conn, "source", "TEXT NOT NULL DEFAULT 'proxy'")?;
        ensure_column(&conn, "bookmarked", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_column(&conn, "notes", "TEXT NOT NULL DEFAULT ''")?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp); CREATE INDEX IF NOT EXISTS idx_traffic_cursor ON traffic(timestamp, id); CREATE INDEX IF NOT EXISTS idx_traffic_workspace_cursor ON traffic(workspace_id, timestamp, id);
            CREATE INDEX IF NOT EXISTS idx_traffic_host ON traffic(host);
            CREATE INDEX IF NOT EXISTS idx_traffic_method ON traffic(method);
            CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic(status_code);
            CREATE INDEX IF NOT EXISTS idx_traffic_workspace ON traffic(workspace_id);

            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                created_at TEXT NOT NULL
            );

            -- Replay tabs per workspace, stored as one JSON document (tabs + which one is active).
            CREATE TABLE IF NOT EXISTS replay_runs (
                id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, tab_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL, data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_replay_runs_tab ON replay_runs(workspace_id, tab_id, timestamp, id);
            CREATE INDEX IF NOT EXISTS idx_traffic_bookmark ON traffic(bookmarked, timestamp, id);
            CREATE TABLE IF NOT EXISTS scan_runs (
                workspace_id TEXT NOT NULL, id TEXT NOT NULL, started_at TEXT NOT NULL, data TEXT NOT NULL,
                PRIMARY KEY(workspace_id,id)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_runs_time ON scan_runs(workspace_id,started_at DESC);
            CREATE TABLE IF NOT EXISTS intruder_documents (workspace_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS intruder_sources (workspace_id TEXT NOT NULL,id TEXT NOT NULL,name TEXT NOT NULL,count INTEGER NOT NULL DEFAULT 0,bytes INTEGER NOT NULL DEFAULT 0,ready INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,PRIMARY KEY(workspace_id,id));
            CREATE TABLE IF NOT EXISTS intruder_payloads (workspace_id TEXT NOT NULL,source_id TEXT NOT NULL,ordinal INTEGER NOT NULL,value TEXT NOT NULL,PRIMARY KEY(workspace_id,source_id,ordinal));
            CREATE TABLE IF NOT EXISTS intruder_runs (workspace_id TEXT NOT NULL,id TEXT NOT NULL,started_at TEXT NOT NULL,data TEXT NOT NULL,completed INTEGER NOT NULL DEFAULT 0,bytes INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(workspace_id,id));
            CREATE TABLE IF NOT EXISTS intruder_results (workspace_id TEXT NOT NULL,run_id TEXT NOT NULL,ordinal INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(workspace_id,run_id,ordinal));
            CREATE INDEX IF NOT EXISTS idx_intruder_runs_time ON intruder_runs(workspace_id,started_at,id);
            CREATE TABLE IF NOT EXISTS auth_profiles (
                workspace_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS matrix_runs (
                workspace_id TEXT NOT NULL, id TEXT NOT NULL, started_at TEXT NOT NULL,
                data TEXT NOT NULL, PRIMARY KEY(workspace_id,id)
            );
            CREATE INDEX IF NOT EXISTS idx_matrix_runs_time ON matrix_runs(workspace_id,started_at,id);
            CREATE TABLE IF NOT EXISTS flow_documents (
                workspace_id TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS flow_runs (
                workspace_id TEXT NOT NULL, id TEXT NOT NULL, started_at TEXT NOT NULL,
                data TEXT NOT NULL, PRIMARY KEY(workspace_id,id)
            );
            CREATE INDEX IF NOT EXISTS idx_flow_runs_time ON flow_runs(workspace_id,started_at,id);
            CREATE TABLE IF NOT EXISTS replay_tabs (
                workspace_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO workspaces (id, name, created_at) VALUES (?1, 'Default', ?2)",
            params![DEFAULT_WORKSPACE_ID, Utc::now().to_rfc3339()],
        )?;

        let mem = Connection::open_in_memory()?;
        mem.execute_batch(TRAFFIC_TABLE)?;
        mem.execute_batch(crate::websocket::SCHEMA)?;
        mem.execute_batch("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp); CREATE INDEX IF NOT EXISTS idx_traffic_cursor ON traffic(timestamp, id); CREATE INDEX IF NOT EXISTS idx_traffic_workspace_cursor ON traffic(workspace_id, timestamp, id);")?;

        let (tx, _) = broadcast::channel(1024);

        Ok(Arc::new(Self {
            db: Mutex::new(conn),
            mem: Mutex::new(mem),
            tx,
            max_body_size,
            target: Mutex::new(Target::Unchosen),
        }))
    }

    /// Broadcast an event to all subscribers (ignored when nobody is listening).
    pub fn publish(&self, event: TrafficEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to real-time traffic events.
    pub fn subscribe(&self) -> broadcast::Receiver<TrafficEvent> {
        self.tx.subscribe()
    }

    fn lock_db(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.db.lock().map_err(|e| anyhow::anyhow!("DB lock: {}", e))
    }

    fn lock_mem(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.mem.lock().map_err(|e| anyhow::anyhow!("memory DB lock: {}", e))
    }

    /// The database holding a workspace: memory for the temporary session, disk otherwise
    /// (including "all workspaces", which means all *saved* workspaces).
    pub(crate) fn lock_for(&self, workspace: Option<&str>) -> Result<std::sync::MutexGuard<'_, Connection>> {
        if workspace == Some(TEMP_WORKSPACE_ID) {
            self.lock_mem()
        } else {
            self.lock_db()
        }
    }

    /// Where new traffic is going right now.
    pub fn target(&self) -> Target {
        self.target.lock().map(|t| t.clone()).unwrap_or(Target::Unchosen)
    }

    fn set_target(&self, target: Target) {
        if let Ok(mut t) = self.target.lock() {
            *t = target;
        }
        self.notify_workspaces_changed();
    }

    /// Session state for the UI.
    pub fn session(&self) -> Result<SessionInfo> {
        let temporary_count: u64 = self.lock_mem()?.query_row("SELECT COUNT(*) FROM traffic", [], |r| r.get(0))?;
        let (target, workspace_id) = match self.target() {
            Target::Unchosen => ("unchosen", None),
            Target::Temporary => ("temporary", None),
            Target::Workspace(id) => ("workspace", Some(id)),
        };
        Ok(SessionInfo { target: target.to_string(), workspace_id, temporary_count })
    }

    /// Keep new traffic in memory only. Counts as a deliberate choice (the UI stops asking).
    pub fn use_temporary(&self) {
        self.set_target(Target::Temporary);
    }

    /// Insert a complete traffic entry (request + response).
    ///
    /// New entries go to the chosen workspace on disk, or to memory when no workspace is chosen.
    /// Re-inserting an existing id keeps it where it was first stored.
    pub fn insert(&self, entry: &TrafficEntry) -> Result<()> {
        let mut entry = entry.clone();

        // Truncate bodies if too large
        if entry.request_body.len() > self.max_body_size {
            entry.request_body.truncate(self.max_body_size);
        }
        if entry.response_body.len() > self.max_body_size {
            entry.response_body.truncate(self.max_body_size);
        }

        // Locks are taken one at a time, never nested.
        let existing_on_disk: Option<String> = self
            .lock_db()?
            .query_row("SELECT workspace_id FROM traffic WHERE id = ?1", params![entry.id], |r| r.get(0))
            .ok();
        let existing_in_memory = self
            .lock_mem()?
            .query_row("SELECT 1 FROM traffic WHERE id = ?1", params![entry.id], |_| Ok(()))
            .is_ok();

        let in_memory = match (&existing_on_disk, existing_in_memory) {
            (Some(ws), _) => {
                entry.workspace_id = ws.clone();
                false
            }
            (None, true) => {
                entry.workspace_id = TEMP_WORKSPACE_ID.to_string();
                true
            }
            (None, false) => match self.target() {
                Target::Workspace(id) => {
                    entry.workspace_id = id;
                    false
                }
                Target::Temporary | Target::Unchosen => {
                    entry.workspace_id = TEMP_WORKSPACE_ID.to_string();
                    true
                }
            },
        };

        let conn = if in_memory { self.lock_mem()? } else { self.lock_db()? };
        write_entry(&conn, &entry)?;
        (entry.bookmarked,entry.notes)=conn.query_row("SELECT bookmarked,notes FROM traffic WHERE id=?1",params![entry.id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        drop(conn);

        // Broadcast to subscribers (ignore error if no subscribers)
        let _ = self.tx.send(TrafficEvent::NewEntry { entry });

        Ok(())
    }

    /// Save a replay to its explicit workspace without changing the capture target.
    pub fn insert_in_workspace(&self, entry: &TrafficEntry, workspace: &str) -> Result<()> {
        let mut entry = entry.clone();
        entry.workspace_id = workspace.to_string();
        entry.request_body.truncate(self.max_body_size);
        entry.response_body.truncate(self.max_body_size);
        let db = self.lock_db()?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id = ?1")?.exists(params![workspace])? {
            anyhow::bail!("Workspace not found");
        }
        write_entry(&db, &entry)?;
        (entry.bookmarked,entry.notes)=db.query_row("SELECT bookmarked,notes FROM traffic WHERE id=?1",params![entry.id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        drop(db);
        self.publish(TrafficEvent::NewEntry { entry });
        Ok(())
    }

    /// List traffic entries (newest first) matching the filter.
    pub fn list(&self, limit: usize, offset: usize, filter: &TrafficFilter<'_>) -> Result<Vec<TrafficEntry>> {
        let db = self.lock_for(filter.workspace)?;
        let (where_sql, mut param_values) = filter.to_sql();
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM traffic{where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        );
        param_values.push(Box::new(limit as i64));
        param_values.push(Box::new(offset as i64));
        let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = db.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), row_to_entry)?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Keyset pagination: the cursor contains the last (timestamp, id), so new
    /// captures do not shift later pages. Both directions use the same tie-breaker.
    pub fn history_page(&self, limit: usize, filter: &TrafficFilter<'_>, cursor: Option<(&str, &str)>, ascending: bool, domains: &[String], status_class: Option<u16>, bookmarked: bool) -> Result<(Vec<TrafficEntry>, u64)> {
        let db = self.lock_for(filter.workspace)?;
        let (mut clause, mut values) = filter.to_sql();
        if bookmarked { clause.push_str(" AND bookmarked = 1"); }
        if !domains.is_empty() {
            clause.push_str(&format!(" AND lower(rtrim(host, '.')) IN ({})", vec!["?"; domains.len()].join(",")));
            for domain in domains { values.push(Box::new(domain.clone())); }
        }
        if let Some(class) = status_class {
            clause.push_str(" AND status_code >= ? AND status_code < ?");
            values.push(Box::new(class as i64 * 100));
            values.push(Box::new((class as i64 + 1) * 100));
        }
        let refs: Vec<&dyn rusqlite::types::ToSql> = values.iter().map(|v| v.as_ref()).collect();
        let total = db.query_row(&format!("SELECT COUNT(*) FROM traffic{clause}"), refs.as_slice(), |r| r.get(0))?;
        if let Some((timestamp, id)) = cursor {
            clause.push_str(if ascending { " AND (timestamp, id) > (?, ?)" } else { " AND (timestamp, id) < (?, ?)" });
            values.push(Box::new(timestamp.to_string()));
            values.push(Box::new(id.to_string()));
        }
        let direction = if ascending { "ASC" } else { "DESC" };
        values.push(Box::new(limit as i64));
        let refs: Vec<&dyn rusqlite::types::ToSql> = values.iter().map(|v| v.as_ref()).collect();
        // Lists do not read large body blobs; GET /api/traffic/:id supplies them on demand.
        let columns = ENTRY_COLUMNS.replace("request_body,", "X'' AS request_body,").replace("response_body,", "X'' AS response_body,");
        let mut statement = db.prepare(&format!("SELECT {columns} FROM traffic{clause} ORDER BY timestamp {direction}, id {direction} LIMIT ?"))?;
        let entries = statement.query_map(refs.as_slice(), row_to_entry)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((entries, total))
    }

    pub fn annotate(&self, id: &str, bookmarked: Option<bool>, notes: Option<&str>) -> Result<Option<(bool, String)>> {
        if notes.is_some_and(|n| n.len() > 16_000) { anyhow::bail!("Notes exceed 16 KB"); }
        for db in [self.lock_db()?, self.lock_mem()?] {
            let changed = db.execute("UPDATE traffic SET bookmarked = COALESCE(?2, bookmarked), notes = COALESCE(?3, notes) WHERE id = ?1", params![id, bookmarked, notes])?;
            if changed > 0 {
                let value: (bool, String) = db.query_row("SELECT bookmarked, notes FROM traffic WHERE id = ?1",params![id], |r| Ok((r.get(0)?,r.get(1)?)))?;
                self.publish(TrafficEvent::AnnotationChanged { id: id.into(), bookmarked: value.0, notes: value.1.clone() });
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    /// Immutable full snapshots live outside the tabs document, so autosaving tabs
    /// cannot erase runs and list queries never load all response bodies.
    pub fn max_replay_tab_id(&self, workspace: &str) -> Result<u64> {
        Ok(self.lock_db()?.query_row("SELECT COALESCE(MAX(tab_id),0) FROM replay_runs WHERE workspace_id=?1",params![workspace],|r|r.get(0))?)
    }

    pub fn add_replay_run(&self, workspace: &str, tab: u64, mut data: serde_json::Value) -> Result<serde_json::Value> {
        let db = self.lock_db()?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? { anyhow::bail!("Workspace not found"); }
        let id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        data["id"] = serde_json::json!(id); data["timestamp"] = serde_json::json!(timestamp);
        db.execute("INSERT INTO replay_runs(id,workspace_id,tab_id,timestamp,data) VALUES(?1,?2,?3,?4,?5)",params![id,workspace,tab,timestamp,data.to_string()])?;
        Ok(data)
    }

    pub fn list_replay_runs(&self, workspace: &str, tab: u64, offset: usize) -> Result<Vec<serde_json::Value>> {
        let db = self.lock_db()?;
        let mut statement = db.prepare("SELECT json_object('id',id,'timestamp',timestamp,'method',json_extract(data,'$.request.method'),'url',json_extract(data,'$.request.url'),'status',json_extract(data,'$.response.status'),'duration',json_extract(data,'$.duration'),'error',json_extract(data,'$.error')) FROM replay_runs WHERE workspace_id=?1 AND tab_id=?2 ORDER BY timestamp DESC,id DESC LIMIT 50 OFFSET ?3")?;
        let rows = statement.query_map(params![workspace,tab,offset], |r| r.get::<_,String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }

    pub fn get_replay_run(&self, workspace: &str, tab: u64, id: &str) -> Result<Option<serde_json::Value>> {
        let db = self.lock_db()?;
        match db.query_row("SELECT data FROM replay_runs WHERE workspace_id=?1 AND tab_id=?2 AND id=?3",params![workspace,tab,id],|r|r.get::<_,String>(0)) {
            Ok(data) => Ok(Some(serde_json::from_str(&data)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Delete a single captured entry from its saved or temporary store.
    pub fn delete(&self, id: &str) -> Result<bool> {
        for db in [self.lock_db()?, self.lock_mem()?] {
            if db.execute("DELETE FROM traffic WHERE id = ?1", params![id])? > 0 {
                let _ = self.tx.send(TrafficEvent::EntryDeleted { id: id.to_owned() });
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Get a single traffic entry by ID, from disk or from the temporary session.
    pub fn get(&self, id: &str) -> Result<Option<TrafficEntry>> {
        for conn in [self.lock_db()?, self.lock_mem()?] {
            let mut stmt = conn.prepare(&format!("SELECT {ENTRY_COLUMNS} FROM traffic WHERE id = ?1"))?;
            let mut rows = stmt.query_map(params![id], row_to_entry)?;
            if let Some(entry) = rows.next() {
                return Ok(Some(entry?));
            }
        }
        Ok(None)
    }

    /// Get traffic statistics, optionally for a single workspace.
    pub fn stats(&self, workspace: Option<&str>) -> Result<TrafficStats> {
        let db = self.lock_for(workspace)?;
        let filter = TrafficFilter { workspace, ..Default::default() };
        let (where_sql, param_values) = filter.to_sql();
        let refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();

        let total: u64 = db.query_row(&format!("SELECT COUNT(*) FROM traffic{where_sql}"), refs.as_slice(), |r| r.get(0))?;
        let total_request_bytes: u64 = db.query_row(
            &format!("SELECT COALESCE(SUM(request_size), 0) FROM traffic{where_sql}"),
            refs.as_slice(),
            |r| r.get(0),
        )?;
        let total_response_bytes: u64 = db.query_row(
            &format!("SELECT COALESCE(SUM(response_size), 0) FROM traffic{where_sql}"),
            refs.as_slice(),
            |r| r.get(0),
        )?;
        let error_count: u64 = db.query_row(
            &format!("SELECT COUNT(*) FROM traffic{where_sql} AND error IS NOT NULL"),
            refs.as_slice(),
            |r| r.get(0),
        )?;

        let mut stmt = db.prepare(&format!(
            "SELECT host, COUNT(*) as cnt FROM traffic{where_sql} GROUP BY host ORDER BY cnt DESC LIMIT 10"
        ))?;
        let top_hosts: Vec<(String, u64)> = stmt
            .query_map(refs.as_slice(), |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(TrafficStats {
            total_requests: total,
            total_request_bytes,
            total_response_bytes,
            error_count,
            top_hosts,
        })
    }

    /// Clear traffic: one workspace (or the temporary session) if given, otherwise everything,
    /// temporary session included.
    pub fn clear(&self, workspace: Option<&str>) -> Result<()> {
        self.clear_websockets(workspace)?;
        match workspace {
            Some(TEMP_WORKSPACE_ID) => {
                self.lock_mem()?.execute("DELETE FROM traffic", [])?;
            }
            Some(ws) => {
                self.lock_db()?.execute("DELETE FROM traffic WHERE workspace_id = ?1", params![ws])?;
            }
            None => {
                self.lock_db()?.execute("DELETE FROM traffic", [])?;
                self.lock_mem()?.execute("DELETE FROM traffic", [])?;
            }
        }

        let _ = self.tx.send(match workspace {
            Some(ws) => TrafficEvent::WorkspaceCleared { workspace_id: ws.to_string() },
            None => TrafficEvent::Cleared,
        });
        Ok(())
    }

    /// Count entries matching the filter (ignores limit/offset, so it is the true total).
    pub fn count(&self, filter: &TrafficFilter<'_>) -> Result<u64> {
        let db = self.lock_for(filter.workspace)?;
        let (where_sql, param_values) = filter.to_sql();
        let refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        Ok(db.query_row(&format!("SELECT COUNT(*) FROM traffic{where_sql}"), refs.as_slice(), |r| r.get(0))?)
    }

    // ── Workspaces ───────────────────────────────────────────────

    fn notify_workspaces_changed(&self) {
        let _ = self.tx.send(TrafficEvent::WorkspacesChanged);
    }

    fn clean_name(name: &str) -> Result<String, WorkspaceError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
            return Err(WorkspaceError::InvalidName);
        }
        Ok(name.to_string())
    }

    /// All saved workspaces with their request counts, oldest first (Default first).
    pub fn list_workspaces(&self) -> Result<Vec<Workspace>> {
        let active = match self.target() {
            Target::Workspace(id) => Some(id),
            _ => None,
        };
        let db = self.lock_db()?;
        let mut stmt = db.prepare(
            "SELECT w.id, w.name, w.created_at,
                    (SELECT COUNT(*) FROM traffic t WHERE t.workspace_id = w.id)
             FROM workspaces w ORDER BY (w.id = 'default') DESC, w.created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            Ok(Workspace {
                active: active.as_deref() == Some(id.as_str()),
                id,
                name: row.get(1)?,
                created_at: row.get::<_, String>(2)?.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now()),
                request_count: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn create_workspace(&self, name: &str) -> Result<Workspace, WorkspaceError> {
        let name = Self::clean_name(name)?;
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        {
            let db = self.lock_db().map_err(WorkspaceError::Other)?;
            db.execute(
                "INSERT INTO workspaces (id, name, created_at) VALUES (?1, ?2, ?3)",
                params![id, name, created_at.to_rfc3339()],
            )?;
        }
        self.notify_workspaces_changed();
        Ok(Workspace { id, name, created_at, request_count: 0, active: false })
    }

    pub fn rename_workspace(&self, id: &str, name: &str) -> Result<(), WorkspaceError> {
        let name = Self::clean_name(name)?;
        let changed = {
            let db = self.lock_db().map_err(WorkspaceError::Other)?;
            db.execute("UPDATE workspaces SET name = ?1 WHERE id = ?2", params![name, id])?
        };
        if changed == 0 {
            return Err(WorkspaceError::NotFound);
        }
        self.notify_workspaces_changed();
        Ok(())
    }

    /// Delete a workspace and all traffic in it. The default workspace is protected.
    /// If it was the capture target, the target goes back to "unchosen" so the UI asks again.
    pub fn delete_workspace(&self, id: &str) -> Result<(), WorkspaceError> {
        if id == DEFAULT_WORKSPACE_ID {
            return Err(WorkspaceError::Protected);
        }
        {
            let db = self.lock_db().map_err(WorkspaceError::Other)?;
            db.execute("DELETE FROM websocket_requests WHERE id IN (SELECT id FROM websocket_connections WHERE workspace_id=?1)",params![id])?;
            db.execute("DELETE FROM websocket_frames WHERE connection_id IN (SELECT id FROM websocket_connections WHERE workspace_id=?1)", params![id])?;
            db.execute("DELETE FROM websocket_connections WHERE workspace_id=?1", params![id])?;
            db.execute("DELETE FROM traffic WHERE workspace_id = ?1", params![id])?;
            db.execute("DELETE FROM replay_tabs WHERE workspace_id = ?1", params![id])?;
            db.execute("DELETE FROM replay_runs WHERE workspace_id = ?1", params![id])?;
            for table in ["scan_runs","intruder_documents","intruder_sources","intruder_payloads","intruder_runs","intruder_results"] {
                db.execute(&format!("DELETE FROM {table} WHERE workspace_id=?1"),params![id])?;
            }
            db.execute("DELETE FROM auth_profiles WHERE workspace_id = ?1", params![id])?;
            db.execute("DELETE FROM matrix_runs WHERE workspace_id = ?1", params![id])?;
            db.execute("DELETE FROM flow_documents WHERE workspace_id = ?1", params![id])?;
            db.execute("DELETE FROM flow_runs WHERE workspace_id = ?1", params![id])?;
            if db.execute("DELETE FROM workspaces WHERE id = ?1", params![id])? == 0 {
                return Err(WorkspaceError::NotFound);
            }
        }
        if self.target() == Target::Workspace(id.to_string()) {
            self.set_target(Target::Unchosen);
        }
        let _ = self.tx.send(TrafficEvent::WorkspaceCleared { workspace_id: id.to_string() });
        self.notify_workspaces_changed();
        Ok(())
    }

    /// The stored Replay tabs of a workspace (a JSON document), or `None` if nothing was saved yet.
    pub fn get_replay_tabs(&self, workspace_id: &str) -> Result<Option<String>, WorkspaceError> {
        let db = self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id = ?1")?.exists(params![workspace_id])? {
            return Err(WorkspaceError::NotFound);
        }
        match db.query_row("SELECT data FROM replay_tabs WHERE workspace_id = ?1", params![workspace_id], |r| r.get(0)) {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Replace the stored Replay tabs of a workspace. The caller validates the document.
    pub fn put_replay_tabs(&self, workspace_id: &str, data: &str) -> Result<(), WorkspaceError> {
        let db = self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id = ?1")?.exists(params![workspace_id])? {
            return Err(WorkspaceError::NotFound);
        }
        db.execute(
            "INSERT OR REPLACE INTO replay_tabs (workspace_id, data, updated_at) VALUES (?1, ?2, ?3)",
            params![workspace_id, data, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_auth_profiles(&self, workspace: &str) -> Result<(u64, String), WorkspaceError> {
        let db = self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? { return Err(WorkspaceError::NotFound); }
        match db.query_row("SELECT revision,data FROM auth_profiles WHERE workspace_id=?1", params![workspace], |r| Ok((r.get(0)?,r.get(1)?))) {
            Ok(value) => Ok(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok((0, "{\"profiles\":[],\"active\":null}".into())),
            Err(error) => Err(error.into()),
        }
    }
    /// Optimistic concurrency prevents another browser from overwriting credentials/cookies.
    pub fn put_auth_profiles(&self, workspace: &str, revision: u64, data: &str) -> Result<Option<u64>, WorkspaceError> {
        let mut db = self.lock_db().map_err(WorkspaceError::Other)?;
        let tx = db.transaction()?;
        if !tx.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? { return Err(WorkspaceError::NotFound); }
        tx.execute("INSERT OR IGNORE INTO auth_profiles(workspace_id,revision,data) VALUES(?1,0,?2)",params![workspace,"{\"profiles\":[],\"active\":null}"])?;
        let changed = tx.execute("UPDATE auth_profiles SET revision=revision+1,data=?3 WHERE workspace_id=?1 AND revision=?2", params![workspace,revision,data])?;
        tx.commit()?;
        Ok(if changed == 1 { Some(revision+1) } else { None })
    }
    pub fn put_matrix_run(&self, workspace: &str, id: &str, data: &serde_json::Value) -> Result<(), WorkspaceError> {
        let mut db = self.lock_db().map_err(WorkspaceError::Other)?;
        let tx = db.transaction()?;
        if !tx.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? { return Err(WorkspaceError::NotFound); }
        let serialized = data.to_string();
        let previous = tx.query_row("SELECT data FROM matrix_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id],|r|r.get::<_,String>(0));
        match previous {
            Ok(old) if old != serialized => return Err(WorkspaceError::Other(anyhow::anyhow!("Saved matrix results are immutable"))),
            Err(rusqlite::Error::QueryReturnedNoRows) | Ok(_) => {},
            Err(error) => return Err(error.into()),
        }
        tx.execute("INSERT OR IGNORE INTO matrix_runs(workspace_id,id,started_at,data) VALUES(?1,?2,?3,?4)",params![workspace,id,data["startedAt"].as_str().unwrap_or(""),serialized])?;
        tx.execute("DELETE FROM matrix_runs WHERE workspace_id=?1 AND id NOT IN (SELECT id FROM matrix_runs WHERE workspace_id=?1 ORDER BY started_at DESC,id DESC LIMIT 50)",params![workspace])?;
        tx.commit()?;
        Ok(())
    }
    pub fn list_matrix_runs(&self, workspace: &str, offset: usize) -> Result<Vec<serde_json::Value>> {
        let db = self.lock_db()?;
        let mut query = db.prepare("SELECT json_object('id',id,'startedAt',started_at,'status',json_extract(data,'$.status'),'cells',json_array_length(data,'$.results')) FROM matrix_runs WHERE workspace_id=?1 ORDER BY started_at DESC,id DESC LIMIT 50 OFFSET ?2")?;
        let rows = query.query_map(params![workspace,offset],|r|r.get::<_,String>(0))?;
        rows.map(|r|Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn get_matrix_run(&self, workspace: &str, id: &str) -> Result<Option<serde_json::Value>> {
        let db = self.lock_db()?;
        match db.query_row("SELECT data FROM matrix_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id],|r|r.get::<_,String>(0)) {
            Ok(data) => Ok(Some(serde_json::from_str(&data)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None), Err(error) => Err(error.into()),
        }
    }

    pub fn get_flow_document(&self, workspace: &str) -> Result<Option<String>, WorkspaceError> {
        let db=self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? {return Err(WorkspaceError::NotFound);}
        match db.query_row("SELECT data FROM flow_documents WHERE workspace_id=?1",params![workspace],|r|r.get(0)) {
            Ok(data)=>Ok(Some(data)),Err(rusqlite::Error::QueryReturnedNoRows)=>Ok(None),Err(error)=>Err(error.into())
        }
    }
    pub fn put_flow_document(&self, workspace: &str, data: &str) -> Result<(), WorkspaceError> {
        let db=self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? {return Err(WorkspaceError::NotFound);}
        db.execute("INSERT OR REPLACE INTO flow_documents(workspace_id,data) VALUES(?1,?2)",params![workspace,data])?;Ok(())
    }
    pub fn put_flow_run(&self, workspace:&str,id:&str,data:&serde_json::Value)->Result<(),WorkspaceError>{
        let db=self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? {return Err(WorkspaceError::NotFound);}
        db.execute("INSERT INTO flow_runs(workspace_id,id,started_at,data) VALUES(?1,?2,?3,?4) ON CONFLICT(workspace_id,id) DO UPDATE SET data=excluded.data",params![workspace,id,data["startedAt"].as_str().unwrap_or(""),data.to_string()])?;Ok(())
    }
    pub fn list_flow_runs(&self,workspace:&str,offset:usize)->Result<Vec<serde_json::Value>>{
        let db=self.lock_db()?;
        let mut statement=db.prepare("SELECT json_object('id',id,'flowId',json_extract(data,'$.flow.id'),'name',json_extract(data,'$.flow.name'),'startedAt',started_at,'status',json_extract(data,'$.status'),'duration',json_extract(data,'$.duration'),'steps',json_array_length(data,'$.results')) FROM flow_runs WHERE workspace_id=?1 ORDER BY started_at DESC,id DESC LIMIT 50 OFFSET ?2")?;
        let rows=statement.query_map(params![workspace,offset],|r|r.get::<_,String>(0))?;
        rows.map(|r|Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn get_flow_run(&self,workspace:&str,id:&str)->Result<Option<serde_json::Value>>{
        let db=self.lock_db()?;
        match db.query_row("SELECT data FROM flow_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id],|r|r.get::<_,String>(0)){
            Ok(data)=>Ok(Some(serde_json::from_str(&data)?)),Err(rusqlite::Error::QueryReturnedNoRows)=>Ok(None),Err(error)=>Err(error.into())
        }
    }

    /// Make a workspace the target for newly captured traffic.
    pub fn set_active_workspace(&self, id: &str) -> Result<(), WorkspaceError> {
        {
            let db = self.lock_db().map_err(WorkspaceError::Other)?;
            if !db.prepare("SELECT 1 FROM workspaces WHERE id = ?1")?.exists(params![id])? {
                return Err(WorkspaceError::NotFound);
            }
        }
        self.set_target(Target::Workspace(id.to_string()));
        Ok(())
    }
}

/// Aggregate statistics about captured traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub total_requests: u64,
    pub total_request_bytes: u64,
    pub total_response_bytes: u64,
    pub error_count: u64,
    pub top_hosts: Vec<(String, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str) -> TrafficEntry {
        TrafficEntry::new_request("GET", url, "example.com", "/", "http", "{}", Vec::new(), None)
    }

    fn storage() -> Arc<TrafficStorage> {
        TrafficStorage::new(":memory:", 1024).unwrap()
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hd-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn saved(ws: &str) -> TrafficFilter<'_> {
        TrafficFilter { workspace: Some(ws), ..Default::default() }
    }

    #[test]
    fn flows_and_run_history_survive_restart_and_are_deleted_with_their_workspace() {
        let dir=temp_dir("flow-history");let path=dir.join("traffic.db");let workspace;
        let run=serde_json::json!({"id":"run-1","flow":{"id":"flow-1","name":"Login"},"startedAt":"2026-10-16T00:00:00Z","status":"passed","duration":10,"variables":{"token":"snapshot"},"results":[{"response":{"responseBody":"original"}}]});
        {let s=TrafficStorage::new(path.to_str().unwrap(),1024).unwrap();let w=s.create_workspace("Flows").unwrap();workspace=w.id;
        s.put_flow_document(&workspace,r#"{"flows":[],"active":null}"#).unwrap();s.put_flow_run(&workspace,"run-1",&run).unwrap();}
        let s=TrafficStorage::new(path.to_str().unwrap(),1024).unwrap();
        assert!(s.get_flow_document(&workspace).unwrap().is_some());
        assert_eq!(s.get_flow_run(&workspace,"run-1").unwrap().unwrap(),run);
        assert!(s.get_flow_run("default","run-1").unwrap().is_none());
        assert!(s.list_flow_runs(&workspace,0).unwrap()[0].get("variables").is_none());
        s.delete_workspace(&workspace).unwrap();assert!(s.get_flow_document(&workspace).is_err());assert!(s.get_flow_run(&workspace,"run-1").unwrap().is_none());
        assert!(s.put_flow_run("missing","run-1",&run).is_err());
    }

    #[test]
    fn annotations_survive_updates_and_bookmark_filter_search_and_temporary_sessions() {
        let s=storage();s.set_active_workspace(DEFAULT_WORKSPACE_ID).unwrap();
        let e=entry("https://example.com/a");s.insert(&e).unwrap();
        assert_eq!(s.annotate(&e.id,Some(true),Some("needs auth review")).unwrap(),Some((true,"needs auth review".into())));
        s.insert(&e).unwrap();
        let saved=s.get(&e.id).unwrap().unwrap();assert!(saved.bookmarked);assert_eq!(saved.notes,"needs auth review");
        let (rows,total)=s.history_page(100,&TrafficFilter{search:Some("auth review"),..Default::default()},None,false,&[],None,true).unwrap();
        assert_eq!(total,1);assert_eq!(rows[0].id,e.id);
        s.annotate(&e.id,Some(false),None).unwrap();assert_eq!(s.get(&e.id).unwrap().unwrap().notes,"needs auth review");
        assert_eq!(s.history_page(100,&TrafficFilter::default(),None,false,&[],None,true).unwrap().1,0);
        s.use_temporary();let temporary=entry("https://example.com/temp");s.insert(&temporary).unwrap();
        s.annotate(&temporary.id,Some(true),Some("local")).unwrap();assert!(s.get(&temporary.id).unwrap().unwrap().bookmarked);
        assert!(s.annotate(&temporary.id,None,Some(&"x".repeat(16001))).is_err());
        assert_eq!(s.annotate("missing",Some(true),None).unwrap(),None);
    }

    #[test]
    fn send_history_is_durable_scoped_and_independent_of_traffic_and_tab_autosaves() {
        let dir=temp_dir("runs");let path=dir.join("history.sqlite");let id;
        {
            let s=TrafficStorage::new(path.to_str().unwrap(),1024).unwrap();
            let run=s.add_replay_run(DEFAULT_WORKSPACE_ID,7,serde_json::json!({"template":{"method":"GET","url":"{{base}}"},"request":{"method":"GET","url":"https://example.com","body":"request body"},"response":{"status":200,"responseBody":"response body"},"duration":5})).unwrap();
            id=run["id"].as_str().unwrap().to_string();
            s.put_replay_tabs(DEFAULT_WORKSPACE_ID,"{\"tabs\":[],\"variables\":{\"token\":\"changed\"}}").unwrap();
            s.clear(None).unwrap();
            assert_eq!(s.list_replay_runs(DEFAULT_WORKSPACE_ID,7,0).unwrap().len(),1);
            assert!(s.list_replay_runs(DEFAULT_WORKSPACE_ID,8,0).unwrap().is_empty());
            assert!(s.get_replay_run("other",7,&id).unwrap().is_none());
            let summary=&s.list_replay_runs(DEFAULT_WORKSPACE_ID,7,0).unwrap()[0];
            assert!(summary.get("response").is_none());assert_eq!(summary["status"],200);
        }
        let s=TrafficStorage::new(path.to_str().unwrap(),1024).unwrap();
        let run=s.get_replay_run(DEFAULT_WORKSPACE_ID,7,&id).unwrap().unwrap();
        assert_eq!(run["response"]["responseBody"],"response body");assert_eq!(run["request"]["body"],"request body");assert_eq!(run["template"]["url"],"{{base}}");
    }

    #[test]
    fn history_cursor_handles_ties_new_inserts_filters_and_both_directions() {
        let s = storage();
        s.set_active_workspace(DEFAULT_WORKSPACE_ID).unwrap();
        let time = Utc::now();
        for i in 0..7 {
            let mut e = entry(&format!("https://example.com/{i}"));
            e.id = format!("id-{i}"); e.timestamp = time; e.status_code = 200; e.request_body = b"payload".to_vec();
            s.insert(&e).unwrap();
        }
        let filter = saved(DEFAULT_WORKSPACE_ID);
        let (first,total) = s.history_page(3,&filter,None,false,&[],None,false).unwrap();
        assert_eq!(total,7);
        assert!(first[0].request_body.is_empty());
        assert_eq!(s.get(&first[0].id).unwrap().unwrap().request_body, b"payload");
        assert_eq!(first.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),vec!["id-6","id-5","id-4"]);
        let mut newer = entry("https://example.com/new"); newer.timestamp = time + chrono::Duration::seconds(1); s.insert(&newer).unwrap();
        let cursor = first.last().unwrap(); let stamp = cursor.timestamp.to_rfc3339();
        let (second,_) = s.history_page(3,&filter,Some((&stamp,&cursor.id)),false,&[],None,false).unwrap();
        assert_eq!(second.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),vec!["id-3","id-2","id-1"]);
        let (asc,_) = s.history_page(3,&filter,None,true,&[],None,false).unwrap();
        assert_eq!(asc[0].id,"id-0");
        let (next,_) = s.history_page(3,&filter,Some((&stamp,"id-2")),true,&[],None,false).unwrap();
        assert_eq!(next[0].id,"id-3");
        let (excluded,total) = s.history_page(3,&filter,None,false,&["other.com".into()],None,false).unwrap();
        assert!(excluded.is_empty()); assert_eq!(total,0);
        let (_,total) = s.history_page(3,&filter,None,false,&["example.com".into()],Some(2),false).unwrap();
        assert_eq!(total,7);
        let (_,total) = s.history_page(3,&TrafficFilter{search:Some("/5"),..filter},None,false,&[],None,false).unwrap();
        assert_eq!(total,1);
    }

    #[test]
    fn default_workspace_exists_but_nothing_is_chosen_at_start() {
        let s = storage();
        let list = s.list_workspaces().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, DEFAULT_WORKSPACE_ID);
        assert!(!list[0].active, "no workspace is active until the user picks one");
        assert_eq!(s.target(), Target::Unchosen);
        assert_eq!(s.session().unwrap().target, "unchosen");
    }

    #[test]
    fn unchosen_and_temporary_traffic_is_kept_in_memory_only() {
        let s = storage();
        s.insert(&entry("http://a/1")).unwrap();
        s.use_temporary();
        s.insert(&entry("http://a/2")).unwrap();

        let info = s.session().unwrap();
        assert_eq!((info.target.as_str(), info.temporary_count), ("temporary", 2));
        // Not in any saved workspace, and not in "all saved workspaces".
        assert_eq!(s.count(&TrafficFilter::default()).unwrap(), 0);
        assert_eq!(s.count(&saved(DEFAULT_WORKSPACE_ID)).unwrap(), 0);
        assert_eq!(s.count(&saved(TEMP_WORKSPACE_ID)).unwrap(), 2);
        let listed = s.list(10, 0, &saved(TEMP_WORKSPACE_ID)).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|e| e.workspace_id == TEMP_WORKSPACE_ID));
        // Still reachable by id, and stats work for the temporary session.
        assert!(s.get(&listed[0].id).unwrap().is_some());
        assert_eq!(s.stats(Some(TEMP_WORKSPACE_ID)).unwrap().total_requests, 2);
    }

    #[test]
    fn temporary_traffic_is_not_written_to_disk_and_is_gone_after_restart() {
        let dir = temp_dir("temp");
        let path = dir.join("t.db");
        let path_str = path.to_str().unwrap();
        let marker = "http://secret-marker.example/token-abc123";
        {
            let s = TrafficStorage::new(path_str, 1024).unwrap();
            let ws = s.create_workspace("Kept").unwrap();
            s.use_temporary();
            s.insert(&entry(marker)).unwrap();
            s.set_active_workspace(&ws.id).unwrap();
            s.insert(&entry("http://saved.example/")).unwrap();
            assert_eq!(s.session().unwrap().temporary_count, 1);
        }
        // Nothing of the temporary request may be on disk, in the database or its write-ahead log.
        for file in std::fs::read_dir(&dir).unwrap() {
            let bytes = std::fs::read(file.unwrap().path()).unwrap();
            assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()), "temporary request leaked to disk");
        }
        let s = TrafficStorage::new(path_str, 1024).unwrap();
        assert_eq!(s.session().unwrap().temporary_count, 0);
        assert_eq!(s.count(&TrafficFilter::default()).unwrap(), 1, "the saved request survived the restart");
        assert_eq!(s.target(), Target::Unchosen, "every launch asks for a workspace again");
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn delete_one_entry_in_saved_and_temporary_history() {
        let s = storage();
        s.set_active_workspace(DEFAULT_WORKSPACE_ID).unwrap();
        let saved_entry = entry("http://a/saved");
        let retained = entry("http://a/retained");
        s.insert(&saved_entry).unwrap();
        s.insert(&retained).unwrap();
        s.use_temporary();
        let temporary = entry("http://a/temp");
        s.insert(&temporary).unwrap();
        let mut events = s.subscribe();
        assert!(s.delete(&saved_entry.id).unwrap());
        assert!(matches!(events.try_recv().unwrap(), TrafficEvent::EntryDeleted { id } if id == saved_entry.id));
        assert!(s.get(&saved_entry.id).unwrap().is_none());
        assert!(!s.delete(&saved_entry.id).unwrap());
        assert!(s.get(&retained.id).unwrap().is_some());
        assert!(s.delete(&temporary.id).unwrap());
        assert!(s.get(&temporary.id).unwrap().is_none());
        assert!(s.get(&retained.id).unwrap().is_some());
    }

    #[test]
    fn traffic_goes_to_the_chosen_workspace_and_filters() {
        let s = storage();
        s.set_active_workspace(DEFAULT_WORKSPACE_ID).unwrap();
        s.insert(&entry("http://a/1")).unwrap();
        let ws = s.create_workspace("Staging").unwrap();
        s.set_active_workspace(&ws.id).unwrap();
        s.insert(&entry("http://a/2")).unwrap();
        s.insert(&entry("http://a/3")).unwrap();

        assert_eq!(s.count(&saved(&ws.id)).unwrap(), 2);
        assert_eq!(s.list(10, 0, &saved(&ws.id)).unwrap().len(), 2);
        assert_eq!(s.count(&saved(DEFAULT_WORKSPACE_ID)).unwrap(), 1);
        assert_eq!(s.count(&TrafficFilter::default()).unwrap(), 3);
        assert_eq!(s.stats(Some(&ws.id)).unwrap().total_requests, 2);
        let active: Vec<_> = s.list_workspaces().unwrap().into_iter().filter(|w| w.active).map(|w| w.id).collect();
        assert_eq!(active, vec![ws.id]);
    }

    #[test]
    fn replayed_requests_are_saved_with_their_source() {
        let s = storage();
        s.set_active_workspace(DEFAULT_WORKSPACE_ID).unwrap();
        let mut e = entry("http://a/replayed");
        e.source = "replay".into();
        s.insert(&e).unwrap();
        s.insert(&entry("http://a/proxied")).unwrap();
        let got = s.get(&e.id).unwrap().unwrap();
        assert_eq!((got.source.as_str(), got.workspace_id.as_str()), ("replay", DEFAULT_WORKSPACE_ID));
        assert!(s.list(10, 0, &TrafficFilter::default()).unwrap().iter().any(|x| x.source == "proxy"));
    }

    #[test]
    fn reinserting_keeps_original_location() {
        let s = storage();
        let mut e = entry("http://a/1");
        s.use_temporary();
        s.insert(&e).unwrap();
        let ws = s.create_workspace("Other").unwrap();
        s.set_active_workspace(&ws.id).unwrap();
        e.status_code = 200; // the response arrives after the target changed
        s.insert(&e).unwrap();
        assert_eq!(s.get(&e.id).unwrap().unwrap().workspace_id, TEMP_WORKSPACE_ID);
        assert_eq!(s.count(&TrafficFilter::default()).unwrap(), 0);
    }

    #[test]
    fn names_are_validated_and_unique() {
        let s = storage();
        assert!(matches!(s.create_workspace("   "), Err(WorkspaceError::InvalidName)));
        assert!(matches!(s.create_workspace(&"x".repeat(61)), Err(WorkspaceError::InvalidName)));
        s.create_workspace("Prod").unwrap();
        assert!(matches!(s.create_workspace("prod"), Err(WorkspaceError::NameTaken)));
        let id = s.create_workspace("Dev").unwrap().id;
        assert!(matches!(s.rename_workspace(&id, "PROD"), Err(WorkspaceError::NameTaken)));
        s.rename_workspace(&id, "Development").unwrap();
        assert!(matches!(s.rename_workspace("nope", "X"), Err(WorkspaceError::NotFound)));
    }

    #[test]
    fn deleting_the_active_workspace_asks_for_a_new_choice() {
        let s = storage();
        let ws = s.create_workspace("Temp").unwrap();
        s.set_active_workspace(&ws.id).unwrap();
        s.insert(&entry("http://a/1")).unwrap();
        s.delete_workspace(&ws.id).unwrap();
        assert_eq!(s.count(&TrafficFilter::default()).unwrap(), 0);
        assert_eq!(s.target(), Target::Unchosen);
        assert!(matches!(s.delete_workspace(DEFAULT_WORKSPACE_ID), Err(WorkspaceError::Protected)));
        assert!(matches!(s.delete_workspace(&ws.id), Err(WorkspaceError::NotFound)));
        assert!(matches!(s.set_active_workspace(&ws.id), Err(WorkspaceError::NotFound)));
    }

    #[test]
    fn deleting_another_workspace_keeps_the_choice() {
        let s = storage();
        let keep = s.create_workspace("Keep").unwrap();
        let other = s.create_workspace("Other").unwrap();
        s.set_active_workspace(&keep.id).unwrap();
        s.delete_workspace(&other.id).unwrap();
        assert_eq!(s.target(), Target::Workspace(keep.id));
    }

    #[test]
    fn clear_can_target_one_workspace_or_everything() {
        let s = storage();
        s.set_active_workspace(DEFAULT_WORKSPACE_ID).unwrap();
        s.insert(&entry("http://a/1")).unwrap();
        let ws = s.create_workspace("B").unwrap();
        s.set_active_workspace(&ws.id).unwrap();
        s.insert(&entry("http://a/2")).unwrap();
        s.use_temporary();
        s.insert(&entry("http://a/3")).unwrap();

        s.clear(Some(&ws.id)).unwrap();
        assert_eq!(s.count(&TrafficFilter::default()).unwrap(), 1);
        assert_eq!(s.session().unwrap().temporary_count, 1);
        s.clear(Some(TEMP_WORKSPACE_ID)).unwrap();
        assert_eq!(s.session().unwrap().temporary_count, 0);
        assert_eq!(s.count(&TrafficFilter::default()).unwrap(), 1);

        s.insert(&entry("http://a/4")).unwrap();
        s.clear(None).unwrap();
        assert_eq!(s.count(&TrafficFilter::default()).unwrap(), 0);
        assert_eq!(s.session().unwrap().temporary_count, 0, "clearing everything includes the temporary session");
    }

    #[test]
    fn replay_tabs_are_stored_per_workspace_and_removed_with_it() {
        let s = storage();
        let a = s.create_workspace("A").unwrap();
        let b = s.create_workspace("B").unwrap();
        assert_eq!(s.get_replay_tabs(&a.id).unwrap(), None, "nothing saved yet");

        s.put_replay_tabs(&a.id, r#"{"tabs":[{"id":1}],"active":1}"#).unwrap();
        s.put_replay_tabs(&b.id, r#"{"tabs":[],"active":null}"#).unwrap();
        assert_eq!(s.get_replay_tabs(&a.id).unwrap().as_deref(), Some(r#"{"tabs":[{"id":1}],"active":1}"#));
        assert_eq!(s.get_replay_tabs(&b.id).unwrap().as_deref(), Some(r#"{"tabs":[],"active":null}"#));

        // Saving again replaces, it does not append.
        s.put_replay_tabs(&a.id, r#"{"tabs":[{"id":2}],"active":2}"#).unwrap();
        assert_eq!(s.get_replay_tabs(&a.id).unwrap().as_deref(), Some(r#"{"tabs":[{"id":2}],"active":2}"#));

        s.delete_workspace(&a.id).unwrap();
        assert!(matches!(s.get_replay_tabs(&a.id), Err(WorkspaceError::NotFound)));
        assert!(s.get_replay_tabs(&b.id).unwrap().is_some(), "other workspaces are untouched");
        assert!(matches!(s.put_replay_tabs("nope", "{}"), Err(WorkspaceError::NotFound)));
    }

    #[test]
    fn replay_tabs_survive_a_restart() {
        let dir = temp_dir("tabs");
        let path = dir.join("t.db");
        let id = {
            let s = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
            let w = s.create_workspace("Kept").unwrap();
            s.put_replay_tabs(&w.id, r#"{"tabs":[{"id":7}],"active":7}"#).unwrap();
            w.id
        };
        let s = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
        assert_eq!(s.get_replay_tabs(&id).unwrap().as_deref(), Some(r#"{"tabs":[{"id":7}],"active":7}"#));
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn migrates_database_without_newer_columns() {
        let dir = temp_dir("migrate");
        let path = dir.join("old.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE traffic (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, method TEXT NOT NULL,
                 url TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL, scheme TEXT NOT NULL DEFAULT 'http',
                 request_headers TEXT NOT NULL DEFAULT '{}', request_body BLOB NOT NULL DEFAULT x'',
                 request_content_type TEXT, status_code INTEGER NOT NULL DEFAULT 0,
                 response_headers TEXT NOT NULL DEFAULT '{}', response_body BLOB NOT NULL DEFAULT x'',
                 response_content_type TEXT, duration_ms INTEGER NOT NULL DEFAULT 0,
                 request_size INTEGER NOT NULL DEFAULT 0, response_size INTEGER NOT NULL DEFAULT 0, error TEXT);
                 INSERT INTO traffic (id, timestamp, method, url, host, path) VALUES ('1','2026-01-01T00:00:00Z','GET','http://a','a','/');",
            )
            .unwrap();
        }
        let s = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
        let old = s.get("1").unwrap().unwrap();
        assert_eq!((old.workspace_id.as_str(), old.source.as_str()), (DEFAULT_WORKSPACE_ID, "proxy"));
        assert_eq!(s.list_workspaces().unwrap()[0].request_count, 1);
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }
}


impl TrafficStorage {
    pub fn get_intruder_document(&self, workspace: &str) -> Result<(u64,Option<String>),WorkspaceError> {
        let db=self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? {return Err(WorkspaceError::NotFound);}
        match db.query_row("SELECT revision,data FROM intruder_documents WHERE workspace_id=?1",params![workspace],|r|Ok((r.get(0)?,Some(r.get(1)?)))) {
            Ok(value)=>Ok(value),Err(rusqlite::Error::QueryReturnedNoRows)=>Ok((0,None)),Err(e)=>Err(e.into())
        }
    }
    pub fn put_intruder_document(&self,workspace:&str,revision:u64,data:&str)->Result<Option<u64>,WorkspaceError>{
        let mut db=self.lock_db().map_err(WorkspaceError::Other)?;let tx=db.transaction()?;
        if !tx.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? {return Err(WorkspaceError::NotFound);}
        tx.execute("INSERT OR IGNORE INTO intruder_documents(workspace_id,revision,data) VALUES(?1,0,'null')",params![workspace])?;
        let changed=tx.execute("UPDATE intruder_documents SET revision=revision+1,data=?3 WHERE workspace_id=?1 AND revision=?2",params![workspace,revision,data])?;
        tx.commit()?;Ok(if changed==1{Some(revision+1)}else{None})
    }
    pub fn create_intruder_source(&self,workspace:&str,name:&str)->Result<String,WorkspaceError>{
        let db=self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? {return Err(WorkspaceError::NotFound);}
        let count:i64=db.query_row("SELECT count(*) FROM intruder_sources WHERE workspace_id=?1",params![workspace],|r|r.get(0))?;
        if count>=20{return Err(WorkspaceError::Other(anyhow::anyhow!("Maximum 20 payload files per workspace")));}
        let id=Uuid::new_v4().to_string();
        db.execute("INSERT INTO intruder_sources(workspace_id,id,name,created_at) VALUES(?1,?2,?3,?4)",params![workspace,id,name,Utc::now().to_rfc3339()])?;Ok(id)
    }
    pub fn append_intruder_payloads(&self,workspace:&str,id:&str,offset:usize,values:&[String])->Result<usize,WorkspaceError>{
        let mut db=self.lock_db().map_err(WorkspaceError::Other)?;let tx=db.transaction()?;
        let (count,ready):(usize,bool)=tx.query_row("SELECT count,ready FROM intruder_sources WHERE workspace_id=?1 AND id=?2",params![workspace,id],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|if matches!(e,rusqlite::Error::QueryReturnedNoRows){WorkspaceError::NotFound}else{e.into()})?;
        if offset<count {
            let mut query=tx.prepare("SELECT value FROM intruder_payloads WHERE workspace_id=?1 AND source_id=?2 AND ordinal>=?3 ORDER BY ordinal LIMIT ?4")?;
            let old=query.query_map(params![workspace,id,offset,values.len()],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
            if old==values{return Ok(count);}
        }
        if ready||offset!=count{return Err(WorkspaceError::Other(anyhow::anyhow!("Payload upload offset mismatch or file already finalized")));}
        let bytes:usize=values.iter().map(|s|s.len()).sum();
        let total:usize=tx.query_row("SELECT coalesce(sum(bytes),0) FROM intruder_sources WHERE workspace_id=?1",params![workspace],|r|r.get(0))?;
        if count+values.len()>1_000_000||total+bytes>128*1024*1024{return Err(WorkspaceError::Other(anyhow::anyhow!("Payload files exceed 1 million rows per file or 128 MB per workspace")));}
        {let mut insert=tx.prepare("INSERT INTO intruder_payloads(workspace_id,source_id,ordinal,value) VALUES(?1,?2,?3,?4)")?;
        for (index,value) in values.iter().enumerate(){insert.execute(params![workspace,id,count+index,value])?;}}
        tx.execute("UPDATE intruder_sources SET count=count+?3,bytes=bytes+?4 WHERE workspace_id=?1 AND id=?2",params![workspace,id,values.len(),bytes])?;tx.commit()?;Ok(count+values.len())
    }
    pub fn finalize_intruder_source(&self,workspace:&str,id:&str)->Result<(),WorkspaceError>{
        let db=self.lock_db().map_err(WorkspaceError::Other)?;
        if db.execute("UPDATE intruder_sources SET ready=1 WHERE workspace_id=?1 AND id=?2 AND count>0",params![workspace,id])?==0{return Err(WorkspaceError::NotFound);}Ok(())
    }
    pub fn list_intruder_sources(&self,workspace:&str)->Result<Vec<serde_json::Value>>{
        let db=self.lock_db()?;let mut query=db.prepare("SELECT json_object('id',id,'name',name,'count',count,'bytes',bytes,'ready',json(CASE WHEN ready=1 THEN 'true' ELSE 'false' END)) FROM intruder_sources WHERE workspace_id=?1 ORDER BY created_at DESC")?;
        let rows=query.query_map(params![workspace],|r|r.get::<_,String>(0))?;rows.map(|r|Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn intruder_payload_page(&self,workspace:&str,id:&str,offset:usize)->Result<Vec<String>,WorkspaceError>{
        let db=self.lock_db().map_err(WorkspaceError::Other)?;
        if !db.prepare("SELECT 1 FROM intruder_sources WHERE workspace_id=?1 AND id=?2 AND ready=1")?.exists(params![workspace,id])?{return Err(WorkspaceError::NotFound);}
        let mut query=db.prepare("SELECT value FROM intruder_payloads WHERE workspace_id=?1 AND source_id=?2 AND ordinal>=?3 ORDER BY ordinal LIMIT 128")?;
        let rows=query.query_map(params![workspace,id,offset],|r|r.get::<_,String>(0))?;rows.collect::<Result<Vec<_>,_>>().map_err(Into::into)
    }
    pub fn delete_intruder_source(&self,workspace:&str,id:&str)->Result<(),WorkspaceError>{
        let mut db=self.lock_db().map_err(WorkspaceError::Other)?;let tx=db.transaction()?;
        tx.execute("DELETE FROM intruder_payloads WHERE workspace_id=?1 AND source_id=?2",params![workspace,id])?;
        tx.execute("DELETE FROM intruder_sources WHERE workspace_id=?1 AND id=?2",params![workspace,id])?;tx.commit()?;Ok(())
    }
    pub fn put_intruder_run(&self,workspace:&str,id:&str,data:&serde_json::Value)->Result<(),WorkspaceError>{
        let mut db=self.lock_db().map_err(WorkspaceError::Other)?;let tx=db.transaction()?;
        if !tx.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])?{return Err(WorkspaceError::NotFound);}
        let previous:Option<String>=tx.query_row("SELECT data FROM intruder_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id],|r|r.get(0)).optional()?;
        if let Some(old)=previous {
            let old:serde_json::Value=serde_json::from_str(&old).map_err(|e|WorkspaceError::Other(e.into()))?;
            if !matches!(old["status"].as_str(),Some("running"|"paused"))&&old!=*data{return Err(WorkspaceError::Other(anyhow::anyhow!("Finished Intruder runs are immutable")));}
            if old["config"]!=data["config"]||old["startedAt"]!=data["startedAt"]||old["count"]!=data["count"]{return Err(WorkspaceError::Other(anyhow::anyhow!("Run configuration is immutable")));}
        }
        tx.execute("INSERT INTO intruder_runs(workspace_id,id,started_at,data) VALUES(?1,?2,?3,?4) ON CONFLICT(workspace_id,id) DO UPDATE SET data=excluded.data",params![workspace,id,data["startedAt"].as_str().unwrap_or(""),data.to_string()])?;
        tx.commit()?;Ok(())
    }
    pub fn put_intruder_result(&self,workspace:&str,run:&str,index:usize,value:&serde_json::Value)->Result<(),WorkspaceError>{
        let mut db=self.lock_db().map_err(WorkspaceError::Other)?;let tx=db.transaction()?;
        let (data,bytes):(String,usize)=tx.query_row("SELECT data,bytes FROM intruder_runs WHERE workspace_id=?1 AND id=?2",params![workspace,run],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|if matches!(e,rusqlite::Error::QueryReturnedNoRows){WorkspaceError::NotFound}else{e.into()})?;
        let meta:serde_json::Value=serde_json::from_str(&data).map_err(|e|WorkspaceError::Other(e.into()))?;
        if index>=meta["count"].as_u64().unwrap_or(0) as usize{return Err(WorkspaceError::Other(anyhow::anyhow!("Result index outside run range")));}
        if !matches!(meta["status"].as_str(),Some("running"|"paused")) && index>=meta["launched"].as_u64().unwrap_or(0) as usize {return Err(WorkspaceError::Other(anyhow::anyhow!("Result was never scheduled")));}
        let serialized=value.to_string();
        let previous:Option<String>=tx.query_row("SELECT data FROM intruder_results WHERE workspace_id=?1 AND run_id=?2 AND ordinal=?3",params![workspace,run,index],|r|r.get(0)).optional()?;
        if let Some(old)=previous {if old==serialized{return Ok(());}return Err(WorkspaceError::Other(anyhow::anyhow!("Result evidence is immutable")));}
        if bytes+serialized.len()>32*1024*1024{return Err(WorkspaceError::Other(anyhow::anyhow!("Run evidence exceeds 32 MB")));}
        tx.execute("INSERT INTO intruder_results(workspace_id,run_id,ordinal,data) VALUES(?1,?2,?3,?4)",params![workspace,run,index,serialized])?;
        tx.execute("UPDATE intruder_runs SET completed=completed+1,bytes=bytes+?3 WHERE workspace_id=?1 AND id=?2",params![workspace,run,serialized.len()])?;tx.commit()?;Ok(())
    }
    pub fn get_intruder_run(&self,workspace:&str,id:&str)->Result<Option<serde_json::Value>>{
        let db=self.lock_db()?;
        let raw:Option<String>=db.query_row("SELECT json_set(data,'$.saved',completed,'$.bytes',bytes) FROM intruder_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id],|r|r.get(0)).optional()?;
        raw.map(|s|serde_json::from_str(&s).map_err(Into::into)).transpose()
    }
    pub fn list_intruder_runs(&self,workspace:&str,offset:usize)->Result<Vec<serde_json::Value>>{
        let db=self.lock_db()?;let mut query=db.prepare("SELECT json_object('id',id,'startedAt',started_at,'status',json_extract(data,'$.status'),'count',json_extract(data,'$.count'),'completed',completed,'bytes',bytes) FROM intruder_runs WHERE workspace_id=?1 ORDER BY started_at DESC,id DESC LIMIT 50 OFFSET ?2")?;
        let rows=query.query_map(params![workspace,offset],|r|r.get::<_,String>(0))?;rows.map(|r|Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn get_intruder_result(&self,workspace:&str,run:&str,index:usize)->Result<Option<serde_json::Value>>{
        let db=self.lock_db()?;let raw:Option<String>=db.query_row("SELECT data FROM intruder_results WHERE workspace_id=?1 AND run_id=?2 AND ordinal=?3",params![workspace,run,index],|r|r.get(0)).optional()?;raw.map(|s|serde_json::from_str(&s).map_err(Into::into)).transpose()
    }
    pub fn list_intruder_results(&self,workspace:&str,run:&str,offset:usize,search:&str,status:u16,matched:bool,errors:bool,sort:&str,descending:bool)->Result<(usize,Vec<serde_json::Value>)>{
        let db=self.lock_db()?;
        let filter="workspace_id=?1 AND run_id=?2 AND (?3='' OR instr(lower(json_extract(data,'$.payload')),lower(?3))>0) AND (?4=0 OR json_extract(data,'$.status')=?4) AND (?5=0 OR json_extract(data,'$.matched')=1) AND (?6=0 OR json_extract(data,'$.error') IS NOT NULL)";
        let total:usize=db.query_row(&format!("SELECT count(*) FROM intruder_results WHERE {filter}"),params![workspace,run,search,status,matched,errors],|r|r.get(0))?;
        let order=match sort{"status"=>"json_extract(data,'$.status')","size"=>"json_extract(data,'$.size')","duration"=>"json_extract(data,'$.duration')",_=>"ordinal"};
        let direction=if descending{"DESC"}else{"ASC"};
        let mut query=db.prepare(&format!("SELECT json_object('index',ordinal,'payloadIndex',json_extract(data,'$.payloadIndex'),'payload',json_extract(data,'$.payload'),'status',json_extract(data,'$.status'),'size',json_extract(data,'$.size'),'duration',json_extract(data,'$.duration'),'matched',json_extract(data,'$.matched'),'error',json_extract(data,'$.error'),'truncated',json_extract(data,'$.truncated')) FROM intruder_results WHERE {filter} ORDER BY {order} {direction},ordinal ASC LIMIT 100 OFFSET ?7"))?;
        let rows=query.query_map(params![workspace,run,search,status,matched,errors,offset],|r|r.get::<_,String>(0))?;let data=rows.map(|r|Ok(serde_json::from_str(&r?)?)).collect::<Result<Vec<_>>>()?;Ok((total,data))
    }
    pub fn delete_intruder_run(&self,workspace:&str,id:&str)->Result<(),WorkspaceError>{
        let mut db=self.lock_db().map_err(WorkspaceError::Other)?;let tx=db.transaction()?;
        tx.execute("DELETE FROM intruder_results WHERE workspace_id=?1 AND run_id=?2",params![workspace,id])?;
        tx.execute("DELETE FROM intruder_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id])?;tx.commit()?;Ok(())
    }
}

#[cfg(test)]
mod intruder_tests {
 use super::*;
 use serde_json::json;
 #[test]
 fn intruder_sources_cas_and_evidence_are_isolated_and_immutable(){
 let s=TrafficStorage::new(":memory:",1024).unwrap();let w=s.create_workspace("Intruder").unwrap().id;
 assert_eq!(s.get_intruder_document(&w).unwrap().0,0);
 assert_eq!(s.put_intruder_document(&w,0,"{}").unwrap(),Some(1));
 assert_eq!(s.put_intruder_document(&w,0,"{}").unwrap(),None);
 let source=s.create_intruder_source(&w,"values.txt").unwrap();let values:Vec<String>=(0..140).map(|i|format!("é{i}")).collect();
 assert!(s.intruder_payload_page(&w,&source,0).is_err());
 assert_eq!(s.append_intruder_payloads(&w,&source,0,&values).unwrap(),140);
 assert_eq!(s.append_intruder_payloads(&w,&source,0,&values).unwrap(),140);
 assert!(s.append_intruder_payloads(&w,&source,0,&["changed".into()]).is_err());
 s.finalize_intruder_source(&w,&source).unwrap();assert_eq!(s.intruder_payload_page(&w,&source,128).unwrap().len(),12);
 assert!(s.intruder_payload_page("default",&source,0).is_err());
 let run=json!({"id":"r","startedAt":"2026-10-16","config":{},"status":"running","count":2,"launched":0});s.put_intruder_run(&w,"r",&run).unwrap();
 let result=json!({"index":0,"payloadIndex":0,"payload":"needle","status":200,"size":3,"duration":10,"matched":true,"truncated":false});
 s.put_intruder_result(&w,"r",0,&result).unwrap();s.put_intruder_result(&w,"r",0,&result).unwrap();
 assert!(s.put_intruder_result(&w,"r",0,&json!({"payload":"changed"})).is_err());
 let (count,rows)=s.list_intruder_results(&w,"r",0,"needle",200,true,false,"size",false).unwrap();assert_eq!(count,1);assert_eq!(rows.len(),1);
 assert_eq!(s.list_intruder_results("default","r",0,"",0,false,false,"index",false).unwrap().0,0);
 let terminal=run.clone();
 // Construct terminal metadata explicitly; evidence retries remain idempotent.
 let mut terminal=terminal;terminal["status"]=json!("stopped");terminal["launched"]=json!(1);
 s.put_intruder_run(&w,"r",&terminal).unwrap();assert!(s.put_intruder_result(&w,"r",1,&result).is_err());
 assert!(s.put_intruder_run(&w,"r",&run).is_err());
 s.delete_workspace(&w).unwrap();assert!(s.get_intruder_result(&w,"r",0).unwrap().is_none());assert!(s.list_intruder_sources(&w).unwrap().is_empty());
 }
}

impl TrafficStorage {
    pub fn put_scan_run(&self,workspace:&str,id:&str,data:&serde_json::Value)->Result<(),WorkspaceError>{
        let mut db=self.lock_db().map_err(WorkspaceError::Other)?;let tx=db.transaction()?;
        if !tx.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![workspace])? {return Err(WorkspaceError::NotFound);}
        let serialized=data.to_string();
        let old:Option<String>=tx.query_row("SELECT data FROM scan_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id],|r|r.get(0)).optional()?;
        if old.is_some_and(|value|value!=serialized){return Err(WorkspaceError::Other(anyhow::anyhow!("Scan evidence is immutable")));}
        tx.execute("INSERT OR IGNORE INTO scan_runs(workspace_id,id,started_at,data) VALUES(?1,?2,?3,?4)",params![workspace,id,data["startedAt"].as_str().unwrap_or(""),serialized])?;tx.commit()?;Ok(())
    }
    pub fn get_scan_run(&self,workspace:&str,id:&str)->Result<Option<serde_json::Value>>{
        let db=self.lock_db()?;let raw:Option<String>=db.query_row("SELECT data FROM scan_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id],|r|r.get(0)).optional()?;raw.map(|s|serde_json::from_str(&s).map_err(Into::into)).transpose()
    }
    pub fn list_scan_runs(&self,workspace:&str,offset:usize)->Result<Vec<serde_json::Value>>{
        let db=self.lock_db()?;let mut query=db.prepare("SELECT json_object('id',id,'startedAt',started_at,'status',json_extract(data,'$.status'),'sent',json_extract(data,'$.sent'),'findings',json_array_length(data,'$.findings'),'url',json_extract(data,'$.plan.request.url'),'method',json_extract(data,'$.plan.request.method'),'mode',json_extract(data,'$.plan.mode'),'maxRequests',json_extract(data,'$.plan.maxRequests'),'profileName',json_extract(data,'$.profileName')) FROM scan_runs WHERE workspace_id=?1 ORDER BY started_at DESC,id DESC LIMIT 50 OFFSET ?2")?;
        let rows=query.query_map(params![workspace,offset],|r|r.get::<_,String>(0))?;rows.map(|r|Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn delete_scan_run(&self,workspace:&str,id:&str)->Result<(),WorkspaceError>{
        let db=self.lock_db().map_err(WorkspaceError::Other)?;db.execute("DELETE FROM scan_runs WHERE workspace_id=?1 AND id=?2",params![workspace,id])?;Ok(())
    }
}

impl TrafficStorage {
 pub fn list_scan_findings(&self,workspace:&str,offset:usize,search:&str,status:&str,severity:&str)->Result<(usize,Vec<serde_json::Value>)>{
  let db=self.lock_db()?;
  let filter="r.workspace_id=?1 AND (?2='' OR instr(lower(json_extract(f.value,'$.title') || ' ' || json_extract(r.data,'$.plan.request.url')),lower(?2))>0) AND (?3='' OR json_extract(f.value,'$.status')=?3) AND (?4='' OR json_extract(f.value,'$.severity')=?4)";
  let total:usize=db.query_row(&format!("SELECT count(*) FROM scan_runs r,json_each(r.data,'$.findings') f WHERE {filter}"),params![workspace,search,status,severity],|r|r.get(0))?;
  let mut query=db.prepare(&format!("SELECT json_object('runId',r.id,'startedAt',r.started_at,'url',json_extract(r.data,'$.plan.request.url'),'method',json_extract(r.data,'$.plan.request.method'),'finding',json(f.value)) FROM scan_runs r,json_each(r.data,'$.findings') f WHERE {filter} ORDER BY r.started_at DESC,r.id DESC,CAST(f.key AS INTEGER) ASC LIMIT 100 OFFSET ?5"))?;
  let rows=query.query_map(params![workspace,search,status,severity,offset],|r|r.get::<_,String>(0))?;let data=rows.map(|r|Ok(serde_json::from_str(&r?)?)).collect::<Result<Vec<_>>>()?;Ok((total,data))
 }
}
