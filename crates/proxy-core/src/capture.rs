//! Remote capture: clients that forward traffic to this server, and the local spool a client keeps
//! until the server has accepted it.
use crate::storage::{TrafficEntry, TrafficStorage, WorkspaceError, ENTRY_COLUMNS};
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, params_from_iter, OptionalExtension};
use serde::Serialize;
use uuid::Uuid;

/// A registered capture client. The token itself is never stored, only its hash.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureClient {
    pub id: String,
    pub name: String,
    pub workspace_id: String,
    pub workspace_name: Option<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

/// Who an ingest token belongs to.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub id: String,
    pub name: String,
    pub workspace_id: String,
}

impl ClientIdentity {
    /// The `source` recorded on every entry this client uploads.
    pub fn source(&self) -> String {
        format!("client:{}", self.name)
    }
}

#[derive(Debug)]
pub enum IngestError {
    /// The client's workspace no longer exists.
    NotFound,
    /// The entry id is already used by traffic from somewhere else.
    Conflict,
    Other(anyhow::Error),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "workspace not found"),
            Self::Conflict => write!(f, "entry id belongs to other traffic"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IngestError {}

impl From<rusqlite::Error> for IngestError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Other(e.into())
    }
}
impl From<anyhow::Error> for IngestError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

impl TrafficStorage {
    /// Register a client whose token hash is `token_hash`, bound to `workspace_id`.
    pub fn create_capture_client(&self, name: &str, workspace_id: &str, token_hash: &str) -> Result<CaptureClient, WorkspaceError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 40 || name.chars().any(|c| c.is_control() || c == ',') {
            return Err(WorkspaceError::InvalidName);
        }
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now().to_rfc3339();
        let workspace_name: String = {
            let db = self.lock_db().map_err(WorkspaceError::Other)?;
            let workspace_name = db
                .query_row("SELECT name FROM workspaces WHERE id=?1", params![workspace_id], |r| r.get(0))
                .optional()?
                .ok_or(WorkspaceError::NotFound)?;
            db.execute(
                "INSERT INTO capture_clients (id, name, workspace_id, token_hash, created_at) VALUES (?1,?2,?3,?4,?5)",
                params![id, name, workspace_id, token_hash, created_at],
            )?;
            workspace_name
        };
        Ok(CaptureClient { id, name: name.into(), workspace_id: workspace_id.into(), workspace_name: Some(workspace_name), created_at, last_seen_at: None })
    }

    pub fn list_capture_clients(&self) -> Result<Vec<CaptureClient>> {
        let db = self.lock_db()?;
        let mut stmt = db.prepare(
            "SELECT c.id, c.name, c.workspace_id, w.name, c.created_at, c.last_seen_at
             FROM capture_clients c LEFT JOIN workspaces w ON w.id = c.workspace_id ORDER BY c.created_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(CaptureClient { id: r.get(0)?, name: r.get(1)?, workspace_id: r.get(2)?, workspace_name: r.get(3)?, created_at: r.get(4)?, last_seen_at: r.get(5)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Revoke a client; its token stops working immediately.
    pub fn delete_capture_client(&self, id: &str) -> Result<bool> {
        Ok(self.lock_db()?.execute("DELETE FROM capture_clients WHERE id=?1", params![id])? > 0)
    }

    /// Look a client up by token hash and record that it was seen.
    pub fn authenticate_capture_client(&self, token_hash: &str) -> Result<Option<ClientIdentity>> {
        let db = self.lock_db()?;
        let found = db
            .query_row("SELECT id, name, workspace_id FROM capture_clients WHERE token_hash=?1", params![token_hash], |r| {
                Ok(ClientIdentity { id: r.get(0)?, name: r.get(1)?, workspace_id: r.get(2)? })
            })
            .optional()?;
        if let Some(client) = &found {
            db.execute("UPDATE capture_clients SET last_seen_at=?1 WHERE id=?2", params![Utc::now().to_rfc3339(), client.id])?;
        }
        Ok(found)
    }

    /// Store an uploaded entry in the client's workspace. Re-sending the same entry is harmless,
    /// but a client can never overwrite traffic that was not its own.
    pub fn ingest_entry(&self, entry: &TrafficEntry, client: &ClientIdentity) -> Result<(), IngestError> {
        {
            let db = self.lock_db()?;
            if !db.prepare("SELECT 1 FROM workspaces WHERE id=?1")?.exists(params![client.workspace_id])? {
                return Err(IngestError::NotFound);
            }
            let existing: Option<(String, String)> = db
                .query_row("SELECT workspace_id, source FROM traffic WHERE id=?1", params![entry.id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            if existing.is_some_and(|(workspace, source)| workspace != client.workspace_id || source != client.source()) {
                return Err(IngestError::Conflict);
            }
        }
        let mut entry = entry.clone();
        entry.source = client.source();
        self.insert_in_workspace(&entry, &client.workspace_id)?;
        Ok(())
    }

    /// The oldest entries of `workspace` not yet removed, as `(rowid, entry)`. A client's spool is
    /// just its local workspace: whatever is still there has not been uploaded.
    pub fn spooled_entries(&self, workspace: &str, limit: usize) -> Result<Vec<(i64, TrafficEntry)>> {
        let db = self.lock_db()?;
        let mut stmt = db.prepare(&format!("SELECT rowid, {ENTRY_COLUMNS} FROM traffic WHERE workspace_id=?1 ORDER BY rowid LIMIT ?2"))?;
        let rows = stmt.query_map(params![workspace, limit as i64], |row| Ok((row.get::<_, i64>(0)?, entry_after_rowid(row)?)))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn spool_len(&self, workspace: &str) -> Result<u64> {
        Ok(self.lock_db()?.query_row("SELECT COUNT(*) FROM traffic WHERE workspace_id=?1", params![workspace], |r| r.get(0))?)
    }

    /// Remove uploaded (or filtered-out) entries without notifying subscribers.
    pub fn remove_entries(&self, ids: &[String]) -> Result<()> {
        let db = self.lock_db()?;
        let tx = db.unchecked_transaction()?;
        for chunk in ids.chunks(500) {
            let marks = (1..=chunk.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(",");
            tx.execute(&format!("DELETE FROM traffic WHERE id IN ({marks})"), params_from_iter(chunk.iter()))?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Drop the oldest entries beyond `max` so an unreachable server cannot fill the disk.
    pub fn trim_spool(&self, workspace: &str, max: u64) -> Result<u64> {
        Ok(self.lock_db()?.execute(
            "DELETE FROM traffic WHERE workspace_id=?1 AND rowid <= (SELECT rowid FROM traffic WHERE workspace_id=?1 ORDER BY rowid DESC LIMIT 1 OFFSET ?2)",
            params![workspace, max as i64],
        )? as u64)
    }

    /// WebSocket history is not forwarded yet, so a client discards what its proxy recorded.
    pub fn clear_websocket_history(&self, workspace: &str) -> Result<()> {
        let db = self.lock_db()?;
        db.execute("DELETE FROM websocket_requests WHERE id IN (SELECT id FROM websocket_connections WHERE workspace_id=?1)", params![workspace])?;
        db.execute("DELETE FROM websocket_frames WHERE connection_id IN (SELECT id FROM websocket_connections WHERE workspace_id=?1)", params![workspace])?;
        db.execute("DELETE FROM websocket_connections WHERE workspace_id=?1", params![workspace])?;
        Ok(())
    }
}

/// `row_to_entry` for a row whose first column is the rowid.
fn entry_after_rowid(row: &rusqlite::Row<'_>) -> rusqlite::Result<TrafficEntry> {
    use chrono::{DateTime, Utc};
    Ok(TrafficEntry {
        id: row.get(1)?,
        timestamp: row.get::<_, String>(2)?.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now()),
        method: row.get(3)?,
        url: row.get(4)?,
        host: row.get(5)?,
        path: row.get(6)?,
        scheme: row.get(7)?,
        request_headers: row.get(8)?,
        request_body: row.get(9)?,
        request_content_type: row.get(10)?,
        status_code: row.get(11)?,
        response_headers: row.get(12)?,
        response_body: row.get(13)?,
        response_content_type: row.get(14)?,
        duration_ms: row.get(15)?,
        request_size: row.get(16)?,
        response_size: row.get(17)?,
        error: row.get(18)?,
        workspace_id: row.get(19)?,
        source: row.get(20)?,
        bookmarked: row.get(21)?,
        notes: row.get(22)?,
    })
}
