//! Transparent WebSocket relay. Capture bounded frame previews without changing wire bytes.
use crate::storage::{Target, TrafficStorage, TEMP_WORKSPACE_ID};
use anyhow::Result;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS websocket_connections(id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, url TEXT NOT NULL, host TEXT NOT NULL, opened_at TEXT NOT NULL, closed_at TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS ws_workspace ON websocket_connections(workspace_id,opened_at);
CREATE TABLE IF NOT EXISTS websocket_frames(id INTEGER PRIMARY KEY AUTOINCREMENT, connection_id TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS websocket_requests(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ws_frames ON websocket_frames(connection_id,id);
";
#[derive(Debug, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub workspace_id: String,
    pub url: String,
    pub host: String,
    pub opened_at: String,
    pub closed_at: Option<String>,
    pub error: Option<String>,
    pub frames: u64,
    pub request: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    #[serde(default)]
    pub dropped: bool,
    pub id: i64,
    pub direction: String,
    pub timestamp: String,
    pub opcode: u8,
    pub fin: bool,
    pub compressed: bool,
    pub masked: bool,
    pub size: u64,
    pub text: Option<String>,
    pub hex: String,
    pub truncated: bool,
}
impl TrafficStorage {
    pub fn open_websocket(&self, url: &str, host: &str) -> Result<(String, String)> {
        let workspace = match self.target() {
            Target::Workspace(id) => id,
            _ => TEMP_WORKSPACE_ID.into(),
        };
        let id = uuid::Uuid::new_v4().to_string();
        let db = self.lock_for(Some(&workspace))?;
        if workspace != TEMP_WORKSPACE_ID
            && !db
                .prepare("SELECT 1 FROM workspaces WHERE id=?1")?
                .exists(params![workspace])?
        {
            anyhow::bail!("Workspace no longer exists");
        }
        db.execute("INSERT INTO websocket_connections(id,workspace_id,url,host,opened_at) VALUES(?1,?2,?3,?4,?5)", params![id,workspace,url,host,chrono::Utc::now().to_rfc3339()])?;
        Ok((id, workspace))
    }
    pub fn set_websocket_request(
        &self,
        workspace: &str,
        id: &str,
        request: &serde_json::Value,
    ) -> Result<()> {
        self.lock_for(Some(workspace))?.execute("INSERT OR REPLACE INTO websocket_requests(id,data) SELECT id,?2 FROM websocket_connections WHERE id=?1",params![id,request.to_string()])?;
        Ok(())
    }
    pub fn websocket_connections(
        &self,
        workspace: Option<&str>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Connection>> {
        let db = self.lock_for(workspace)?;
        let mut stmt=db.prepare("SELECT id,workspace_id,url,host,opened_at,closed_at,error,(SELECT count(*) FROM websocket_frames f WHERE f.connection_id=c.id),(SELECT data FROM websocket_requests r WHERE r.id=c.id) FROM websocket_connections c WHERE (?1 IS NULL OR workspace_id=?1) AND (?2 IS NULL OR opened_at < ?2) ORDER BY opened_at DESC LIMIT ?3")?;
        let rows = stmt.query_map(params![workspace, before, limit.min(200)], |r| {
            Ok(Connection {
                id: r.get(0)?,
                workspace_id: r.get(1)?,
                url: r.get(2)?,
                host: r.get(3)?,
                opened_at: r.get(4)?,
                closed_at: r.get(5)?,
                error: r.get(6)?,
                frames: r.get(7)?,
                request: r
                    .get::<_, Option<String>>(8)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    pub fn websocket_frames(
        &self,
        workspace: Option<&str>,
        id: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<Frame>> {
        let db = self.lock_for(workspace)?;
        let mut stmt=db.prepare("SELECT f.id,f.data FROM websocket_frames f JOIN websocket_connections c ON c.id=f.connection_id WHERE c.id=?1 AND (?2 IS NULL OR c.workspace_id=?2) AND f.id>?3 ORDER BY f.id LIMIT ?4")?;
        let rows = stmt.query_map(params![id, workspace, after, limit.min(200)], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut frames = Vec::new();
        for row in rows {
            let (id, data) = row?;
            let mut frame: Frame = serde_json::from_str(&data)?;
            frame.id = id;
            frames.push(frame);
        }
        Ok(frames)
    }
    fn websocket_frame(&self, workspace: &str, id: &str, frame: &Frame) -> Result<()> {
        // INSERT ... SELECT prevents deleted/cleared connections from being resurrected.
        self.lock_for(Some(workspace))?.execute("INSERT INTO websocket_frames(connection_id,data) SELECT id,?2 FROM websocket_connections WHERE id=?1",params![id,serde_json::to_string(frame)?])?;
        Ok(())
    }
    pub fn close_websocket(&self, workspace: &str, id: &str, error: Option<String>) -> Result<()> {
        self.lock_for(Some(workspace))?.execute(
            "UPDATE websocket_connections SET closed_at=?2,error=?3 WHERE id=?1",
            params![id, chrono::Utc::now().to_rfc3339(), error],
        )?;
        Ok(())
    }
    pub(crate) fn clear_websockets(&self, workspace: Option<&str>) -> Result<()> {
        for target in if workspace.is_none() {
            vec![None, Some(TEMP_WORKSPACE_ID)]
        } else {
            vec![workspace]
        } {
            let db = self.lock_for(target)?;
            db.execute("DELETE FROM websocket_requests WHERE id IN (SELECT id FROM websocket_connections WHERE ?1 IS NULL OR workspace_id=?1)",params![target])?;
            db.execute("DELETE FROM websocket_frames WHERE connection_id IN (SELECT id FROM websocket_connections WHERE ?1 IS NULL OR workspace_id=?1)",params![target])?;
            db.execute(
                "DELETE FROM websocket_connections WHERE ?1 IS NULL OR workspace_id=?1",
                params![target],
            )?;
        }
        Ok(())
    }
}

async fn pipe<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    storage: Arc<TrafficStorage>,
    capture: Option<(String, String)>,
    direction: &str,
    interception: Option<(Arc<crate::Intercept>, crate::intercept::HoldContext)>,
) -> std::io::Result<()> {
    let mut compressed_message = false;
    let mut text_message = false;
    loop {
        let mut head = [0u8; 2];
        match reader.read_exact(&mut head[..1]).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                writer.shutdown().await?;
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        reader.read_exact(&mut head[1..]).await?;
        let mut wire = head.to_vec();
        let opcode = head[0] & 15;
        let fin = head[0] & 128 != 0;
        let masked = head[1] & 128 != 0;
        let mut size = (head[1] & 127) as u64;
        if size >= 126 {
            let n = if size == 126 { 2 } else { 8 };
            let mut ext = [0u8; 8];
            reader.read_exact(&mut ext[8 - n..]).await?;
            wire.extend_from_slice(&ext[8 - n..]);
            size = u64::from_be_bytes(ext);
        }
        let mut mask = [0u8; 4];
        if masked {
            reader.read_exact(&mut mask).await?;
            wire.extend_from_slice(&mask);
        }
        if opcode == 1 || opcode == 2 {
            compressed_message = head[0] & 64 != 0;
            text_message = opcode == 1;
        }
        let compressed = opcode < 8 && compressed_message;
        let should_hold = interception.as_ref().is_some_and(|(i, ctx)| {
            i.scope().matches(&ctx.host)
                && if direction == "client_to_server" {
                    i.settings().requests
                } else {
                    i.settings().responses
                }
        });
        // Buffer only a bounded prefix. No header or payload byte is sent before Forward.
        let prefix_len = if should_hold {
            size.min(65536) as usize
        } else {
            0
        };
        let mut prefix = vec![0u8; prefix_len];
        reader.read_exact(&mut prefix).await?;
        let mut preview: Vec<u8> = prefix
            .iter()
            .enumerate()
            .map(|(n, b)| if masked { *b ^ mask[n % 4] } else { *b })
            .collect();
        let make_frame = |preview: &Vec<u8>, dropped| Frame {
            id: 0,
            dropped,
            direction: direction.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            opcode,
            fin,
            compressed,
            masked,
            size,
            text: if !compressed
                && (opcode == 1 || (opcode == 0 && text_message) || opcode == 9 || opcode == 10)
            {
                String::from_utf8(preview.clone()).ok()
            } else {
                None
            },
            hex: preview.iter().map(|b| format!("{b:02x}")).collect(),
            truncated: size > preview.len() as u64,
        };
        let forward = if should_hold {
            let (i, ctx) = interception.as_ref().unwrap();
            i.hold_websocket_frame(ctx, make_frame(&preview, false))
                .await
        } else {
            true
        };
        if forward {
            writer.write_all(&wire).await?;
            writer.write_all(&prefix).await?;
        }
        let mut remaining = size - prefix_len as u64;
        let mut offset = prefix_len as u64;
        let mut buf = [0u8; 16384];
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..n]).await?;
            if forward {
                writer.write_all(&buf[..n]).await?;
            }
            if capture.is_some() {
                for (i, b) in buf[..n]
                    .iter()
                    .enumerate()
                    .take(65536usize.saturating_sub(preview.len()))
                {
                    preview.push(if masked {
                        *b ^ mask[((offset + i as u64) % 4) as usize]
                    } else {
                        *b
                    });
                }
            }
            offset += n as u64;
            remaining -= n as u64;
        }
        if let Some((id, workspace)) = &capture {
            if let Err(e) = storage.websocket_frame(workspace, id, &make_frame(&preview, !forward))
            {
                tracing::warn!("WebSocket capture: {e}");
            }
        }
        if opcode < 8 && fin {
            compressed_message = false;
        }
    }
}
pub async fn relay(
    client: hyper::upgrade::OnUpgrade,
    server: hyper::upgrade::OnUpgrade,
    storage: Arc<TrafficStorage>,
    capture: Option<(String, String)>,
    intercept: Arc<crate::Intercept>,
    context: crate::intercept::HoldContext,
) {
    let result = async {
        let (client, server) = tokio::try_join!(client, server)?;
        let (cr, cw) = tokio::io::split(hyper_util::rt::TokioIo::new(client));
        let (sr, sw) = tokio::io::split(hyper_util::rt::TokioIo::new(server));
        tokio::try_join!(
            pipe(
                cr,
                sw,
                storage.clone(),
                capture.clone(),
                "client_to_server",
                Some((intercept.clone(), context.clone()))
            ),
            pipe(
                sr,
                cw,
                storage.clone(),
                capture.clone(),
                "server_to_client",
                Some((intercept, context))
            )
        )?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Some((id, workspace)) = capture {
        let _ = storage.close_websocket(&workspace, &id, result.err().map(|e| e.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn masked_fragmented_compressed_and_large_frames_are_forwarded_unchanged() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let capture = storage
            .open_websocket("ws://example.com/socket", "example.com")
            .unwrap();
        let (mut input, reader) = tokio::io::duplex(1024);
        let (writer, mut output) = tokio::io::duplex(1024);
        let worker = tokio::spawn(pipe(
            reader,
            writer,
            storage.clone(),
            Some(capture.clone()),
            "client_to_server",
            None,
        ));
        let mut wire = vec![
            0x01,
            0x83,
            1,
            2,
            3,
            4,
            b'a' ^ 1,
            b'b' ^ 2,
            b'c' ^ 3,
            0x80,
            2,
            b'd',
            b'e',
            0x89,
            0,
            0xc2,
            3,
            0xff,
            0,
            0xaa,
            0x82,
            127,
        ];
        wire.extend_from_slice(&70000u64.to_be_bytes());
        wire.extend(vec![42u8; 70000]);
        let expected = wire.clone();
        let producer = tokio::spawn(async move {
            for part in wire.chunks(7) {
                input.write_all(part).await.unwrap();
            }
            input.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        output.read_to_end(&mut received).await.unwrap();
        producer.await.unwrap();
        worker.await.unwrap().unwrap();
        assert_eq!(received, expected);
        let frames = storage
            .websocket_frames(Some(&capture.1), &capture.0, 0, 100)
            .unwrap();
        assert_eq!(frames.len(), 5);
        assert_eq!(frames[0].text.as_deref(), Some("abc"));
        assert!(!frames[0].fin);
        assert_eq!(frames[1].text.as_deref(), Some("de"));
        assert_eq!(frames[2].opcode, 9);
        assert!(frames[3].compressed);
        assert_eq!(frames[3].hex, "ff00aa");
        assert_eq!(frames[4].size, 70000);
        assert!(frames[4].truncated);
        assert_eq!(frames[4].hex.len(), 65536 * 2);
    }

    #[tokio::test]
    async fn websocket_frames_wait_for_forward_drop_and_switch_off_in_both_directions() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for direction in ["client_to_server", "server_to_client"] {
                let storage = TrafficStorage::new(":memory:", 1024).unwrap();
                let interceptor = crate::Intercept::new(storage.clone());
                interceptor.update_settings(crate::SettingsUpdate {
                    requests: Some(true),
                    responses: Some(true),
                });
                let capture = storage
                    .open_websocket("ws://example.com/socket", "example.com")
                    .unwrap();
                let ctx = crate::intercept::HoldContext {
                    request: None,
                    scheme: "ws".into(),
                    host: "example.com".into(),
                    url: "ws://example.com/socket".into(),
                    method: "GET".into(),
                    path: "/socket".into(),
                };
                let (mut input, reader) = tokio::io::duplex(1024);
                let (writer, mut output) = tokio::io::duplex(1024);
                let task = tokio::spawn(pipe(
                    reader,
                    writer,
                    storage.clone(),
                    Some(capture.clone()),
                    direction,
                    Some((interceptor.clone(), ctx)),
                ));
                let wire = if direction == "client_to_server" {
                    vec![0x81, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2]
                } else {
                    vec![0x81, 2, b'h', b'i']
                };
                input.write_all(&wire).await.unwrap();
                while interceptor.list().is_empty() {
                    tokio::task::yield_now().await;
                }
                let held = interceptor.list()[0].clone();
                assert_eq!(held.websocket.as_ref().unwrap().text.as_deref(), Some("hi"));
                assert_eq!(
                    held.phase,
                    if direction == "client_to_server" {
                        crate::Phase::Request
                    } else {
                        crate::Phase::Response
                    }
                );
                assert!(tokio::time::timeout(
                    std::time::Duration::from_millis(30),
                    output.read_u8()
                )
                .await
                .is_err());
                assert!(interceptor
                    .resolve(
                        &held.id,
                        crate::InterceptAction::Forward(Some(crate::InterceptEdit::default()))
                    )
                    .is_err());
                interceptor
                    .resolve(&held.id, crate::InterceptAction::Drop)
                    .unwrap();
                input.write_all(&wire).await.unwrap();
                while interceptor.list().is_empty() {
                    tokio::task::yield_now().await;
                }
                assert!(tokio::time::timeout(
                    std::time::Duration::from_millis(30),
                    output.read_u8()
                )
                .await
                .is_err());
                let held = interceptor.list()[0].clone();
                interceptor
                    .resolve(&held.id, crate::InterceptAction::Forward(None))
                    .unwrap();
                let mut received = vec![0; wire.len()];
                output.read_exact(&mut received).await.unwrap();
                assert_eq!(received, wire);
                input.write_all(&wire).await.unwrap();
                while interceptor.list().is_empty() {
                    tokio::task::yield_now().await;
                }
                interceptor.update_settings(crate::SettingsUpdate {
                    requests: Some(false),
                    responses: Some(false),
                });
                output.read_exact(&mut received).await.unwrap();
                assert_eq!(received, wire);
                input.shutdown().await.unwrap();
                task.await.unwrap().unwrap();
                let frames = storage
                    .websocket_frames(Some(&capture.1), &capture.0, 0, 100)
                    .unwrap();
                assert_eq!(frames.len(), 3);
                assert!(frames[0].dropped);
                assert!(!frames[1].dropped);
                assert!(!frames[2].dropped);
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn workspace_isolation_persistence_pagination_and_clear_do_not_resurrect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ws.db");
        let s = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
        let temporary = s.open_websocket("ws://temp/", "temp").unwrap();
        let ws = s.create_workspace("WebSocket test").unwrap();
        s.set_active_workspace(&ws.id).unwrap();
        let c = s
            .open_websocket("wss://example.com/", "example.com")
            .unwrap();
        s.set_websocket_request(&c.1,&c.0,&serde_json::json!({"method":"GET","url":"wss://example.com/","headers":{"Authorization":"Bearer saved"},"body":""})).unwrap();
        let frame = Frame {
            dropped: false,
            id: 0,
            direction: "server_to_client".into(),
            timestamp: "now".into(),
            opcode: 1,
            fin: true,
            masked: false,
            compressed: false,
            size: 2,
            text: Some("hi".into()),
            hex: "6869".into(),
            truncated: false,
        };
        s.websocket_frame(&c.1, &c.0, &frame).unwrap();
        s.websocket_frame(&c.1, &c.0, &frame).unwrap();
        let first = s.websocket_frames(Some(&c.1), &c.0, 0, 1).unwrap();
        assert_eq!(
            s.websocket_frames(Some(&c.1), &c.0, first[0].id, 100)
                .unwrap()
                .len(),
            1
        );
        assert!(s
            .websocket_frames(Some(TEMP_WORKSPACE_ID), &c.0, 0, 100)
            .unwrap()
            .is_empty());
        assert_eq!(s.websocket_connections(None, None, 100).unwrap().len(), 1);
        drop(s);
        let s = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
        assert_eq!(
            s.websocket_connections(Some(&c.1), None, 100).unwrap()[0]
                .request
                .as_ref()
                .unwrap()["headers"]["Authorization"],
            "Bearer saved"
        );
        assert_eq!(
            s.websocket_frames(Some(&c.1), &c.0, 0, 100).unwrap().len(),
            2
        );
        assert!(s
            .websocket_connections(Some(&temporary.1), None, 100)
            .unwrap()
            .is_empty());
        s.clear(Some(&c.1)).unwrap();
        s.websocket_frame(&c.1, &c.0, &frame).unwrap();
        assert!(s
            .websocket_frames(Some(&c.1), &c.0, 0, 100)
            .unwrap()
            .is_empty());
        s.set_active_workspace(&ws.id).unwrap();
        let c = s.open_websocket("ws://a/", "a").unwrap();
        s.delete_workspace(&ws.id).unwrap();
        s.websocket_frame(&c.1, &c.0, &frame).unwrap();
        assert!(s
            .websocket_connections(Some(&c.1), None, 100)
            .unwrap()
            .is_empty());
    }
}
