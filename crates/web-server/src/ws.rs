/// WebSocket handler for real-time traffic streaming.
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use proxy_core::TrafficStorage;
use std::sync::Arc;
use tracing::{debug, info};

/// `GET /api/ws` — upgrade to WebSocket for live traffic feed.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(storage): State<Arc<TrafficStorage>>,
) -> impl IntoResponse {
    ws.protocols(["slurp.v1"]).on_upgrade(move |socket| handle_socket(socket, storage))
}

async fn handle_socket(socket: WebSocket, storage: Arc<TrafficStorage>) {
    let (mut tx, mut rx) = socket.split();

    // Subscribe to traffic events from the broadcast channel
    let mut receiver = storage.subscribe();

    info!("🔌 WebSocket client connected");

    // Spawn a task to forward broadcast events to the WebSocket client
    let send_task = tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    let json = match serde_json::to_string(&event) {
                        Ok(j) => j,
                        Err(e) => {
                            debug!("Failed to serialize event: {}", e);
                            continue;
                        }
                    };
                    if tx.send(Message::Text(json.into())).await.is_err() {
                        // Client disconnected
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    debug!("WebSocket client lagged by {} messages", n);
                    // Send a notification about lagged messages
                    let msg = serde_json::json!({
                        "type": "lagged",
                        "count": n
                    });
                    let _ = tx
                        .send(Message::Text(msg.to_string().into()))
                        .await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    // Read from the WebSocket (handle pings, client messages, close)
    while let Some(msg) = rx.next().await {
        match msg {
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(data)) => {
                // Pong is sent automatically by axum
                debug!("Received ping: {:?}", data);
            }
            Ok(_) => {
                // We don't expect messages from the client, but handle gracefully
            }
            Err(e) => {
                debug!("WebSocket receive error: {}", e);
                break;
            }
        }
    }

    // Abort the send task when the client disconnects
    send_task.abort();

    info!("🔌 WebSocket client disconnected");
}
