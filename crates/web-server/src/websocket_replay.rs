//! Interactive browser WebSocket Replay with public DNS pinning and bounded messages.
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    protocol::{Message as TargetMessage, WebSocketConfig},
};

fn request(
    data: &Value,
) -> Result<
    (
        reqwest::Url,
        tokio_tungstenite::tungstenite::http::Request<()>,
    ),
    String,
> {
    let url = reqwest::Url::parse(data["url"].as_str().ok_or("URL required")?)
        .map_err(|e| e.to_string())?;
    if !matches!(
        (url.scheme(), url.port_or_known_default()),
        ("ws", Some(80)) | ("wss", Some(443))
    ) || url.fragment().is_some()
    {
        return Err("Use a public ws:// host on port 80 or wss:// host on port 443.".into());
    }
    let mut validation = url.clone();
    let host = url.host_str().unwrap_or("");
    if host.parse::<std::net::IpAddr>().is_ok()
        || host.starts_with('[')
        || !host.contains('.')
        || ["localhost", "local", "internal", "test", "invalid"].iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return Err("Use a public WebSocket hostname.".into());
    }
    validation
        .set_scheme("https")
        .map_err(|_| "Invalid scheme")?;
    validation.set_port(None).map_err(|_| "Invalid port")?;
    let input = json!({"url":validation.as_str(),"method":"GET","headers":data["headers"],"body":"","timeout":15000});
    super::http_sender::validate(&input)?;
    let mut req = url
        .as_str()
        .into_client_request()
        .map_err(|e| e.to_string())?;
    for (name, value) in data["headers"]
        .as_object()
        .ok_or("Headers must be an object")?
    {
        let lower = name.to_ascii_lowercase();
        // Generate fresh mandatory handshake headers. Preserve Origin, cookies, auth and subprotocols.
        if [
            "host",
            "connection",
            "upgrade",
            "content-length",
            "transfer-encoding",
            "expect",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-accept",
        ]
        .contains(&lower.as_str())
            || lower.starts_with("proxy-")
        {
            continue;
        }
        let name = tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| e.to_string())?;
        let value = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(
            value.as_str().ok_or("Header must be text")?,
        )
        .map_err(|e| e.to_string())?;
        req.headers_mut().insert(name, value);
    }
    Ok((url, req))
}
fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if text.len() > 2_000_000 || text.len() % 2 != 0 || !text.is_ascii() {
        return Err("Binary message must be hex, at most 1 MB".into());
    }
    text.as_bytes()
        .chunks(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16)
                .map_err(|_| "Invalid hex".into())
        })
        .collect()
}
fn outgoing(data: &Value) -> Result<TargetMessage, String> {
    let body = data["body"].as_str().ok_or("Message body required")?;
    if body.len() > 2_000_000 {
        return Err("Message exceeds 1 MB".into());
    }
    match data["kind"].as_str() {
        Some("binary") => Ok(TargetMessage::Binary(decode_hex(body)?)),
        Some("text") if body.len() <= 1_000_000 => Ok(TargetMessage::Text(body.into())),
        _ => Err("Choose text or binary hex (at most 1 MB)".into()),
    }
}
async fn emit(socket: &mut WebSocket, value: Value) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(10),
            socket.send(Message::Text(value.to_string()))
        )
        .await,
        Ok(Ok(()))
    )
}
pub async fn handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.max_message_size(2_100_000).on_upgrade(run)
}
async fn run(mut browser: WebSocket) {
    let result = async {
        let Some(Ok(Message::Text(first))) =
            tokio::time::timeout(Duration::from_secs(15), browser.recv())
                .await
                .map_err(|_| "Connection configuration timed out".to_string())?
        else {
            return Err("Connection configuration required".to_string());
        };
        let data: Value = serde_json::from_str(&first).map_err(|e| e.to_string())?;
        let (url, request) = request(&data)?;
        let host = url.host_str().unwrap();
        let port = url.port_or_known_default().unwrap();
        let (target, response) = tokio::time::timeout(Duration::from_secs(15), async {
            let addresses: Vec<_> = tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| e.to_string())?
                .collect();
            if addresses.is_empty() || addresses.iter().any(|a| !super::replay::public_ip(a.ip())) {
                return Err("Target must resolve exclusively to public addresses".into());
            }
            // Connect to the validated IPs directly; TLS still validates the original hostname.
            let stream = tokio::net::TcpStream::connect(addresses.as_slice())
                .await
                .map_err(|e| e.to_string())?;
            let config = WebSocketConfig {
                max_message_size: Some(1_000_000),
                max_frame_size: Some(1_000_000),
                ..Default::default()
            };
            tokio_tungstenite::client_async_tls_with_config(request, stream, Some(config), None)
                .await
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|_| "WebSocket handshake timed out".to_string())??;
        exchange(&mut browser, target, response).await?;
        Ok::<(), String>(())
    }
    .await;
    if let Err(error) = result {
        emit(&mut browser, json!({"type":"error","error":error})).await;
    }
    emit(&mut browser, json!({"type":"closed"})).await;
    let _ = browser.close().await;
}
async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    browser: &mut WebSocket,
    mut target: tokio_tungstenite::WebSocketStream<S>,
    response: tokio_tungstenite::tungstenite::handshake::client::Response,
) -> Result<(), String> {
    let headers: Vec<_> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str(), v.to_str().unwrap_or("")))
        .collect();
    if !emit(
        browser,
        json!({"type":"connected","status":response.status().as_u16(),"headers":headers}),
    )
    .await
    {
        return Ok(());
    }
    loop {
        tokio::select! {
            command=browser.recv()=>{
                match command {
                    Some(Ok(Message::Text(command)))=>{
                        let parsed=serde_json::from_str::<Value>(&command).map_err(|e|e.to_string());
                        let data=match parsed {Ok(v)=>v,Err(e)=>{if !emit(browser,json!({"type":"error","error":e})).await {break;}continue;}};
                        if data["type"]=="close" {let _=tokio::time::timeout(Duration::from_secs(2),target.close(None)).await;break;}
                        let message=match outgoing(&data) {Ok(v)=>v,Err(e)=>{if !emit(browser,json!({"type":"error","error":e})).await {break;}continue;}};
                        tokio::time::timeout(Duration::from_secs(10),target.send(message)).await.map_err(|_|"Message send timed out".to_string())?.map_err(|e|e.to_string())?;
                        if !emit(browser,json!({"type":"message","direction":"outgoing","kind":data["kind"],"body":data["body"]})).await {break;}
                    },Some(Ok(Message::Ping(p)))=>{browser.send(Message::Pong(p)).await.map_err(|e|e.to_string())?;},_=>{let _=tokio::time::timeout(Duration::from_secs(2),target.close(None)).await;break;}
                }
            },
            incoming=target.next()=>{
                let Some(incoming)=incoming else {break;};
                let msg=incoming.map_err(|e|e.to_string())?;
                let (kind,body)=match msg {
                    TargetMessage::Text(text)=>("text",text),
                    TargetMessage::Binary(bytes)=>("binary",bytes.iter().map(|b|format!("{b:02x}")).collect()),
                    TargetMessage::Ping(bytes)=>{tokio::time::timeout(Duration::from_secs(10),target.flush()).await.map_err(|_|"Ping response timed out".to_string())?.map_err(|e|e.to_string())?;("ping",bytes.iter().map(|b|format!("{b:02x}")).collect())},
                    TargetMessage::Pong(bytes)=>("pong",bytes.iter().map(|b|format!("{b:02x}")).collect()),
                    TargetMessage::Close(frame)=>{emit(browser,json!({"type":"closed","reason":frame.map(|f|format!("{} {}",f.code,f.reason))})).await;break;},_=>continue,
                };
                if !emit(browser,json!({"type":"message","direction":"incoming","kind":kind,"body":body})).await {break;}
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_targets_and_regenerates_handshake_headers() {
        for url in [
            "ws://127.0.0.1/",
            "wss://localhost/",
            "wss://example.com:444/",
            "wss://u:p@example.com/",
            "http://example.com/",
        ] {
            assert!(request(&json!({"url":url,"headers":{}})).is_err(), "{url}");
        }
        let (_,req)=request(&json!({"url":"wss://example.com/ws","headers":{"Authorization":"Bearer abc","Sec-WebSocket-Key":"old","Sec-WebSocket-Extensions":"permessage-deflate"}})).unwrap();
        assert_eq!(req.headers()["authorization"], "Bearer abc");
        assert_ne!(req.headers()["sec-websocket-key"], "old");
        assert!(!req.headers().contains_key("sec-websocket-extensions"));
        assert!(request(&json!({"url":"ws://example.com/ws","headers":{}})).is_ok());
    }
    #[tokio::test]
    async fn interactive_bridge_sends_text_binary_and_reports_invalid_hex() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = upstream.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = upstream.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    if message.is_close() {
                        break;
                    }
                    socket.send(message).await.unwrap();
                }
            });
            let app = axum::Router::new().route(
                "/bridge",
                axum::routing::get(move |ws: WebSocketUpgrade| async move {
                    ws.on_upgrade(move |mut browser| async move {
                        let (target, response) =
                            tokio_tungstenite::connect_async(format!("ws://{addr}/"))
                                .await
                                .unwrap();
                        exchange(&mut browser, target, response).await.unwrap();
                    })
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let api = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let (mut client, _) =
                tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/bridge"))
                    .await
                    .unwrap();
            let connected: Value =
                serde_json::from_str(client.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_eq!(connected["type"], "connected");
            client
                .send(TargetMessage::Text(
                    json!({"kind":"binary","body":"zz"}).to_string(),
                ))
                .await
                .unwrap();
            let invalid: Value =
                serde_json::from_str(client.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_eq!(invalid["type"], "error");
            for (kind, body) in [("text", "edited message"), ("binary", "00ff2a")] {
                client
                    .send(TargetMessage::Text(
                        json!({"kind":kind,"body":body}).to_string(),
                    ))
                    .await
                    .unwrap();
                let sent: Value =
                    serde_json::from_str(client.next().await.unwrap().unwrap().to_text().unwrap())
                        .unwrap();
                assert_eq!(sent["direction"], "outgoing");
                let reply: Value =
                    serde_json::from_str(client.next().await.unwrap().unwrap().to_text().unwrap())
                        .unwrap();
                assert_eq!(reply["direction"], "incoming");
                assert_eq!(reply["body"], body);
                assert_eq!(reply["kind"], kind);
            }
            client.close(None).await.unwrap();
            drop(client);
            server.await.unwrap();
            api.abort();
        })
        .await
        .unwrap();
    }
    #[test]
    fn validates_message_encoding() {
        assert_eq!(decode_hex("00 ff 2A").unwrap(), vec![0, 255, 42]);
        assert!(decode_hex("a").is_err());
        assert!(decode_hex("zz").is_err());
        assert!(outgoing(&json!({"kind":"text","body":"hello"})).is_ok());
    }
}
