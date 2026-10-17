//! Management credentials are separate from proxy traffic and never embedded in UI assets.
use anyhow::Result;
use axum::{extract::{Request,State},http::{header,StatusCode},middleware::Next,response::{IntoResponse,Response},Json};
use std::{path::Path,sync::Arc};
#[derive(Clone)] pub struct ApiAccess(Arc<String>);
impl ApiAccess {
    pub fn load(directory:&Path)->Result<Self> {
        proxy_core::private_files::directory(directory)?;
        let path=directory.join("api-token");
        if !path.exists() {
            let token=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());
            match proxy_core::private_files::create(&path,token.as_bytes()) { Ok(())=>{},Err(error) if !path.exists()=>return Err(error),Err(_)=>{} }
        }
        proxy_core::private_files::restrict(&path,false)?;
        let token=std::fs::read_to_string(path)?;
        anyhow::ensure!(token.len()==64 && token.bytes().all(|v|v.is_ascii_hexdigit()),"Invalid management token file");
        Ok(Self(Arc::new(token)))
    }
    pub fn token(&self)->&str {&self.0}
    fn accepts(&self,value:&str)->bool {
        if value.len()!=self.0.len(){return false;}
        self.0.bytes().zip(value.bytes()).fold(0,|difference,(a,b)|difference|(a^b))==0
    }
    fn authorized(&self,request:&Request)->bool {
        if request.headers().get(header::AUTHORIZATION).and_then(|v|v.to_str().ok()).and_then(|v|v.strip_prefix("Bearer ")).is_some_and(|v|self.accepts(v)){return true;}
        // Browser WebSocket API cannot set Authorization; use a non-echoed subprotocol.
        request.headers().get(header::UPGRADE).is_some_and(|v|v.as_bytes().eq_ignore_ascii_case(b"websocket")) &&
            request.headers().get(header::SEC_WEBSOCKET_PROTOCOL).and_then(|v|v.to_str().ok()).is_some_and(|v|v.split(',').any(|p|p.trim().strip_prefix("slurp-auth.").is_some_and(|v|self.accepts(v))))
    }
}
pub async fn guard(State(access):State<ApiAccess>,request:Request,next:Next)->Response {
    if request.uri().path().starts_with("/api/") && request.method()!=axum::http::Method::OPTIONS && !access.authorized(&request) {
        return (StatusCode::UNAUTHORIZED,[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"error":"Open the authenticated Slurp URL printed at startup to connect this browser."}))).into_response();
    }
    next.run(request).await
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn tokens_persist_and_only_exact_credentials_work() {
        let directory=tempfile::tempdir().unwrap();let access=ApiAccess::load(directory.path()).unwrap();assert_eq!(access.token(),ApiAccess::load(directory.path()).unwrap().token());
        let req=|value:&str|Request::builder().uri("/api/session").header("Authorization",value).body(axum::body::Body::empty()).unwrap();
        assert!(!access.authorized(&req("")));assert!(!access.authorized(&req("Bearer wrong")));
        assert!(access.authorized(&req(&format!("Bearer {}",access.token()))));
        let ws=Request::builder().uri("/api/ws").header("Upgrade","websocket").header("Sec-WebSocket-Protocol",format!("slurp-auth.{}",access.token())).body(axum::body::Body::empty()).unwrap();assert!(access.authorized(&ws));
    }
}

#[cfg(test)] mod route_tests {
    use super::*;
    use axum::{routing::get,Router};
    use tower::ServiceExt;
    #[tokio::test]
    async fn browser_websockets_select_public_protocol_without_echoing_credentials() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let directory = tempfile::tempdir().unwrap();
        let access = ApiAccess::load(directory.path()).unwrap();
        let storage = proxy_core::TrafficStorage::new(":memory:", 1024).unwrap();
        let app = Router::new()
            .route("/api/ws", get(crate::ws::ws_handler))
            .route("/api/replay/websocket", get(crate::websocket_replay::handler))
            .with_state(storage)
            .layer(axum::middleware::from_fn_with_state(access.clone(), guard));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        for path in ["/api/ws", "/api/replay/websocket"] {
            let url = format!("ws://{address}{path}");
            let mut request = url.as_str().into_client_request().unwrap();
            request.headers_mut().insert(header::SEC_WEBSOCKET_PROTOCOL,
                format!("slurp.v1, slurp-auth.{}", access.token()).parse().unwrap());
            let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
            assert_eq!(response.headers()[header::SEC_WEBSOCKET_PROTOCOL], "slurp.v1");
            socket.close(None).await.unwrap();
            let error = tokio_tungstenite::connect_async(url).await.unwrap_err();
            assert!(matches!(error, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == StatusCode::UNAUTHORIZED));
        }
        server.abort();
    }
    #[tokio::test] async fn rejects_missing_credentials_foreign_hosts_and_unrelated_local_origins() {
        let directory=tempfile::tempdir().unwrap();let access=ApiAccess::load(directory.path()).unwrap();
        let app=Router::new().route("/api/probe",get(||async{"ok"}))
            .layer(axum::middleware::from_fn_with_state(access.clone(),guard))
            .layer(axum::middleware::from_fn_with_state(crate::origin::AllowedOrigins::default(),crate::origin::guard));
        for (host,origin,token,expected) in [
            ("127.0.0.1:5174",None,None,StatusCode::UNAUTHORIZED),
            ("127.0.0.1:5174",None,Some(access.token()),StatusCode::OK),
            ("evil.test:5174",None,Some(access.token()),StatusCode::FORBIDDEN),
            ("127.0.0.1:5174",Some("http://localhost:45678"),Some(access.token()),StatusCode::FORBIDDEN),
            ("127.0.0.1:5174",Some("http://127.0.0.1:5174"),Some(access.token()),StatusCode::OK),
        ] {
            let mut request=Request::builder().uri("/api/probe").header("Host",host);
            if let Some(origin)=origin {request=request.header("Origin",origin);}
            if let Some(token)=token {request=request.header("Authorization",format!("Bearer {token}"));}
            let response=app.clone().oneshot(request.body(axum::body::Body::empty()).unwrap()).await.unwrap();assert_eq!(response.status(),expected,"{host} {origin:?}");
        }
    }
}
