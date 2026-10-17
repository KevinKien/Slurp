use axum::{extract::Extension, http::StatusCode, Json};
use proxy_core::ProxyControl;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct Settings { host: String, port: u16 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update { host: std::net::IpAddr, port: u16 }
type ApiResult = Result<Json<Settings>, (StatusCode, Json<serde_json::Value>)>;
fn response(result: Result<std::net::SocketAddr, String>) -> ApiResult {
    result.map(|address| Json(Settings { host: address.ip().to_string(), port: address.port() }))
        .map_err(|error| (StatusCode::CONFLICT, Json(serde_json::json!({"error": error}))))
}
pub async fn get(Extension(control): Extension<ProxyControl>) -> ApiResult {
    response(control.address().await)
}
pub async fn update(Extension(control): Extension<ProxyControl>, Json(update): Json<Update>) -> ApiResult {
    if update.port == 0 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Port must be between 1 and 65535"}))));
    }
    response(control.set_address(std::net::SocketAddr::new(update.host, update.port)).await)
}

#[derive(Serialize)]
pub struct LocalInterface { name: String, address: String }

/// Enumerate addresses on the backend host, including LAN and VPN interfaces.
pub async fn interfaces() -> Result<Json<Vec<LocalInterface>>, (StatusCode, Json<serde_json::Value>)> {
    let detected = if_addrs::get_if_addrs().map_err(|error| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": format!("Cannot detect local IP addresses: {error}")})),
    ))?;
    let mut addresses: Vec<_> = detected.into_iter().filter_map(|interface| {
        let ip = interface.ip();
        // IPv6 link-local addresses require interface scope IDs. Keep discovery
        // IPv4-only so every offered address can be applied directly.
        if ip.is_ipv4() && !ip.is_unspecified() {
            Some(LocalInterface { name: interface.name, address: ip.to_string() })
        } else { None }
    }).collect();
    addresses.sort_by(|a, b| (&a.address, &a.name).cmp(&(&b.address, &b.name)));
    addresses.dedup_by(|a, b| a.address == b.address);
    Ok(Json(addresses))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn detects_real_local_ipv4_addresses() {
        let Json(addresses) = interfaces().await.unwrap();
        assert!(addresses.iter().any(|item| item.address == "127.0.0.1"));
        for item in &addresses {
            assert!(item.address.parse::<std::net::Ipv4Addr>().is_ok());
            assert!(!item.name.is_empty());
        }
    }
    #[test]
    fn rejects_invalid_ip_addresses() {
        for host in ["localhost", "192.168.1.999", "", "http://192.168.1.1"] {
            assert!(serde_json::from_value::<Update>(serde_json::json!({"host":host,"port":8888})).is_err());
        }
    }
}
