use axum::{extract::Extension, http::header, response::{IntoResponse, Response}};
use std::sync::Arc;

/// Only the public certificate is supplied to the web server, never the CA key.
#[derive(Clone)]
pub struct PublicCaCertificate(pub Arc<[u8]>);

pub async fn download(Extension(certificate): Extension<PublicCaCertificate>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"ca.crt\""),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        certificate.0.to_vec(),
    ).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn download_returns_exact_public_certificate_as_attachment() {
        let pem = b"-----BEGIN CERTIFICATE-----\npublic-ca\n-----END CERTIFICATE-----\n";
        let response = download(Extension(PublicCaCertificate(Arc::from(pem.as_slice())))).await;
        assert_eq!(response.headers()[header::CONTENT_DISPOSITION], "attachment; filename=\"ca.crt\"");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), pem);
    }
}
