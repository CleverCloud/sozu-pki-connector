//! # Handler module
//!
//! This module provides handlers to use with the server implementation

use std::time::SystemTime;

use axum::http::{HeaderValue, Request, Response};
use hyper::{Body, StatusCode};
use prometheus::{Encoder, TextEncoder};

// -----------------------------------------------------------------------------
// Constants

pub const X_REQUEST_ID: &str = "X-Request-Id";
pub const X_TIMESTAMP: &str = "X-Timestamp";

// -----------------------------------------------------------------------------
// Not found

#[tracing::instrument]
pub async fn not_found(_req: Request<Body>) -> Response<Body> {
    let mut res = Response::default();

    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

// -----------------------------------------------------------------------------
// Healthz

#[tracing::instrument]
pub async fn healthz(req: Request<Body>) -> Response<Body> {
    let mut res = Response::default();

    *res.status_mut() = StatusCode::OK;
    let headers = res.headers_mut();
    if let Some(header) = req.headers().get(X_REQUEST_ID) {
        headers.insert(X_REQUEST_ID, header.to_owned());
    }

    if let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        headers.insert(
            X_TIMESTAMP,
            HeaderValue::from_str(&now.as_secs().to_string())
                .expect("number to be iso8859-1 compliant"),
        );
    }

    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_str(mime::APPLICATION_JSON.as_ref())
            .expect("constant to be iso8859-1 compliant"),
    );

    let message = serde_json::json!({"message": "Everything is fine! 🚀"}).to_string();

    headers.insert(
        hyper::header::CONTENT_LENGTH,
        HeaderValue::from_str(&message.len().to_string())
            .expect("constant to be iso8859-1 compliant"),
    );

    *res.body_mut() = Body::from(message);
    res
}

// -----------------------------------------------------------------------------
// Telemetry

#[tracing::instrument]
/// Retrieve Sōzu internals and connector telemetry
pub async fn telemetry(_req: Request<Body>) -> Response<Body> {
    let mut res = Response::default();

    let encoder = TextEncoder::new();
    let metrics = prometheus::gather();

    let mut buf = vec![];
    match encoder.encode(&metrics, &mut buf) {
        Ok(_) => {
            let headers = res.headers_mut();

            headers.insert(
                hyper::header::CONTENT_TYPE,
                HeaderValue::from_str(mime::TEXT_PLAIN_UTF_8.as_ref())
                    .expect("constant to be iso8859-1 compliant"),
            );

            headers.insert(
                hyper::header::CONTENT_LENGTH,
                HeaderValue::from_str(&buf.len().to_string())
                    .expect("buffer size to be iso8859-1 compliant"),
            );

            *res.status_mut() = StatusCode::OK;
            *res.body_mut() = Body::from(buf);
        }
        Err(err) => {
            let headers = res.headers_mut();
            let message = serde_json::json!({"error": err.to_string() }).to_string();

            headers.insert(
                hyper::header::CONTENT_TYPE,
                HeaderValue::from_str(mime::APPLICATION_JSON.as_ref())
                    .expect("constant to be iso8859-1 compliant"),
            );

            headers.insert(
                hyper::header::CONTENT_LENGTH,
                HeaderValue::from_str(&message.len().to_string())
                    .expect("buffer size to be iso8859-1 compliant"),
            );

            *res.status_mut() = StatusCode::OK;
            *res.body_mut() = Body::from(message);
        }
    }

    res
}
