pub mod vfs_commands;

use std::sync::Arc;

use futures::stream::StreamExt;
use tauri::http::{header, Request, Response, StatusCode};
use tauri::{Runtime, UriSchemeContext, UriSchemeResponder};
use tokio_util::sync::CancellationToken;

use crate::vfs::{VfsEngine, VfsError, VfsUri};

/// Request path is `/<percent-encoded canonical VfsUri>`; the host portion
/// (`vfs://localhost/...` on macOS/Linux, `http://vfs.localhost/...` on
/// Windows/Android) is Tauri's per-platform custom-protocol convention and is
/// not otherwise significant here.
pub fn vfs_protocol_handler<R: Runtime>(
    engine: Arc<VfsEngine>,
) -> impl Fn(UriSchemeContext<'_, R>, Request<Vec<u8>>, UriSchemeResponder) + Send + Sync + 'static
{
    move |_ctx, request, responder| {
        let engine = engine.clone();
        let path = request.uri().path().to_string();
        let range_header = request
            .headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        tokio::spawn(async move {
            let response = handle_request(&engine, &path, range_header.as_deref()).await;
            responder.respond(response);
        });
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(message.as_bytes().to_vec())
        .unwrap()
}

fn status_for_error(err: &VfsError) -> StatusCode {
    match err {
        VfsError::NotFound(_) => StatusCode::NOT_FOUND,
        VfsError::PermissionDenied(_) => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Parses a single `Range: bytes=...` spec (no multi-range support). Returns
/// an inclusive `(start, end)` byte range clamped to `size`.
fn parse_single_range(header: &str, size: u64) -> Option<(u64, u64)> {
    let spec = header.strip_prefix("bytes=")?;
    let first = spec.split(',').next()?.trim();
    let (start_str, end_str) = first.split_once('-')?;
    if start_str.is_empty() {
        let suffix_len: u64 = end_str.parse().ok()?;
        if suffix_len == 0 || size == 0 {
            return None;
        }
        let len = suffix_len.min(size);
        return Some((size - len, size - 1));
    }
    let start: u64 = start_str.parse().ok()?;
    if start >= size {
        return None;
    }
    let end = if end_str.is_empty() {
        size.saturating_sub(1)
    } else {
        end_str.parse::<u64>().ok()?.min(size.saturating_sub(1))
    };
    if end < start {
        return None;
    }
    Some((start, end))
}

async fn handle_request(
    engine: &Arc<VfsEngine>,
    path: &str,
    range_header: Option<&str>,
) -> Response<Vec<u8>> {
    let encoded = path.trim_start_matches('/');
    let decoded = match percent_encoding::percent_decode_str(encoded).decode_utf8() {
        Ok(s) => s.into_owned(),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid path encoding"),
    };
    let uri = match VfsUri::parse(&decoded) {
        Ok(u) => u,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };

    let stat = match engine.stat(&uri).await {
        Ok(s) => s,
        Err(e) => return error_response(status_for_error(&e), &e.to_string()),
    };

    let mime = uri
        .name()
        .and_then(|n| mime_guess::from_path(n).first())
        .map(|m| m.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let range = range_header.and_then(|h| parse_single_range(h, stat.size));
    let (status, content_range, byte_range) = match range {
        Some((start, end)) => (
            StatusCode::PARTIAL_CONTENT,
            Some(format!("bytes {start}-{end}/{}", stat.size)),
            Some(start..end + 1),
        ),
        None => (StatusCode::OK, None, None),
    };

    let mut stream = match engine
        .read_stream(&uri, byte_range, CancellationToken::new())
        .await
    {
        Ok(s) => s,
        Err(e) => return error_response(status_for_error(&e), &e.to_string()),
    };
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => body.extend_from_slice(&bytes),
            Err(e) => return error_response(status_for_error(&e), &e.to_string()),
        }
    }

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, mime)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, body.len().to_string());
    if let Some(cr) = content_range {
        builder = builder.header(header::CONTENT_RANGE, cr);
    }
    builder.body(body).unwrap()
}
