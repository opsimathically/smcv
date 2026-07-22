use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};

const INDEX: &str = include_str!("../web/index.html");
const STYLES: &str = include_str!("../web/styles.css");
const APP: &str = include_str!("../web/app.js");
const API: &str = include_str!("../web/api.js");

const WEB_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub(super) async fn index() -> Response {
    asset_response(INDEX, "text/html; charset=utf-8", true)
}

pub(super) async fn styles() -> Response {
    asset_response(STYLES, "text/css; charset=utf-8", false)
}

pub(super) async fn app() -> Response {
    asset_response(APP, "text/javascript; charset=utf-8", false)
}

pub(super) async fn api() -> Response {
    asset_response(API, "text/javascript; charset=utf-8", false)
}

fn asset_response(content: &'static str, content_type: &'static str, document: bool) -> Response {
    let mut response = Response::new(Body::from(content));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if document {
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(WEB_CSP),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{API, APP, INDEX, STYLES};

    #[test]
    fn embedded_web_assets_have_no_remote_runtime_dependency_or_inline_script() {
        for asset in [INDEX, STYLES, APP, API] {
            assert!(!asset.contains("https://"));
            assert!(!asset.contains("http://"));
        }
        assert!(!INDEX.contains("<script>"));
        assert!(!INDEX.contains(" style="));
        assert!(!APP.contains("localStorage"));
        assert!(!APP.contains("sessionStorage"));
        assert!(!APP.contains("innerHTML"));
        assert!(!APP.contains("\"Idempotency-Key\": crypto.randomUUID()"));
        assert!(APP.contains("data-clear-sensitive"));
        assert!(API.contains("X-SMCV-Session-Lock"));
    }
}
