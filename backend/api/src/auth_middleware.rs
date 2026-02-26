use crate::auth::AuthManager;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub publisher_address: String,
}

#[derive(Serialize)]
struct AuthErrorBody {
    error: &'static str,
    message: &'static str,
}

pub async fn auth_middleware(mut request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);

    let Some(token) = token else {
        return unauthorized("missing_bearer_token");
    };

    let mgr = match AuthManager::from_env() {
        Ok(mgr) => mgr,
        Err(err) => {
            tracing::error!(error = %err, "JWT authentication middleware is misconfigured");
            return internal_error("auth_misconfigured");
        }
    };
    let claims = match mgr.validate_jwt(token) {
        Ok(c) => c,
        Err(_) => return unauthorized("invalid_token"),
    };

    request.extensions_mut().insert(AuthContext {
        publisher_address: claims.sub,
    });

    next.run(request).await
}

fn unauthorized(reason: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(AuthErrorBody {
            error: "Unauthorized",
            message: reason,
        }),
    )
        .into_response()
}

fn internal_error(reason: &'static str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(AuthErrorBody {
            error: "InternalServerError",
            message: reason,
        }),
    )
        .into_response()
}
