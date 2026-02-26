use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

pub async fn batch_verify_contracts() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "not_implemented",
            "message": "Batch verification endpoint is planned but not yet functional"
        })),
    )
}
