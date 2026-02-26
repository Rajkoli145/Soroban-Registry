use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{json, Value};
use shared::models::{
    CreateAlertConfigRequest, PerformanceAlert, PerformanceAlertConfig, PerformanceAnomaly,
    PerformanceMetric, PerformanceTrend, RecordPerformanceMetricRequest,
};
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    state::AppState,
};

// ───────────────────── Query params ─────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct ListMetricsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub metric_type: Option<String>,
    pub function_name: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ListAlertsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub resolved: Option<bool>,
    pub severity: Option<String>,
}

fn default_limit() -> i64 {
    20
}

// ───────────────────── Handlers ─────────────────────

/// POST /api/contracts/:id/perf/metrics — record a performance metric
pub async fn record_metric(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Json(req): Json<RecordPerformanceMetricRequest>,
) -> ApiResult<impl IntoResponse> {
    let contract_uuid = parse_uuid(&contract_id, "contract")?;

    let metric: PerformanceMetric = sqlx::query_as(
        r#"
        INSERT INTO performance_metrics
            (contract_id, metric_type, function_name, value, p50, p95, p99, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(contract_uuid)
    .bind(&req.metric_type)
    .bind(req.function_name.as_deref())
    .bind(rust_decimal::Decimal::try_from(req.value).unwrap_or_default())
    .bind(
        req.p50
            .map(|v| rust_decimal::Decimal::try_from(v).unwrap_or_default()),
    )
    .bind(
        req.p95
            .map(|v| rust_decimal::Decimal::try_from(v).unwrap_or_default()),
    )
    .bind(
        req.p99
            .map(|v| rust_decimal::Decimal::try_from(v).unwrap_or_default()),
    )
    .bind(&req.metadata)
    .fetch_one(&state.db)
    .await
    .map_err(|e| db_err("record performance metric", e))?;

    Ok((StatusCode::CREATED, Json(metric)))
}

/// GET /api/contracts/:id/perf/metrics — list performance metrics for a contract
pub async fn list_metrics(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(params): Query<ListMetricsQuery>,
) -> ApiResult<Json<Value>> {
    let contract_uuid = parse_uuid(&contract_id, "contract")?;
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    // Build dynamic query filters
    let mut query = String::from("SELECT * FROM performance_metrics WHERE contract_id = $1");
    let mut count_query =
        String::from("SELECT COUNT(*) FROM performance_metrics WHERE contract_id = $1");

    if let Some(ref mt) = params.metric_type {
        let clause = format!(" AND metric_type::text = '{}'", mt.replace('\'', "''"));
        query.push_str(&clause);
        count_query.push_str(&clause);
    }
    if let Some(ref func) = params.function_name {
        let clause = format!(" AND function_name = '{}'", func.replace('\'', "''"));
        query.push_str(&clause);
        count_query.push_str(&clause);
    }

    query.push_str(&format!(
        " ORDER BY timestamp DESC LIMIT {} OFFSET {}",
        limit, offset
    ));

    let metrics: Vec<PerformanceMetric> = sqlx::query_as(&query)
        .bind(contract_uuid)
        .fetch_all(&state.db)
        .await
        .map_err(|e| db_err("list performance metrics", e))?;

    let total: i64 = sqlx::query_scalar(&count_query)
        .bind(contract_uuid)
        .fetch_one(&state.db)
        .await
        .map_err(|e| db_err("count performance metrics", e))?;

    Ok(Json(json!({
        "items": metrics,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

/// GET /api/contracts/:id/perf/anomalies — list performance anomalies
pub async fn list_anomalies(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(params): Query<ListAlertsQuery>,
) -> ApiResult<Json<Value>> {
    let contract_uuid = parse_uuid(&contract_id, "contract")?;
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let mut query = String::from("SELECT * FROM performance_anomalies WHERE contract_id = $1");
    let mut count_query =
        String::from("SELECT COUNT(*) FROM performance_anomalies WHERE contract_id = $1");

    if let Some(resolved) = params.resolved {
        let clause = format!(" AND resolved = {}", resolved);
        query.push_str(&clause);
        count_query.push_str(&clause);
    }
    if let Some(ref severity) = params.severity {
        let clause = format!(" AND severity::text = '{}'", severity.replace('\'', "''"));
        query.push_str(&clause);
        count_query.push_str(&clause);
    }

    query.push_str(&format!(
        " ORDER BY detected_at DESC LIMIT {} OFFSET {}",
        limit, offset
    ));

    let anomalies: Vec<PerformanceAnomaly> = sqlx::query_as(&query)
        .bind(contract_uuid)
        .fetch_all(&state.db)
        .await
        .map_err(|e| db_err("list performance anomalies", e))?;

    let total: i64 = sqlx::query_scalar(&count_query)
        .bind(contract_uuid)
        .fetch_one(&state.db)
        .await
        .map_err(|e| db_err("count performance anomalies", e))?;

    Ok(Json(json!({
        "items": anomalies,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

/// GET /api/contracts/:id/perf/alerts — list performance alerts
pub async fn list_alerts(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(params): Query<ListAlertsQuery>,
) -> ApiResult<Json<Value>> {
    let contract_uuid = parse_uuid(&contract_id, "contract")?;
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let mut query = String::from("SELECT * FROM performance_alerts WHERE contract_id = $1");
    let mut count_query =
        String::from("SELECT COUNT(*) FROM performance_alerts WHERE contract_id = $1");

    if let Some(resolved) = params.resolved {
        let clause = format!(" AND resolved = {}", resolved);
        query.push_str(&clause);
        count_query.push_str(&clause);
    }
    if let Some(ref severity) = params.severity {
        let clause = format!(" AND severity::text = '{}'", severity.replace('\'', "''"));
        query.push_str(&clause);
        count_query.push_str(&clause);
    }

    query.push_str(&format!(
        " ORDER BY triggered_at DESC LIMIT {} OFFSET {}",
        limit, offset
    ));

    let alerts: Vec<PerformanceAlert> = sqlx::query_as(&query)
        .bind(contract_uuid)
        .fetch_all(&state.db)
        .await
        .map_err(|e| db_err("list performance alerts", e))?;

    let total: i64 = sqlx::query_scalar(&count_query)
        .bind(contract_uuid)
        .fetch_one(&state.db)
        .await
        .map_err(|e| db_err("count performance alerts", e))?;

    Ok(Json(json!({
        "items": alerts,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

/// POST /api/perf/alerts/:alert_id/acknowledge — acknowledge a performance alert
pub async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<PerformanceAlert>> {
    let alert_uuid = parse_uuid(&alert_id, "alert")?;
    let acknowledged_by = body
        .get("acknowledged_by")
        .and_then(|v| v.as_str())
        .unwrap_or("system");

    let alert: PerformanceAlert = sqlx::query_as(
        r#"
        UPDATE performance_alerts
        SET acknowledged = true,
            acknowledged_at = NOW(),
            acknowledged_by = $2
        WHERE id = $1 AND acknowledged = false
        RETURNING *
        "#,
    )
    .bind(alert_uuid)
    .bind(acknowledged_by)
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => ApiError::not_found(
            "AlertNotFound",
            "No unacknowledged alert found with this ID",
        ),
        _ => db_err("acknowledge alert", e),
    })?;

    Ok(Json(alert))
}

/// POST /api/perf/alerts/:alert_id/resolve — resolve a performance alert
pub async fn resolve_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
) -> ApiResult<Json<PerformanceAlert>> {
    let alert_uuid = parse_uuid(&alert_id, "alert")?;

    let alert: PerformanceAlert = sqlx::query_as(
        r#"
        UPDATE performance_alerts
        SET resolved = true, resolved_at = NOW()
        WHERE id = $1 AND resolved = false
        RETURNING *
        "#,
    )
    .bind(alert_uuid)
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => {
            ApiError::not_found("AlertNotFound", "No unresolved alert found with this ID")
        }
        _ => db_err("resolve alert", e),
    })?;

    Ok(Json(alert))
}

/// POST /api/contracts/:id/perf/alert-configs — configure an alert threshold
pub async fn create_alert_config(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Json(req): Json<CreateAlertConfigRequest>,
) -> ApiResult<impl IntoResponse> {
    let contract_uuid = parse_uuid(&contract_id, "contract")?;

    let config: PerformanceAlertConfig = sqlx::query_as(
        r#"
        INSERT INTO performance_alert_configs
            (contract_id, metric_type, threshold_type, threshold_value, severity)
        VALUES ($1, $2, $3, $4, COALESCE($5, 'warning'))
        ON CONFLICT (contract_id, metric_type, threshold_type)
        DO UPDATE SET
            threshold_value = EXCLUDED.threshold_value,
            severity = EXCLUDED.severity,
            updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(contract_uuid)
    .bind(&req.metric_type)
    .bind(&req.threshold_type)
    .bind(rust_decimal::Decimal::try_from(req.threshold_value).unwrap_or_default())
    .bind(&req.severity)
    .fetch_one(&state.db)
    .await
    .map_err(|e| db_err("create alert config", e))?;

    Ok((StatusCode::CREATED, Json(config)))
}

/// GET /api/contracts/:id/perf/alert-configs — list alert configurations
pub async fn list_alert_configs(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
) -> ApiResult<Json<Vec<PerformanceAlertConfig>>> {
    let contract_uuid = parse_uuid(&contract_id, "contract")?;

    let configs: Vec<PerformanceAlertConfig> = sqlx::query_as(
        "SELECT * FROM performance_alert_configs WHERE contract_id = $1 ORDER BY created_at DESC",
    )
    .bind(contract_uuid)
    .fetch_all(&state.db)
    .await
    .map_err(|e| db_err("list alert configs", e))?;

    Ok(Json(configs))
}

/// GET /api/contracts/:id/perf/trends — list performance trends
pub async fn list_trends(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(params): Query<ListMetricsQuery>,
) -> ApiResult<Json<Value>> {
    let contract_uuid = parse_uuid(&contract_id, "contract")?;
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let mut query = String::from("SELECT * FROM performance_trends WHERE contract_id = $1");

    if let Some(ref mt) = params.metric_type {
        query.push_str(&format!(
            " AND metric_type::text = '{}'",
            mt.replace('\'', "''")
        ));
    }

    query.push_str(&format!(
        " ORDER BY timeframe_end DESC LIMIT {} OFFSET {}",
        limit, offset
    ));

    let trends: Vec<PerformanceTrend> = sqlx::query_as(&query)
        .bind(contract_uuid)
        .fetch_all(&state.db)
        .await
        .map_err(|e| db_err("list performance trends", e))?;

    Ok(Json(json!({
        "items": trends,
        "limit": limit,
        "offset": offset,
    })))
}

/// GET /api/contracts/:id/perf/summary — get a comprehensive performance summary
pub async fn get_performance_summary(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let contract_uuid = parse_uuid(&contract_id, "contract")?;

    // Latest metrics per type
    let latest_metrics: Vec<PerformanceMetric> = sqlx::query_as(
        r#"
        SELECT DISTINCT ON (metric_type) *
        FROM performance_metrics
        WHERE contract_id = $1
        ORDER BY metric_type, timestamp DESC
        "#,
    )
    .bind(contract_uuid)
    .fetch_all(&state.db)
    .await
    .map_err(|e| db_err("get latest metrics", e))?;

    // Unresolved anomaly count
    let anomaly_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM performance_anomalies WHERE contract_id = $1 AND resolved = false",
    )
    .bind(contract_uuid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    // Unresolved alert count
    let alert_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM performance_alerts WHERE contract_id = $1 AND resolved = false",
    )
    .bind(contract_uuid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    // Active alert config count
    let config_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM performance_alert_configs WHERE contract_id = $1 AND enabled = true",
    )
    .bind(contract_uuid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    Ok(Json(json!({
        "contract_id": contract_uuid,
        "latest_metrics": latest_metrics,
        "unresolved_anomalies": anomaly_count,
        "unresolved_alerts": alert_count,
        "active_alert_configs": config_count,
    })))
}

// ───────────────────── Helpers ─────────────────────

fn parse_uuid(id: &str, label: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|_| {
        ApiError::bad_request("InvalidId", format!("Invalid {} ID format: {}", label, id))
    })
}

fn db_err(operation: &str, err: sqlx::Error) -> ApiError {
    tracing::error!(operation = operation, error = ?err, "database operation failed");
    ApiError::internal("An unexpected database error occurred")
}
