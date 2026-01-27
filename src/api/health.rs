//! Health check endpoints for Kubernetes liveness and readiness probes

use actix_web::{HttpResponse, Responder, get, web};
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;

use crate::service::VulnerabilityCache;

#[derive(Serialize, ToSchema)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
}

#[derive(Serialize, ToSchema)]
pub struct ReadinessStatus {
    pub status: String,
    pub version: String,
    pub dependencies: DependencyHealth,
}

#[derive(Serialize, ToSchema)]
pub struct DependencyHealth {
    pub database: String,
    pub cache: String,
}

/// Liveness probe endpoint
///
/// Always returns 200 OK if the service is running.
/// Used by Kubernetes to determine if the pod should be restarted.
#[utoipa::path(
    get,
    path = "/health/live",
    responses(
        (status = 200, description = "Service is alive", body = HealthStatus)
    ),
    tag = "health"
)]
#[get("/health/live")]
pub async fn liveness() -> impl Responder {
    HttpResponse::Ok().json(HealthStatus {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Readiness probe endpoint
///
/// Returns 200 OK if the service is ready to accept traffic.
/// Checks database connection health.
/// Used by Kubernetes to determine if traffic should be routed to the pod.
#[utoipa::path(
    get,
    path = "/health/ready",
    responses(
        (status = 200, description = "Service is ready", body = ReadinessStatus),
        (status = 503, description = "Service is not ready", body = ReadinessStatus)
    ),
    tag = "health"
)]
#[get("/health/ready")]
pub async fn readiness(
    db_pool: web::Data<PgPool>,
    cache: web::Data<Option<VulnerabilityCache>>,
) -> impl Responder {
    // Check database connection
    let db_status = match sqlx::query("SELECT 1").fetch_one(db_pool.get_ref()).await {
        Ok(_) => {
            tracing::debug!("Database health check passed");
            "healthy"
        }
        Err(e) => {
            tracing::error!(error = %e, "Database health check failed");
            "unhealthy"
        }
    };

    // Check cache availability (non-critical)
    let cache_status = match cache.as_ref() {
        Some(_) => "healthy",
        None => "disabled",
    };

    let all_healthy = db_status == "healthy";

    let status = ReadinessStatus {
        status: if all_healthy { "ready" } else { "not_ready" }.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        dependencies: DependencyHealth {
            database: db_status.to_string(),
            cache: cache_status.to_string(),
        },
    };

    if all_healthy {
        HttpResponse::Ok().json(status)
    } else {
        HttpResponse::ServiceUnavailable().json(status)
    }
}

/// Configure health check routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(liveness).service(readiness);
}
