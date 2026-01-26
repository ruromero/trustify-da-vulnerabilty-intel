//! OpenAPI specification endpoints

use actix_web::{HttpResponse, Responder, get};
use utoipa::OpenApi;

use crate::api::vulnerability::ApiDoc;

/// Serve OpenAPI JSON specification
#[get("/openapi.json")]
pub async fn openapi_json() -> impl Responder {
    HttpResponse::Ok().json(ApiDoc::openapi())
}

/// Serve OpenAPI YAML specification
#[get("/openapi.yaml")]
pub async fn openapi_yaml() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/yaml")
        .body(ApiDoc::openapi().to_yaml().unwrap())
}

/// Configure OpenAPI routes
pub fn configure(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.service(openapi_json).service(openapi_yaml);
}
