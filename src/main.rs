use actix_web::{App, HttpServer, web};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod app;
mod db;
mod model;
mod retriever;
mod service;

use app::AppState;
use model::Config;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Load .env file if present (ignore if missing)
    let _ = dotenvy::dotenv();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env();
    let bind_addr = config.bind_addr();

    // Initialize application state with all services
    let state = AppState::new(config)
        .await
        .expect("Failed to initialize application state");

    // Prepare shared state for Actix-web
    let db_pool_data = web::Data::from(state.db_pool.clone());
    let cache_data = web::Data::new(state.cache.clone());
    let vulnerability_service_data = web::Data::from(state.vulnerability_service.clone());
    let remediation_service = web::Data::new(state.remediation_service);
    let document_service_data = web::Data::from(state.document_service.clone());

    tracing::info!("Starting Trustify Vulnerability Intelligence server on {}", bind_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(vulnerability_service_data.clone())
            .app_data(remediation_service.clone())
            .app_data(document_service_data.clone())
            .app_data(db_pool_data.clone())
            .app_data(cache_data.clone())
            .configure(api::health::configure)
            .configure(api::vulnerability::configure)
            .configure(api::document::configure)
            .configure(api::openapi::configure)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
