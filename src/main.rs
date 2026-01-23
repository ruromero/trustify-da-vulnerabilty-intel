use actix_web::{App, HttpServer, web};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod db;
mod model;
mod retriever;
mod service;

use db::repository::ReferenceDocumentRepository;
use model::Config;
use service::{DepsDevClient, DocumentService, OsvClient, VulnerabilityCache, VulnerabilityService};

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

    // Initialize PostgreSQL database
    let db_pool = db::create_pool()
        .await
        .expect("Failed to create database pool");

    // Initialize database schema
    db::init_schema(&db_pool)
        .await
        .expect("Failed to initialize database schema");

    // Initialize Redis cache (optional - will log warning if Redis is unavailable)
    let cache = match VulnerabilityCache::new().await {
        Ok(cache) => {
            tracing::info!("Redis cache enabled");
            Some(cache)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Redis cache unavailable, running without cache");
            None
        }
    };

    // Create services
    let document_repository = ReferenceDocumentRepository::new(db_pool.clone());
    let retriever_config = config.retrievers.clone();
    let document_service = DocumentService::new(
        document_repository.clone(),
        retriever_config.clone(),
        cache.clone(),
    );

    let vulnerability_service = web::Data::new(VulnerabilityService::new(
        OsvClient::new(),
        DepsDevClient::new(),
        document_service,
        cache.clone(),
    ));

    let document_service_data = web::Data::new(DocumentService::new(
        document_repository,
        retriever_config,
        cache,
    ));

    tracing::info!("Starting Trustify DA Agents server on {}", bind_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(vulnerability_service.clone())
            .app_data(document_service_data.clone())
            .configure(api::vulnerability::configure)
            .configure(api::document::configure)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
