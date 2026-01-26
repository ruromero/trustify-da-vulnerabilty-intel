use std::sync::Arc;

use actix_web::{App, HttpServer, web};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod db;
mod model;
mod retriever;
mod service;

use db::repository::ReferenceDocumentRepository;
use model::Config;
use service::{
    ClaimExtractionService, DepsDevClient, DocumentService, LlmClient, OsvClient,
    RemediationService, VulnerabilityAssessmentService, VulnerabilityCache, VulnerabilityService,
};

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

    // Create shared document service (used by claim extraction and API)
    let document_service = Arc::new(DocumentService::new(
        document_repository,
        retriever_config,
        cache.clone(),
    ));

    // Create shared LLM client (used by both claim extraction and assessment)
    // OpenAI API key is required
    let api_key = std::env::var("OPENAI_API_KEY")
        .expect("Missing required environment variable: OPENAI_API_KEY");
    let llm_client =
        LlmClient::new(&api_key).expect("Failed to create LLM client: invalid OPENAI_API_KEY");

    // Create claim extraction service with shared LLM client
    let claim_extraction_service = ClaimExtractionService::new(
        llm_client.clone(),
        Arc::clone(&document_service),
        cache.clone(),
    );

    // Create vulnerability assessment service with shared LLM client (can use different model)
    let assessment_service = VulnerabilityAssessmentService::new(llm_client);

    let vulnerability_service = Arc::new(VulnerabilityService::new(
        OsvClient::new(),
        DepsDevClient::new(),
        Arc::clone(&document_service),
        claim_extraction_service,
        assessment_service,
        cache,
    ));

    let remediation_service =
        web::Data::new(RemediationService::new(Arc::clone(&vulnerability_service)));
    let vulnerability_service_data = web::Data::from(vulnerability_service);
    let document_service_data = web::Data::new(document_service);

    tracing::info!("Starting Trustify DA Agents server on {}", bind_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(vulnerability_service_data.clone())
            .app_data(remediation_service.clone())
            .app_data(document_service_data.clone())
            .configure(api::vulnerability::configure)
            .configure(api::document::configure)
            .configure(api::openapi::configure)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
