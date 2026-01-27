//! Application state and service initialization
//!
//! This module centralizes all service initialization and dependency injection,
//! making it easier to manage the application lifecycle and test services.

use std::sync::Arc;

use sqlx::PgPool;

use crate::db::repository::ReferenceDocumentRepository;
use crate::model::Config;
use crate::service::{
    ClaimExtractionService, DepsDevClient, DocumentService, LlmClient, OsvClient,
    RemediationService, VulnerabilityAssessmentService, VulnerabilityCache, VulnerabilityService,
};

/// Application state containing all services and shared resources
///
/// This struct centralizes service initialization and makes it easy to inject
/// dependencies into Actix-web handlers.
pub struct AppState {
    /// Database connection pool
    pub db_pool: Arc<PgPool>,
    /// Redis cache (optional)
    pub cache: Option<VulnerabilityCache>,
    /// Vulnerability intelligence service
    pub vulnerability_service: Arc<VulnerabilityService>,
    /// Remediation plan generation service
    pub remediation_service: RemediationService,
    /// Document retrieval and persistence service
    pub document_service: Arc<DocumentService>,
}

impl AppState {
    /// Initialize all services and build application state
    ///
    /// This performs:
    /// 1. Database connection and schema initialization
    /// 2. Redis cache initialization (optional)
    /// 3. LLM client initialization (requires OPENAI_API_KEY)
    /// 4. Service dependency graph construction
    pub async fn new(config: Config) -> Result<Self, AppError> {
        // Initialize PostgreSQL database
        let db_pool = crate::db::create_pool()
            .await
            .map_err(|e| AppError::DatabaseInit(e.to_string()))?;

        // Initialize database schema
        crate::db::init_schema(&db_pool)
            .await
            .map_err(|e| AppError::DatabaseInit(e.to_string()))?;

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

        // Create shared LLM client (required)
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| AppError::MissingConfig("OPENAI_API_KEY"))?;

        let llm_client = LlmClient::new(&api_key)
            .map_err(|_| AppError::InvalidConfig("Invalid OPENAI_API_KEY"))?;

        // Build service dependency graph
        let document_service = Arc::new(Self::build_document_service(
            db_pool.clone(),
            config.retrievers,
            cache.clone(),
        ));

        let vulnerability_service = Arc::new(Self::build_vulnerability_service(
            Arc::clone(&document_service),
            llm_client.clone(),
            cache.clone(),
        ));

        let remediation_service =
            RemediationService::new(Arc::clone(&vulnerability_service), llm_client);

        Ok(Self {
            db_pool: Arc::new(db_pool),
            cache,
            vulnerability_service,
            remediation_service,
            document_service,
        })
    }

    /// Build document service with all dependencies
    fn build_document_service(
        db_pool: PgPool,
        retriever_config: crate::model::RetrieverConfig,
        cache: Option<VulnerabilityCache>,
    ) -> DocumentService {
        let repository = ReferenceDocumentRepository::new(db_pool);
        DocumentService::new(repository, retriever_config, cache)
    }

    /// Build vulnerability service with all dependencies
    fn build_vulnerability_service(
        document_service: Arc<DocumentService>,
        llm_client: LlmClient,
        cache: Option<VulnerabilityCache>,
    ) -> VulnerabilityService {
        let claim_extraction_service = ClaimExtractionService::new(
            llm_client.clone(),
            Arc::clone(&document_service),
            cache.clone(),
        );

        let assessment_service = VulnerabilityAssessmentService::new(llm_client);

        VulnerabilityService::new(
            OsvClient::new(),
            DepsDevClient::new(),
            document_service,
            claim_extraction_service,
            assessment_service,
            cache,
        )
    }
}

/// Application-level errors
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AppError {
    /// Database initialization failed
    #[error("Database initialization failed: {0}")]
    DatabaseInit(String),

    /// Missing required configuration
    #[error("Missing required configuration: {0}")]
    MissingConfig(&'static str),

    /// Invalid configuration value
    #[error("Invalid configuration: {0}")]
    InvalidConfig(&'static str),
}
