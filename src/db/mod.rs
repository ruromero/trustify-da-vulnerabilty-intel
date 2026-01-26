//! Database module for PostgreSQL persistence

pub mod models;
pub mod repository;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;

// Environment variable names
const ENV_POSTGRES_HOST: &str = "DA_AGENT_POSTGRES_HOST";
const ENV_POSTGRES_PORT: &str = "DA_AGENT_POSTGRES_PORT";
const ENV_POSTGRES_USER: &str = "DA_AGENT_POSTGRES_USER";
const ENV_POSTGRES_PASSWORD: &str = "DA_AGENT_POSTGRES_PASSWORD";
const ENV_POSTGRES_DB: &str = "DA_AGENT_POSTGRES_DB";

// Default values
const DEFAULT_POSTGRES_HOST: &str = "127.0.0.1";
const DEFAULT_POSTGRES_PORT: &str = "5432";
const DEFAULT_POSTGRES_USER: &str = "da_agent";
const DEFAULT_POSTGRES_PASSWORD: &str = "da_agent";
const DEFAULT_POSTGRES_DB: &str = "da_agent";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    Connection(#[from] sqlx::Error),

    #[error("Record not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Create a new database connection pool
pub async fn create_pool() -> Result<PgPool, DbError> {
    let host = env::var(ENV_POSTGRES_HOST).unwrap_or_else(|_| DEFAULT_POSTGRES_HOST.to_string());
    let port = env::var(ENV_POSTGRES_PORT).unwrap_or_else(|_| DEFAULT_POSTGRES_PORT.to_string());
    let user = env::var(ENV_POSTGRES_USER).unwrap_or_else(|_| DEFAULT_POSTGRES_USER.to_string());
    let password =
        env::var(ENV_POSTGRES_PASSWORD).unwrap_or_else(|_| DEFAULT_POSTGRES_PASSWORD.to_string());
    let database = env::var(ENV_POSTGRES_DB).unwrap_or_else(|_| DEFAULT_POSTGRES_DB.to_string());

    let database_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        user, password, host, port, database
    );

    tracing::debug!(host = %host, port = %port, database = %database, "Connecting to PostgreSQL");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    tracing::info!(host = %host, port = %port, "PostgreSQL connection established");

    Ok(pool)
}

/// Initialize database schema
pub async fn init_schema(pool: &PgPool) -> Result<(), DbError> {
    // Create table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS reference_documents (
            id VARCHAR(64) PRIMARY KEY,
            retrieved_from TEXT NOT NULL,
            canonical_url TEXT NOT NULL,
            domain_url TEXT,
            retriever_type VARCHAR(50) NOT NULL,
            retrieved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            published TIMESTAMPTZ,
            last_modified TIMESTAMPTZ,
            raw_content TEXT,
            normalized_content TEXT,
            content_type VARCHAR(100),
            metadata JSONB NOT NULL DEFAULT '{}'
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes separately
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_reference_documents_retriever_type ON reference_documents(retriever_type)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_reference_documents_domain_url ON reference_documents(domain_url)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_reference_documents_retrieved_at ON reference_documents(retrieved_at)",
    )
    .execute(pool)
    .await?;

    tracing::info!("Database schema initialized");

    Ok(())
}
