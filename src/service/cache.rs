//! Redis cache service for vulnerability data

use std::env;

use redis::{AsyncCommands, Client};
use serde::{Serialize, de::DeserializeOwned};

// Environment variable names
const ENV_REDIS_HOST: &str = "DA_INTEL_REDIS_HOST";
const ENV_REDIS_PORT: &str = "DA_INTEL_REDIS_PORT";
const ENV_REDIS_PASSWORD: &str = "DA_INTEL_REDIS_PASSWORD";
const ENV_REDIS_DB: &str = "DA_INTEL_REDIS_DB";
const ENV_CACHE_TTL: &str = "DA_INTEL_CACHE_TTL";

// Default values
const DEFAULT_REDIS_HOST: &str = "127.0.0.1";
const DEFAULT_REDIS_PORT: &str = "6379";
const DEFAULT_REDIS_DB: &str = "0";
const DEFAULT_TTL_SECONDS: u64 = 3600; // 1 hour

// TTL for assessments, remediation plans, and claims (30 days in seconds)
const ASSESSMENT_TTL_SECONDS: u64 = 30 * 24 * 60 * 60; // 30 days

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    #[error("Redis connection error: {0}")]
    Connection(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cache miss for key: {0}")]
    Miss(String),
}

// Cache key prefixes
const PREFIX_VULNERABILITY: &str = "vuln:";
const PREFIX_PACKAGE: &str = "pkg:";
const PREFIX_CSAF: &str = "csaf:";
const PREFIX_CLAIMS: &str = "claims:";
const PREFIX_ASSESSMENT: &str = "assessment:";
const PREFIX_REMEDIATION: &str = "remediation:";

/// Redis-based cache for vulnerability and package data
#[derive(Clone)]
pub struct VulnerabilityCache {
    client: Client,
    ttl_seconds: u64,
}

impl VulnerabilityCache {
    /// Create a new cache instance and verify connection
    ///
    /// Configuration via environment variables:
    /// - `DA_INTEL_REDIS_HOST` - Redis host (default: 127.0.0.1)
    /// - `DA_INTEL_REDIS_PORT` - Redis port (default: 6379)
    /// - `DA_INTEL_REDIS_PASSWORD` - Redis password (default: none)
    /// - `DA_INTEL_REDIS_DB` - Redis database number (default: 0)
    /// - `DA_INTEL_CACHE_TTL` - Cache TTL in seconds (default: 3600)
    pub async fn new() -> Result<Self, CacheError> {
        let host = env::var(ENV_REDIS_HOST).unwrap_or_else(|_| DEFAULT_REDIS_HOST.to_string());
        let port = env::var(ENV_REDIS_PORT).unwrap_or_else(|_| DEFAULT_REDIS_PORT.to_string());
        let password = env::var(ENV_REDIS_PASSWORD).ok();
        let db = env::var(ENV_REDIS_DB).unwrap_or_else(|_| DEFAULT_REDIS_DB.to_string());

        let ttl_seconds = env::var(ENV_CACHE_TTL)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TTL_SECONDS);

        // Build Redis URL: redis://[password@]host:port/db
        let redis_url = match password {
            Some(pwd) if !pwd.is_empty() => format!("redis://:{}@{}:{}/{}", pwd, host, port, db),
            _ => format!("redis://{}:{}/{}", host, port, db),
        };

        tracing::debug!(host = %host, port = %port, db = %db, "Connecting to Redis");

        let client = Client::open(redis_url)?;

        // Test the connection by pinging Redis
        let mut conn = client.get_multiplexed_async_connection().await?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;

        tracing::info!(host = %host, port = %port, "Redis connection established");

        Ok(Self {
            client,
            ttl_seconds,
        })
    }

    /// Get cached vulnerability data by CVE ID
    pub async fn get_vulnerability<T: DeserializeOwned>(&self, cve: &str) -> Result<T, CacheError> {
        self.get_with_prefix(PREFIX_VULNERABILITY, cve).await
    }

    /// Cache vulnerability data by CVE ID
    pub async fn set_vulnerability<T: Serialize>(
        &self,
        cve: &str,
        data: &T,
    ) -> Result<(), CacheError> {
        self.set_with_prefix(PREFIX_VULNERABILITY, cve, data).await
    }

    /// Get cached package metadata by purl
    pub async fn get_package<T: DeserializeOwned>(&self, purl: &str) -> Result<T, CacheError> {
        self.get_with_prefix(PREFIX_PACKAGE, purl).await
    }

    /// Cache package metadata by purl
    pub async fn set_package<T: Serialize>(&self, purl: &str, data: &T) -> Result<(), CacheError> {
        self.set_with_prefix(PREFIX_PACKAGE, purl, data).await
    }

    /// Get cached Red Hat CSAF data by CVE ID
    pub async fn get_csaf<T: DeserializeOwned>(&self, cve: &str) -> Result<T, CacheError> {
        self.get_with_prefix(PREFIX_CSAF, cve).await
    }

    /// Cache Red Hat CSAF data by CVE ID
    pub async fn set_csaf<T: Serialize>(&self, cve: &str, data: &T) -> Result<(), CacheError> {
        self.set_with_prefix(PREFIX_CSAF, cve, data).await
    }

    /// Get cached claims by document ID (document ID is already URL + content hash)
    pub async fn get_claims<T: DeserializeOwned>(&self, doc_id: &str) -> Result<T, CacheError> {
        self.get_with_prefix(PREFIX_CLAIMS, doc_id).await
    }

    /// Cache claims by document ID
    pub async fn set_claims<T: Serialize>(&self, doc_id: &str, data: &T) -> Result<(), CacheError> {
        // Use 30-day TTL for claims
        self.set_with_prefix_and_ttl(PREFIX_CLAIMS, doc_id, data, ASSESSMENT_TTL_SECONDS).await
    }

    /// Get cached vulnerability assessment by composite key hash
    pub async fn get_assessment<T: DeserializeOwned>(&self, key_hash: &str) -> Result<T, CacheError> {
        self.get_with_prefix(PREFIX_ASSESSMENT, key_hash).await
    }

    /// Cache vulnerability assessment by composite key hash
    pub async fn set_assessment<T: Serialize>(
        &self,
        key_hash: &str,
        data: &T,
    ) -> Result<(), CacheError> {
        // Use 30-day TTL for assessments
        self.set_with_prefix_and_ttl(PREFIX_ASSESSMENT, key_hash, data, ASSESSMENT_TTL_SECONDS).await
    }

    /// Get cached remediation plan by composite key hash
    pub async fn get_remediation_plan<T: DeserializeOwned>(&self, key_hash: &str) -> Result<T, CacheError> {
        self.get_with_prefix(PREFIX_REMEDIATION, key_hash).await
    }

    /// Cache remediation plan by composite key hash
    pub async fn set_remediation_plan<T: Serialize>(
        &self,
        key_hash: &str,
        data: &T,
    ) -> Result<(), CacheError> {
        // Use 30-day TTL for remediation plans
        self.set_with_prefix_and_ttl(PREFIX_REMEDIATION, key_hash, data, ASSESSMENT_TTL_SECONDS).await
    }

    /// Invalidate cached assessment for a CVE (when OSV/CSAF/VEX data changes)
    /// This removes all assessment cache entries that start with the CVE ID
    pub async fn invalidate_assessments_for_cve(&self, cve: &str) -> Result<(), CacheError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let pattern = format!("{}*", PREFIX_ASSESSMENT);
        
        // Scan for keys matching the pattern
        let mut cursor = 0u64;
        loop {
            let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await?;

            // Delete keys that contain the CVE ID in their hash
            for key in keys {
                // The key format is "assessment:{hash}" where hash includes CVE
                // We need to check if the cached assessment contains this CVE
                // For simplicity, we'll delete all assessments and let them regenerate
                // A more sophisticated approach would require storing CVE->key mappings
                let _: () = conn.del(&key).await?;
            }

            if new_cursor == 0 {
                break;
            }
            cursor = new_cursor;
        }

        tracing::debug!(cve = %cve, "Invalidated assessment cache entries");
        Ok(())
    }

    /// Invalidate cached remediation plans when assessment is invalidated
    /// This removes all remediation plan cache entries
    pub async fn invalidate_remediation_plans(&self) -> Result<(), CacheError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let pattern = format!("{}*", PREFIX_REMEDIATION);
        
        // Scan for keys matching the pattern
        let mut cursor = 0u64;
        loop {
            let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await?;

            // Delete all remediation plan keys
            for key in keys {
                let _: () = conn.del(&key).await?;
            }

            if new_cursor == 0 {
                break;
            }
            cursor = new_cursor;
        }

        tracing::debug!("Invalidated remediation plan cache entries");
        Ok(())
    }

    async fn get_with_prefix<T: DeserializeOwned>(
        &self,
        prefix: &str,
        key: &str,
    ) -> Result<T, CacheError> {
        let full_key = format!("{}{}", prefix, key);
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let data: Option<String> = conn.get(&full_key).await?;

        match data {
            Some(json) => {
                serde_json::from_str(&json).map_err(|e| CacheError::Serialization(e.to_string()))
            }
            None => Err(CacheError::Miss(key.to_string())),
        }
    }

    async fn set_with_prefix<T: Serialize>(
        &self,
        prefix: &str,
        key: &str,
        data: &T,
    ) -> Result<(), CacheError> {
        self.set_with_prefix_and_ttl(prefix, key, data, self.ttl_seconds).await
    }

    async fn set_with_prefix_and_ttl<T: Serialize>(
        &self,
        prefix: &str,
        key: &str,
        data: &T,
        ttl: u64,
    ) -> Result<(), CacheError> {
        let full_key = format!("{}{}", prefix, key);
        let json =
            serde_json::to_string(data).map_err(|e| CacheError::Serialization(e.to_string()))?;

        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.set_ex(&full_key, json, ttl).await?;

        tracing::debug!(key = %full_key, ttl = ttl, "Cached data");
        Ok(())
    }
}
