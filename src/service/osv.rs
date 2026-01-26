//! OSV.dev API client service
//!
//! Provides access to the Open Source Vulnerabilities database.

use std::env;

use crate::model::osv::OsvVulnerability;
use reqwest::Client;

const OSV_API_BASE_URL: &str = "https://api.osv.dev/v1";
const OSV_BASE_URL_ENV: &str = "OSV_BASE_URL";

#[derive(Debug, thiserror::Error)]
pub enum OsvError {
    #[error("Vulnerability not found: {0}")]
    NotFound(String),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Failed to parse response: {0}")]
    ParseError(String),
}

/// Client for interacting with the OSV.dev API
pub struct OsvClient {
    client: Client,
    base_url: String,
}

impl OsvClient {
    /// Create a new OSV client
    ///
    /// The base URL is resolved in this order:
    /// 1. `OSV_BASE_URL` environment variable if set
    /// 2. Default OSV.dev API URL
    pub fn new() -> Self {
        let resolved_url = env::var(OSV_BASE_URL_ENV)
            .ok()
            .unwrap_or_else(|| OSV_API_BASE_URL.to_string());

        Self {
            client: Client::new(),
            base_url: resolved_url,
        }
    }

    /// Get vulnerability data by ID (CVE, GHSA, or OSV ID)
    ///
    /// # Arguments
    /// * `vuln_id` - The vulnerability ID (e.g., "CVE-2021-44228", "GHSA-xxx", "OSV-2020-111")
    ///
    /// # Returns
    /// The vulnerability record from OSV.dev
    ///
    /// # Example
    /// ```ignore
    /// let client = OsvClient::new(None);
    /// let vuln = client.get_vulnerability("CVE-2021-44228").await?;
    /// println!("Summary: {:?}", vuln.summary);
    /// ```
    pub async fn get_vulnerability(&self, vuln_id: &str) -> Result<OsvVulnerability, OsvError> {
        let url = format!("{}/vulns/{}", self.base_url, vuln_id);

        tracing::debug!(vuln_id = %vuln_id, url = %url, "Fetching vulnerability from OSV.dev");

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(OsvError::NotFound(vuln_id.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(OsvError::ParseError(format!(
                "Unexpected status {}: {}",
                status, body
            )));
        }

        let vuln: OsvVulnerability = response.json().await.map_err(|e| {
            OsvError::ParseError(format!("Failed to deserialize vulnerability: {}", e))
        })?;

        tracing::debug!(
            vuln_id = %vuln.id,
            aliases = ?vuln.aliases,
            affected_count = vuln.affected.len(),
            "Successfully fetched vulnerability"
        );

        Ok(vuln)
    }
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_get_known_cve() {
        let client = OsvClient::new();
        let result = client.get_vulnerability("CVE-2021-44228").await;
        assert!(result.is_ok());
        let vuln = result.unwrap();
        assert_eq!(vuln.id, "CVE-2021-44228");
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_get_nonexistent_cve() {
        let client = OsvClient::new();
        let result = client.get_vulnerability("CVE-9999-99999").await;
        assert!(matches!(result, Err(OsvError::NotFound(_))));
    }
}
