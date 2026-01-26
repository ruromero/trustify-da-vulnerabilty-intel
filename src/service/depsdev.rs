//! deps.dev API client service
//!
//! Fetches package metadata from the deps.dev API.

use std::env;

use reqwest::Client;
use serde::Deserialize;
use url::Url;

use crate::model::PackageMetadata;

const DEPSDEV_API_BASE_URL: &str = "https://api.deps.dev/v3alpha";
const ENV_DEPSDEV_BASE_URL: &str = "DEPSDEV_BASE_URL";

#[derive(Debug, thiserror::Error)]
pub enum DepsDevError {
    #[error("Package not found: {0}")]
    NotFound(String),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Failed to parse response: {0}")]
    ParseError(String),
}

/// Client for interacting with the deps.dev API
pub struct DepsDevClient {
    client: Client,
    base_url: String,
}

// Response models - only the fields we need
#[derive(Debug, Deserialize)]
struct PurlResponse {
    version: Option<VersionInfo>,
}

#[derive(Debug, Deserialize)]
struct VersionInfo {
    #[serde(default)]
    links: Vec<Link>,
    #[serde(default)]
    licenses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Link {
    label: String,
    url: String,
}

impl DepsDevClient {
    /// Create a new deps.dev client
    ///
    /// The base URL is resolved from:
    /// 1. `DEPSDEV_BASE_URL` environment variable
    /// 2. Default deps.dev API URL
    pub fn new() -> Self {
        let base_url =
            env::var(ENV_DEPSDEV_BASE_URL).unwrap_or_else(|_| DEPSDEV_API_BASE_URL.to_string());

        Self {
            client: Client::new(),
            base_url,
        }
    }

    /// Get package metadata by purl
    ///
    /// Fetches package info from deps.dev and extracts:
    /// - SOURCE_REPO link
    /// - HOMEPAGE link
    /// - ISSUE_TRACKER link
    /// - Licenses
    pub async fn get_package_metadata(&self, purl: &str) -> Result<PackageMetadata, DepsDevError> {
        let encoded_purl = urlencoding::encode(purl);
        let url = format!("{}/purl/{}", self.base_url, encoded_purl);

        tracing::debug!(purl = %purl, url = %url, "Fetching package metadata from deps.dev");

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DepsDevError::NotFound(purl.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DepsDevError::ParseError(format!(
                "Unexpected status {}: {}",
                status, body
            )));
        }

        let purl_response: PurlResponse = response.json().await.map_err(|e| {
            DepsDevError::ParseError(format!("Failed to deserialize response: {}", e))
        })?;

        let metadata = self.extract_metadata(purl_response);

        tracing::debug!(
            purl = %purl,
            source_repo = ?metadata.source_repo,
            licenses_count = metadata.licenses.len(),
            "Fetched package metadata"
        );

        Ok(metadata)
    }

    fn extract_metadata(&self, response: PurlResponse) -> PackageMetadata {
        let version = response.version.unwrap_or(VersionInfo {
            links: vec![],
            licenses: vec![],
        });

        let mut source_repo = None;
        let mut homepage = None;
        let mut issue_tracker = None;

        for link in version.links {
            match link.label.as_str() {
                "SOURCE_REPO" => source_repo = Url::parse(&link.url).ok(),
                "HOMEPAGE" => homepage = Url::parse(&link.url).ok(),
                "ISSUE_TRACKER" => issue_tracker = Url::parse(&link.url).ok(),
                _ => {}
            }
        }

        PackageMetadata {
            source_repo,
            homepage,
            issue_tracker,
            licenses: version.licenses,
        }
    }
}

impl Default for DepsDevClient {
    fn default() -> Self {
        Self::new()
    }
}
