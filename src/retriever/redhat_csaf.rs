//! Red Hat CSAF retriever for access.redhat.com URLs
//!
//! Uses cached CSAF VEX data to generate normalized content from vulnerability notes.

use async_trait::async_trait;
use regex::Regex;
use url::Url;

use super::{DocumentRetriever, RetrievedDocument, RetrieverError, extract_domain};
use crate::model::redhat_csaf::RedHatCsafResponse;
use crate::model::{ContentType, ReferenceMetadata, RetrieverType};
use crate::service::cache::VulnerabilityCache;

/// Retriever for Red Hat security advisory pages (access.redhat.com)
///
/// Uses the cached CSAF VEX data instead of fetching the web page directly.
pub struct RedHatCsafRetriever {
    cache: Option<VulnerabilityCache>,
    cve_pattern: Regex,
}

impl RedHatCsafRetriever {
    pub fn new(cache: Option<VulnerabilityCache>) -> Self {
        Self {
            cache,
            // Matches CVE IDs in URLs like:
            // - security.access.redhat.com/cve/cve-2024-12345
            // - access.redhat.com/security/cve/cve-2024-12345
            cve_pattern: Regex::new(r"(?i)cve[/-](cve-\d{4}-\d+)").unwrap(),
        }
    }

    fn extract_cve_from_url(&self, url: &Url) -> Option<String> {
        let url_str = url.as_str();
        self.cve_pattern
            .captures(url_str)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_uppercase())
    }

    /// Build the CSAF JSON URL for a CVE ID
    /// Format: https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve}.json
    fn build_csaf_json_url(&self, cve_id: &str) -> Option<Url> {
        // Extract year from CVE ID (e.g., CVE-2025-49574 -> 2025)
        let parts: Vec<&str> = cve_id.split('-').collect();
        if parts.len() < 2 {
            return None;
        }
        let year = parts[1];
        let url_str = format!(
            "https://security.access.redhat.com/data/csaf/v2/vex/{}/{}.json",
            year,
            cve_id.to_lowercase()
        );
        Url::parse(&url_str).ok()
    }
}

#[async_trait]
impl DocumentRetriever for RedHatCsafRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        url.host_str()
            .map(|h| {
                (h == "access.redhat.com" || h == "security.access.redhat.com")
                    && self.extract_cve_from_url(url).is_some()
            })
            .unwrap_or(false)
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::RedHatCsaf
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let cve_id = self.extract_cve_from_url(url).ok_or_else(|| {
            RetrieverError::ParseError("Could not extract CVE ID from URL".to_string())
        })?;

        tracing::debug!(
            url = %url,
            cve = %cve_id,
            "Fetching Red Hat CSAF data for URL"
        );

        // Try to get from cache
        let csaf_response: RedHatCsafResponse = match &self.cache {
            Some(cache) => match cache.get_csaf::<RedHatCsafResponse>(&cve_id).await {
                Ok(cached) => {
                    tracing::debug!(cve = %cve_id, "Cache hit for Red Hat CSAF in retriever");
                    cached
                }
                Err(_) => {
                    tracing::debug!(cve = %cve_id, "Cache miss for Red Hat CSAF in retriever");
                    return Err(RetrieverError::NotFound(format!(
                        "Red Hat CSAF data not cached for {}. Will be fetched during vulnerability intel request.",
                        cve_id
                    )));
                }
            },
            None => {
                return Err(RetrieverError::ParseError(
                    "Cache not available for Red Hat CSAF retriever".to_string(),
                ));
            }
        };

        // Build normalized markdown from notes
        let normalized_content = csaf_response.build_normalized_content();
        let normalized = if normalized_content.is_empty() {
            None
        } else {
            Some(normalized_content)
        };

        // Use raw JSON from the cached response, or empty object if not available
        let raw_content = csaf_response.raw_json.unwrap_or_else(|| "{}".to_string());

        // Extract title from notes or use CVE ID
        let title = csaf_response
            .notes
            .first()
            .and_then(|n| n.title.clone())
            .unwrap_or_else(|| format!("Red Hat Security Advisory - {}", cve_id));

        // Build the CSAF JSON URL for retrieved_from
        // Format: https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve}.json
        let retrieved_from = self
            .build_csaf_json_url(&cve_id)
            .unwrap_or_else(|| url.clone());

        Ok(RetrievedDocument {
            retrieved_from,
            canonical_url: url.clone(),
            domain_url: extract_domain(url),
            retriever: self.retriever_type(),
            raw_content,
            normalized_content: normalized,
            content_type: ContentType::Json,
            published: None,
            last_modified: None,
            metadata: Some(ReferenceMetadata {
                title: Some(title),
                description: None,
                commit_message: None,
                authors: vec![],
                tags: vec!["Red Hat".to_string(), cve_id],
                labels: vec![],
                issue_number: None,
                repository: None,
                file_changes: vec![],
                code_snippets: vec![],
                comments: vec![],
            }),
        })
    }
}
