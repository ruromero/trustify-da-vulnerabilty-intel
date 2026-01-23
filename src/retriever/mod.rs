//! Document retrievers for fetching reference content from various sources

mod generic;
mod github_advisory;
mod github_commit;
mod github_cve;
mod github_issue;
mod github_release;
mod nvd;

use std::env;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use url::Url;

use crate::model::{ContentType, ReferenceDocument, ReferenceMetadata, RetrieverType};

pub use generic::GenericWebRetriever;
pub use github_advisory::GitHubAdvisoryRetriever;
pub use github_commit::GitHubCommitRetriever;
pub use github_cve::GitHubCveRetriever;
pub use github_issue::GitHubIssueRetriever;
pub use github_release::GitHubReleaseRetriever;
pub use nvd::NvdRetriever;

const ENV_GITHUB_TOKEN: &str = "GITHUB_TOKEN";

#[derive(Debug, thiserror::Error)]
pub enum RetrieverError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Failed to parse response: {0}")]
    ParseError(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("URL blocked by configuration: {0}")]
    Blocked(String),

    #[error("Not found: {0}")]
    NotFound(String),
}

/// Result of a document retrieval
#[derive(Debug, Clone)]
pub struct RetrievedDocument {
    /// The actual URL used to retrieve the content (e.g., API URL)
    pub retrieved_from: Url,
    /// The original reference URL (e.g., web URL from vulnerability references)
    pub canonical_url: Url,
    pub domain_url: Option<Url>,
    pub retriever: RetrieverType,
    pub raw_content: String,
    pub normalized_content: Option<String>,
    pub content_type: ContentType,
    pub published: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    pub metadata: Option<ReferenceMetadata>,
}

impl RetrievedDocument {
    /// Convert to ReferenceDocument with computed hash ID
    pub fn into_reference_document(self) -> ReferenceDocument {
        // Hash based on canonical URL + content for deduplication
        let content_hash = compute_hash(&self.canonical_url.to_string(), &self.raw_content);

        ReferenceDocument {
            id: content_hash.clone(),
            retrieved_from: self.retrieved_from,
            canonical_url: self.canonical_url,
            domain_url: self.domain_url,
            retriever: self.retriever,
            retrieved_at: Utc::now(),
            published: self.published.unwrap_or_else(Utc::now),
            last_modified: self.last_modified.unwrap_or_else(Utc::now),
            raw_content: self.raw_content,
            normalized_content: self.normalized_content,
            content_type: self.content_type,
            content_hash,
            metadata: self.metadata,
        }
    }
}

/// Trait for document retrievers
#[async_trait]
pub trait DocumentRetriever: Send + Sync {
    /// Check if this retriever can handle the given URL
    fn can_handle(&self, url: &Url) -> bool;

    /// Retrieve the document from the URL
    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError>;

    /// Get the retriever type
    fn retriever_type(&self) -> RetrieverType;
}

/// Compute SHA256 hash of URL + content
fn compute_hash(url: &str, content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Get GitHub token from environment
fn get_github_token() -> Option<String> {
    env::var(ENV_GITHUB_TOKEN).ok()
}

/// Extract domain from URL
fn extract_domain(url: &Url) -> Option<Url> {
    let domain = format!("{}://{}", url.scheme(), url.host_str()?);
    Url::parse(&domain).ok()
}

/// Convert HTML to Markdown
fn html_to_markdown(html: &str) -> String {
    htmd::convert(html).unwrap_or_else(|_| html.to_string())
}

/// URL pattern matching helpers
fn is_github_url(url: &Url) -> bool {
    url.host_str()
        .map(|h| h == "github.com" || h == "www.github.com")
        .unwrap_or(false)
}

fn is_nvd_url(url: &Url) -> bool {
    url.host_str()
        .map(|h| h == "nvd.nist.gov" || h == "www.nvd.nist.gov")
        .unwrap_or(false)
}

use crate::model::RetrieverConfig;

/// Retriever dispatcher that selects the appropriate retriever for a URL
pub struct RetrieverDispatcher {
    config: RetrieverConfig,
    nvd: NvdRetriever,
    github_cve: GitHubCveRetriever,
    github_advisory: GitHubAdvisoryRetriever,
    github_issue: GitHubIssueRetriever,
    github_commit: GitHubCommitRetriever,
    github_release: GitHubReleaseRetriever,
    generic: GenericWebRetriever,
}

impl RetrieverDispatcher {
    pub fn new(config: RetrieverConfig) -> Self {
        let github_token = get_github_token();

        if !config.allow.is_empty() {
            tracing::info!(allow = ?config.allow, "Retriever whitelist configured");
        }
        if !config.deny.is_empty() {
            tracing::info!(deny = ?config.deny, "Retriever blacklist configured");
        }

        Self {
            config,
            nvd: NvdRetriever::new(),
            github_cve: GitHubCveRetriever::new(github_token.clone()),
            github_advisory: GitHubAdvisoryRetriever::new(github_token.clone()),
            github_issue: GitHubIssueRetriever::new(github_token.clone()),
            github_commit: GitHubCommitRetriever::new(github_token.clone()),
            github_release: GitHubReleaseRetriever::new(github_token),
            generic: GenericWebRetriever::new(),
        }
    }

    /// Retrieve a document from a URL, using the appropriate retriever
    pub async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        // Check allow/deny lists
        if !self.config.is_url_allowed(url) {
            tracing::debug!(url = %url, "URL blocked by configuration");
            return Err(RetrieverError::Blocked(url.to_string()));
        }

        // Try retrievers in order of specificity
        if self.nvd.can_handle(url) {
            return self.nvd.retrieve(url).await;
        }

        if self.github_cve.can_handle(url) {
            return self.github_cve.retrieve(url).await;
        }

        if self.github_advisory.can_handle(url) {
            return self.github_advisory.retrieve(url).await;
        }

        if self.github_commit.can_handle(url) {
            return self.github_commit.retrieve(url).await;
        }

        if self.github_release.can_handle(url) {
            return self.github_release.retrieve(url).await;
        }

        if self.github_issue.can_handle(url) {
            return self.github_issue.retrieve(url).await;
        }

        // Fallback to generic
        self.generic.retrieve(url).await
    }
}
