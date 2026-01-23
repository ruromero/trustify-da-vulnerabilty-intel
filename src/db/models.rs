//! Database models for reference documents

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::model::{ContentType, ReferenceDocument, ReferenceMetadata, RetrieverType};
use url::Url;

/// Database representation of a reference document
#[derive(Debug, Clone, FromRow)]
pub struct ReferenceDocumentRow {
    pub id: String,
    pub retrieved_from: String,
    pub canonical_url: String,
    pub domain_url: Option<String>,
    pub retriever_type: String,
    pub retrieved_at: DateTime<Utc>,
    pub published: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    pub raw_content: Option<String>,
    pub normalized_content: Option<String>,
    pub content_type: Option<String>,
    pub metadata: serde_json::Value,
}

impl ReferenceDocumentRow {
    /// Convert database row to domain model
    pub fn into_domain(self) -> Result<ReferenceDocument, String> {
        let retrieved_from = Url::parse(&self.retrieved_from).map_err(|e| format!("Invalid retrieved_from URL: {}", e))?;
        let canonical_url = Url::parse(&self.canonical_url).map_err(|e| format!("Invalid canonical URL: {}", e))?;
        let domain_url = self.domain_url.as_ref().and_then(|u| Url::parse(u).ok());

        let retriever = match self.retriever_type.as_str() {
            "nvd" => RetrieverType::Nvd,
            "cve_org" => RetrieverType::CveOrg,
            "git_cve_v5" => RetrieverType::GitCveV5,
            "git_advisory" => RetrieverType::GitAdvisory,
            "git_issue" => RetrieverType::GitIssue,
            "git_commit" => RetrieverType::GitCommit,
            "git_release" => RetrieverType::GitRelease,
            "bugzilla" => RetrieverType::Bugzilla,
            "redhat_csaf" => RetrieverType::RedHatCsaf,
            _ => RetrieverType::Generic,
        };

        let content_type = match self.content_type.as_deref() {
            Some("markdown") => ContentType::Markdown,
            Some("html") => ContentType::Html,
            Some("json") => ContentType::Json,
            Some("git_commit") => ContentType::GitCommit,
            Some("issue") => ContentType::Issue,
            _ => ContentType::Html,
        };

        let metadata: Option<ReferenceMetadata> = serde_json::from_value(self.metadata).ok();

        Ok(ReferenceDocument {
            id: self.id.clone(),
            retrieved_from,
            canonical_url,
            domain_url,
            retriever,
            retrieved_at: self.retrieved_at,
            published: self.published.unwrap_or_else(Utc::now),
            last_modified: self.last_modified.unwrap_or_else(Utc::now),
            raw_content: self.raw_content.unwrap_or_default(),
            normalized_content: self.normalized_content,
            content_type,
            content_hash: self.id, // ID is the content hash
            metadata,
        })
    }
}

/// Helper to convert RetrieverType to string for database storage
pub fn retriever_type_to_string(retriever: &RetrieverType) -> &'static str {
    match retriever {
        RetrieverType::Nvd => "nvd",
        RetrieverType::CveOrg => "cve_org",
        RetrieverType::GitCveV5 => "git_cve_v5",
        RetrieverType::GitAdvisory => "git_advisory",
        RetrieverType::GitIssue => "git_issue",
        RetrieverType::GitCommit => "git_commit",
        RetrieverType::GitRelease => "git_release",
        RetrieverType::Bugzilla => "bugzilla",
        RetrieverType::RedHatCsaf => "redhat_csaf",
        RetrieverType::Generic => "generic",
    }
}

/// Helper to convert ContentType to string for database storage
pub fn content_type_to_string(content_type: &ContentType) -> &'static str {
    match content_type {
        ContentType::Markdown => "markdown",
        ContentType::Html => "html",
        ContentType::Json => "json",
        ContentType::GitCommit => "git_commit",
        ContentType::Issue => "issue",
    }
}

/// Query parameters for listing documents
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListDocumentsQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub retriever_type: Option<String>,
    pub domain_url: Option<String>,
}

/// Paginated response for documents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedDocuments {
    pub documents: Vec<ReferenceDocument>,
    pub page: u32,
    pub page_size: u32,
    pub total_count: i64,
    pub total_pages: u32,
}
