//! GitHub Security Advisory retriever

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{extract_domain, html_to_markdown, DocumentRetriever, RetrievedDocument, RetrieverError};
use crate::model::{ContentType, ReferenceMetadata, RetrieverType};

/// Retriever for GitHub Security Advisories
pub struct GitHubAdvisoryRetriever {
    client: Client,
    token: Option<String>,
    ghsa_pattern: Regex,
}

impl GitHubAdvisoryRetriever {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            token,
            ghsa_pattern: Regex::new(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}").unwrap(),
        }
    }

    fn extract_ghsa_id(&self, url: &Url) -> Option<String> {
        self.ghsa_pattern
            .find(url.as_str())
            .map(|m| m.as_str().to_string())
    }

    fn is_advisory_url(&self, url: &Url) -> bool {
        let host = url.host_str().unwrap_or("");
        let path = url.path();

        // Global advisories: github.com/advisories/GHSA-xxxx-xxxx-xxxx
        if (host == "github.com" || host == "www.github.com")
            && path.starts_with("/advisories/")
        {
            return true;
        }

        // Repository security advisories: github.com/owner/repo/security/advisories/GHSA-xxxx
        if (host == "github.com" || host == "www.github.com")
            && path.contains("/security/advisories/")
        {
            return true;
        }

        false
    }
}

/// GitHub Advisory REST API response
#[derive(Debug, Deserialize)]
struct GitHubAdvisory {
    ghsa_id: String,
    summary: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    published_at: Option<String>,
    updated_at: Option<String>,
}

#[async_trait]
impl DocumentRetriever for GitHubAdvisoryRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        self.is_advisory_url(url)
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::GitAdvisory
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let ghsa_id = self.extract_ghsa_id(url);

        tracing::debug!(url = %url, ghsa_id = ?ghsa_id, "Fetching GitHub Advisory");

        // Try REST API first if we have a token and GHSA ID
        if let (Some(token), Some(id)) = (&self.token, &ghsa_id) {
            if let Ok(doc) = self.fetch_via_api(url, token, id).await {
                return Ok(doc);
            }
        }

        // Fallback to HTML scraping
        self.fetch_html(url).await
    }
}

impl GitHubAdvisoryRetriever {
    async fn fetch_via_api(
        &self,
        original_url: &Url,
        token: &str,
        ghsa_id: &str,
    ) -> Result<RetrievedDocument, RetrieverError> {
        let api_url = format!("https://api.github.com/advisories/{}", ghsa_id);

        tracing::debug!(api_url = %api_url, "Fetching advisory from GitHub REST API");

        let response = self
            .client
            .get(&api_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("User-Agent", "trustify-da-agent/1.0")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(ghsa_id.to_string()));
        }

        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
        {
            tracing::warn!(url = %api_url, status = %response.status(), "GitHub Advisory API rate limited");
            return Err(RetrieverError::RateLimited);
        }

        if !response.status().is_success() {
            return Err(RetrieverError::ParseError(format!(
                "HTTP {}: {}",
                response.status(),
                api_url
            )));
        }

        let json_text = response.text().await?;
        let advisory: GitHubAdvisory = serde_json::from_str(&json_text)
            .map_err(|e| RetrieverError::ParseError(e.to_string()))?;

        let published = advisory
            .published_at
            .as_ref()
            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&Utc));

        let last_modified = advisory
            .updated_at
            .as_ref()
            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&Utc));

        let normalized = format!(
            "# {}\n\n**Severity:** {}\n\n{}\n\n{}",
            advisory.ghsa_id,
            advisory.severity.as_deref().unwrap_or("Unknown"),
            advisory.summary.as_deref().unwrap_or(""),
            advisory.description.as_deref().unwrap_or("")
        );

        let retrieved_from = Url::parse(&api_url)
            .unwrap_or_else(|_| original_url.clone());

        Ok(RetrievedDocument {
            retrieved_from,
            canonical_url: original_url.clone(),
            domain_url: extract_domain(original_url),
            retriever: self.retriever_type(),
            raw_content: json_text,
            normalized_content: Some(normalized),
            content_type: ContentType::Json,
            published,
            last_modified,
            metadata: Some(ReferenceMetadata {
                title: advisory.summary,
                description: None,
                commit_message: None,
                authors: vec![],
                tags: advisory.severity.into_iter().collect(),
                labels: vec![],
                issue_number: None,
                repository: None,
                file_changes: vec![],
                code_snippets: vec![],
            }),
        })
    }

    async fn fetch_html(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let mut request = self.client.get(url.as_str())
            .header("User-Agent", "trustify-da-agent/1.0");

        if let Some(ref token) = self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(url.to_string()));
        }

        if !response.status().is_success() {
            return Err(RetrieverError::ParseError(format!(
                "HTTP {}: {}",
                response.status(),
                url
            )));
        }

        let html = response.text().await?;
        let normalized = html_to_markdown(&html);

        Ok(RetrievedDocument {
            retrieved_from: url.clone(),
            canonical_url: url.clone(),
            domain_url: extract_domain(url),
            retriever: self.retriever_type(),
            raw_content: html,
            normalized_content: Some(normalized),
            content_type: ContentType::Html,
            published: None,
            last_modified: None,
            metadata: Some(ReferenceMetadata {
                title: self.extract_ghsa_id(url),
                description: None,
                commit_message: None,
                authors: vec![],
                tags: vec![],
                labels: vec![],
                issue_number: None,
                repository: None,
                file_changes: vec![],
                code_snippets: vec![],
            }),
        })
    }
}
