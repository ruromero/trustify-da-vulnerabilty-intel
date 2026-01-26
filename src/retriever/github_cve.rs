//! GitHub CVE retriever for CVEProject/cvelistV5

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{DocumentRetriever, RetrievedDocument, RetrieverError, extract_domain};
use crate::model::{ContentType, ReferenceMetadata, RetrieverType};

/// Retriever for GitHub CVE data from CVEProject/cvelistV5
pub struct GitHubCveRetriever {
    client: Client,
    token: Option<String>,
    cve_pattern: Regex,
}

impl GitHubCveRetriever {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            token,
            cve_pattern: Regex::new(r"CVE-(\d{4})-(\d+)").unwrap(),
        }
    }

    /// Build the raw GitHub URL for a CVE JSON file
    fn build_cve_url(&self, cve_id: &str) -> Option<Url> {
        let caps = self.cve_pattern.captures(cve_id)?;
        let year = caps.get(1)?.as_str();
        let number: u64 = caps.get(2)?.as_str().parse().ok()?;

        // CVEs are organized in folders by year and thousands
        // e.g., CVE-2021-44228 -> cves/2021/44xxx/CVE-2021-44228.json
        let thousands = (number / 1000) * 1000;
        let folder = format!("{}xxx", thousands);

        let url = format!(
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{}/{}/{}.json",
            year, folder, cve_id
        );

        Url::parse(&url).ok()
    }

    fn extract_cve_id(&self, url: &Url) -> Option<String> {
        self.cve_pattern
            .find(url.as_str())
            .map(|m| m.as_str().to_string())
    }
}

#[derive(Debug, Deserialize)]
struct CveRecord {
    #[serde(rename = "cveMetadata")]
    cve_metadata: Option<CveMetadata>,
    containers: Option<CveContainers>,
}

#[derive(Debug, Deserialize)]
struct CveMetadata {
    #[serde(rename = "datePublished")]
    date_published: Option<String>,
    #[serde(rename = "dateUpdated")]
    date_updated: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CveContainers {
    cna: Option<CnaContainer>,
}

#[derive(Debug, Deserialize)]
struct CnaContainer {
    title: Option<String>,
}

#[async_trait]
impl DocumentRetriever for GitHubCveRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        // Handle URLs to CVEProject/cvelistV5 or direct CVE references
        url.host_str().is_some_and(|h| {
            (h == "github.com" || h == "raw.githubusercontent.com")
                && url.path().contains("CVEProject/cvelistV5")
        })
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::GitCveV5
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let cve_id = self
            .extract_cve_id(url)
            .ok_or_else(|| RetrieverError::ParseError("Could not extract CVE ID".to_string()))?;

        // Build the raw content URL
        let fetch_url = if url.host_str() == Some("raw.githubusercontent.com") {
            url.clone()
        } else {
            self.build_cve_url(&cve_id)
                .ok_or_else(|| RetrieverError::ParseError("Could not build CVE URL".to_string()))?
        };

        tracing::debug!(url = %fetch_url, cve_id = %cve_id, "Fetching CVE JSON");

        let mut request = self.client.get(fetch_url.as_str());

        if let Some(ref token) = self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(cve_id));
        }

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            || response.status() == reqwest::StatusCode::FORBIDDEN
        {
            tracing::warn!(url = %fetch_url, status = %response.status(), "GitHub raw content rate limited");
            return Err(RetrieverError::RateLimited);
        }

        if !response.status().is_success() {
            return Err(RetrieverError::ParseError(format!(
                "HTTP {}: {}",
                response.status(),
                fetch_url
            )));
        }

        let json_text = response.text().await?;

        // Parse for metadata extraction
        let record: CveRecord = serde_json::from_str(&json_text)
            .map_err(|e| RetrieverError::ParseError(e.to_string()))?;

        let published = record
            .cve_metadata
            .as_ref()
            .and_then(|m| m.date_published.as_ref())
            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&Utc));

        let last_modified = record
            .cve_metadata
            .as_ref()
            .and_then(|m| m.date_updated.as_ref())
            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&Utc));

        let title = record
            .containers
            .as_ref()
            .and_then(|c| c.cna.as_ref())
            .and_then(|cna| cna.title.clone())
            .or_else(|| Some(cve_id.clone()));

        Ok(RetrievedDocument {
            retrieved_from: fetch_url,
            canonical_url: url.clone(),
            domain_url: extract_domain(url),
            retriever: self.retriever_type(),
            raw_content: json_text.clone(),
            normalized_content: Some(json_text), // JSON is already structured
            content_type: ContentType::Json,
            published,
            last_modified,
            metadata: Some(ReferenceMetadata {
                title,
                description: None,
                commit_message: None,
                authors: vec![],
                tags: vec![],
                labels: vec![],
                issue_number: None,
                repository: Some(Url::parse("https://github.com/CVEProject/cvelistV5").unwrap()),
                file_changes: vec![],
                code_snippets: vec![],
                comments: vec![],
            }),
        })
    }
}
