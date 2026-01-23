//! NVD (National Vulnerability Database) retriever

use async_trait::async_trait;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

use super::{
    extract_domain, is_nvd_url, DocumentRetriever, RetrievedDocument,
    RetrieverError,
};
use crate::model::{ContentType, ReferenceMetadata, RetrieverType};

/// Retriever for NVD vulnerability pages
pub struct NvdRetriever {
    client: Client,
    cve_pattern: Regex,
}

impl NvdRetriever {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            cve_pattern: Regex::new(r"CVE-\d{4}-\d+").unwrap(),
        }
    }

    fn extract_cve_id(&self, url: &Url) -> Option<String> {
        self.cve_pattern
            .find(url.as_str())
            .map(|m| m.as_str().to_string())
    }

    /// Extract vulnerability description from NVD HTML
    fn extract_description(&self, html: &str) -> Option<String> {
        let document = Html::parse_document(html);
        
        // Select element with data-testid="vuln-description"
        let selector = Selector::parse(r#"[data-testid="vuln-description"]"#).ok()?;
        
        document
            .select(&selector)
            .next()
            .map(|el| el.text().collect::<String>().trim().to_string())
    }

    /// Build normalized markdown content
    fn build_normalized(&self, cve_id: Option<&str>, description: Option<&str>) -> String {
        let mut content = String::new();

        if let Some(id) = cve_id {
            content.push_str(&format!("# {}\n\n", id));
        }

        if let Some(desc) = description {
            content.push_str("## Description\n\n");
            content.push_str(desc);
            content.push('\n');
        }

        content
    }
}

#[async_trait]
impl DocumentRetriever for NvdRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        is_nvd_url(url) && url.path().contains("/vuln/detail/")
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::Nvd
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        tracing::debug!(url = %url, "Fetching NVD page");

        let response = self
            .client
            .get(url.as_str())
            .header("User-Agent", "trustify-da-agent/1.0")
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(url.to_string()));
        }

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(url = %url, "NVD rate limited");
            return Err(RetrieverError::RateLimited);
        }

        if !response.status().is_success() {
            return Err(RetrieverError::ParseError(format!(
                "HTTP {}: {}",
                response.status(),
                url
            )));
        }

        let html = response.text().await?;
        
        let cve_id = self.extract_cve_id(url);
        let description = self.extract_description(&html);
        let normalized = self.build_normalized(cve_id.as_deref(), description.as_deref());

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
                title: cve_id.map(|id| format!("NVD - {}", id)),
                description: None,
                commit_message: None,
                authors: vec![],
                tags: vec![],
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

impl Default for NvdRetriever {
    fn default() -> Self {
        Self::new()
    }
}
