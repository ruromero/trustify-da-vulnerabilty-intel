//! CVE.org retriever using the MITRE CVE API
//!
//! Uses the CVE API at https://cveawg.mitre.org/api/cve/{id}
//! API documentation: https://cveawg.mitre.org/api-docs/

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{extract_domain, DocumentRetriever, RetrievedDocument, RetrieverError};
use crate::model::{ContentType, ReferenceMetadata, RetrieverType};

const CVE_API_BASE: &str = "https://cveawg.mitre.org/api/cve";

/// Retriever for www.cve.org URLs using the MITRE CVE API
pub struct CveOrgRetriever {
    client: Client,
    cve_pattern: Regex,
}

impl CveOrgRetriever {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("trustify-da-agent/1.0")
                .build()
                .unwrap_or_else(|_| Client::new()),
            cve_pattern: Regex::new(r"(?i)(CVE-\d{4}-\d+)").unwrap(),
        }
    }

    fn extract_cve_id(&self, url: &Url) -> Option<String> {
        self.cve_pattern
            .find(url.as_str())
            .map(|m| m.as_str().to_uppercase())
    }

    /// Build normalized markdown content from CVE record
    fn build_normalized(&self, record: &CveRecord) -> String {
        let mut content = String::new();

        // Title
        let title = record
            .containers
            .cna
            .title
            .as_deref()
            .unwrap_or(&record.cve_metadata.cve_id);
        content.push_str(&format!("# {}\n\n", title));

        // CVE ID
        content.push_str(&format!("**CVE ID:** {}\n\n", record.cve_metadata.cve_id));

        // State
        if let Some(ref state) = record.cve_metadata.state {
            content.push_str(&format!("**State:** {}\n\n", state));
        }

        // Assigner
        if let Some(ref assigner) = record.cve_metadata.assigner_short_name {
            content.push_str(&format!("**Assigner:** {}\n\n", assigner));
        }

        // Description
        content.push_str("## Description\n\n");
        for desc in &record.containers.cna.descriptions {
            if desc.lang.as_deref() == Some("en") || desc.lang.is_none() {
                content.push_str(&desc.value);
                content.push_str("\n\n");
                break;
            }
        }
        // If no English description found, use first available
        if content.ends_with("## Description\n\n") {
            if let Some(desc) = record.containers.cna.descriptions.first() {
                content.push_str(&desc.value);
                content.push_str("\n\n");
            }
        }

        // Problem types (CWE)
        if !record.containers.cna.problem_types.is_empty() {
            content.push_str("## Problem Types\n\n");
            for pt in &record.containers.cna.problem_types {
                for desc in &pt.descriptions {
                    if let Some(ref cwe_id) = desc.cwe_id {
                        content.push_str(&format!("- **{}**: {}\n", cwe_id, desc.description));
                    } else {
                        content.push_str(&format!("- {}\n", desc.description));
                    }
                }
            }
            content.push('\n');
        }

        // Affected products
        if !record.containers.cna.affected.is_empty() {
            content.push_str("## Affected Products\n\n");
            for affected in &record.containers.cna.affected {
                let vendor = affected.vendor.as_deref().unwrap_or("Unknown");
                let product = affected.product.as_deref().unwrap_or("Unknown");
                content.push_str(&format!("- **{}** / {}\n", vendor, product));
            }
            content.push('\n');
        }

        // Metrics (CVSS)
        if !record.containers.cna.metrics.is_empty() {
            content.push_str("## Metrics\n\n");
            for metric in &record.containers.cna.metrics {
                if let Some(ref cvss) = metric.cvss_v3_1 {
                    content.push_str(&format!(
                        "- **CVSS v3.1**: {} ({})\n",
                        cvss.base_score.unwrap_or(0.0),
                        cvss.base_severity.as_deref().unwrap_or("Unknown")
                    ));
                    if let Some(ref vector) = cvss.vector_string {
                        content.push_str(&format!("  - Vector: `{}`\n", vector));
                    }
                }
                if let Some(ref cvss) = metric.cvss_v3_0 {
                    content.push_str(&format!(
                        "- **CVSS v3.0**: {} ({})\n",
                        cvss.base_score.unwrap_or(0.0),
                        cvss.base_severity.as_deref().unwrap_or("Unknown")
                    ));
                }
            }
            content.push('\n');
        }

        content.trim().to_string()
    }
}

impl Default for CveOrgRetriever {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DocumentRetriever for CveOrgRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        url.host_str()
            .map(|h| h == "www.cve.org" || h == "cve.org")
            .unwrap_or(false)
            && self.extract_cve_id(url).is_some()
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::CveOrg
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let cve_id = self
            .extract_cve_id(url)
            .ok_or_else(|| RetrieverError::ParseError("Could not extract CVE ID".to_string()))?;

        tracing::debug!(
            url = %url,
            cve_id = %cve_id,
            "Fetching CVE record from MITRE API"
        );

        let api_url = format!("{}/{}", CVE_API_BASE, cve_id);
        let response = self.client.get(&api_url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(cve_id));
        }

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(url = %url, "CVE API rate limited");
            return Err(RetrieverError::RateLimited);
        }

        if !response.status().is_success() {
            return Err(RetrieverError::ParseError(format!(
                "HTTP {}: {}",
                response.status(),
                api_url
            )));
        }

        let raw_content = response.text().await?;
        let record: CveRecord = serde_json::from_str(&raw_content)
            .map_err(|e| RetrieverError::ParseError(e.to_string()))?;

        let normalized_content = self.build_normalized(&record);

        // Extract dates
        let published = record
            .cve_metadata
            .date_published
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let last_modified = record
            .cve_metadata
            .date_updated
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        // Extract title
        let title = record
            .containers
            .cna
            .title
            .clone()
            .unwrap_or_else(|| cve_id.clone());

        // Extract description for metadata
        let description = record
            .containers
            .cna
            .descriptions
            .iter()
            .find(|d| d.lang.as_deref() == Some("en") || d.lang.is_none())
            .or_else(|| record.containers.cna.descriptions.first())
            .map(|d| d.value.clone());

        // Extract CWE tags
        let mut tags: Vec<String> = vec![cve_id.clone()];
        for pt in &record.containers.cna.problem_types {
            for desc in &pt.descriptions {
                if let Some(ref cwe_id) = desc.cwe_id {
                    tags.push(cwe_id.clone());
                }
            }
        }

        let retrieved_from = Url::parse(&api_url).unwrap_or_else(|_| url.clone());

        Ok(RetrievedDocument {
            retrieved_from,
            canonical_url: url.clone(),
            domain_url: extract_domain(url),
            retriever: self.retriever_type(),
            raw_content,
            normalized_content: Some(normalized_content),
            content_type: ContentType::Json,
            published,
            last_modified,
            metadata: Some(ReferenceMetadata {
                title: Some(title),
                description,
                commit_message: None,
                authors: record
                    .cve_metadata
                    .assigner_short_name
                    .map(|a| vec![a])
                    .unwrap_or_default(),
                tags,
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

// CVE API response structures (CVE JSON 5.x format)

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveRecord {
    cve_metadata: CveMetadata,
    containers: CveContainers,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveMetadata {
    cve_id: String,
    #[serde(default)]
    assigner_short_name: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    date_published: Option<String>,
    #[serde(default)]
    date_updated: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CveContainers {
    cna: CnaContainer,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CnaContainer {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    descriptions: Vec<CveDescription>,
    #[serde(default)]
    affected: Vec<CveAffected>,
    #[serde(default)]
    problem_types: Vec<CveProblemType>,
    #[serde(default)]
    metrics: Vec<CveMetric>,
}

#[derive(Debug, Deserialize)]
struct CveDescription {
    value: String,
    #[serde(default)]
    lang: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CveAffected {
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    product: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CveProblemType {
    #[serde(default)]
    descriptions: Vec<CveProblemTypeDescription>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveProblemTypeDescription {
    description: String,
    #[serde(default)]
    cwe_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveMetric {
    #[serde(default)]
    cvss_v3_1: Option<CvssScore>,
    #[serde(default)]
    cvss_v3_0: Option<CvssScore>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssScore {
    #[serde(default)]
    base_score: Option<f64>,
    #[serde(default)]
    base_severity: Option<String>,
    #[serde(default)]
    vector_string: Option<String>,
}
