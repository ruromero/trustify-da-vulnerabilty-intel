//! Red Hat Bugzilla retriever

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{DocumentRetriever, RetrievedDocument, RetrieverError, extract_domain};
use crate::model::{Comment, ContentType, ReferenceMetadata, RetrieverType};

const BUGZILLA_API_BASE: &str = "https://bugzilla.redhat.com/rest";

/// Retriever for Red Hat Bugzilla bugs
pub struct BugzillaRetriever {
    client: Client,
    bug_pattern: Regex,
}

impl BugzillaRetriever {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("trustify-da-agent/1.0")
                .build()
                .unwrap_or_else(|_| Client::new()),
            // Matches: bugzilla.redhat.com/show_bug.cgi?id=123456 or bugzilla.redhat.com/123456
            bug_pattern: Regex::new(r"bugzilla\.redhat\.com/(?:show_bug\.cgi\?id=)?(\d+)").unwrap(),
        }
    }

    fn extract_bug_id(&self, url: &Url) -> Option<String> {
        let url_str = url.as_str();
        self.bug_pattern
            .captures(url_str)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
}

impl Default for BugzillaRetriever {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DocumentRetriever for BugzillaRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        url.host_str()
            .map(|h| h.contains("bugzilla.redhat.com"))
            .unwrap_or(false)
            && self.extract_bug_id(url).is_some()
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::Bugzilla
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let bug_id = self
            .extract_bug_id(url)
            .ok_or_else(|| RetrieverError::ParseError("Could not extract bug ID".to_string()))?;

        tracing::debug!(
            url = %url,
            bug_id = %bug_id,
            "Fetching Bugzilla bug"
        );

        // Fetch bug details
        let bug_url = format!("{}/bug/{}", BUGZILLA_API_BASE, bug_id);
        let bug_response = self.client.get(&bug_url).send().await?;

        if bug_response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(url.to_string()));
        }

        if bug_response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            || bug_response.status() == reqwest::StatusCode::FORBIDDEN
        {
            tracing::warn!(url = %url, status = %bug_response.status(), "Bugzilla rate limited");
            return Err(RetrieverError::RateLimited);
        }

        if !bug_response.status().is_success() {
            return Err(RetrieverError::ParseError(format!(
                "HTTP {}: {}",
                bug_response.status(),
                bug_url
            )));
        }

        let bug_json = bug_response.text().await?;
        let bug_data: BugzillaBugResponse = serde_json::from_str(&bug_json)
            .map_err(|e| RetrieverError::ParseError(e.to_string()))?;

        let bug = bug_data
            .bugs
            .into_iter()
            .next()
            .ok_or_else(|| RetrieverError::NotFound(bug_id.clone()))?;

        // Fetch comments
        let comments_url = format!("{}/bug/{}/comment", BUGZILLA_API_BASE, bug_id);
        let comments = match self.client.get(&comments_url).send().await {
            Ok(response) if response.status().is_success() => {
                let comments_json = response.text().await.unwrap_or_default();
                let comments_data: BugzillaCommentsResponse =
                    serde_json::from_str(&comments_json).unwrap_or_default();

                comments_data
                    .bugs
                    .get(&bug_id)
                    .map(|bug_comments| {
                        bug_comments
                            .comments
                            .iter()
                            .map(|c| Comment {
                                text: c.text.clone(),
                                author: Some(c.creator.clone()),
                                timestamp: c
                                    .creation_time
                                    .as_ref()
                                    .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                                    .map(|dt| dt.with_timezone(&Utc)),
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            }
            _ => vec![],
        };

        // Build normalized content
        let normalized = format!(
            "# Bug {} - {}\n\n**Status:** {}\n**Product:** {}\n**Component:** {}\n**Severity:** {}\n\n---\n\n## Comments\n\n{}",
            bug.id,
            bug.summary,
            bug.status,
            bug.product.as_deref().unwrap_or("Unknown"),
            bug.component.as_deref().unwrap_or("Unknown"),
            bug.severity.as_deref().unwrap_or("Unknown"),
            comments
                .iter()
                .map(|c| {
                    format!(
                        "**{}** ({})\n\n{}\n\n---\n",
                        c.author.as_deref().unwrap_or("Anonymous"),
                        c.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                        c.text
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        );

        let created_at = bug
            .creation_time
            .as_ref()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let last_modified = bug
            .last_change_time
            .as_ref()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let retrieved_from = Url::parse(&bug_url).unwrap_or_else(|_| url.clone());

        Ok(RetrievedDocument {
            retrieved_from,
            canonical_url: url.clone(),
            domain_url: extract_domain(url),
            retriever: self.retriever_type(),
            raw_content: bug_json,
            normalized_content: Some(normalized),
            content_type: ContentType::Json,
            published: created_at,
            last_modified,
            metadata: Some(ReferenceMetadata {
                title: Some(bug.summary),
                description: None,
                commit_message: None,
                authors: bug.creator.map(|c| vec![c]).unwrap_or_default(),
                tags: bug.keywords.unwrap_or_default(),
                labels: vec![bug.status, bug.severity.unwrap_or_default()]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect(),
                issue_number: bug.id.to_string().parse().ok(),
                repository: None,
                file_changes: vec![],
                code_snippets: vec![],
                comments,
            }),
        })
    }
}

// Bugzilla API response structures

#[derive(Debug, Deserialize)]
struct BugzillaBugResponse {
    #[serde(default)]
    bugs: Vec<BugzillaBug>,
}

#[derive(Debug, Deserialize)]
struct BugzillaBug {
    id: u64,
    summary: String,
    status: String,
    product: Option<String>,
    component: Option<String>,
    severity: Option<String>,
    creator: Option<String>,
    creation_time: Option<String>,
    last_change_time: Option<String>,
    keywords: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct BugzillaCommentsResponse {
    #[serde(default)]
    bugs: std::collections::HashMap<String, BugzillaBugComments>,
}

#[derive(Debug, Default, Deserialize)]
struct BugzillaBugComments {
    #[serde(default)]
    comments: Vec<BugzillaComment>,
}

#[derive(Debug, Deserialize)]
struct BugzillaComment {
    text: String,
    creator: String,
    creation_time: Option<String>,
}
