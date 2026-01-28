//! GitHub Issue retriever

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{
    DocumentRetriever, RetrievedDocument, RetrieverError, extract_domain, html_to_markdown,
    is_github_url,
};
use crate::model::{ContentType, ReferenceMetadata, RetrieverType};

/// Retriever for GitHub Issues
pub struct GitHubIssueRetriever {
    client: Client,
    token: Option<String>,
    issue_pattern: Regex,
}

impl GitHubIssueRetriever {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            token,
            // Matches: /owner/repo/issues/123 or /owner/repo/pull/123
            issue_pattern: Regex::new(r"/([^/]+)/([^/]+)/(issues|pull)/(\d+)").unwrap(),
        }
    }

    fn parse_issue_url(&self, url: &Url) -> Option<(String, String, u64, bool)> {
        let caps = self.issue_pattern.captures(url.path())?;
        let owner = caps.get(1)?.as_str().to_string();
        let repo = caps.get(2)?.as_str().to_string();
        let is_pr = caps.get(3)?.as_str() == "pull";
        let number: u64 = caps.get(4)?.as_str().parse().ok()?;
        Some((owner, repo, number, is_pr))
    }
}

#[derive(Debug, Deserialize)]
struct GitHubIssue {
    title: String,
    body: Option<String>,
    state: String,
    #[serde(rename = "created_at")]
    created_at: String,
    #[serde(rename = "updated_at")]
    updated_at: String,
    user: Option<GitHubUser>,
    labels: Vec<GitHubLabel>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    login: String,
}

#[derive(Debug, Deserialize)]
struct GitHubLabel {
    name: String,
}

#[async_trait]
impl DocumentRetriever for GitHubIssueRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        is_github_url(url) && self.issue_pattern.is_match(url.path())
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::GitIssue
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let (owner, repo, number, is_pr) = self
            .parse_issue_url(url)
            .ok_or_else(|| RetrieverError::ParseError("Invalid issue URL".to_string()))?;

        tracing::debug!(
            url = %url,
            owner = %owner,
            repo = %repo,
            number = number,
            is_pr = is_pr,
            "Fetching GitHub issue/PR"
        );

        // Try API first if we have a token
        if let Some(ref token) = self.token
            && let Ok(doc) = self.fetch_via_api(url, token, &owner, &repo, number).await
        {
            return Ok(doc);
        }

        // Fallback to HTML
        self.fetch_html(url, &owner, &repo, number).await
    }
}

impl GitHubIssueRetriever {
    async fn fetch_via_api(
        &self,
        original_url: &Url,
        token: &str,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<RetrievedDocument, RetrieverError> {
        let api_url = format!(
            "https://api.github.com/repos/{}/{}/issues/{}",
            owner, repo, number
        );

        let response = self
            .client
            .get(&api_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("User-Agent", "trustify-da-intel/1.0")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(original_url.to_string()));
        }

        if response.status() == reqwest::StatusCode::FORBIDDEN
            || response.status() == reqwest::StatusCode::UNAUTHORIZED
        {
            tracing::warn!(url = %original_url, status = %response.status(), "GitHub API rate limited");
            return Err(RetrieverError::RateLimited);
        }

        let json_text = response.text().await?;
        let issue: GitHubIssue = serde_json::from_str(&json_text)
            .map_err(|e| RetrieverError::ParseError(e.to_string()))?;

        let created_at = DateTime::parse_from_rfc3339(&issue.created_at)
            .ok()
            .map(|d| d.with_timezone(&Utc));

        let updated_at = DateTime::parse_from_rfc3339(&issue.updated_at)
            .ok()
            .map(|d| d.with_timezone(&Utc));

        let normalized = format!(
            "# {}\n\n**State:** {}\n**Author:** {}\n**Labels:** {}\n\n---\n\n{}",
            issue.title,
            issue.state,
            issue
                .user
                .as_ref()
                .map(|u| u.login.as_str())
                .unwrap_or("Unknown"),
            issue
                .labels
                .iter()
                .map(|l| l.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            issue.body.as_deref().unwrap_or("")
        );

        let authors = issue.user.map(|u| vec![u.login]).unwrap_or_default();

        let labels: Vec<String> = issue.labels.into_iter().map(|l| l.name).collect();

        let retrieved_from = Url::parse(&api_url).unwrap_or_else(|_| original_url.clone());

        Ok(RetrievedDocument {
            retrieved_from,
            canonical_url: original_url.clone(),
            domain_url: extract_domain(original_url),
            retriever: self.retriever_type(),
            raw_content: json_text,
            normalized_content: Some(normalized),
            content_type: ContentType::Issue,
            published: created_at,
            last_modified: updated_at,
            metadata: Some(ReferenceMetadata {
                title: Some(issue.title),
                description: None,
                commit_message: None,
                authors,
                tags: vec![],
                labels,
                issue_number: Some(number),
                repository: Url::parse(&format!("https://github.com/{}/{}", owner, repo)).ok(),
                file_changes: vec![],
                code_snippets: vec![],
                comments: vec![],
            }),
        })
    }

    async fn fetch_html(
        &self,
        url: &Url,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<RetrievedDocument, RetrieverError> {
        let mut request = self
            .client
            .get(url.as_str())
            .header("User-Agent", "trustify-da-intel/1.0");

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
                title: None,
                description: None,
                commit_message: None,
                authors: vec![],
                tags: vec![],
                labels: vec![],
                issue_number: Some(number),
                repository: Url::parse(&format!("https://github.com/{}/{}", owner, repo)).ok(),
                file_changes: vec![],
                code_snippets: vec![],
                comments: vec![],
            }),
        })
    }
}
