//! GitHub Release retriever

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{extract_domain, is_github_url, DocumentRetriever, RetrievedDocument, RetrieverError};
use crate::model::{ContentType, ReferenceMetadata, RetrieverType};

/// Retriever for GitHub Releases
pub struct GitHubReleaseRetriever {
    client: Client,
    token: Option<String>,
    release_pattern: Regex,
}

impl GitHubReleaseRetriever {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            token,
            // Matches: /owner/repo/releases/tag/tagId
            release_pattern: Regex::new(r"/([^/]+)/([^/]+)/releases/tag/(.+)$").unwrap(),
        }
    }

    fn parse_release_url(&self, url: &Url) -> Option<(String, String, String)> {
        let caps = self.release_pattern.captures(url.path())?;
        let owner = caps.get(1)?.as_str().to_string();
        let repo = caps.get(2)?.as_str().to_string();
        let tag = caps.get(3)?.as_str().to_string();
        Some((owner, repo, tag))
    }
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    published_at: Option<String>,
    author: Option<GitHubUser>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    login: String,
}

#[async_trait]
impl DocumentRetriever for GitHubReleaseRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        is_github_url(url) && self.release_pattern.is_match(url.path())
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::GitRelease
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let (owner, repo, tag) = self
            .parse_release_url(url)
            .ok_or_else(|| RetrieverError::ParseError("Invalid release URL".to_string()))?;

        tracing::debug!(
            url = %url,
            owner = %owner,
            repo = %repo,
            tag = %tag,
            "Fetching GitHub release"
        );

        // URL decode the tag (it may contain special characters like 'v1.0.0')
        let decoded_tag = urlencoding::decode(&tag)
            .map(|s| s.into_owned())
            .unwrap_or(tag);

        let api_url = format!(
            "https://api.github.com/repos/{}/{}/releases/tags/{}",
            owner, repo, decoded_tag
        );

        let mut request = self
            .client
            .get(&api_url)
            .header("User-Agent", "trustify-da-agent/1.0")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");

        if let Some(ref token) = self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(url.to_string()));
        }

        if response.status() == reqwest::StatusCode::FORBIDDEN
            || response.status() == reqwest::StatusCode::UNAUTHORIZED
        {
            tracing::warn!(url = %api_url, status = %response.status(), "GitHub API rate limited");
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
        let release: GitHubRelease = serde_json::from_str(&json_text)
            .map_err(|e| RetrieverError::ParseError(e.to_string()))?;

        let published = release
            .published_at
            .as_ref()
            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&Utc));

        // Build normalized markdown content
        let title = release
            .name
            .clone()
            .unwrap_or_else(|| release.tag_name.clone());

        let normalized = format!(
            "# {}\n\n**Tag:** {}\n**Author:** {}\n\n---\n\n{}",
            title,
            release.tag_name,
            release.author.as_ref().map(|a| a.login.as_str()).unwrap_or("Unknown"),
            release.body.as_deref().unwrap_or("")
        );

        let authors = release
            .author
            .map(|a| vec![a.login])
            .unwrap_or_default();

        let retrieved_from = Url::parse(&api_url)
            .unwrap_or_else(|_| url.clone());

        Ok(RetrievedDocument {
            retrieved_from,
            canonical_url: url.clone(),
            domain_url: extract_domain(url),
            retriever: self.retriever_type(),
            raw_content: json_text,
            normalized_content: Some(normalized),
            content_type: ContentType::Markdown,
            published,
            last_modified: published,
            metadata: Some(ReferenceMetadata {
                title: Some(title),
                description: None,
                commit_message: None,
                authors,
                tags: vec![release.tag_name],
                labels: vec![],
                issue_number: None,
                repository: Url::parse(&format!("https://github.com/{}/{}", owner, repo)).ok(),
                file_changes: vec![],
                code_snippets: vec![],
            }),
        })
    }
}
