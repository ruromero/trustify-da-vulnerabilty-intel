//! GitHub Commit retriever

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{DocumentRetriever, RetrievedDocument, RetrieverError, extract_domain, is_github_url};
use crate::model::{ContentType, FileChange, FileStatus, ReferenceMetadata, RetrieverType};

/// Retriever for GitHub Commits
pub struct GitHubCommitRetriever {
    client: Client,
    token: Option<String>,
    commit_pattern: Regex,
}

impl GitHubCommitRetriever {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            token,
            // Matches: /owner/repo/commit/sha
            commit_pattern: Regex::new(r"/([^/]+)/([^/]+)/commit/([a-fA-F0-9]{7,40})").unwrap(),
        }
    }

    fn parse_commit_url(&self, url: &Url) -> Option<(String, String, String)> {
        let caps = self.commit_pattern.captures(url.path())?;
        let owner = caps.get(1)?.as_str().to_string();
        let repo = caps.get(2)?.as_str().to_string();
        let sha = caps.get(3)?.as_str().to_string();
        Some((owner, repo, sha))
    }
}

#[derive(Debug, Deserialize)]
struct GitHubCommit {
    commit: CommitInfo,
    author: Option<GitHubUser>,
    files: Option<Vec<CommitFile>>,
}

#[derive(Debug, Deserialize)]
struct CommitInfo {
    message: String,
    author: Option<CommitAuthor>,
}

#[derive(Debug, Deserialize)]
struct CommitAuthor {
    name: String,
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    login: String,
}

#[derive(Debug, Deserialize)]
struct CommitFile {
    filename: String,
    status: String,
    patch: Option<String>,
}

#[async_trait]
impl DocumentRetriever for GitHubCommitRetriever {
    fn can_handle(&self, url: &Url) -> bool {
        is_github_url(url) && self.commit_pattern.is_match(url.path())
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::GitCommit
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        let (owner, repo, sha) = self
            .parse_commit_url(url)
            .ok_or_else(|| RetrieverError::ParseError("Invalid commit URL".to_string()))?;

        tracing::debug!(
            url = %url,
            owner = %owner,
            repo = %repo,
            sha = %sha,
            "Fetching GitHub commit"
        );

        if let Some(ref token) = self.token {
            self.fetch_via_api(url, token, &owner, &repo, &sha).await
        } else {
            Err(RetrieverError::ParseError(
                "GitHub token required for commit retrieval".to_string(),
            ))
        }
    }
}

impl GitHubCommitRetriever {
    async fn fetch_via_api(
        &self,
        original_url: &Url,
        token: &str,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<RetrievedDocument, RetrieverError> {
        let api_url = format!(
            "https://api.github.com/repos/{}/{}/commits/{}",
            owner, repo, sha
        );

        let response = self
            .client
            .get(&api_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("User-Agent", "trustify-da-agent/1.0")
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
        let commit: GitHubCommit = serde_json::from_str(&json_text)
            .map_err(|e| RetrieverError::ParseError(e.to_string()))?;

        let commit_date = commit
            .commit
            .author
            .as_ref()
            .and_then(|a| a.date.as_ref())
            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&Utc));

        // Build file changes from commit files
        let file_changes: Vec<FileChange> = commit
            .files
            .as_ref()
            .map(|files| {
                files
                    .iter()
                    .map(|f| FileChange {
                        filename: f.filename.clone(),
                        status: match f.status.as_str() {
                            "added" => FileStatus::Added,
                            "removed" => FileStatus::Deleted,
                            "renamed" => FileStatus::Renamed,
                            _ => FileStatus::Modified,
                        },
                        patch: f.patch.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let authors: Vec<String> = vec![
            commit.commit.author.map(|a| a.name),
            commit.author.map(|u| u.login),
        ]
        .into_iter()
        .flatten()
        .collect();

        // Extract first line of commit message as title
        let title = commit.commit.message.lines().next().map(|s| s.to_string());

        let retrieved_from = Url::parse(&api_url).unwrap_or_else(|_| original_url.clone());

        Ok(RetrievedDocument {
            retrieved_from,
            canonical_url: original_url.clone(),
            domain_url: extract_domain(original_url),
            retriever: self.retriever_type(),
            raw_content: json_text,
            normalized_content: None,
            content_type: ContentType::GitCommit,
            published: commit_date,
            last_modified: commit_date,
            metadata: Some(ReferenceMetadata {
                title,
                description: None,
                commit_message: Some(commit.commit.message),
                authors,
                tags: vec![],
                labels: vec![],
                issue_number: None,
                repository: Url::parse(&format!("https://github.com/{}/{}", owner, repo)).ok(),
                file_changes,
                code_snippets: vec![],
                comments: vec![],
            }),
        })
    }
}
