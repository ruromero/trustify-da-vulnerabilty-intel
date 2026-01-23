//! Generic web page retriever with enhanced metadata extraction

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

use super::{extract_domain, html_to_markdown, DocumentRetriever, RetrievedDocument, RetrieverError};
use crate::model::{CodeSnippet, ContentType, ReferenceMetadata, RetrieverType};

/// Generic retriever for web pages with enhanced metadata extraction
pub struct GenericWebRetriever {
    client: Client,
}

impl GenericWebRetriever {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("trustify-da-agent/1.0")
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    /// Extract title from <title> or <meta property="og:title">
    fn extract_title(&self, document: &Html) -> Option<String> {
        // Try <title> first
        if let Ok(selector) = Selector::parse("title") {
            if let Some(el) = document.select(&selector).next() {
                let title = el.text().collect::<String>().trim().to_string();
                if !title.is_empty() {
                    return Some(title);
                }
            }
        }

        // Fallback to og:title
        self.extract_meta_property(document, "og:title")
    }

    /// Extract description from <meta name="description"> or <meta property="og:description">
    fn extract_description(&self, document: &Html) -> Option<String> {
        self.extract_meta_name(document, "description")
            .or_else(|| self.extract_meta_property(document, "og:description"))
    }

    /// Extract authors from various meta tags
    fn extract_authors(&self, document: &Html) -> Vec<String> {
        let mut authors = Vec::new();

        // <meta name="author">
        if let Some(author) = self.extract_meta_name(document, "author") {
            authors.push(author);
        }

        // <meta property="article:author">
        if let Some(author) = self.extract_meta_property(document, "article:author") {
            if !authors.contains(&author) {
                authors.push(author);
            }
        }

        // <meta name="dc.creator"> (Dublin Core)
        if let Some(author) = self.extract_meta_name(document, "dc.creator") {
            if !authors.contains(&author) {
                authors.push(author);
            }
        }

        authors
    }

    /// Extract keywords/tags from <meta name="keywords">
    fn extract_tags(&self, document: &Html) -> Vec<String> {
        self.extract_meta_name(document, "keywords")
            .map(|keywords| {
                keywords
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Extract published date from <meta property="article:published_time">
    fn extract_published(&self, document: &Html) -> Option<DateTime<Utc>> {
        self.extract_meta_property(document, "article:published_time")
            .or_else(|| self.extract_meta_name(document, "date"))
            .or_else(|| self.extract_meta_name(document, "dc.date"))
            .and_then(|date_str| self.parse_date(&date_str))
    }

    /// Extract last modified date from <meta property="article:modified_time">
    fn extract_modified(&self, document: &Html) -> Option<DateTime<Utc>> {
        self.extract_meta_property(document, "article:modified_time")
            .or_else(|| self.extract_meta_name(document, "last-modified"))
            .and_then(|date_str| self.parse_date(&date_str))
    }

    /// Extract code snippets from <pre><code> blocks
    fn extract_code_snippets(&self, document: &Html) -> Vec<CodeSnippet> {
        let mut snippets = Vec::new();

        // Try <pre><code> blocks first
        if let Ok(selector) = Selector::parse("pre code") {
            for element in document.select(&selector) {
                let content = element.text().collect::<String>();
                if content.trim().is_empty() {
                    continue;
                }

                // Try to extract language from class attribute
                let language = element
                    .value()
                    .attr("class")
                    .and_then(|class| {
                        class.split_whitespace().find_map(|c| {
                            if c.starts_with("language-") {
                                Some(c.strip_prefix("language-").unwrap().to_string())
                            } else if c.starts_with("lang-") {
                                Some(c.strip_prefix("lang-").unwrap().to_string())
                            } else {
                                None
                            }
                        })
                    });

                snippets.push(CodeSnippet {
                    language,
                    content: content.trim().to_string(),
                });
            }
        }

        // Also try standalone <pre> blocks without <code>
        if let Ok(selector) = Selector::parse("pre:not(:has(code))") {
            for element in document.select(&selector) {
                let content = element.text().collect::<String>();
                if content.trim().is_empty() {
                    continue;
                }

                snippets.push(CodeSnippet {
                    language: None,
                    content: content.trim().to_string(),
                });
            }
        }

        snippets
    }

    /// Helper: Extract content from <meta name="...">
    fn extract_meta_name(&self, document: &Html, name: &str) -> Option<String> {
        let selector_str = format!("meta[name=\"{}\"]", name);
        if let Ok(selector) = Selector::parse(&selector_str) {
            if let Some(el) = document.select(&selector).next() {
                return el.value().attr("content").map(|s| s.trim().to_string());
            }
        }

        // Also try case-insensitive match
        let selector_str_lower = format!("meta[name=\"{}\"]", name.to_lowercase());
        if let Ok(selector) = Selector::parse(&selector_str_lower) {
            if let Some(el) = document.select(&selector).next() {
                return el.value().attr("content").map(|s| s.trim().to_string());
            }
        }

        None
    }

    /// Helper: Extract content from <meta property="...">
    fn extract_meta_property(&self, document: &Html, property: &str) -> Option<String> {
        let selector_str = format!("meta[property=\"{}\"]", property);
        if let Ok(selector) = Selector::parse(&selector_str) {
            if let Some(el) = document.select(&selector).next() {
                return el.value().attr("content").map(|s| s.trim().to_string());
            }
        }
        None
    }

    /// Helper: Parse various date formats
    fn parse_date(&self, date_str: &str) -> Option<DateTime<Utc>> {
        // Try ISO 8601 / RFC 3339
        if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
            return Some(dt.with_timezone(&Utc));
        }

        // Try RFC 2822
        if let Ok(dt) = DateTime::parse_from_rfc2822(date_str) {
            return Some(dt.with_timezone(&Utc));
        }

        // Try common formats
        let formats = [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%B %d, %Y",
            "%d %B %Y",
        ];

        for fmt in formats {
            if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(date_str, fmt) {
                return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
            }
            if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(date_str, fmt) {
                return Some(DateTime::from_naive_utc_and_offset(
                    naive_date.and_hms_opt(0, 0, 0).unwrap(),
                    Utc,
                ));
            }
        }

        None
    }
}

#[async_trait]
impl DocumentRetriever for GenericWebRetriever {
    fn can_handle(&self, _url: &Url) -> bool {
        // Generic retriever handles any URL as fallback
        true
    }

    fn retriever_type(&self) -> RetrieverType {
        RetrieverType::Generic
    }

    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError> {
        tracing::debug!(url = %url, "Fetching generic web page");

        let response = self.client.get(url.as_str()).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RetrieverError::NotFound(url.to_string()));
        }

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(url = %url, "Web request rate limited");
            return Err(RetrieverError::RateLimited);
        }

        if !response.status().is_success() {
            return Err(RetrieverError::ParseError(format!(
                "HTTP {}: {}",
                response.status(),
                url
            )));
        }

        let content_type_header = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "text/html".to_string());

        let raw_content = response.text().await?;

        // Determine content type and extract metadata
        let (content_type, normalized_content, metadata) =
            if content_type_header.contains("application/json") {
                (
                    ContentType::Json,
                    Some(raw_content.clone()),
                    ReferenceMetadata {
                        title: None,
                        description: None,
                        commit_message: None,
                        authors: vec![],
                        tags: vec![],
                        labels: vec![],
                        issue_number: None,
                        repository: None,
                        file_changes: vec![],
                        code_snippets: vec![],
                    },
                )
            } else if content_type_header.contains("text/markdown") {
                (
                    ContentType::Markdown,
                    Some(raw_content.clone()),
                    ReferenceMetadata {
                        title: None,
                        description: None,
                        commit_message: None,
                        authors: vec![],
                        tags: vec![],
                        labels: vec![],
                        issue_number: None,
                        repository: None,
                        file_changes: vec![],
                        code_snippets: vec![],
                    },
                )
            } else {
                // Parse HTML and extract metadata
                let document = Html::parse_document(&raw_content);

                let title = self.extract_title(&document);
                let description = self.extract_description(&document);
                let authors = self.extract_authors(&document);
                let tags = self.extract_tags(&document);
                let code_snippets = self.extract_code_snippets(&document);

                // Convert HTML to markdown for normalized content
                let markdown = html_to_markdown(&raw_content);

                (
                    ContentType::Html,
                    Some(markdown),
                    ReferenceMetadata {
                        title,
                        description,
                        commit_message: None,
                        authors,
                        tags,
                        labels: vec![],
                        issue_number: None,
                        repository: None,
                        file_changes: vec![],
                        code_snippets,
                    },
                )
            };

        // Extract dates for HTML pages
        let (published, last_modified) = if content_type_header.contains("text/html")
            || !content_type_header.contains("application/json")
        {
            let document = Html::parse_document(&raw_content);
            (
                self.extract_published(&document),
                self.extract_modified(&document),
            )
        } else {
            (None, None)
        };

        Ok(RetrievedDocument {
            retrieved_from: url.clone(),
            canonical_url: url.clone(),
            domain_url: extract_domain(url),
            retriever: self.retriever_type(),
            raw_content,
            normalized_content,
            content_type,
            published,
            last_modified,
            metadata: Some(metadata),
        })
    }
}

impl Default for GenericWebRetriever {
    fn default() -> Self {
        Self::new()
    }
}
