//! Red Hat CSAF/VEX client for fetching vendor-specific vulnerability data

use reqwest::Client;
use serde::Deserialize;
use url::Url;

use crate::model::redhat_csaf::{CsafNote as ModelCsafNote, RedHatCsafResponse, Reference};
use crate::model::{RemediationCategory, VendorRemediation};

const CSAF_BASE_URL: &str = "https://security.access.redhat.com/data/csaf/v2/vex";

#[derive(Debug, thiserror::Error)]
pub enum CsafError {
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Red Hat CSAF/VEX client
pub struct RedHatCsafClient {
    client: Client,
    base_url: String,
}

impl RedHatCsafClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("trustify-da-agent/1.0")
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url: CSAF_BASE_URL.to_string(),
        }
    }

    /// Fetch CSAF/VEX document for a CVE
    /// URL format: https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve}.json
    pub async fn get_vulnerability(&self, cve: &str) -> Result<RedHatCsafResponse, CsafError> {
        // Extract year from CVE ID (e.g., CVE-2024-12345 -> 2024)
        let year = self.extract_year(cve)?;

        let url = format!("{}/{}/{}.json", self.base_url, year, cve.to_lowercase());
        tracing::debug!(url = %url, cve = %cve, "Fetching Red Hat CSAF data");

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::debug!(cve = %cve, "Red Hat CSAF not found");
            return Ok(RedHatCsafResponse::empty());
        }

        if !response.status().is_success() {
            tracing::warn!(
                cve = %cve,
                status = %response.status(),
                "Failed to fetch Red Hat CSAF"
            );
            return Ok(RedHatCsafResponse::empty());
        }

        let raw_json = response
            .text()
            .await
            .map_err(|e| CsafError::ParseError(e.to_string()))?;

        let csaf: CsafDocument =
            serde_json::from_str(&raw_json).map_err(|e| CsafError::ParseError(e.to_string()))?;

        Ok(self.extract_data(&csaf, cve, Some(raw_json)))
    }

    /// Extract year from CVE ID
    fn extract_year(&self, cve: &str) -> Result<String, CsafError> {
        // CVE format: CVE-YYYY-NNNNN
        let parts: Vec<&str> = cve.split('-').collect();
        if parts.len() >= 2 {
            Ok(parts[1].to_string())
        } else {
            Err(CsafError::ParseError(format!(
                "Invalid CVE format: {}",
                cve
            )))
        }
    }

    /// Extract references, remediations, and notes from CSAF document
    fn extract_data(
        &self,
        csaf: &CsafDocument,
        cve: &str,
        raw_json: Option<String>,
    ) -> RedHatCsafResponse {
        let mut remediations = Vec::new();
        let mut references = Vec::new();
        let mut notes: Vec<ModelCsafNote> = Vec::new();

        // Extract document-level references
        for reference in &csaf.document.references {
            if let Ok(url) = Url::parse(&reference.url) {
                references.push(Reference {
                    url,
                    category: reference.category.clone().unwrap_or_default(),
                });
            }
        }

        for vulnerability in &csaf.vulnerabilities {
            // Check if this vulnerability matches our CVE
            if let Some(ref vuln_cve) = vulnerability.cve
                && !vuln_cve.eq_ignore_ascii_case(cve)
            {
                continue;
            }

            // Extract vulnerability-level references
            for reference in &vulnerability.references {
                if let Ok(url) = Url::parse(&reference.url) {
                    // Avoid duplicates
                    if !references.iter().any(|r| r.url == url) {
                        references.push(Reference {
                            url,
                            category: reference.category.clone().unwrap_or_default(),
                        });
                    }
                }
            }

            // Extract notes
            for note in &vulnerability.notes {
                notes.push(ModelCsafNote {
                    title: note.title.clone(),
                    text: note.text.clone(),
                    category: note.category.clone(),
                });
            }

            // Extract remediations
            for remediation in &vulnerability.remediations {
                let (category, other_category) = self.map_category(&remediation.category);

                remediations.push(VendorRemediation {
                    vendor: "Red Hat".to_string(),
                    category,
                    other_category,
                    details: remediation.details.clone(),
                    url: remediation.url.as_ref().and_then(|u| Url::parse(u).ok()),
                    product_ids: remediation.product_ids.clone(),
                });
            }
        }

        // Deduplicate: if both access.redhat.com and security.access.redhat.com exist
        // for the same path, keep only access.redhat.com
        let references = self.deduplicate_redhat_references(references);

        tracing::debug!(
            cve = %cve,
            reference_count = references.len(),
            remediation_count = remediations.len(),
            note_count = notes.len(),
            "Extracted Red Hat CSAF data"
        );

        RedHatCsafResponse {
            references,
            remediations,
            notes,
            raw_json,
        }
    }

    /// Deduplicate Red Hat references:
    /// 1. Filter out raw CSAF JSON URLs (security.access.redhat.com/data/csaf/...)
    /// 2. If both access.redhat.com and security.access.redhat.com exist for same CVE path, keep only access.redhat.com
    fn deduplicate_redhat_references(&self, references: Vec<Reference>) -> Vec<Reference> {
        let mut result = Vec::new();
        let mut security_urls_to_skip: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // First pass: find security.access.redhat.com URLs that have an access.redhat.com equivalent
        for reference in &references {
            if reference.url.host_str() == Some("access.redhat.com") {
                // Build the equivalent security.access.redhat.com URL
                let path = reference.url.path();
                let security_equivalent = format!("https://security.access.redhat.com{}", path);
                security_urls_to_skip.insert(security_equivalent);
            }
        }

        // Second pass: filter references
        for reference in references {
            let url_str = reference.url.to_string();
            let host = reference.url.host_str().unwrap_or("");
            let path = reference.url.path();

            // Skip raw CSAF JSON URLs - the RedHatCsaf retriever will use the cached data
            if host == "security.access.redhat.com" && path.starts_with("/data/csaf/") {
                tracing::debug!(
                    url = %url_str,
                    "Skipping raw CSAF JSON URL (data available via RedHatCsaf retriever)"
                );
                continue;
            }

            // Skip duplicate security.access.redhat.com URLs
            let is_security_duplicate =
                host == "security.access.redhat.com" && security_urls_to_skip.contains(&url_str);

            if is_security_duplicate {
                tracing::debug!(
                    url = %url_str,
                    "Skipping duplicate security.access.redhat.com reference"
                );
                continue;
            }

            result.push(reference);
        }

        result
    }

    /// Map CSAF remediation category to our RemediationCategory
    fn map_category(&self, category: &str) -> (RemediationCategory, Option<String>) {
        match category.to_lowercase().as_str() {
            "vendor_fix" => (RemediationCategory::VendorFix, None),
            "workaround" => (RemediationCategory::Workaround, None),
            "no_fix_planned" => (RemediationCategory::NoFixPlanned, None),
            "none_available" => (RemediationCategory::NoneAvailable, None),
            other => (RemediationCategory::Other, Some(other.to_string())),
        }
    }
}

impl Default for RedHatCsafClient {
    fn default() -> Self {
        Self::new()
    }
}

// CSAF Document structures

#[derive(Debug, Deserialize)]
pub struct CsafDocument {
    #[serde(default)]
    pub document: CsafDocumentMeta,
    #[serde(default)]
    pub vulnerabilities: Vec<CsafVulnerability>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CsafDocumentMeta {
    #[serde(default)]
    pub references: Vec<CsafReference>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CsafVulnerability {
    pub cve: Option<String>,
    #[serde(default)]
    pub references: Vec<CsafReference>,
    #[serde(default)]
    pub remediations: Vec<CsafRemediation>,
    #[serde(default)]
    pub notes: Vec<CsafNote>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CsafNote {
    pub title: Option<String>,
    pub text: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CsafReference {
    pub url: String,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CsafRemediation {
    pub category: String,
    pub details: Option<String>,
    pub url: Option<String>,
    #[serde(default)]
    pub product_ids: Vec<String>,
}
