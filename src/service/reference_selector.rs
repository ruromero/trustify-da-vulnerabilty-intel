//! Reference URL prioritization and limit for CVE document retrieval.
//!
//! Reduces cost and latency by fetching only the most useful references when a CVE
//! has many (tens or hundreds). Combines:
//! - **Type priority** (from OSV): Advisory and Fix first, then Report/Evidence, then Web.
//! - **Domain priority**: Prefer advisory/fix-heavy domains (GitHub advisories, NVD, CVE.org, Red Hat).
//! - **Cap**: Configurable max number of references to retrieve (env `REFERENCE_MAX_DOCS`).

use std::collections::HashSet;

use url::Url;

use crate::model::osv::OsvReferenceType;

/// Default max references to retrieve per CVE when env is unset.
pub const DEFAULT_MAX_REFERENCE_DOCS: usize = 20;

/// Env var to override max reference documents per CVE.
pub const ENV_REFERENCE_MAX_DOCS: &str = "REFERENCE_MAX_DOCS";

/// Returns the configured max reference docs (from env or default).
pub fn max_reference_docs() -> usize {
    std::env::var(ENV_REFERENCE_MAX_DOCS)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_REFERENCE_DOCS)
}

/// Priority score for OSV reference type (higher = fetched first).
fn ref_type_priority(t: &OsvReferenceType) -> u32 {
    match t {
        OsvReferenceType::Advisory => 100,
        OsvReferenceType::Fix => 95,
        OsvReferenceType::Report => 80,
        OsvReferenceType::Evidence => 75,
        OsvReferenceType::Article => 70,
        OsvReferenceType::Detection => 65,
        OsvReferenceType::Web => 50,
        OsvReferenceType::Discussion => 40,
        OsvReferenceType::Package => 30,
        OsvReferenceType::Introduced => 25,
        OsvReferenceType::Unknown => 20,
    }
}

/// Priority score for URL domain (higher = preferred when type is missing or equal).
fn domain_priority(url: &Url) -> u32 {
    let host = match url.host_str() {
        Some(h) => h.to_lowercase(),
        None => return 0,
    };
    if host.contains("github.com") {
        // Advisories and security fixes
        return 90;
    }
    if host.contains("nvd.nist.gov") {
        return 85;
    }
    if host.contains("cve.org") || host == "www.cve.org" {
        return 82;
    }
    if host.contains("access.redhat.com") || host.contains("redhat.com") {
        return 80;
    }
    if host.contains("bugzilla") {
        return 75;
    }
    if host.contains("security") || host.contains("advisory") {
        return 70;
    }
    50
}

/// One reference with optional OSV type (CSAF refs have no type).
#[derive(Clone)]
pub struct ReferenceWithType {
    pub url: Url,
    pub ref_type: Option<OsvReferenceType>,
}

impl ReferenceWithType {
    fn score(&self) -> u32 {
        let type_score = self
            .ref_type
            .as_ref()
            .map(ref_type_priority)
            .unwrap_or(0);
        let domain_score = domain_priority(&self.url);
        // Type dominates; domain breaks ties or scores refs without type (e.g. CSAF)
        type_score * 1000 + domain_score
    }
}

/// Prioritize and limit reference URLs for retrieval.
///
/// - Deduplicates by URL (keeps first occurrence in combined list).
/// - Sorts by (ref_type priority, then domain priority) descending.
/// - Returns at most `max` URLs.
pub fn prioritize_and_limit(
    osv_refs: Vec<(Url, OsvReferenceType)>,
    csaf_urls: Vec<Url>,
    max: usize,
) -> Vec<Url> {
    let mut with_type: Vec<ReferenceWithType> = osv_refs
        .into_iter()
        .map(|(url, t)| ReferenceWithType {
            url,
            ref_type: Some(t),
        })
        .collect();
    for url in csaf_urls {
        with_type.push(ReferenceWithType {
            url,
            ref_type: None,
        });
    }

    // Dedupe by URL (keep first = OSV refs preferred when same URL appears in both)
    let mut seen = HashSet::new();
    with_type.retain(|r| seen.insert(r.url.as_str().to_string()));

    // Sort by score descending
    with_type.sort_by(|a, b| b.score().cmp(&a.score()));

    // Take first max and return URLs only
    with_type
        .into_iter()
        .take(max)
        .map(|r| r.url)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prioritize_advisory_first() {
        let osv = vec![
            (Url::parse("https://example.com/web").unwrap(), OsvReferenceType::Web),
            (Url::parse("https://github.com/advisory").unwrap(), OsvReferenceType::Advisory),
        ];
        let csaf: Vec<Url> = vec![];
        let out = prioritize_and_limit(osv, csaf, 10);
        assert_eq!(out.len(), 2);
        assert!(out[0].as_str().contains("github"));
        assert_eq!(out[1].as_str(), "https://example.com/web");
    }

    #[test]
    fn test_limit_caps() {
        let osv: Vec<(Url, OsvReferenceType)> = (0..30)
            .map(|i| {
                (
                    Url::parse(&format!("https://example.com/ref{}", i)).unwrap(),
                    OsvReferenceType::Web,
                )
            })
            .collect();
        let out = prioritize_and_limit(osv, vec![], 15);
        assert_eq!(out.len(), 15);
    }

    #[test]
    fn test_dedup() {
        let u = Url::parse("https://nvd.nist.gov/vuln/detail/CVE-2024-1").unwrap();
        let osv = vec![(u.clone(), OsvReferenceType::Advisory)];
        let csaf = vec![u.clone()];
        let out = prioritize_and_limit(osv, csaf, 20);
        assert_eq!(out.len(), 1);
    }
}
