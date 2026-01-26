//! Claim filtering logic

use crate::model::{ReferenceDocument, RetrieverType, SourceClaim, SourceClaimReason};

/// Security-related terms that must appear in excerpts for Identification claims
const SECURITY_TERMS: &[&str] = &[
    "vulnerab", // vulnerability, vulnerable
    "cve",
    "cwe",
    "security",
    "exploit",
    "attack",
    "inject", // injection
    "overflow",
    "bypass",
    "leak",   // data leak, memory leak
    "denial", // denial of service
    "dos",
    "rce", // remote code execution
    "xss",
    "csrf",
    "sqli",
    "ssrf",
    "lfi",
    "rfi",
    "unauthorized",
    "privilege",
    "escalat", // escalation
    "malicious",
    "arbitrary",
    "remote code",
    "sensitive data",
    "authentication",
    "authorization",
    "confidential",
    "integrity",
    "availability",
];

/// Patterns that indicate non-security noise (version bumps, backports, etc.)
const NOISE_PATTERNS: &[&str] = &[
    "backport",
    "version bump",
    "version bumps",
    "align",
    "alignment",
    "also include",
    "mutiny",
    "netty",
    "vert.x",
    "dependency update",
    "dependency updates",
];

/// Check if claim extraction should be skipped for this document type
/// Git commits are evidence sources, not claim sources - they should not
/// generate standalone claims, only support existing claims from authoritative sources
pub fn should_skip_extraction(doc: &ReferenceDocument) -> bool {
    matches!(doc.retriever, RetrieverType::GitCommit)
}

/// Filter out weak/noise claims that don't contain security-related content
pub fn filter_weak_claims(claims: Vec<SourceClaim>, doc: &ReferenceDocument) -> Vec<SourceClaim> {
    claims
        .into_iter()
        .filter(|claim| is_valid_security_claim(claim, doc))
        .collect()
}

/// Check if a claim is a valid security claim based on excerpt content
fn is_valid_security_claim(claim: &SourceClaim, _doc: &ReferenceDocument) -> bool {
    // Get excerpt for validation
    let excerpt = claim
        .evidence
        .first()
        .and_then(|e| e.excerpt.as_ref())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // Skip claims with no excerpt (invalid)
    if excerpt.is_empty() {
        tracing::debug!(
            reason = ?claim.reason,
            "Filtering out claim with empty excerpt"
        );
        return false;
    }

    // For Identification claims, check for security-related terms
    // But be lenient - only filter if it's clearly not security-related
    if matches!(claim.reason, SourceClaimReason::Identification) {
        let has_security_terms = SECURITY_TERMS.iter().any(|term| excerpt.contains(term));

        // Also check for common non-security patterns that indicate noise
        let is_noise = NOISE_PATTERNS
            .iter()
            .any(|pattern| excerpt.contains(pattern));

        if !has_security_terms && is_noise {
            tracing::debug!(
                reason = ?claim.reason,
                excerpt_preview = excerpt.chars().take(100).collect::<String>(),
                "Filtering out noise Identification claim"
            );
            return false;
        }

        // If it has security terms, keep it even if it also has noise patterns
        if !has_security_terms {
            tracing::debug!(
                reason = ?claim.reason,
                excerpt_preview = excerpt.chars().take(100).collect::<String>(),
                "Keeping Identification claim (may be valid but no explicit security terms)"
            );
        }
    }

    true
}
