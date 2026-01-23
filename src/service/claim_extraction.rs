//! Claim extraction service using LLM
//!
//! Extracts structured SourceClaims from reference documents using rig-core.

use rig::providers::openai;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use crate::model::{
    ClaimCertainty, ClaimEvidence, ReferenceDocument, ReferenceId, SourceClaim, SourceClaimReason,
    SourceType, TrustLevel,
};
use crate::service::cache::VulnerabilityCache;
use crate::service::document::DocumentService;

/// Environment variable for OpenAI API key
const ENV_OPENAI_API_KEY: &str = "OPENAI_API_KEY";

/// Default model to use for extraction
const DEFAULT_MODEL: &str = openai::GPT_4O_MINI;

/// Security-related terms that must appear in excerpts for Identification claims
const SECURITY_TERMS: &[&str] = &[
    "vulnerab",      // vulnerability, vulnerable
    "cve",
    "cwe",
    "security",
    "exploit",
    "attack",
    "inject",        // injection
    "overflow",
    "bypass",
    "leak",          // data leak, memory leak
    "denial",        // denial of service
    "dos",
    "rce",           // remote code execution
    "xss",
    "csrf",
    "sqli",
    "ssrf",
    "lfi",
    "rfi",
    "unauthorized",
    "privilege",
    "escalat",       // escalation
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

/// LLM-extractable claim structure
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedClaims {
    pub claims: Vec<ExtractedClaim>,
}

/// A single extracted claim
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedClaim {
    #[serde(rename = "reason")]
    pub reason: ExtractedReason,
    pub certainty: ExtractedCertainty,
    pub excerpt: Option<String>,
    pub rationale: String,
}

/// Claim reason categories
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedReason {
    Identification,
    Exploitability,
    Impact,
    Mitigation,
}

/// Certainty levels
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedCertainty {
    Conditional,
    Strong,
    IdentificationOnly,
    Indicative,
}

/// Error type for claim extraction
#[derive(Debug, thiserror::Error)]
pub enum ClaimExtractionError {
    #[error("LLM extraction failed: {0}")]
    ExtractionFailed(String),

    #[error("OpenAI client not configured (missing {ENV_OPENAI_API_KEY})")]
    NotConfigured,
}

/// Service for extracting claims from reference documents
pub struct ClaimExtractionService {
    client: Option<openai::Client>,
    document_service: Arc<DocumentService>,
    cache: Option<VulnerabilityCache>,
    model: String,
}

impl ClaimExtractionService {
    /// Create a new claim extraction service
    pub fn new(document_service: Arc<DocumentService>, cache: Option<VulnerabilityCache>) -> Self {
        let client = std::env::var(ENV_OPENAI_API_KEY)
            .ok()
            .and_then(|key| {
                match openai::Client::new(&key) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to create OpenAI client");
                        None
                    }
                }
            });

        if client.is_none() {
            tracing::warn!(
                "OpenAI API key not found ({ENV_OPENAI_API_KEY}), claim extraction disabled"
            );
        }

        Self {
            client,
            document_service,
            cache,
            model: DEFAULT_MODEL.to_string(),
        }
    }

    /// Check if the service is available
    pub fn is_available(&self) -> bool {
        self.client.is_some()
    }

    /// Extract claims from reference documents by their IDs
    /// Only fetches documents from DB on cache miss (when LLM extraction needed)
    pub async fn extract_claims_from_ids(
        &self,
        cve_id: &str,
        document_ids: &[String],
    ) -> Vec<SourceClaim> {
        let client = match &self.client {
            Some(c) => c,
            None => {
                tracing::debug!("Claim extraction skipped: OpenAI client not configured");
                return vec![];
            }
        };

        let mut all_claims = Vec::new();
        let mut cache_hits = 0;
        let mut cache_misses = 0;
        let mut db_fetches = 0;

        for doc_id in document_ids {
            // Check cache first - no DB fetch needed if hit
            if let Some(cached_claims) = self.get_cached_claims(doc_id).await {
                tracing::debug!(
                    doc_id = %doc_id,
                    cached_claim_count = cached_claims.len(),
                    "Cache hit for claims (no DB fetch)"
                );
                if cached_claims.is_empty() {
                    tracing::debug!(
                        doc_id = %doc_id,
                        "Cached claims are empty (likely Git commit or previous extraction)"
                    );
                }
                all_claims.extend(cached_claims);
                cache_hits += 1;
                continue;
            }

            // Cache miss - fetch document from DB
            let doc = match self.document_service.get_by_id(doc_id).await {
                Ok(doc) => {
                    db_fetches += 1;
                    doc
                }
                Err(e) => {
                    tracing::debug!(
                        doc_id = %doc_id,
                        error = %e,
                        "Failed to fetch document for claim extraction"
                    );
                    continue;
                }
            };

            // Skip claim extraction for Git commits - they are evidence, not claim sources
            // Commits can only support existing claims or provide fix confirmation
            if self.should_skip_extraction(&doc) {
                tracing::debug!(
                    doc_id = %doc_id,
                    retriever = ?doc.retriever,
                    "Skipping claim extraction (evidence-only source)"
                );
                // Cache empty claims so we don't re-process
                self.cache_claims(doc_id, &[]).await;
                continue;
            }

            // Extract claims using LLM
            match self.extract_claims_from_document(client, cve_id, &doc).await {
                Ok(claims) => {
                    let raw_claim_count = claims.len();
                    tracing::debug!(
                        doc_id = %doc_id,
                        raw_claim_count = raw_claim_count,
                        "Raw claims extracted from document"
                    );
                    // Post-filter: remove weak/noise claims
                    let filtered_claims = self.filter_weak_claims(claims, &doc);
                    tracing::debug!(
                        doc_id = %doc_id,
                        raw_claim_count = raw_claim_count,
                        filtered_claim_count = filtered_claims.len(),
                        "Filtered claims from document"
                    );
                    // Cache the filtered results
                    self.cache_claims(doc_id, &filtered_claims).await;
                    all_claims.extend(filtered_claims);
                    cache_misses += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        doc_id = %doc_id,
                        error = %e,
                        "Failed to extract claims from document"
                    );
                }
            }
        }

        // Synthesize and deduplicate claims from multiple sources
        let claims_before_synthesis = all_claims.len();
        let synthesized_claims = self.synthesize_claims(all_claims);

        tracing::info!(
            cve = %cve_id,
            total_claims_before_synthesis = claims_before_synthesis,
            total_claims_after_synthesis = synthesized_claims.len(),
            documents_total = document_ids.len(),
            cache_hits = cache_hits,
            cache_misses = cache_misses,
            db_fetches = db_fetches,
            "Claim extraction complete"
        );

        synthesized_claims
    }

    /// Get cached claims for a document
    async fn get_cached_claims(&self, doc_id: &str) -> Option<Vec<SourceClaim>> {
        let cache = self.cache.as_ref()?;
        match cache.get_claims::<Vec<SourceClaim>>(doc_id).await {
            Ok(claims) => Some(claims),
            Err(_) => None,
        }
    }

    /// Cache claims for a document
    async fn cache_claims(&self, doc_id: &str, claims: &[SourceClaim]) {
        if let Some(ref cache) = self.cache {
            if let Err(e) = cache.set_claims(doc_id, &claims.to_vec()).await {
                tracing::debug!(doc_id = %doc_id, error = %e, "Failed to cache claims");
            }
        }
    }

    /// Check if claim extraction should be skipped for this document type
    /// Git commits are evidence sources, not claim sources - they should not
    /// generate standalone claims, only support existing claims from authoritative sources
    fn should_skip_extraction(&self, doc: &ReferenceDocument) -> bool {
        use crate::model::RetrieverType;
        matches!(doc.retriever, RetrieverType::GitCommit)
    }

    /// Filter out weak/noise claims that don't contain security-related content
    fn filter_weak_claims(&self, claims: Vec<SourceClaim>, doc: &ReferenceDocument) -> Vec<SourceClaim> {
        claims
            .into_iter()
            .filter(|claim| self.is_valid_security_claim(claim, doc))
            .collect()
    }

    /// Check if a claim is a valid security claim based on excerpt content
    fn is_valid_security_claim(&self, claim: &SourceClaim, _doc: &ReferenceDocument) -> bool {
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
            let has_security_terms = SECURITY_TERMS
                .iter()
                .any(|term| excerpt.contains(term));

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

    /// Synthesize and deduplicate claims from multiple sources
    /// Groups claims by (reason, semantic_meaning) and keeps the best one, merging evidence
    fn synthesize_claims(&self, claims: Vec<SourceClaim>) -> Vec<SourceClaim> {
        if claims.is_empty() {
            return claims;
        }

        // Group claims by reason first
        let mut by_reason: std::collections::HashMap<SourceClaimReason, Vec<SourceClaim>> =
            std::collections::HashMap::new();

        for claim in claims {
            by_reason.entry(claim.reason.clone()).or_default().push(claim);
        }

        let mut synthesized = Vec::new();

        // Process each reason group
        for (_reason, reason_claims) in by_reason {
            // Group semantically similar claims within this reason
            let mut groups: Vec<Vec<SourceClaim>> = Vec::new();

            for claim in reason_claims {
                // Find a group with similar semantic meaning
                let group_index = groups.iter().position(|group| {
                    self.are_semantically_similar(&claim, &group[0])
                });

                match group_index {
                    Some(idx) => {
                        groups[idx].push(claim);
                    }
                    None => {
                        groups.push(vec![claim]);
                    }
                }
            }

            // For each group of similar claims, merge them into one
            for group in groups {
                if group.len() == 1 {
                    synthesized.push(group.into_iter().next().unwrap());
                } else {
                    synthesized.push(self.merge_claim_group(group));
                }
            }
        }

        synthesized
    }

    /// Check if two claims are semantically similar (same meaning, different sources)
    fn are_semantically_similar(&self, claim1: &SourceClaim, claim2: &SourceClaim) -> bool {
        // Must have same reason
        if claim1.reason != claim2.reason {
            return false;
        }

        // Extract normalized excerpts for comparison
        let excerpt1 = self.normalize_excerpt(claim1);
        let excerpt2 = self.normalize_excerpt(claim2);

        // If excerpts are very similar (high overlap), they're semantically similar
        self.excerpts_similar(&excerpt1, &excerpt2)
    }

    /// Normalize excerpt text for comparison
    fn normalize_excerpt(&self, claim: &SourceClaim) -> String {
        claim
            .evidence
            .first()
            .and_then(|e| e.excerpt.as_ref())
            .map(|s| {
                s.to_lowercase()
                    .chars()
                    .filter(|c| c.is_alphanumeric() || c.is_whitespace())
                    .collect::<String>()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default()
    }

    /// Check if two normalized excerpts are similar (using word overlap)
    fn excerpts_similar(&self, excerpt1: &str, excerpt2: &str) -> bool {
        if excerpt1.is_empty() || excerpt2.is_empty() {
            return false;
        }

        let words1: std::collections::HashSet<&str> =
            excerpt1.split_whitespace().collect();
        let words2: std::collections::HashSet<&str> =
            excerpt2.split_whitespace().collect();

        // Calculate Jaccard similarity (intersection over union)
        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();

        if union == 0 {
            return false;
        }

        let similarity = intersection as f64 / union as f64;

        // Consider similar if > 0.3 overlap (30% of words in common)
        // This catches same claim from different sources with slight wording differences
        similarity > 0.3
    }

    /// Merge a group of semantically similar claims into one canonical claim
    fn merge_claim_group(&self, mut group: Vec<SourceClaim>) -> SourceClaim {
        // Sort by trust level (High > Medium > Low), then by certainty strength
        group.sort_by(|a, b| {
            let trust_a = self.get_highest_trust(&a.evidence);
            let trust_b = self.get_highest_trust(&b.evidence);

            match trust_a.cmp(&trust_b) {
                std::cmp::Ordering::Equal => {
                    // Same trust - prefer stronger certainty
                    self.certainty_strength(&a.certainty).cmp(&self.certainty_strength(&b.certainty))
                }
                other => other.reverse(), // Reverse because High > Medium > Low
            }
        });

        // Take the best claim as the base
        let mut merged = group.remove(0);

        // Merge evidence from all other claims (avoid duplicates)
        let mut seen_evidence_ids: std::collections::HashSet<String> = merged
            .evidence
            .iter()
            .map(|e| format!("{}:{}", e.reference_id.source, e.reference_id.id))
            .collect();

        for claim in group {
            for evidence in claim.evidence {
                let evidence_key = format!("{}:{}", evidence.reference_id.source, evidence.reference_id.id);
                if !seen_evidence_ids.contains(&evidence_key) {
                    merged.evidence.push(evidence);
                    seen_evidence_ids.insert(evidence_key);
                }
            }

            // Merge rationale if the merged one is empty or shorter
            if let Some(ref other_rationale) = claim.rationale {
                if merged.rationale.as_ref().map(|r| r.len()).unwrap_or(0) < other_rationale.len() {
                    merged.rationale = Some(other_rationale.clone());
                }
            }
        }

        merged
    }

    /// Get the highest trust level from evidence
    fn get_highest_trust(&self, evidence: &[ClaimEvidence]) -> u8 {
        evidence
            .iter()
            .map(|e| match e.trust_level {
                TrustLevel::High => 3,
                TrustLevel::Medium => 2,
                TrustLevel::Low => 1,
            })
            .max()
            .unwrap_or(0)
    }

    /// Get certainty strength for comparison (higher = stronger)
    fn certainty_strength(&self, certainty: &ClaimCertainty) -> u8 {
        match certainty {
            ClaimCertainty::Strong => 4,
            ClaimCertainty::Conditional => 3,
            ClaimCertainty::IdentificationOnly => 2,
            ClaimCertainty::Indicative => 1,
        }
    }

    /// Extract claims from a single reference document
    async fn extract_claims_from_document(
        &self,
        client: &openai::Client,
        cve_id: &str,
        doc: &ReferenceDocument,
    ) -> Result<Vec<SourceClaim>, ClaimExtractionError> {
        // Use normalized content if available, otherwise raw content
        let content = doc
            .normalized_content
            .as_ref()
            .unwrap_or(&doc.raw_content);

        // Skip empty or very short content
        if content.len() < 50 {
            return Ok(vec![]);
        }

        // Truncate very long content to avoid token limits
        let truncated_content = if content.len() > 15000 {
            &content[..15000]
        } else {
            content.as_str()
        };

        // Build the extraction prompt
        let prompt = self.build_extraction_prompt(cve_id, &doc.canonical_url.to_string(), truncated_content);

        // Create extractor and extract claims
        let extractor = client
            .extractor::<ExtractedClaims>(&self.model)
            .preamble(EXTRACTION_SYSTEM_PROMPT)
            .build();

        let extracted = extractor
            .extract(&prompt)
            .await
            .map_err(|e| ClaimExtractionError::ExtractionFailed(e.to_string()))?;

        // Convert extracted claims to SourceClaims
        let source_claims = extracted
            .claims
            .into_iter()
            .map(|ec| self.convert_to_source_claim(ec, doc))
            .collect();

        Ok(source_claims)
    }

    /// Build the extraction prompt for a document
    fn build_extraction_prompt(&self, cve_id: &str, url: &str, content: &str) -> String {
        format!(
            r#"Analyze this vulnerability reference document for {cve_id}.

Source URL: {url}

Document Content:
---
{content}
---

Extract all relevant security claims from this document."#
        )
    }

    /// Convert an extracted claim to a SourceClaim
    fn convert_to_source_claim(&self, extracted: ExtractedClaim, doc: &ReferenceDocument) -> SourceClaim {
        let reason = match extracted.reason {
            ExtractedReason::Identification => SourceClaimReason::Identification,
            ExtractedReason::Exploitability => SourceClaimReason::Exploitability,
            ExtractedReason::Impact => SourceClaimReason::Impact,
            ExtractedReason::Mitigation => SourceClaimReason::Mitigation,
        };

        let certainty = match extracted.certainty {
            ExtractedCertainty::Conditional => ClaimCertainty::Conditional,
            ExtractedCertainty::Strong => ClaimCertainty::Strong,
            ExtractedCertainty::IdentificationOnly => ClaimCertainty::IdentificationOnly,
            ExtractedCertainty::Indicative => ClaimCertainty::Indicative,
        };

        // Determine trust level based on retriever type
        let trust_level = self.determine_trust_level(doc);

        // Determine source roles based on retriever type
        let source_roles = self.determine_source_roles(doc);

        SourceClaim {
            reason,
            certainty,
            evidence: vec![ClaimEvidence {
                reference_id: ReferenceId {
                    source: doc.canonical_url.to_string(),
                    id: doc.id.clone(),
                },
                trust_level,
                excerpt: extracted.excerpt,
                source_roles,
            }],
            rationale: Some(extracted.rationale),
        }
    }

    /// Determine trust level based on document retriever type
    fn determine_trust_level(&self, doc: &ReferenceDocument) -> TrustLevel {
        use crate::model::RetrieverType;
        match doc.retriever {
            RetrieverType::Nvd | RetrieverType::CveOrg | RetrieverType::RedHatCsaf => TrustLevel::High,
            RetrieverType::GitAdvisory | RetrieverType::GitCveV5 | RetrieverType::Bugzilla => TrustLevel::Medium,
            RetrieverType::GitCommit | RetrieverType::GitIssue | RetrieverType::GitRelease => TrustLevel::Medium,
            RetrieverType::Generic => TrustLevel::Low,
        }
    }

    /// Determine source roles based on document retriever type
    fn determine_source_roles(&self, doc: &ReferenceDocument) -> Vec<SourceType> {
        use crate::model::RetrieverType;
        match doc.retriever {
            RetrieverType::Nvd | RetrieverType::CveOrg => vec![SourceType::Advisory],
            RetrieverType::RedHatCsaf => vec![SourceType::Advisory],
            RetrieverType::GitAdvisory => vec![SourceType::Advisory],
            RetrieverType::GitCveV5 => vec![SourceType::Advisory],
            RetrieverType::GitCommit => vec![SourceType::Fix],
            RetrieverType::GitIssue => vec![SourceType::Discussion],
            RetrieverType::GitRelease => vec![SourceType::Fix],
            RetrieverType::Bugzilla => vec![SourceType::Discussion],
            RetrieverType::Generic => vec![SourceType::Web],
        }
    }
}


/// System prompt for claim extraction
const EXTRACTION_SYSTEM_PROMPT: &str = r#"You are a security vulnerability analyst. Your task is to extract structured, evidence-based security claims from vulnerability reference documents.

## Critical Rules

1. **Only extract claims that explicitly discuss security vulnerabilities.**
   - The excerpt MUST contain security-related terminology (vulnerability, exploit, attack, injection, overflow, CVE, CWE, etc.)
   - General development notes, version bumps, refactoring, or code quality improvements are NOT security claims.

2. **A claim is a security-relevant assertion, not a contextual fact.**
   - "Fixes buffer overflow in parser" → Valid Mitigation claim
   - "Backport of #48486" → NOT a claim (contextual fact)
   - "Version bumps for Vert.x 4.5.16" → NOT a claim (contextual fact)
   - "Also include Mutiny and Netty alignments" → NOT a claim (contextual fact)

3. **The excerpt must directly support the claim category.**
   - Identification: Must describe what the vulnerability IS (type, affected component, CVE/CWE)
   - Exploitability: Must describe HOW to exploit (attack vector, conditions, PoC)
   - Impact: Must describe CONSEQUENCES (data loss, privilege escalation, DoS)
   - Mitigation: Must describe HOW TO FIX (patch, upgrade, workaround)

## Claim Categories

- **Identification**: What the vulnerability is (CVE ID, vulnerability type, CWE, affected component)
- **Exploitability**: How it can be exploited (attack vectors, conditions, PoC availability)
- **Impact**: Consequences of exploitation (confidentiality/integrity/availability effects)
- **Mitigation**: How to fix or reduce risk (patches, upgrades, workarounds)

## Certainty Levels

- "strong": Explicitly stated by an authoritative source
- "conditional": True only under specific stated conditions
- "indicative": Suggested but not definitively confirmed
- "identification_only": Basic identification without detailed analysis

## Output Requirements

- Extract a **verbatim excerpt** (1-3 sentences) that directly supports the claim
- Provide a brief rationale explaining the security relevance
- Prefer **fewer, high-confidence claims** over many weak ones
- Return an **empty claims array** if no valid security claims exist

## What to Skip

- Version bump notifications without security context
- Backport references without vulnerability details
- Code refactoring or cleanup notes
- Dependency alignment without security implications
- Usage recommendations unless they mitigate a specific vulnerability
"#;
