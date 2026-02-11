//! Claim extraction service using LLM
//!
//! Extracts structured SourceClaims from reference documents using rig-core.

use rig::providers::openai;
use std::sync::Arc;

use crate::model::claims::ExtractedClaims;
use crate::model::{
    ClaimCertainty, ClaimEvidence, ReferenceDocument, ReferenceId, SourceClaim, SourceClaimReason,
    SourceType, TrustLevel,
};
use crate::service::cache::VulnerabilityCache;
use crate::service::claims::filters::{filter_weak_claims, should_skip_extraction};
use crate::service::claims::prompts::{EXTRACTION_SYSTEM_PROMPT, build_extraction_prompt};
use crate::service::claims::synthesis::synthesize_claims;
use crate::service::document::DocumentService;
use crate::service::llm::LlmClient;

pub mod error;
pub mod filters;
pub mod prompts;
pub mod synthesis;
pub mod validation;

pub use error::ClaimExtractionError;

/// Environment variable for claim extraction model (defaults to gpt-4o if not set)
const ENV_CLAIM_EXTRACTION_MODEL: &str = "CLAIM_EXTRACTION_MODEL";

/// Default model for claim extraction (gpt-4o for better verbatim excerpts and long-context grounding)
const DEFAULT_MODEL: &str = openai::GPT_4O;

/// Service for extracting claims from reference documents
pub struct ClaimExtractionService {
    llm_client: LlmClient,
    document_service: Arc<DocumentService>,
    cache: Option<VulnerabilityCache>,
    model: String,
}

impl ClaimExtractionService {
    /// Create a new claim extraction service
    /// Uses a shared LLM client passed from startup.
    /// Optionally uses CLAIM_EXTRACTION_MODEL env var (defaults to gpt-4o).
    pub fn new(
        llm_client: LlmClient,
        document_service: Arc<DocumentService>,
        cache: Option<VulnerabilityCache>,
    ) -> Self {
        let model = std::env::var(ENV_CLAIM_EXTRACTION_MODEL)
            .unwrap_or_else(|_| DEFAULT_MODEL.to_string());
        tracing::info!(
            model = %model,
            "Claim extraction service initialized"
        );
        Self {
            llm_client,
            document_service,
            cache,
            model,
        }
    }

    /// Extract claims from reference documents by their IDs
    /// Only fetches documents from DB on cache miss (when LLM extraction needed)
    pub async fn extract_claims_from_ids(
        &self,
        cve_id: &str,
        document_ids: &[String],
    ) -> Vec<SourceClaim> {
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
            if should_skip_extraction(&doc) {
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
            match self.extract_claims_from_document(cve_id, &doc).await {
                Ok(claims) => {
                    let raw_claim_count = claims.len();
                    tracing::debug!(
                        doc_id = %doc_id,
                        raw_claim_count = raw_claim_count,
                        "Raw claims extracted from document"
                    );
                    // Post-filter: remove weak/noise claims
                    let filtered_claims = filter_weak_claims(claims, &doc);
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
        let synthesized_claims = synthesize_claims(all_claims);

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
        cache.get_claims::<Vec<SourceClaim>>(doc_id).await.ok()
    }

    /// Cache claims for a document
    async fn cache_claims(&self, doc_id: &str, claims: &[SourceClaim]) {
        if let Some(ref cache) = self.cache
            && let Err(e) = cache.set_claims(doc_id, &claims.to_vec()).await
        {
            tracing::debug!(doc_id = %doc_id, error = %e, "Failed to cache claims");
        }
    }

    /// Extract claims from a single reference document
    async fn extract_claims_from_document(
        &self,
        cve_id: &str,
        doc: &ReferenceDocument,
    ) -> Result<Vec<SourceClaim>, ClaimExtractionError> {
        // Use normalized content if available, otherwise raw content
        let content = doc.normalized_content.as_ref().unwrap_or(&doc.raw_content);

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
        let prompt = build_extraction_prompt(cve_id, doc);
        let prompt_length = prompt.len();

        // Trace LLM API call details
        tracing::debug!(
            doc_id = %doc.id,
            cve = %cve_id,
            model = %self.model,
            prompt_length = prompt_length,
            content_length = truncated_content.len(),
            "Initiating OpenAI API call for claim extraction"
        );

        let start_time = std::time::Instant::now();

        // Create extractor and extract claims using shared LLM client
        // Use temperature=0.0 and seed for deterministic, reproducible outputs
        let extractor = self
            .llm_client
            .openai_client()
            .extractor::<ExtractedClaims>(&self.model)
            .preamble(EXTRACTION_SYSTEM_PROMPT)
            .additional_params(serde_json::json!({
                "temperature": 0.0,
                "seed": 42
            }))
            .build();

        let extracted = match extractor.extract(&prompt).await {
            Ok(result) => {
                let elapsed = start_time.elapsed();
                tracing::info!(
                    doc_id = %doc.id,
                    cve = %cve_id,
                    model = %self.model,
                    elapsed_ms = elapsed.as_millis(),
                    claims_extracted = result.claims.len(),
                    prompt_length = prompt_length,
                    "OpenAI API call completed successfully"
                );
                result
            }
            Err(e) => {
                let elapsed = start_time.elapsed();
                tracing::error!(
                    doc_id = %doc.id,
                    cve = %cve_id,
                    model = %self.model,
                    elapsed_ms = elapsed.as_millis(),
                    prompt_length = prompt_length,
                    error = %e,
                    "OpenAI API call failed"
                );
                return Err(ClaimExtractionError::ExtractionFailed(e.to_string()));
            }
        };

        // Validate extracted claims for grounding and quality
        // Use the full normalized/raw content for validation (not truncated) to ensure excerpts are found
        let content_to_validate = doc
            .normalized_content
            .as_deref()
            .unwrap_or(&doc.raw_content);
        let validation_result =
            validation::validate_extracted_claims(&extracted, content_to_validate);

        if !validation_result.is_valid {
            tracing::error!(
                doc_id = %doc.id,
                cve = %cve_id,
                errors = ?validation_result.errors,
                "Claim extraction validation failed - claims not grounded in source"
            );
            return Err(ClaimExtractionError::ExtractionFailed(format!(
                "Validation failed: {}",
                validation_result.errors.join("; ")
            )));
        }

        if !validation_result.warnings.is_empty() {
            tracing::warn!(
                doc_id = %doc.id,
                cve = %cve_id,
                warnings = ?validation_result.warnings,
                "Claim extraction produced quality warnings"
            );
        }

        // Convert extracted claims to SourceClaims
        let raw_claims_count = extracted.claims.len();
        let source_claims: Vec<SourceClaim> = extracted
            .claims
            .into_iter()
            .map(|ec| self.convert_to_source_claim(ec, doc))
            .collect();

        tracing::debug!(
            doc_id = %doc.id,
            raw_claims = raw_claims_count,
            final_claims = source_claims.len(),
            "Converted extracted claims to SourceClaims"
        );

        Ok(source_claims)
    }

    /// Convert an extracted claim to a SourceClaim
    fn convert_to_source_claim(
        &self,
        extracted: crate::model::claims::ExtractedClaim,
        doc: &ReferenceDocument,
    ) -> SourceClaim {
        use crate::model::claims::{ExtractedCertainty, ExtractedReason};

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
        let trust_level = determine_trust_level(doc);

        // Determine source roles based on retriever type
        let source_roles = determine_source_roles(doc);

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
}

/// Determine trust level based on document retriever type
fn determine_trust_level(doc: &ReferenceDocument) -> TrustLevel {
    use crate::model::RetrieverType;
    match doc.retriever {
        RetrieverType::Nvd | RetrieverType::CveOrg | RetrieverType::RedHatCsaf => TrustLevel::High,
        RetrieverType::GitAdvisory | RetrieverType::GitCveV5 | RetrieverType::Bugzilla => {
            TrustLevel::Medium
        }
        RetrieverType::GitCommit | RetrieverType::GitIssue | RetrieverType::GitRelease => {
            TrustLevel::Medium
        }
        RetrieverType::Generic => TrustLevel::Low,
    }
}

/// Determine source roles based on document retriever type
fn determine_source_roles(doc: &ReferenceDocument) -> Vec<SourceType> {
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
