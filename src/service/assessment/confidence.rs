//! Confidence computation for vulnerability assessments

use regex::Regex;

use crate::model::{
    ClaimCertainty, ConfidenceLevel, ExploitabilityAssessment, ExploitabilityStatus, Limitation,
    LimitationReason, OverallConfidence, SourceClaimReason, TrustLevel, VulnerabilityIntel,
};
use crate::service::llm::LlmClient;

/// Hard-banned substrings that trigger regeneration
const BANNED_PHRASES: &[&str] = &[
    "however",
    "overall",
    "influence",
    "suggest",
    "indicate",
    "appears",
];

/// Maximum retries for confidence reason generation
const MAX_RETRIES: usize = 3;

/// Compute overall confidence based on claims, limitations, and exploitability
pub async fn compute_confidence(
    llm_client: &LlmClient,
    model: &str,
    intel: &VulnerabilityIntel,
    exploitability: &ExploitabilityAssessment,
    limitations: &[Limitation],
) -> OverallConfidence {
    // Step 1: Compute evidence strength
    let evidence_score = compute_evidence_strength(intel);

    // Step 2: Apply uncertainty penalties
    let penalty_score = compute_uncertainty_penalties(exploitability, limitations);

    // Step 3: Calculate final score and normalize
    let final_score = evidence_score + penalty_score;
    let confidence_level = normalize_confidence(final_score);

    tracing::debug!(
        evidence_score = evidence_score,
        penalty_score = penalty_score,
        final_score = final_score,
        confidence_level = ?confidence_level,
        "Computed confidence score"
    );

    // Step 4: Generate human-readable reason using LLM
    let reason = generate_confidence_reason(
        llm_client,
        model,
        intel,
        exploitability,
        limitations,
        final_score,
        &confidence_level,
    )
    .await
    .unwrap_or_else(|_| {
        format!(
            "Confidence score: {:.1} (evidence: {:.1}, penalties: {:.1})",
            final_score, evidence_score, penalty_score
        )
    });

    OverallConfidence {
        level: confidence_level,
        score: final_score,
        reason,
    }
}

/// Step 1: Compute evidence strength from claims
fn compute_evidence_strength(intel: &VulnerabilityIntel) -> f64 {
    // A. Claim strength score
    let mut claim_scores = Vec::new();

    for claim in &intel.claims {
        // Base score from certainty
        let base_score = match claim.certainty {
            ClaimCertainty::Strong => 3.0,
            ClaimCertainty::Conditional => 2.0,
            ClaimCertainty::Indicative => 1.0,
            ClaimCertainty::IdentificationOnly => 0.5,
        };

        // Highest trust level multiplier
        let trust_multiplier = claim
            .evidence
            .iter()
            .map(|e| match e.trust_level {
                TrustLevel::High => 1.0,
                TrustLevel::Medium => 0.75,
                TrustLevel::Low => 0.5,
            })
            .fold(0.0, f64::max);

        claim_scores.push(base_score * trust_multiplier);
    }

    let claim_total: f64 = claim_scores.iter().sum();

    // B. Coverage bonus
    let mut coverage_bonus = 0.0;
    let has_identification = intel
        .claims
        .iter()
        .any(|c| matches!(c.reason, SourceClaimReason::Identification));
    let has_exploitability = intel
        .claims
        .iter()
        .any(|c| matches!(c.reason, SourceClaimReason::Exploitability));
    let has_impact = intel
        .claims
        .iter()
        .any(|c| matches!(c.reason, SourceClaimReason::Impact));
    let has_mitigation = intel
        .claims
        .iter()
        .any(|c| matches!(c.reason, SourceClaimReason::Mitigation));

    if has_identification {
        coverage_bonus += 1.0;
    }
    if has_exploitability {
        coverage_bonus += 1.0;
    }
    if has_impact {
        coverage_bonus += 1.0;
    }
    if has_mitigation {
        coverage_bonus += 1.0;
    }

    claim_total + coverage_bonus
}

/// Step 2: Compute uncertainty penalties
fn compute_uncertainty_penalties(
    exploitability: &ExploitabilityAssessment,
    limitations: &[Limitation],
) -> f64 {
    let mut penalty = 0.0;

    // A. Limitations penalties
    for limitation in limitations {
        let limitation_penalty = match limitation.reason {
            LimitationReason::InsufficientData => -2.0,
            LimitationReason::ConflictingData => -3.0,
            LimitationReason::RuntimeDependent => -1.5,
            LimitationReason::EnvironmentSpecific => -1.0,
        };
        penalty += limitation_penalty;
    }

    // B. Exploitability ambiguity penalty
    match exploitability.status {
        ExploitabilityStatus::Unknown => penalty -= 3.0,
        ExploitabilityStatus::ConditionallyExploitable => penalty -= 1.0,
        ExploitabilityStatus::NotExploitable => {
            // If certainty is low, there might be disagreement
            if matches!(
                exploitability.certainty,
                ClaimCertainty::Indicative | ClaimCertainty::IdentificationOnly
            ) {
                penalty -= 2.0;
            }
        }
        ExploitabilityStatus::Exploitable => {
            // No penalty for clear exploitability
        }
    }

    penalty
}

/// Step 3: Normalize score to confidence level
fn normalize_confidence(score: f64) -> ConfidenceLevel {
    if score >= 10.0 {
        ConfidenceLevel::High
    } else if score >= 6.0 {
        ConfidenceLevel::Medium
    } else {
        ConfidenceLevel::Low
    }
}

/// Step 4: Generate human-readable reason using LLM
async fn generate_confidence_reason(
    llm_client: &LlmClient,
    model: &str,
    intel: &VulnerabilityIntel,
    exploitability: &ExploitabilityAssessment,
    limitations: &[Limitation],
    score: f64,
    confidence_level: &ConfidenceLevel,
) -> Result<String, String> {
    // Count claims by certainty
    let strong_claims = intel
        .claims
        .iter()
        .filter(|c| matches!(c.certainty, ClaimCertainty::Strong))
        .count();
    let high_trust_claims = intel
        .claims
        .iter()
        .filter(|c| {
            c.evidence
                .iter()
                .any(|e| matches!(e.trust_level, TrustLevel::High))
        })
        .count();

    // Confidence-consistent tone guidance
    let tone_guidance = match confidence_level {
        ConfidenceLevel::High => {
            "Use language like 'predominantly', 'clearly supported', 'limited limitations'"
        }
        ConfidenceLevel::Medium => "Use language like 'mixed evidence', 'some uncertainty'",
        ConfidenceLevel::Low => "Use language like 'limited evidence', 'significant uncertainty'",
    };

    let prompt = format!(
        r#"Generate a concise, factual justification (2–3 sentences) for an already-determined confidence level.

## Facts:
- Confidence Level: {:?}
- Confidence Score: {:.1}
- Total Claims: {}
- Strong Claims: {}
- High Trust Sources: {}
- Limitations: {}
- Exploitability Status: {:?}

## Instructions:
Explain why this confidence level is justified based strictly on the facts above.

Rules:
- Treat the confidence level as final and correct
- Do NOT re-evaluate or question the score
- Do NOT use meta-language (e.g., "overall assessment", "this suggests", "influences")
- Describe limitations only in terms of whether they materially affect confidence
- Use declarative, factual sentences only
- Tone guidance: {}

Do NOT:
- Restate vulnerability details
- Invent new facts
- Add recommendations or analysis
- Use banned phrases: however, overall, influence, suggest, indicate, appears"#,
        confidence_level,
        score,
        intel.claims.len(),
        strong_claims,
        high_trust_claims,
        limitations.len(),
        exploitability.status,
        tone_guidance
    );

    #[derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
    struct ConfidenceReason {
        reason: String,
    }

    let extractor = llm_client
        .openai_client()
        .extractor::<ConfidenceReason>(model)
        .preamble("You are a technical writer. Generate concise, factual explanations based on provided data.")
        .build();

    // Try up to 3 times to get a valid response
    for attempt in 1..=MAX_RETRIES {
        match extractor.extract(&prompt).await {
            Ok(result) => {
                let reason = result.reason;

                // A. Post-validate: Reject phrases automatically
                let reason_lower = reason.to_lowercase();
                if let Some(banned) = BANNED_PHRASES
                    .iter()
                    .find(|phrase| reason_lower.contains(*phrase))
                {
                    tracing::warn!(
                        attempt = attempt,
                        banned_phrase = banned,
                        "Generated reason contains banned phrase, regenerating"
                    );
                    if attempt < MAX_RETRIES {
                        continue;
                    } else {
                        // Last attempt failed validation, use sanitized version
                        let sanitized = sanitize_reason(&reason, BANNED_PHRASES);
                        return Ok(sanitized);
                    }
                }

                // B. Enforce confidence-consistent tone
                if !validate_tone(&reason, confidence_level) {
                    tracing::warn!(
                        attempt = attempt,
                        "Generated reason does not match confidence tone, regenerating"
                    );
                    if attempt < MAX_RETRIES {
                        continue;
                    }
                    // If tone validation fails on last attempt, still return the result
                    // as it passed the hard-banned phrase check
                }

                return Ok(reason);
            }
            Err(e) => {
                if attempt == MAX_RETRIES {
                    tracing::warn!(error = %e, "Failed to generate confidence reason after retries, using fallback");
                    return Err(e.to_string());
                }
                tracing::debug!(attempt = attempt, error = %e, "Retrying confidence reason generation");
            }
        }
    }

    Err("Failed to generate valid confidence reason after retries".to_string())
}

/// Sanitize reason by removing or replacing banned phrases
fn sanitize_reason(reason: &str, banned_phrases: &[&str]) -> String {
    let mut sanitized = reason.to_string();
    let reason_lower = sanitized.to_lowercase();

    // Compile regex once for whitespace cleanup
    let whitespace_regex = Regex::new(r"\s+").unwrap();

    for phrase in banned_phrases {
        if reason_lower.contains(phrase) {
            // Try to remove the phrase and surrounding context
            let pattern = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(phrase)))
                .unwrap_or_else(|_| Regex::new(phrase).unwrap());
            sanitized = pattern.replace_all(&sanitized, "").to_string();
            // Clean up extra spaces
            sanitized = whitespace_regex.replace_all(&sanitized, " ").to_string();
            sanitized = sanitized.trim().to_string();
        }
    }

    sanitized
}

/// Validate that the reason matches the expected tone for the confidence level
/// Returns true if the tone is consistent, false if it clearly contradicts the confidence level
fn validate_tone(reason: &str, confidence_level: &ConfidenceLevel) -> bool {
    let reason_lower = reason.to_lowercase();

    match confidence_level {
        ConfidenceLevel::High => {
            // High confidence should not contain low-confidence language
            let low_confidence_indicators = [
                "limited evidence",
                "significant uncertainty",
                "uncertain",
                "incomplete",
                "insufficient",
                "lacks",
            ];
            !low_confidence_indicators
                .iter()
                .any(|indicator| reason_lower.contains(indicator))
        }
        ConfidenceLevel::Medium => {
            // Medium confidence should not contain extreme language (very high or very low)
            let extreme_indicators = [
                "predominantly",
                "clearly supported",
                "significant uncertainty",
                "completely",
            ];
            !extreme_indicators
                .iter()
                .any(|indicator| reason_lower.contains(indicator))
        }
        ConfidenceLevel::Low => {
            // Low confidence should not contain high-confidence language
            let high_confidence_indicators = [
                "predominantly",
                "clearly supported",
                "comprehensive",
                "strong evidence",
                "definitive",
            ];
            !high_confidence_indicators
                .iter()
                .any(|indicator| reason_lower.contains(indicator))
        }
    }
}
