//! Claim synthesis and deduplication

use std::collections::{HashMap, HashSet};

use crate::model::{ClaimCertainty, ClaimEvidence, SourceClaim, SourceClaimReason, TrustLevel};

/// Synthesize and deduplicate claims from multiple sources
/// Groups claims by (reason, semantic_meaning) and keeps the best one, merging evidence
pub fn synthesize_claims(claims: Vec<SourceClaim>) -> Vec<SourceClaim> {
    if claims.is_empty() {
        return claims;
    }

    // Group claims by reason first
    let mut by_reason: HashMap<SourceClaimReason, Vec<SourceClaim>> = HashMap::new();

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
                are_semantically_similar(&claim, &group[0])
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
                synthesized.push(merge_claim_group(group));
            }
        }
    }

    synthesized
}

/// Check if two claims are semantically similar (same meaning, different sources)
fn are_semantically_similar(claim1: &SourceClaim, claim2: &SourceClaim) -> bool {
    // Must have same reason
    if claim1.reason != claim2.reason {
        return false;
    }

    // Extract normalized excerpts for comparison
    let excerpt1 = normalize_excerpt(claim1);
    let excerpt2 = normalize_excerpt(claim2);

    // If excerpts are very similar (high overlap), they're semantically similar
    excerpts_similar(&excerpt1, &excerpt2)
}

/// Normalize excerpt text for comparison
fn normalize_excerpt(claim: &SourceClaim) -> String {
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
fn excerpts_similar(excerpt1: &str, excerpt2: &str) -> bool {
    if excerpt1.is_empty() || excerpt2.is_empty() {
        return false;
    }

    let words1: HashSet<&str> = excerpt1.split_whitespace().collect();
    let words2: HashSet<&str> = excerpt2.split_whitespace().collect();

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
fn merge_claim_group(mut group: Vec<SourceClaim>) -> SourceClaim {
    // Sort by trust level (High > Medium > Low), then by certainty strength
    group.sort_by(|a, b| {
        let trust_a = get_highest_trust(&a.evidence);
        let trust_b = get_highest_trust(&b.evidence);

        match trust_a.cmp(&trust_b) {
            std::cmp::Ordering::Equal => {
                // Same trust - prefer stronger certainty
                certainty_strength(&a.certainty).cmp(&certainty_strength(&b.certainty))
            }
            other => other.reverse(), // Reverse because High > Medium > Low
        }
    });

    // Take the best claim as the base
    let mut merged = group.remove(0);

    // Merge evidence from all other claims (avoid duplicates)
    let mut seen_evidence_ids: HashSet<String> = merged
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
fn get_highest_trust(evidence: &[ClaimEvidence]) -> u8 {
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
fn certainty_strength(certainty: &ClaimCertainty) -> u8 {
    match certainty {
        ClaimCertainty::Strong => 4,
        ClaimCertainty::Conditional => 3,
        ClaimCertainty::IdentificationOnly => 2,
        ClaimCertainty::Indicative => 1,
    }
}
