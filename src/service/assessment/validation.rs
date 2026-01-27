//! Validation logic for LLM-extracted vulnerability assessments
//!
//! Ensures that assessments are grounded in claims and include proper evidence

use crate::model::assessments::ExtractedAssessment;
use crate::model::VulnerabilityIntel;

/// Result of assessment validation
#[derive(Debug)]
pub struct AssessmentValidationResult {
    /// Whether the assessment passed validation
    pub is_valid: bool,
    /// Critical errors that indicate invalid output
    pub errors: Vec<String>,
    /// Warnings that indicate potential quality issues
    pub warnings: Vec<String>,
}

impl AssessmentValidationResult {
    /// Create a new validation result with no issues
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Add an error to the validation result
    pub fn add_error(&mut self, error: String) {
        self.is_valid = false;
        self.errors.push(error);
    }

    /// Add a warning to the validation result
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

/// Validate extracted assessment for grounding and completeness
///
/// Checks:
/// 1. Non-unknown assessments have supporting evidence (supported_by)
/// 2. Supporting evidence references exist in the provided claims
/// 3. Reasoning is provided for auditability (warning if missing)
/// 4. Exploitability conditions are provided when status is conditionally_exploitable
pub fn validate_extracted_assessment(
    assessment: &ExtractedAssessment,
    intel: &VulnerabilityIntel,
) -> AssessmentValidationResult {
    let mut result = AssessmentValidationResult::valid();

    // Collect all claim excerpts for validation
    let claim_excerpts: Vec<String> = intel
        .claims
        .iter()
        .flat_map(|c| {
            c.evidence.iter().filter_map(|e| e.excerpt.clone())
        })
        .collect();

    // Validate exploitability assessment
    let exploitability_status = format!("{:?}", assessment.exploitability.status);
    if exploitability_status != "Unknown" && assessment.exploitability.supported_by.is_empty() {
        result.add_error(format!(
            "Exploitability assessment has status '{}' but no supporting evidence",
            exploitability_status
        ));
    }

    // Validate that supported_by references exist in claims
    for evidence in &assessment.exploitability.supported_by {
        if !evidence_exists_in_claims(evidence, &claim_excerpts) {
            result.add_warning(format!(
                "Exploitability evidence '{}' not found in claims",
                evidence.chars().take(80).collect::<String>()
            ));
        }
    }

    // Check for conditions when status is conditionally_exploitable
    if exploitability_status == "ConditionallyExploitable"
        && assessment.exploitability.conditions.is_empty()
    {
        result.add_warning(
            "Exploitability status is conditionally_exploitable but no conditions specified"
                .to_string(),
        );
    }

    // Validate impact assessment
    let impact_severity = format!("{:?}", assessment.impact.severity);
    if impact_severity != "Unknown" && assessment.impact.supported_by.is_empty() {
        result.add_error(format!(
            "Impact assessment has severity '{}' but no supporting evidence",
            impact_severity
        ));
    }

    // Validate that impact supported_by references exist in claims
    for evidence in &assessment.impact.supported_by {
        if !evidence_exists_in_claims(evidence, &claim_excerpts) {
            result.add_warning(format!(
                "Impact evidence '{}' not found in claims",
                evidence.chars().take(80).collect::<String>()
            ));
        }
    }

    // Validate limitations
    for (i, limitation) in assessment.limitations.iter().enumerate() {
        if limitation.description.trim().len() < 10 {
            result.add_warning(format!(
                "Limitation {} has very short description: '{}'",
                i + 1,
                limitation.description
            ));
        }

        // If supported_by is provided, validate references
        if let Some(ref supported_by) = limitation.supported_by {
            for evidence in supported_by {
                if !evidence_exists_in_claims(evidence, &claim_excerpts) {
                    result.add_warning(format!(
                        "Limitation {} evidence '{}' not found in claims",
                        i + 1,
                        evidence.chars().take(80).collect::<String>()
                    ));
                }
            }
        }
    }

    // Check for reasoning (recommended for auditability)
    if assessment.reasoning.is_none() {
        result.add_warning(
            "Assessment lacks reasoning field - recommended for auditability".to_string(),
        );
    } else if let Some(ref reasoning) = assessment.reasoning {
        if reasoning.trim().len() < 50 {
            result.add_warning(format!(
                "Reasoning is very short ({} chars) - may lack detail",
                reasoning.len()
            ));
        }
    }

    result
}

/// Check if evidence text exists in any of the claim excerpts
fn evidence_exists_in_claims(evidence: &str, claim_excerpts: &[String]) -> bool {
    let evidence_lower = evidence.to_lowercase();

    // Exact match first
    for excerpt in claim_excerpts {
        if excerpt.to_lowercase().contains(&evidence_lower) {
            return true;
        }
    }

    // Fuzzy match: check if evidence is a substring of any claim
    // or if any claim is a substring of evidence
    for excerpt in claim_excerpts {
        let excerpt_lower = excerpt.to_lowercase();
        if evidence_lower.contains(&excerpt_lower) || excerpt_lower.contains(&evidence_lower) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::assessments::*;
    use crate::model::{
        ClaimCertainty, ClaimEvidence, CveIdentity, PackageIdentity, PackageMetadata, ReferenceId,
        Scope, SourceClaim, SourceClaimReason, SourceType, TrustLevel,
    };
    use chrono::Utc;

    fn create_test_intel() -> VulnerabilityIntel {
        VulnerabilityIntel {
            cve_identity: CveIdentity {
                cve: "CVE-2024-1234".to_string(),
                description: "Test vulnerability".to_string(),
                aliases: vec![],
                cvss_vectors: vec![],
                references: vec![],
                published: Utc::now(),
                last_modified: Utc::now(),
            },
            package_metadata: PackageMetadata {
                source_repo: None,
                homepage: None,
                issue_tracker: None,
                licenses: vec![],
            },
            package_identity: PackageIdentity {
                purl: url::Url::parse("pkg:maven/test/package@1.0.0").unwrap(),
                dependency_graph: vec![],
                scope: Scope::Runtime,
            },
            claims: vec![SourceClaim {
                reason: SourceClaimReason::Exploitability,
                certainty: ClaimCertainty::Strong,
                evidence: vec![ClaimEvidence {
                    reference_id: ReferenceId {
                        source: "https://test.example.com".to_string(),
                        id: "test-doc-1".to_string(),
                    },
                    trust_level: TrustLevel::High,
                    excerpt: Some("The vulnerability can be exploited remotely".to_string()),
                    source_roles: vec![SourceType::Advisory],
                }],
                rationale: Some("Exploitability claim".to_string()),
            }],
            affected_versions: vec![],
            fixed_versions: vec![],
            vendor_remediations: vec![],
            reference_ids: vec!["test-doc-1".to_string()],
        }
    }

    #[test]
    fn test_valid_assessment() {
        let assessment = ExtractedAssessment {
            exploitability: ExtractedExploitability {
                status: ExtractedExploitabilityStatus::Exploitable,
                certainty: ExtractedCertainty::Strong,
                conditions: vec![],
                notes: None,
                supported_by: vec!["The vulnerability can be exploited remotely".to_string()],
            },
            impact: ExtractedImpact {
                severity: ExtractedImpactSeverity::High,
                confidentiality: Some(ExtractedImpactLevel::High),
                integrity: None,
                availability: None,
                notes: None,
                supported_by: vec!["The vulnerability can be exploited remotely".to_string()],
            },
            limitations: vec![],
            reasoning: Some("Based on the claim that the vulnerability can be exploited remotely".to_string()),
        };

        let intel = create_test_intel();
        let result = validate_extracted_assessment(&assessment, &intel);

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_missing_exploitability_evidence() {
        let assessment = ExtractedAssessment {
            exploitability: ExtractedExploitability {
                status: ExtractedExploitabilityStatus::Exploitable,
                certainty: ExtractedCertainty::Strong,
                conditions: vec![],
                notes: None,
                supported_by: vec![], // Missing evidence
            },
            impact: ExtractedImpact {
                severity: ExtractedImpactSeverity::Unknown,
                confidentiality: None,
                integrity: None,
                availability: None,
                notes: None,
                supported_by: vec![],
            },
            limitations: vec![],
            reasoning: None,
        };

        let intel = create_test_intel();
        let result = validate_extracted_assessment(&assessment, &intel);

        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].contains("no supporting evidence"));
    }

    #[test]
    fn test_unknown_status_no_evidence_ok() {
        let assessment = ExtractedAssessment {
            exploitability: ExtractedExploitability {
                status: ExtractedExploitabilityStatus::Unknown,
                certainty: ExtractedCertainty::Indicative,
                conditions: vec![],
                notes: Some("Insufficient data".to_string()),
                supported_by: vec![], // OK for unknown status
            },
            impact: ExtractedImpact {
                severity: ExtractedImpactSeverity::Unknown,
                confidentiality: None,
                integrity: None,
                availability: None,
                notes: None,
                supported_by: vec![], // OK for unknown severity
            },
            limitations: vec![ExtractedLimitation {
                reason: ExtractedLimitationReason::InsufficientData,
                description: "No exploitability claims found".to_string(),
                supported_by: None,
            }],
            reasoning: Some("Unknown due to lack of data".to_string()),
        };

        let intel = create_test_intel();
        let result = validate_extracted_assessment(&assessment, &intel);

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_conditionally_exploitable_without_conditions() {
        let assessment = ExtractedAssessment {
            exploitability: ExtractedExploitability {
                status: ExtractedExploitabilityStatus::ConditionallyExploitable,
                certainty: ExtractedCertainty::Strong,
                conditions: vec![], // Missing conditions
                notes: None,
                supported_by: vec!["The vulnerability can be exploited remotely".to_string()],
            },
            impact: ExtractedImpact {
                severity: ExtractedImpactSeverity::Medium,
                confidentiality: None,
                integrity: None,
                availability: None,
                notes: None,
                supported_by: vec!["The vulnerability can be exploited remotely".to_string()],
            },
            limitations: vec![],
            reasoning: Some("Conditional".to_string()),
        };

        let intel = create_test_intel();
        let result = validate_extracted_assessment(&assessment, &intel);

        assert!(result.is_valid); // Only a warning
        assert!(!result.warnings.is_empty());
        assert!(result.warnings.iter().any(|w| w.contains("no conditions")));
    }
}
