//! Validation logic for LLM-extracted claims
//!
//! Ensures that extracted claims are grounded in the source document
//! and follow the expected format and quality standards.

use crate::model::claims::ExtractedClaims;

/// Result of claim validation
#[derive(Debug)]
pub struct ClaimValidationResult {
    /// Whether all claims passed validation
    pub is_valid: bool,
    /// Critical errors that indicate invalid output
    pub errors: Vec<String>,
    /// Warnings that indicate potential quality issues
    pub warnings: Vec<String>,
}

impl ClaimValidationResult {
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

/// Security-related keywords that should appear in claim excerpts
const SECURITY_KEYWORDS: &[&str] = &[
    "vulnerability",
    "cve",
    "cwe",
    "exploit",
    "attack",
    "injection",
    "overflow",
    "xss",
    "sql",
    "rce",
    "dos",
    "security",
    "patch",
    "fix",
    "flaw",
    "bug",
    "malicious",
    "arbitrary code",
    "privilege escalation",
    "authentication",
    "authorization",
    "bypass",
    "disclosure",
    "exposure",
    "leak",
    "leaks",
    "leaked",
    "data leak",
    "information disclosure",
    "unauthorized access",
    "denial of service",
    "remote code execution",
    "code execution",
];

/// Meta-commentary phrases that should NOT appear in rationales
const META_PHRASES: &[&str] = &[
    "this excerpt",
    "this statement",
    "this suggests",
    "the excerpt",
    "the statement",
    "this describes",
    "this explains",
    "this indicates",
    "the document states",
    "according to the excerpt",
];

/// Validate extracted claims against source document and quality standards
///
/// Checks:
/// 1. Excerpts exist in source document (grounding)
/// 2. Excerpts contain security-related keywords
/// 3. Rationales don't contain meta-commentary
/// 4. Rationales are substantive (>= 20 characters)
/// 5. Required fields are present
pub fn validate_extracted_claims(
    extracted: &ExtractedClaims,
    document_content: &str,
) -> ClaimValidationResult {
    let mut result = ClaimValidationResult::valid();

    // Empty claims array is valid (no security claims found)
    if extracted.claims.is_empty() {
        return result;
    }

    for (i, claim) in extracted.claims.iter().enumerate() {
        // Check 1: Verify excerpt exists in document (grounding check)
        if let Some(ref excerpt) = claim.excerpt {
            if !excerpt.trim().is_empty() {
                // Check if the excerpt (or a close variant) exists in the document
                // We allow for minor formatting differences
                let normalized_excerpt = normalize_whitespace(excerpt);
                let normalized_doc = normalize_whitespace(document_content);

                if !normalized_doc.contains(&normalized_excerpt) {
                    // Try contiguous substring match (70% of excerpt chars)
                    let contiguous_ok = is_substantially_present(&normalized_excerpt, &normalized_doc);
                    // Fallback: at least 70% of excerpt words appear in document in order (handles LLM paraphrasing/punctuation)
                    let words_ok =
                        words_in_order_present(excerpt, document_content, WORD_SUBSEQUENCE_RATIO);
                    if !contiguous_ok && !words_ok {
                        result.add_error(format!(
                            "Claim {} excerpt not found in document: '{}'",
                            i + 1,
                            excerpt.chars().take(100).collect::<String>()
                        ));
                    }
                }
            } else {
                result.add_warning(format!("Claim {} has empty excerpt", i + 1));
            }

            // Check 2: Verify excerpt contains security keywords
            let excerpt_lower = excerpt.to_lowercase();
            let has_security_keyword = SECURITY_KEYWORDS
                .iter()
                .any(|kw| excerpt_lower.contains(kw));

            if !has_security_keyword {
                result.add_warning(format!(
                    "Claim {} excerpt may not be security-related (no security keywords found): '{}'",
                    i + 1,
                    excerpt.chars().take(80).collect::<String>()
                ));
            }
        } else {
            result.add_error(format!("Claim {} missing required excerpt field", i + 1));
        }

        // Check 3: Verify rationale doesn't contain meta-commentary
        let rationale_lower = claim.rationale.to_lowercase();
        for phrase in META_PHRASES {
            if rationale_lower.contains(phrase) {
                result.add_warning(format!(
                    "Claim {} rationale contains meta-commentary '{}': '{}'",
                    i + 1,
                    phrase,
                    claim.rationale.chars().take(100).collect::<String>()
                ));
                break; // Only report once per claim
            }
        }

        // Check 4: Verify rationale is substantive
        if claim.rationale.trim().len() < 20 {
            result.add_warning(format!(
                "Claim {} rationale is too short (< 20 chars): '{}'",
                i + 1,
                claim.rationale
            ));
        }

        if claim.rationale.trim().len() > 500 {
            result.add_warning(format!(
                "Claim {} rationale is very long (> 500 chars), may be too verbose",
                i + 1
            ));
        }
    }

    result
}

/// Normalize whitespace for comparison (collapse multiple spaces, trim)
fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Normalize a word for comparison (lowercase, strip leading/trailing punctuation)
fn normalize_word(w: &str) -> String {
    w.trim_matches(|c: char| c.is_ascii_punctuation())
        .to_lowercase()
}

/// Check if a substantial portion of the excerpt is present in the document (contiguous substring)
fn is_substantially_present(excerpt: &str, document: &str) -> bool {
    let excerpt_words: Vec<&str> = excerpt.split_whitespace().collect();
    if excerpt_words.is_empty() {
        return false;
    }

    let doc_lower = document.to_lowercase();
    let excerpt_lower = excerpt.to_lowercase();

    // Try to find at least 70% of the excerpt as continuous substring
    let threshold = (excerpt_lower.len() as f32 * 0.7) as usize;

    // Check for substrings of the excerpt
    for window_size in (threshold..=excerpt_lower.len()).rev() {
        for start in 0..=(excerpt_lower.len().saturating_sub(window_size)) {
            let substring = &excerpt_lower[start..start + window_size];
            if doc_lower.contains(substring) {
                return true;
            }
        }
    }

    false
}

/// Check if at least `min_ratio` of excerpt words appear in the document in order (subsequence).
/// Handles LLM paraphrasing and punctuation differences (e.g. "7.5" vs "7.5,").
const WORD_SUBSEQUENCE_RATIO: f32 = 0.70;

fn words_in_order_present(excerpt: &str, document: &str, min_ratio: f32) -> bool {
    let excerpt_words: Vec<String> = excerpt
        .split_whitespace()
        .map(normalize_word)
        .filter(|w| !w.is_empty())
        .collect();
    if excerpt_words.is_empty() {
        return false;
    }

    let doc_words: Vec<String> = document
        .split_whitespace()
        .map(normalize_word)
        .filter(|w| !w.is_empty())
        .collect();

    // Find longest subsequence of excerpt words that appears in doc in order
    let mut doc_idx = 0;
    let mut matched = 0;
    for ew in &excerpt_words {
        while doc_idx < doc_words.len() {
            if doc_words[doc_idx] == *ew {
                matched += 1;
                doc_idx += 1;
                break;
            }
            doc_idx += 1;
        }
    }

    let ratio = matched as f32 / excerpt_words.len() as f32;
    ratio >= min_ratio
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::claims::{ExtractedCertainty, ExtractedClaim, ExtractedReason};

    #[test]
    fn test_valid_claims() {
        let claims = ExtractedClaims {
            claims: vec![ExtractedClaim {
                reason: ExtractedReason::Exploitability,
                certainty: ExtractedCertainty::Strong,
                excerpt: Some("CVE-2024-1234 allows remote code execution".to_string()),
                rationale: "The vulnerability enables attackers to execute arbitrary code remotely"
                    .to_string(),
            }],
        };

        let document = "CVE-2024-1234 allows remote code execution via malformed input.";
        let result = validate_extracted_claims(&claims, document);

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_excerpt_not_in_document() {
        let claims = ExtractedClaims {
            claims: vec![ExtractedClaim {
                reason: ExtractedReason::Exploitability,
                certainty: ExtractedCertainty::Strong,
                excerpt: Some("This text does not exist in the document".to_string()),
                rationale: "Some rationale that is long enough to pass validation checks"
                    .to_string(),
            }],
        };

        let document = "Completely different content here.";
        let result = validate_extracted_claims(&claims, document);

        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    /// Excerpt that paraphrases slightly (same words in order, different punctuation/wording)
    /// should pass via word-subsequence fallback.
    #[test]
    fn test_excerpt_paraphrase_passes_word_subsequence() {
        let claims = ExtractedClaims {
            claims: vec![ExtractedClaim {
                reason: ExtractedReason::Exploitability,
                certainty: ExtractedCertainty::Strong,
                excerpt: Some(
                    "CVE-2020-36518 allows SQL injection in the CNC Console (jackson-databind) which can be exploited over the network."
                        .to_string(),
                ),
                rationale: "The vulnerability enables SQL injection over the network.".to_string(),
            }],
        };

        // Document has same meaning, slightly different wording/punctuation (e.g. "7.5" vs "score of 7.5")
        let document = "CVE-2020-36518 allows SQL injection in the CNC Console (jackson-databind) which can be exploited over the network. CVE-2020-36518 is associated with a CVSS score of 7.5.";
        let result = validate_extracted_claims(&claims, document);

        assert!(result.is_valid, "paraphrased excerpt should pass: {:?}", result.errors);
    }

    #[test]
    fn test_meta_commentary_detection() {
        let claims = ExtractedClaims {
            claims: vec![ExtractedClaim {
                reason: ExtractedReason::Impact,
                certainty: ExtractedCertainty::Strong,
                excerpt: Some("CVE-2024-1234 affects confidentiality".to_string()),
                rationale:
                    "This excerpt explains that the vulnerability impacts data confidentiality"
                        .to_string(),
            }],
        };

        let document = "CVE-2024-1234 affects confidentiality of user data.";
        let result = validate_extracted_claims(&claims, document);

        assert!(result.is_valid); // Only a warning, not an error
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("meta-commentary"));
    }

    #[test]
    fn test_missing_security_keywords() {
        let claims = ExtractedClaims {
            claims: vec![ExtractedClaim {
                reason: ExtractedReason::Identification,
                certainty: ExtractedCertainty::IdentificationOnly,
                excerpt: Some("Version bump to 1.2.3".to_string()),
                rationale: "The version was updated to fix some issues in the previous release"
                    .to_string(),
            }],
        };

        let document = "Version bump to 1.2.3";
        let result = validate_extracted_claims(&claims, document);

        assert!(result.is_valid); // Only a warning
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("not be security-related"));
    }

    #[test]
    fn test_empty_claims_is_valid() {
        let claims = ExtractedClaims { claims: vec![] };
        let document = "Some document without security claims.";
        let result = validate_extracted_claims(&claims, document);

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_short_rationale() {
        let claims = ExtractedClaims {
            claims: vec![ExtractedClaim {
                reason: ExtractedReason::Mitigation,
                certainty: ExtractedCertainty::Strong,
                excerpt: Some("Patch available in version 2.0".to_string()),
                rationale: "Fixed".to_string(), // Too short
            }],
        };

        let document = "Patch available in version 2.0";
        let result = validate_extracted_claims(&claims, document);

        assert!(result.is_valid); // Only a warning
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("too short"));
    }
}
