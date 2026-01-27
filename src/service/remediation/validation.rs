//! Validation logic for LLM-extracted remediation actions
//!
//! Ensures that remediation actions are specific, actionable, and follow recommendations

use crate::model::remediations::action_extraction::ExtractedRemediationAction;

/// Result of remediation action validation
#[derive(Debug)]
pub struct RemediationValidationResult {
    /// Whether the action passed validation
    pub is_valid: bool,
    /// Critical errors that indicate invalid output
    pub errors: Vec<String>,
    /// Warnings that indicate potential quality issues
    pub warnings: Vec<String>,
}

impl RemediationValidationResult {
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

/// Validate extracted remediation action for completeness and correctness
///
/// Checks:
/// 1. At least one instruction is provided
/// 2. For dependency instructions, verify recommended version was used (if provided)
/// 3. Action descriptions are substantive
/// 4. Confirmation risks are specific (not vague warnings)
/// 5. Preconditions are actionable
/// 6. Reasoning is provided (recommended for audit trail)
pub fn validate_extracted_remediation(
    action: &ExtractedRemediationAction,
    optimal_fixed_version: Option<&str>,
) -> RemediationValidationResult {
    let mut result = RemediationValidationResult::valid();

    // Check 1: At least one instruction
    if action.instructions.is_empty() {
        result.add_error(
            "No instructions provided - remediation action must include at least one step"
                .to_string(),
        );
        return result; // Can't validate further
    }

    // Check 2: Verify recommended version was used (if applicable)
    if let Some(recommended_version) = optimal_fixed_version {
        let dependency_instructions: Vec<_> = action
            .instructions
            .iter()
            .filter(|i| i.domain == "dependency")
            .collect();

        if !dependency_instructions.is_empty() {
            let mut found_recommended_version = false;

            for instr in &dependency_instructions {
                if let Some(version_value) = instr.parameters.get("version")
                    && let Some(version_str) = version_value.as_str()
                        && version_str == recommended_version {
                            found_recommended_version = true;
                            break;
                        }
            }

            if !found_recommended_version {
                result.add_warning(format!(
                    "Dependency instructions present but recommended version '{}' was not used",
                    recommended_version
                ));
            }
        }
    }

    // Check 3: Action descriptions are substantive
    for (i, instr) in action.instructions.iter().enumerate() {
        if instr.action.trim().len() < 10 {
            result.add_warning(format!(
                "Instruction {} has very short action description: '{}'",
                i + 1,
                instr.action
            ));
        }

        // Check that domain is valid
        let valid_domains = [
            "dependency",
            "code",
            "configuration",
            "build",
            "test",
            "annotation",
        ];
        if !valid_domains.contains(&instr.domain.as_str()) {
            result.add_warning(format!(
                "Instruction {} has unusual domain '{}' (expected one of: {})",
                i + 1,
                instr.domain,
                valid_domains.join(", ")
            ));
        }

        // Check that dependency instructions have required parameters
        if instr.domain == "dependency"
            && !instr.parameters.contains_key("package_name")
                && !instr.parameters.contains_key("version")
            {
                result.add_warning(format!(
                    "Instruction {} is a dependency action but lacks package_name or version parameters",
                    i + 1
                ));
            }
    }

    // Check 4: Confirmation risks are specific (not vague)
    let vague_risk_phrases = [
        "may cause issues",
        "could affect",
        "might break",
        "test thoroughly",
        "review carefully",
        "check for compatibility",
    ];

    for (i, risk) in action.confirmation_risks.iter().enumerate() {
        let risk_lower = risk.to_lowercase();

        for vague_phrase in &vague_risk_phrases {
            if risk_lower.contains(vague_phrase) {
                result.add_warning(format!(
                    "Confirmation risk {} is vague (contains '{}'): '{}'",
                    i + 1,
                    vague_phrase,
                    risk
                ));
                break;
            }
        }

        if risk.trim().len() < 20 {
            result.add_warning(format!(
                "Confirmation risk {} is very short: '{}'",
                i + 1,
                risk
            ));
        }
    }

    // Check 5: Preconditions are actionable (not too vague)
    for (i, precondition) in action.preconditions.iter().enumerate() {
        if precondition.trim().len() < 10 {
            result.add_warning(format!(
                "Precondition {} is very short: '{}'",
                i + 1,
                precondition
            ));
        }
    }

    // Check 6: Reasoning is provided (recommended)
    if action.reasoning.is_none() {
        result.add_warning(
            "Remediation action lacks reasoning field - recommended for auditability".to_string(),
        );
    } else if let Some(ref reasoning) = action.reasoning {
        if reasoning.trim().len() < 50 {
            result.add_warning(format!(
                "Reasoning is very short ({} chars) - may lack detail",
                reasoning.len()
            ));
        }

        // Check that reasoning mentions the version selection (if dependency action)
        if optimal_fixed_version.is_some()
            && action.instructions.iter().any(|i| i.domain == "dependency")
        {
            let reasoning_lower = reasoning.to_lowercase();
            if !reasoning_lower.contains("version") {
                result.add_warning(
                    "Reasoning doesn't explain version selection for dependency action".to_string(),
                );
            }
        }
    }

    // Check 7: Expected outcomes are present and substantive
    if action.expected_outcomes.is_empty() {
        result.add_warning(
            "No expected outcomes provided - recommended for verification".to_string(),
        );
    } else {
        for (i, outcome) in action.expected_outcomes.iter().enumerate() {
            if outcome.trim().len() < 15 {
                result.add_warning(format!(
                    "Expected outcome {} is very short: '{}'",
                    i + 1,
                    outcome
                ));
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::remediations::action_extraction::ExtractedInstruction;
    use std::collections::HashMap;

    #[test]
    fn test_valid_remediation() {
        let action = ExtractedRemediationAction {
            instructions: vec![ExtractedInstruction {
                domain: "dependency".to_string(),
                action: "Upgrade package to version 2.0.0".to_string(),
                parameters: {
                    let mut map = HashMap::new();
                    map.insert(
                        "package_name".to_string(),
                        serde_json::json!("example-package"),
                    );
                    map.insert("version".to_string(), serde_json::json!("2.0.0"));
                    map
                },
            }],
            preconditions: vec!["Create backup of current deployment".to_string()],
            expected_outcomes: vec!["Vulnerability CVE-2024-1234 is patched".to_string()],
            confirmation_risks: vec![
                "This upgrade changes the API from v1 to v2, requiring code changes".to_string(),
            ],
            reasoning: Some(
                "Selected version 2.0.0 as it's the lowest version that patches the vulnerability"
                    .to_string(),
            ),
        };

        let result = validate_extracted_remediation(&action, Some("2.0.0"));

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_no_instructions() {
        let action = ExtractedRemediationAction {
            instructions: vec![],
            preconditions: vec![],
            expected_outcomes: vec![],
            confirmation_risks: vec![],
            reasoning: None,
        };

        let result = validate_extracted_remediation(&action, None);

        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].contains("No instructions"));
    }

    #[test]
    fn test_wrong_version_used() {
        let action = ExtractedRemediationAction {
            instructions: vec![ExtractedInstruction {
                domain: "dependency".to_string(),
                action: "Upgrade to version 3.0.0".to_string(),
                parameters: {
                    let mut map = HashMap::new();
                    map.insert("version".to_string(), serde_json::json!("3.0.0"));
                    map
                },
            }],
            preconditions: vec![],
            expected_outcomes: vec!["Patched".to_string()],
            confirmation_risks: vec![],
            reasoning: Some("Using version 3.0.0".to_string()),
        };

        let result = validate_extracted_remediation(&action, Some("2.0.0"));

        assert!(result.is_valid); // Only a warning
        assert!(!result.warnings.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("recommended version"))
        );
    }

    #[test]
    fn test_vague_confirmation_risk() {
        let action = ExtractedRemediationAction {
            instructions: vec![ExtractedInstruction {
                domain: "configuration".to_string(),
                action: "Update configuration file".to_string(),
                parameters: HashMap::new(),
            }],
            preconditions: vec![],
            expected_outcomes: vec!["Configuration updated".to_string()],
            confirmation_risks: vec!["This may cause issues".to_string()],
            reasoning: Some("Configuration change required".to_string()),
        };

        let result = validate_extracted_remediation(&action, None);

        assert!(result.is_valid); // Only a warning
        assert!(!result.warnings.is_empty());
        assert!(result.warnings.iter().any(|w| w.contains("vague")));
    }

    #[test]
    fn test_missing_reasoning() {
        let action = ExtractedRemediationAction {
            instructions: vec![ExtractedInstruction {
                domain: "code".to_string(),
                action: "Apply security patch".to_string(),
                parameters: HashMap::new(),
            }],
            preconditions: vec![],
            expected_outcomes: vec!["Security vulnerability fixed".to_string()],
            confirmation_risks: vec![],
            reasoning: None, // Missing reasoning
        };

        let result = validate_extracted_remediation(&action, None);

        assert!(result.is_valid); // Only a warning
        assert!(!result.warnings.is_empty());
        assert!(result.warnings.iter().any(|w| w.contains("reasoning")));
    }
}
