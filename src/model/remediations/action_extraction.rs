//! LLM-extractable models for remediation action generation

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// LLM-extracted remediation action structure
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Detailed remediation instructions for addressing a vulnerability")]
pub struct ExtractedRemediationAction {
    /// Instructions broken down by domain
    #[schemars(description = "Step-by-step instructions grouped by domain (dependency, code, configuration, build, test, annotation)")]
    pub instructions: Vec<ExtractedInstruction>,

    /// Preconditions that must be met before applying this action
    #[schemars(description = "Prerequisites before applying remediation (e.g., 'Create backup', 'Verify test environment available')")]
    pub preconditions: Vec<String>,

    /// Expected outcomes after applying this action
    #[schemars(description = "What should happen after successful remediation (e.g., 'Vulnerability CVE-2024-1234 is patched', 'All existing tests pass')")]
    pub expected_outcomes: Vec<String>,

    /// Risks that require confirmation before applying
    #[schemars(description = "User-facing decisions or breaking changes requiring confirmation (NOT general warnings). Examples: 'This upgrade includes breaking API changes', 'This disables legacy feature X'")]
    pub confirmation_risks: Vec<String>,

    /// Reasoning for why these actions remediate the vulnerability
    #[schemars(description = "Step-by-step explanation of the remediation strategy and why the recommended version was selected (optional but recommended for auditability)")]
    pub reasoning: Option<String>,
}

/// LLM-extracted instruction structure
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "A single actionable remediation step")]
pub struct ExtractedInstruction {
    /// Domain of the instruction (dependency, code, configuration, build, annotation)
    #[schemars(description = "Type of action: dependency, code, configuration, build, test, or annotation")]
    pub domain: String,

    /// Action to perform
    #[schemars(description = "Clear, actionable description of the step (at least 10 characters)")]
    pub action: String,

    /// Parameters for the action (key-value pairs)
    #[schemars(description = "Specific parameters for automated execution (e.g., package_name, version, file_path, configuration_key)")]
    pub parameters: std::collections::HashMap<String, serde_json::Value>,
}
