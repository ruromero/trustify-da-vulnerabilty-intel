//! LLM-extractable models for remediation action generation

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// LLM-extracted remediation action structure
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedRemediationAction {
    /// Instructions broken down by domain
    pub instructions: Vec<ExtractedInstruction>,
    /// Preconditions that must be met before applying this action
    pub preconditions: Vec<String>,
    /// Expected outcomes after applying this action
    pub expected_outcomes: Vec<String>,
    /// Risks that require confirmation before applying
    pub confirmation_risks: Vec<String>,
}

/// LLM-extracted instruction structure
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedInstruction {
    /// Domain of the instruction (dependency, code, configuration, build, annotation)
    pub domain: String,
    /// Action to perform
    pub action: String,
    /// Parameters for the action (key-value pairs)
    pub parameters: std::collections::HashMap<String, serde_json::Value>,
}
