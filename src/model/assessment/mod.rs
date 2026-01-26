//! LLM-extractable models for vulnerability assessment

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// LLM-extractable vulnerability assessment structure
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedAssessment {
    pub exploitability: ExtractedExploitability,
    pub impact: ExtractedImpact,
    pub limitations: Vec<ExtractedLimitation>,
}

/// Extracted exploitability assessment
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedExploitability {
    pub status: ExtractedExploitabilityStatus,
    pub certainty: ExtractedCertainty,
    pub conditions: Vec<String>,
    pub notes: Option<String>,
}

/// Extracted exploitability status
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedExploitabilityStatus {
    Exploitable,
    ConditionallyExploitable,
    NotExploitable,
    Unknown,
}

/// Extracted impact assessment
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedImpact {
    pub severity: ExtractedImpactSeverity,
    pub confidentiality: Option<ExtractedImpactLevel>,
    pub integrity: Option<ExtractedImpactLevel>,
    pub availability: Option<ExtractedImpactLevel>,
    pub notes: Option<String>,
}

/// Extracted impact severity
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedImpactSeverity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

/// Extracted impact level
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedImpactLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Extracted limitation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedLimitation {
    pub reason: ExtractedLimitationReason,
    pub description: String,
}

/// Extracted limitation reason
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedLimitationReason {
    InsufficientData,
    RuntimeDependent,
    EnvironmentSpecific,
    ConflictingData,
}

/// Extracted certainty (reused from claim extraction pattern)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedCertainty {
    Conditional,
    Strong,
    IdentificationOnly,
    Indicative,
}
