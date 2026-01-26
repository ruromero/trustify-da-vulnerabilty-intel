use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedAssessment {
    pub exploitability: ExtractedExploitability,
    pub impact: ExtractedImpact,
    pub limitations: Vec<ExtractedLimitation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedExploitability {
    pub status: ExtractedExploitabilityStatus,
    pub certainty: ExtractedCertainty,
    pub conditions: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedExploitabilityStatus {
    Exploitable,
    ConditionallyExploitable,
    NotExploitable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedImpact {
    pub severity: ExtractedImpactSeverity,
    pub confidentiality: Option<ExtractedImpactLevel>,
    pub integrity: Option<ExtractedImpactLevel>,
    pub availability: Option<ExtractedImpactLevel>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedImpactSeverity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedImpactLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedLimitation {
    pub reason: ExtractedLimitationReason,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedLimitationReason {
    InsufficientData,
    RuntimeDependent,
    EnvironmentSpecific,
    ConflictingData,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedCertainty {
    Conditional,
    Strong,
    IdentificationOnly,
    Indicative,
}
