use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Complete vulnerability assessment from LLM
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedAssessment {
    pub exploitability: ExtractedExploitability,

    pub impact: ExtractedImpact,

    pub limitations: Vec<ExtractedLimitation>,

    /// Chain-of-thought reasoning for auditability
    #[schemars(
        description = "Step-by-step explanation of how conclusions were reached (optional but recommended)"
    )]
    pub reasoning: Option<String>,
}

/// Exploitability assessment
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedExploitability {
    pub status: ExtractedExploitabilityStatus,

    pub certainty: ExtractedCertainty,

    /// Conditions required for exploitation (if conditionally_exploitable)
    #[schemars(
        description = "Specific conditions required for exploitation (e.g., 'requires authentication', 'XML parser must be enabled')"
    )]
    pub conditions: Vec<String>,

    /// Additional explanatory notes
    #[schemars(description = "Brief explanation of the exploitability assessment")]
    pub notes: Option<String>,

    /// Verbatim claim excerpts that support this assessment
    #[schemars(
        description = "List of exact claim excerpts that support this conclusion (required for auditability)"
    )]
    pub supported_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedExploitabilityStatus {
    Exploitable,
    ConditionallyExploitable,
    NotExploitable,
    Unknown,
}

/// Impact assessment
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedImpact {
    pub severity: ExtractedImpactSeverity,

    pub confidentiality: Option<ExtractedImpactLevel>,

    pub integrity: Option<ExtractedImpactLevel>,

    pub availability: Option<ExtractedImpactLevel>,

    /// Additional explanatory notes
    #[schemars(description = "Brief explanation of the impact assessment")]
    pub notes: Option<String>,

    /// Verbatim claim excerpts that support this assessment
    #[schemars(description = "List of exact claim excerpts that support this conclusion")]
    pub supported_by: Vec<String>,
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

/// Limitation or uncertainty in the assessment
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedLimitation {
    pub reason: ExtractedLimitationReason,

    /// Detailed explanation of the limitation
    #[schemars(
        description = "Clear explanation of what is uncertain or missing (at least 10 characters)"
    )]
    pub description: String,

    /// Optional: claim excerpts that highlight the limitation
    #[schemars(description = "Claim excerpts that demonstrate the conflict or gap (optional)")]
    pub supported_by: Option<Vec<String>>,
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
