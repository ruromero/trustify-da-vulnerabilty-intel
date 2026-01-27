use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Complete vulnerability assessment from LLM
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Vulnerability assessment based on extracted claims and evidence")]
pub struct ExtractedAssessment {
    /// Exploitability assessment
    #[schemars(description = "Assessment of how the vulnerability can be exploited")]
    pub exploitability: ExtractedExploitability,

    /// Impact assessment
    #[schemars(description = "Assessment of the consequences if exploited")]
    pub impact: ExtractedImpact,

    /// Limitations and uncertainties in the assessment
    #[schemars(description = "Known limitations, conflicts, or gaps in the evidence")]
    pub limitations: Vec<ExtractedLimitation>,

    /// Chain-of-thought reasoning for auditability
    #[schemars(
        description = "Step-by-step explanation of how conclusions were reached (optional but recommended)"
    )]
    pub reasoning: Option<String>,
}

/// Exploitability assessment
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Assessment of exploitability based on provided claims")]
pub struct ExtractedExploitability {
    /// Exploitability status
    pub status: ExtractedExploitabilityStatus,

    /// Certainty of this assessment
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

/// Exploitability status
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "exploitable, conditionally_exploitable, not_exploitable, or unknown")]
#[serde(rename_all = "snake_case")]
pub enum ExtractedExploitabilityStatus {
    Exploitable,
    ConditionallyExploitable,
    NotExploitable,
    Unknown,
}

/// Impact assessment
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Assessment of the consequences if the vulnerability is exploited")]
pub struct ExtractedImpact {
    /// Overall severity
    pub severity: ExtractedImpactSeverity,

    /// Confidentiality impact
    pub confidentiality: Option<ExtractedImpactLevel>,

    /// Integrity impact
    pub integrity: Option<ExtractedImpactLevel>,

    /// Availability impact
    pub availability: Option<ExtractedImpactLevel>,

    /// Additional explanatory notes
    #[schemars(description = "Brief explanation of the impact assessment")]
    pub notes: Option<String>,

    /// Verbatim claim excerpts that support this assessment
    #[schemars(description = "List of exact claim excerpts that support this conclusion")]
    pub supported_by: Vec<String>,
}

/// Impact severity level
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Overall impact severity: low, medium, high, critical, or unknown")]
#[serde(rename_all = "snake_case")]
pub enum ExtractedImpactSeverity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

/// CIA impact level
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Impact level for confidentiality, integrity, or availability: none, low, medium, high, critical")]
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
#[schemars(description = "A known limitation, conflict, or uncertainty in the assessment")]
pub struct ExtractedLimitation {
    /// Category of limitation
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

/// Reason for assessment limitation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Type of limitation: insufficient_data, runtime_dependent, environment_specific, or conflicting_data")]
#[serde(rename_all = "snake_case")]
pub enum ExtractedLimitationReason {
    InsufficientData,
    RuntimeDependent,
    EnvironmentSpecific,
    ConflictingData,
}

/// Certainty level
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Confidence level: strong, conditional, indicative, or identification_only")]
#[serde(rename_all = "snake_case")]
pub enum ExtractedCertainty {
    Conditional,
    Strong,
    IdentificationOnly,
    Indicative,
}
