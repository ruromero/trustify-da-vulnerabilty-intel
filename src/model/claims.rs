use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedClaims {
    pub claims: Vec<ExtractedClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedClaim {
    #[serde(rename = "reason")]
    pub reason: ExtractedReason,
    pub certainty: ExtractedCertainty,
    pub excerpt: Option<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedReason {
    Identification,
    Exploitability,
    Impact,
    Mitigation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedCertainty {
    Conditional,
    Strong,
    IdentificationOnly,
    Indicative,
}
