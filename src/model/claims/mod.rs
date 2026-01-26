//! LLM-extractable models for claim extraction

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// LLM-extractable claim structure
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedClaims {
    pub claims: Vec<ExtractedClaim>,
}

/// A single extracted claim
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedClaim {
    #[serde(rename = "reason")]
    pub reason: ExtractedReason,
    pub certainty: ExtractedCertainty,
    pub excerpt: Option<String>,
    pub rationale: String,
}

/// Claim reason categories
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedReason {
    Identification,
    Exploitability,
    Impact,
    Mitigation,
}

/// Certainty levels
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedCertainty {
    Conditional,
    Strong,
    IdentificationOnly,
    Indicative,
}
