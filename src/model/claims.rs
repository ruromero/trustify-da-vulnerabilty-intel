use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Response from LLM claim extraction
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Security claims extracted from a vulnerability reference document")]
pub struct ExtractedClaims {
    /// Array of security claims. Return empty array if no valid security claims exist.
    #[schemars(description = "List of security-relevant claims with evidence")]
    pub claims: Vec<ExtractedClaim>,
}

/// A single security claim extracted from a document
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "A security-relevant assertion with evidence")]
pub struct ExtractedClaim {
    /// Category of the claim
    #[serde(rename = "reason")]
    #[schemars(
        description = "Type of security claim: identification, exploitability, impact, or mitigation"
    )]
    pub reason: ExtractedReason,

    /// Confidence level of the claim
    #[schemars(
        description = "Certainty level: strong (explicitly stated), conditional (true under conditions), indicative (suggested), or identification_only (basic identification)"
    )]
    pub certainty: ExtractedCertainty,

    /// Verbatim excerpt from the document (1-3 sentences) that directly supports this claim
    #[schemars(
        description = "Exact quote from document, 1-3 sentences, must contain security-related terminology"
    )]
    pub excerpt: Option<String>,

    /// Direct, factual explanation of why this is a security claim
    #[schemars(
        description = "Factual explanation without meta-commentary (avoid 'this excerpt', 'this statement', etc.). Should be 20-300 characters."
    )]
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
