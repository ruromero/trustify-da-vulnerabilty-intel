use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod action_extraction;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicabilityResult {
    pub requires_action: ApplicabilityStatus,
    pub justification: String,
    pub confidence: ConfidenceLevel,
    pub sources: Vec<SourceType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicabilityStatus {
    Applicable,
    NotApplicable,
    Uncertain,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    Customer,
    Vendor,
    VersionCheck,
}
