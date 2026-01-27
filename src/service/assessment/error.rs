//! Error types for vulnerability assessment

use thiserror::Error;

/// Error type for vulnerability assessment
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AssessmentError {
    #[error("LLM assessment failed: {0}")]
    AssessmentFailed(String),
}
