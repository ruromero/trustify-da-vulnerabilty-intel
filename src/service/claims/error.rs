//! Error types for claim extraction

use thiserror::Error;

/// Error type for claim extraction
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClaimExtractionError {
    #[error("LLM extraction failed: {0}")]
    ExtractionFailed(String),
}
