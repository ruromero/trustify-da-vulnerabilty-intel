//! Shared LLM client and interaction utilities
//!
//! Provides a common interface for OpenAI API interactions used across services.

use rig::providers::openai;

/// Shared LLM client wrapper
#[derive(Clone)]
pub struct LlmClient {
    client: openai::Client,
}

impl LlmClient {
    /// Create a new LLM client with the provided API key
    pub fn new(api_key: &str) -> Result<Self, String> {
        let client = openai::Client::new(api_key)
            .map_err(|e| format!("Failed to create OpenAI client: {}", e))?;

        Ok(Self { client })
    }

    /// Get a reference to the underlying OpenAI client
    /// Use this to create extractors with custom configuration
    pub fn openai_client(&self) -> &openai::Client {
        &self.client
    }
}
