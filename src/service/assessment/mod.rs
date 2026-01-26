//! Vulnerability assessment service using LLM
//!
//! Synthesizes exploitability, impact, and limitations from claims and static data.

use rig::providers::openai;

use crate::model::assessments::ExtractedAssessment;
use crate::model::{ExploitabilityAssessment, ImpactAssessment, Limitation, VulnerabilityIntel};
use crate::service::assessment::confidence::compute_confidence;
use crate::service::assessment::converters::{
    convert_exploitability, convert_impact, convert_limitation,
};
use crate::service::assessment::prompts::{ASSESSMENT_SYSTEM_PROMPT, build_assessment_prompt};
use crate::service::llm::LlmClient;

/// Environment variable for assessment model (defaults to GPT-4O if not set)
const ENV_ASSESSMENT_MODEL: &str = "ASSESSMENT_MODEL";

/// Default model for vulnerability assessment (can be different from claim extraction)
const DEFAULT_MODEL: &str = openai::GPT_4O_MINI;

pub mod confidence;
pub mod converters;
pub mod error;
pub mod prompts;

pub use error::AssessmentError;

/// Service for assessing vulnerability exploitability, impact, and limitations
pub struct VulnerabilityAssessmentService {
    llm_client: LlmClient,
    model: String,
}

impl VulnerabilityAssessmentService {
    /// Creates a new assessment service
    ///
    /// Uses a shared LLM client passed from startup.
    /// Optionally uses ASSESSMENT_MODEL env var (defaults to gpt-4o-mini)
    pub fn new(llm_client: LlmClient) -> Self {
        // Allow different model for assessment vs claim extraction
        let model =
            std::env::var(ENV_ASSESSMENT_MODEL).unwrap_or_else(|_| DEFAULT_MODEL.to_string());

        tracing::info!(
            model = %model,
            "Vulnerability assessment service initialized"
        );

        Self { llm_client, model }
    }

    /// Assess exploitability, impact, and limitations from claims and static data
    pub async fn assess_vulnerability(
        &self,
        cve_id: &str,
        intel: &VulnerabilityIntel,
    ) -> Result<(ExploitabilityAssessment, ImpactAssessment, Vec<Limitation>), AssessmentError>
    {
        let start_time = std::time::Instant::now();

        tracing::debug!(
            cve = %cve_id,
            model = %self.model,
            claims_count = intel.claims.len(),
            "Initiating OpenAI API call for vulnerability assessment"
        );

        // Build assessment prompt
        let prompt = build_assessment_prompt(cve_id, intel);
        let prompt_length = prompt.len();

        // Create extractor and extract assessment using shared LLM client
        let extractor = self
            .llm_client
            .openai_client()
            .extractor::<ExtractedAssessment>(&self.model)
            .preamble(ASSESSMENT_SYSTEM_PROMPT)
            .build();

        let extracted = match extractor.extract(&prompt).await {
            Ok(result) => {
                let elapsed = start_time.elapsed();
                tracing::info!(
                    cve = %cve_id,
                    model = %self.model,
                    elapsed_ms = elapsed.as_millis(),
                    prompt_length = prompt_length,
                    "OpenAI API call for vulnerability assessment completed successfully"
                );
                result
            }
            Err(e) => {
                let elapsed = start_time.elapsed();
                tracing::error!(
                    cve = %cve_id,
                    model = %self.model,
                    elapsed_ms = elapsed.as_millis(),
                    prompt_length = prompt_length,
                    error = %e,
                    "OpenAI API call for vulnerability assessment failed"
                );
                return Err(AssessmentError::AssessmentFailed(e.to_string()));
            }
        };

        // Convert extracted assessment to domain models
        let exploitability = convert_exploitability(extracted.exploitability);
        let impact = convert_impact(extracted.impact);
        let limitations: Vec<Limitation> = extracted
            .limitations
            .into_iter()
            .map(convert_limitation)
            .collect();

        tracing::debug!(
            cve = %cve_id,
            limitations_count = limitations.len(),
            "Converted extracted assessment to domain models"
        );

        Ok((exploitability, impact, limitations))
    }

    /// Compute overall confidence based on claims, limitations, and exploitability
    pub async fn compute_confidence(
        &self,
        intel: &VulnerabilityIntel,
        exploitability: &ExploitabilityAssessment,
        limitations: &[Limitation],
    ) -> crate::model::OverallConfidence {
        compute_confidence(
            &self.llm_client,
            &self.model,
            intel,
            exploitability,
            limitations,
        )
        .await
    }
}
