//! Remediation plan service
//!
//! Generates remediation plans based on vulnerability assessments.

use std::sync::Arc;

use crate::model::remediations::action_extraction::ExtractedRemediationAction;
use crate::model::{
    ApplicabilityResult, ApplicabilityStatus, ClaimCertainty, PackageIdentity, RemediationCategory,
    RemediationKind, RemediationOption, RemediationPlan, RemediationPlanRequest, RemediationStatus,
    Scope, SourceClaimReason, VulnerabilityAssessment,
};
use crate::service::cache::VulnerabilityCache;
use crate::service::cache_keys::generate_assessment_cache_key;
use crate::service::cache_keys::generate_remediation_cache_key;
use crate::service::llm::LlmClient;

mod applicability;
mod converters;
pub mod prompts;
mod validation;
mod version;

use applicability::determine_applicability;
use converters::convert_to_remediation_action;
use prompts::{ACTION_GENERATION_SYSTEM_PROMPT, build_action_prompt};
use version::select_optimal_fixed_version;

/// Environment variable for remediation model (defaults to GPT-4O if not set)
const ENV_REMEDIATION_MODEL: &str = "REMEDIATION_MODEL";

/// Default model for remediation action generation
const DEFAULT_REMEDIATION_MODEL: &str = rig::providers::openai::GPT_4O_MINI;

/// Service for generating remediation plans
pub struct RemediationService {
    vulnerability_service: Arc<crate::service::VulnerabilityService>,
    llm_client: LlmClient,
    model: String,
    cache: Option<VulnerabilityCache>,
}

impl RemediationService {
    /// Create a new remediation service
    pub fn new(
        vulnerability_service: Arc<crate::service::VulnerabilityService>,
        llm_client: LlmClient,
        cache: Option<VulnerabilityCache>,
    ) -> Self {
        let model = std::env::var(ENV_REMEDIATION_MODEL)
            .unwrap_or_else(|_| DEFAULT_REMEDIATION_MODEL.to_string());

        tracing::info!(
            model = %model,
            "Remediation service initialized"
        );

        Self {
            vulnerability_service,
            llm_client,
            model,
            cache,
        }
    }

    /// Generate a remediation plan for a vulnerability
    ///
    /// This reuses the vulnerability assessment functionality and uses it as input
    /// to generate a remediation plan.
    pub async fn generate_remediation_plan(
        &self,
        request: &RemediationPlanRequest,
    ) -> Result<(RemediationPlan, VulnerabilityAssessment), RemediationError> {
        let assessment = self
            .vulnerability_service
            .get_vulnerability_intel(&request.cve, &request.package)
            .await
            .map_err(|e| RemediationError::AssessmentFailed(e.to_string()))?;

        // Generate cache key for remediation plan
        // First, we need the assessment cache key to include in the remediation key
        let assessment_model_id = self.vulnerability_service.assessment_model_id();
        let assessment_cache_key = generate_assessment_cache_key(
            &request.cve,
            &assessment.intel,
            assessment_model_id,
        );
        let remediation_cache_key = generate_remediation_cache_key(
            request.trusted_content.as_ref(),
            &request.package,
            &self.model,
            &assessment_cache_key,
        );

        // Try to get from cache first
        if let Some(ref cache) = self.cache {
            match cache.get_remediation_plan::<(RemediationPlan, VulnerabilityAssessment)>(&remediation_cache_key).await {
                Ok((cached_plan, cached_assessment)) => {
                    tracing::debug!(
                        cve = %request.cve,
                        cache_key = %remediation_cache_key,
                        "Cache hit for remediation plan"
                    );
                    return Ok((cached_plan, cached_assessment));
                }
                Err(crate::service::cache::CacheError::Miss(_)) => {
                    tracing::debug!(
                        cve = %request.cve,
                        cache_key = %remediation_cache_key,
                        "Cache miss for remediation plan"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        cve = %request.cve,
                        error = %e,
                        "Cache error for remediation plan, continuing with generation"
                    );
                }
            }
        }

        let applicability = determine_applicability(request, &assessment);

        let options = self.generate_remediation_options(request, &assessment);

        // Step 3.1: Decide which options become actions
        let options_for_actions = self.select_options_for_actions(&applicability, &options);

        // Step 3.2: Generate RemediationAction per option (LLM) - in parallel
        let action_futures: Vec<_> = options_for_actions
            .iter()
            .map(|option| {
                self.generate_action_from_option_with_retry(
                    &assessment.intel,
                    option,
                    &request.package,
                )
            })
            .collect();

        // Wait for all actions to be generated in parallel
        let action_results = futures::future::join_all(action_futures).await;
        let all_actions: Vec<_> = action_results
            .into_iter()
            .filter_map(|result| {
                result
                    .map_err(|e| {
                        tracing::warn!(error = %e, "Failed to generate action after retries");
                        e
                    })
                    .ok()
            })
            .collect();

        // Step 3.3: Classify actions into safe_defaults vs actions
        let (safe_defaults, actions) = self.classify_actions(all_actions);

        // Step 4: Plan Assembly
        let mut confirmation_risks = vec![applicability.justification];
        if matches!(
            applicability.requires_action,
            ApplicabilityStatus::Uncertain
        ) {
            // Add confirmation risks from actions if uncertain
            for action in &actions {
                confirmation_risks.extend(action.confirmation_risks.clone());
            }
        }

        let plan = RemediationPlan {
            applicable: matches!(
                applicability.requires_action,
                ApplicabilityStatus::Applicable
            ),
            actions,
            options,
            safe_defaults,
            confirmation_risks,
        };

        // Cache the remediation plan
        if let Some(ref cache) = self.cache {
            if let Err(e) = cache.set_remediation_plan(&remediation_cache_key, &(plan.clone(), assessment.clone())).await {
                tracing::warn!(
                    cve = %request.cve,
                    error = %e,
                    "Failed to cache remediation plan"
                );
            } else {
                tracing::debug!(
                    cve = %request.cve,
                    cache_key = %remediation_cache_key,
                    "Cached remediation plan"
                );
            }
        }

        Ok((plan, assessment))
    }

    /// Generate remediation options (Phase 2)
    fn generate_remediation_options(
        &self,
        request: &RemediationPlanRequest,
        assessment: &VulnerabilityAssessment,
    ) -> Vec<RemediationOption> {
        let intel = &assessment.intel;
        let mut options = Vec::new();

        // Check each remediation option type
        if let Some(option) = self.check_patch_upgrade_option(intel) {
            options.push(option);
        }
        if let Some(option) = self.check_code_change_option(intel) {
            options.push(option);
        }
        if let Some(option) = self.check_configuration_change_option(intel) {
            options.push(option);
        }
        if let Some(option) = self.check_dependency_removal_option(intel) {
            options.push(option);
        }
        if let Some(option) = self.check_alternative_library_option(intel) {
            options.push(option);
        }
        if let Some(option) = self.check_ignore_false_positive_option(request, intel) {
            options.push(option);
        }

        options
    }

    /// Check if PatchUpgrade option is applicable
    /// Rule: fixed_versions exist AND ecosystem supports upgrades
    fn check_patch_upgrade_option(
        &self,
        intel: &crate::model::VulnerabilityIntel,
    ) -> Option<RemediationOption> {
        if intel.fixed_versions.is_empty() {
            return None;
        }

        if !self.ecosystem_supports_upgrades(&intel.package_identity.purl) {
            return None;
        }

        let fixed_versions_str = intel
            .fixed_versions
            .iter()
            .filter_map(|r| r.fixed.as_ref())
            .map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        let description = if fixed_versions_str.is_empty() {
            "PatchUpgrade (High confidence, vendor advisory): Fixed versions available for upgrade"
                .to_string()
        } else {
            format!(
                "PatchUpgrade (High confidence, vendor advisory): Upgrade to fixed version(s): {}",
                fixed_versions_str
            )
        };

        Some(RemediationOption {
            kind: RemediationKind::PatchUpgrade,
            description,
            migration_guide: None,
            certainty: ClaimCertainty::Strong,
        })
    }

    /// Check if CodeChange option is applicable
    /// Rule: mitigation claims include code snippets OR GitHub advisory suggests workaround
    fn check_code_change_option(
        &self,
        intel: &crate::model::VulnerabilityIntel,
    ) -> Option<RemediationOption> {
        let mitigation_claims: Vec<_> = intel
            .claims
            .iter()
            .filter(|c| matches!(c.reason, SourceClaimReason::Mitigation))
            .collect();

        if mitigation_claims.is_empty() {
            return None;
        }

        // Check if any mitigation claim mentions code or has code-like content
        let has_code_indicators = mitigation_claims.iter().any(|claim| {
            let excerpt = claim
                .evidence
                .first()
                .and_then(|e| e.excerpt.as_ref())
                .map(|s| s.to_lowercase())
                .unwrap_or_default();

            // Check for code-related keywords
            excerpt.contains("code")
                || excerpt.contains("function")
                || excerpt.contains("method")
                || excerpt.contains("class")
                || excerpt.contains("patch")
                || excerpt.contains("fix")
                || excerpt.contains("workaround")
        });

        // Check if any claim comes from GitHub advisory
        let has_github_advisory = mitigation_claims.iter().any(|claim| {
            claim
                .evidence
                .iter()
                .any(|e| e.reference_id.source.contains("github.com"))
        });

        if !has_code_indicators && !has_github_advisory {
            return None;
        }

        let confidence = if has_github_advisory {
            "High"
        } else {
            "Medium"
        };

        let source = if has_github_advisory {
            "GitHub advisory"
        } else {
            "mitigation claims"
        };

        Some(RemediationOption {
            kind: RemediationKind::CodeChange,
            description: format!(
                "CodeChange ({} confidence, {}): Code changes or workarounds suggested in mitigation claims",
                confidence, source
            ),
            migration_guide: None,
            certainty: if has_github_advisory {
                ClaimCertainty::Strong
            } else {
                ClaimCertainty::Conditional
            },
        })
    }

    /// Check if ConfigurationChange option is applicable
    /// Rule: mitigation claims mention flags, env vars, settings
    fn check_configuration_change_option(
        &self,
        intel: &crate::model::VulnerabilityIntel,
    ) -> Option<RemediationOption> {
        let mitigation_claims: Vec<_> = intel
            .claims
            .iter()
            .filter(|c| matches!(c.reason, SourceClaimReason::Mitigation))
            .collect();

        if mitigation_claims.is_empty() {
            return None;
        }

        let has_config_indicators = mitigation_claims.iter().any(|claim| {
            let excerpt = claim
                .evidence
                .first()
                .and_then(|e| e.excerpt.as_ref())
                .map(|s| s.to_lowercase())
                .unwrap_or_default();

            excerpt.contains("flag")
                || excerpt.contains("env")
                || excerpt.contains("environment")
                || excerpt.contains("setting")
                || excerpt.contains("config")
                || excerpt.contains("parameter")
        });

        if !has_config_indicators {
            return None;
        }

        Some(RemediationOption {
            kind: RemediationKind::ConfigurationChange,
            description: "ConfigurationChange (Medium confidence, mitigation claims): Configuration changes suggested in mitigation claims".to_string(),
            migration_guide: None,
            certainty: ClaimCertainty::Conditional,
        })
    }

    /// Check if DependencyRemoval option is applicable
    /// Rule: scope ≠ runtime OR optional dependency
    fn check_dependency_removal_option(
        &self,
        intel: &crate::model::VulnerabilityIntel,
    ) -> Option<RemediationOption> {
        let scope = &intel.package_identity.scope;

        if matches!(scope, Scope::Runtime) {
            return None;
        }

        let scope_desc = format!("{:?}", scope);
        Some(RemediationOption {
            kind: RemediationKind::DependencyRemoval,
            description: format!(
                "DependencyRemoval (Medium confidence, scope analysis): Dependency scope is {} (not runtime)",
                scope_desc
            ),
            migration_guide: None,
            certainty: ClaimCertainty::Conditional,
        })
    }

    /// Check if AlternativeLibrary option is applicable
    /// Rule: no fix available OR no fix planned
    fn check_alternative_library_option(
        &self,
        intel: &crate::model::VulnerabilityIntel,
    ) -> Option<RemediationOption> {
        let has_no_fix = intel.vendor_remediations.iter().any(|r| {
            matches!(
                r.category,
                RemediationCategory::NoneAvailable | RemediationCategory::NoFixPlanned
            )
        });

        if !has_no_fix {
            return None;
        }

        let vendor_info = intel
            .vendor_remediations
            .iter()
            .find(|r| {
                matches!(
                    r.category,
                    RemediationCategory::NoneAvailable | RemediationCategory::NoFixPlanned
                )
            })
            .map(|r| r.vendor.as_str())
            .unwrap_or("vendor");

        Some(RemediationOption {
            kind: RemediationKind::AlternativeLibrary,
            description: format!(
                "AlternativeLibrary (High confidence, {}): No fix available or no fix planned by vendor",
                vendor_info
            ),
            migration_guide: None,
            certainty: ClaimCertainty::Strong,
        })
    }

    /// Check if IgnoreFalsePositive option is applicable
    /// Rule: customer or vendor says NotAffected
    fn check_ignore_false_positive_option(
        &self,
        request: &RemediationPlanRequest,
        _intel: &crate::model::VulnerabilityIntel,
    ) -> Option<RemediationOption> {
        // Check trusted content (customer)
        let customer_says_not_affected = request
            .trusted_content
            .as_ref()
            .map(|t| matches!(t.status, RemediationStatus::NotAffected))
            .unwrap_or(false);

        // Check vendor remediations for NotAffected indication
        // Note: Vendor remediations don't directly say "NotAffected", but we can infer
        // from the context. For now, we'll only check customer trusted content.

        if !customer_says_not_affected {
            return None;
        }

        Some(RemediationOption {
            kind: RemediationKind::IgnoreFalsePositive,
            description: "IgnoreFalsePositive (High confidence, customer): Customer indicates package is not affected".to_string(),
            migration_guide: None,
            certainty: ClaimCertainty::Strong,
        })
    }

    /// Check if ecosystem supports upgrades based on purl type
    /// Most package ecosystems support upgrades (npm, pypi, maven, etc.)
    fn ecosystem_supports_upgrades(&self, purl: &url::Url) -> bool {
        let purl_str = purl.as_str();

        // Most common ecosystems support upgrades
        // This is a simplified check - in production, you might want a more comprehensive list
        purl_str.starts_with("pkg:npm/")
            || purl_str.starts_with("pkg:pypi/")
            || purl_str.starts_with("pkg:maven/")
            || purl_str.starts_with("pkg:cargo/")
            || purl_str.starts_with("pkg:composer/")
            || purl_str.starts_with("pkg:nuget/")
            || purl_str.starts_with("pkg:gem/")
            || purl_str.starts_with("pkg:golang/")
            || purl_str.starts_with("pkg:hex/")
    }

    /// Step 3.1: Decide which options become actions
    /// Rules:
    /// - If applicable = false → no actions, only options
    /// - If applicable = uncertain → actions allowed, but must include confirmation risks
    fn select_options_for_actions(
        &self,
        applicability: &ApplicabilityResult,
        options: &[RemediationOption],
    ) -> Vec<RemediationOption> {
        match applicability.requires_action {
            ApplicabilityStatus::NotApplicable => {
                // No actions if not applicable
                vec![]
            }
            ApplicabilityStatus::Applicable | ApplicabilityStatus::Uncertain => {
                // All options can become actions if applicable or uncertain
                options.to_vec()
            }
        }
    }

    /// Step 3.2: Generate RemediationAction per option (LLM) with retry logic
    async fn generate_action_from_option_with_retry(
        &self,
        intel: &crate::model::VulnerabilityIntel,
        option: &RemediationOption,
        package: &PackageIdentity,
    ) -> Result<crate::model::RemediationAction, RemediationError> {
        const MAX_RETRIES: u32 = 3;
        const INITIAL_RETRY_DELAY_MS: u64 = 500;

        let mut last_error = None;

        for attempt in 0..=MAX_RETRIES {
            match self
                .generate_action_from_option(intel, option, package)
                .await
            {
                Ok(action) => {
                    if attempt > 0 {
                        tracing::info!(
                            cve = %intel.cve_identity.cve,
                            option_kind = ?option.kind,
                            attempt = attempt,
                            "LLM action generation succeeded after retry"
                        );
                    }
                    return Ok(action);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < MAX_RETRIES {
                        let delay_ms = INITIAL_RETRY_DELAY_MS * (1 << attempt); // Exponential backoff
                        tracing::warn!(
                            cve = %intel.cve_identity.cve,
                            option_kind = ?option.kind,
                            attempt = attempt + 1,
                            max_retries = MAX_RETRIES,
                            delay_ms = delay_ms,
                            "LLM action generation failed, retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            RemediationError::ActionGenerationFailed("Failed after all retries".to_string())
        }))
    }

    /// Step 3.2: Generate RemediationAction per option (LLM)
    async fn generate_action_from_option(
        &self,
        intel: &crate::model::VulnerabilityIntel,
        option: &RemediationOption,
        package: &PackageIdentity,
    ) -> Result<crate::model::RemediationAction, RemediationError> {
        let start_time = std::time::Instant::now();

        let ecosystem = self.extract_ecosystem_from_purl(&package.purl);
        let language = self.extract_language_from_purl(&package.purl);

        tracing::debug!(
            cve = %intel.cve_identity.cve,
            option_kind = ?option.kind,
            ecosystem = %ecosystem,
            "Generating remediation action from option"
        );

        // Select optimal fixed version if this is a PatchUpgrade option
        let optimal_fixed_version = if matches!(option.kind, RemediationKind::PatchUpgrade) {
            select_optimal_fixed_version(&intel.fixed_versions, &intel.affected_versions)
        } else {
            None
        };

        // Build prompt
        let prompt = build_action_prompt(
            &intel.cve_identity.cve,
            intel,
            option,
            &ecosystem,
            language.as_deref(),
            optimal_fixed_version.as_deref(),
        );
        let prompt_length = prompt.len();

        // Create extractor and extract action using shared LLM client
        // Use temperature=0.1 (slightly creative for phrasing) and seed for reproducibility
        let extractor = self
            .llm_client
            .openai_client()
            .extractor::<ExtractedRemediationAction>(&self.model)
            .preamble(ACTION_GENERATION_SYSTEM_PROMPT)
            .additional_params(serde_json::json!({
                "temperature": 0.1,
                "seed": 42
            }))
            .build();

        let extracted = match extractor.extract(&prompt).await {
            Ok(result) => {
                let elapsed = start_time.elapsed();
                tracing::info!(
                    cve = %intel.cve_identity.cve,
                    option_kind = ?option.kind,
                    model = %self.model,
                    elapsed_ms = elapsed.as_millis(),
                    prompt_length = prompt_length,
                    "LLM action generation completed successfully"
                );
                result
            }
            Err(e) => {
                let elapsed = start_time.elapsed();
                tracing::error!(
                    cve = %intel.cve_identity.cve,
                    option_kind = ?option.kind,
                    model = %self.model,
                    elapsed_ms = elapsed.as_millis(),
                    prompt_length = prompt_length,
                    error = %e,
                    "LLM action generation failed"
                );
                return Err(RemediationError::ActionGenerationFailed(e.to_string()));
            }
        };

        // Validate extracted remediation action
        let validation_result = validation::validate_extracted_remediation(
            &extracted,
            optimal_fixed_version.as_deref(),
        );

        if !validation_result.is_valid {
            tracing::error!(
                cve = %intel.cve_identity.cve,
                option_kind = ?option.kind,
                errors = ?validation_result.errors,
                "Remediation action validation failed"
            );
            return Err(RemediationError::ActionGenerationFailed(format!(
                "Validation failed: {}",
                validation_result.errors.join("; ")
            )));
        }

        if !validation_result.warnings.is_empty() {
            tracing::warn!(
                cve = %intel.cve_identity.cve,
                option_kind = ?option.kind,
                warnings = ?validation_result.warnings,
                "Remediation action produced quality warnings"
            );
        }

        // Convert extracted action to domain model
        let action = convert_to_remediation_action(
            extracted,
            option.kind.clone(),
            option.description.clone(),
            language,
        );

        Ok(action)
    }

    /// Step 3.3: Classify actions into safe_defaults vs actions
    /// Low risk actions go to safe_defaults:
    /// - Patch upgrade within same minor version
    /// - Suppress false positive with justification
    ///
    /// Everything else goes to actions
    fn classify_actions(
        &self,
        actions: Vec<crate::model::RemediationAction>,
    ) -> (
        Vec<crate::model::RemediationAction>,
        Vec<crate::model::RemediationAction>,
    ) {
        let mut safe_defaults = Vec::new();
        let mut regular_actions = Vec::new();

        for action in actions {
            if self.is_safe_default(&action) {
                safe_defaults.push(action);
            } else {
                regular_actions.push(action);
            }
        }

        (safe_defaults, regular_actions)
    }

    /// Check if an action is a safe default
    fn is_safe_default(&self, action: &crate::model::RemediationAction) -> bool {
        match action.kind {
            RemediationKind::PatchUpgrade => {
                // Check if it's a patch upgrade within same minor version
                // This is a simplified check - in production, you'd parse versions properly
                action.description.to_lowercase().contains("patch")
                    || action.description.to_lowercase().contains("minor")
            }
            RemediationKind::IgnoreFalsePositive => {
                // Suppress false positive with justification is safe
                true
            }
            _ => false,
        }
    }

    /// Extract ecosystem from PURL
    /// PURL format: pkg:type/namespace/name@version
    fn extract_ecosystem_from_purl(&self, purl: &url::Url) -> String {
        let purl_str = purl.as_str();
        // Extract type from pkg:type/...
        if let Some(start) = purl_str.find(':')
            && let Some(end) = purl_str[start + 1..].find('/') {
                return purl_str[start + 1..start + 1 + end].to_string();
            }
        "unknown".to_string()
    }

    /// Extract language from PURL based on ecosystem
    fn extract_language_from_purl(&self, purl: &url::Url) -> Option<String> {
        let ecosystem = self.extract_ecosystem_from_purl(purl);
        match ecosystem.as_str() {
            "npm" => Some("JavaScript".to_string()),
            "pypi" => Some("Python".to_string()),
            "maven" => Some("Java".to_string()),
            "cargo" => Some("Rust".to_string()),
            "composer" => Some("PHP".to_string()),
            "nuget" => Some("C#".to_string()),
            "gem" => Some("Ruby".to_string()),
            "golang" => Some("Go".to_string()),
            "hex" => Some("Elixir".to_string()),
            _ => None,
        }
    }
}

/// Error type for remediation plan generation
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemediationError {
    #[error("Failed to get vulnerability assessment: {0}")]
    AssessmentFailed(String),
    #[error("Failed to generate remediation action: {0}")]
    ActionGenerationFailed(String),
}
