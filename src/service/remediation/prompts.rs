//! Prompts for remediation action generation

use crate::model::{RemediationOption, VulnerabilityIntel};

/// System prompt for remediation action generation
pub const ACTION_GENERATION_SYSTEM_PROMPT: &str = r#"You are a security remediation expert. Your task is to generate detailed, actionable remediation instructions based on a vulnerability assessment and a selected remediation option.

CRITICAL RULES:
1. DO NOT decide applicability - that has already been determined. Focus ONLY on HOW to implement the remediation.
2. Generate concrete, step-by-step instructions that can be executed.
3. Include all necessary preconditions (e.g., backup requirements, testing environments).
4. Clearly state expected outcomes and any risks that require confirmation.
5. Be specific about parameters, versions, and configurations.
6. Consider the package ecosystem and language when generating instructions.
7. Do not introduce remediation steps that are not implied by the selected remediation option.
8. When generating dependency instructions, always select a specific fixed version from Fixed Versions.
  If multiple fixed versions exist, prefer:
    - Lowest fixed version greater than the affected range
    - Stable (non-pre-release) versions

Your output must be structured and actionable."#;

/// Build prompt for generating a remediation action from an option
pub fn build_action_prompt(
    cve_id: &str,
    intel: &VulnerabilityIntel,
    option: &RemediationOption,
    ecosystem: &str,
    language: Option<&str>,
    optimal_fixed_version: Option<&str>,
) -> String {
    let language_info = language
        .map(|l| format!("Language: {}\n", l))
        .unwrap_or_default();

    let claims_summary = if intel.claims.is_empty() {
        "No claims available.".to_string()
    } else {
        intel
            .claims
            .iter()
            .take(10) // Limit to avoid prompt bloat
            .map(|c| {
                format!(
                    "- {}: {}",
                    format!("{:?}", c.reason),
                    c.evidence
                        .first()
                        .and_then(|e| e.excerpt.as_ref())
                        .unwrap_or(&"No excerpt".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"Package Information:
- PURL: {}
- Ecosystem: {}
{}

Selected Remediation Option:
- Kind: {:?}
- Description: {}
- Certainty: {:?}

Vulnerability Context:
- CVE: {}
- Description: {}

Relevant Claims (sample):
{}

Affected Versions:
{}

Fixed Versions:
{}

Recommended Fixed Version: {}

Generate:
1. Instructions: Break down into domain-specific actions (dependency, code, configuration, build, annotation) with specific parameters.
2. Preconditions: What must be true before applying this remediation (e.g., backups, test environment, dependencies).
3. Expected Outcomes: What should happen after successful remediation (e.g., vulnerability patched, no breaking changes).
4. Confirmation Risks must be user-facing decisions, not general warnings.
  Examples:
  - "This upgrade introduces a major version change"
  - "This configuration change disables feature X"
  - Avoid vague risks like "may cause issues".

Remember: Focus on HOW to implement, not whether it's applicable."#,
        intel.package_identity.purl,
        ecosystem,
        language_info,
        option.kind,
        option.description,
        option.certainty,
        cve_id,
        intel.cve_identity.description,
        claims_summary,
        format_versions(&intel.affected_versions),
        format_versions_fixed(&intel.fixed_versions),
        optimal_fixed_version
            .map(|v| format!("Use version: {}", v))
            .unwrap_or_else(|| "See Fixed Versions above".to_string()),
    )
}

fn format_versions(ranges: &[crate::model::AffectedRange]) -> String {
    if ranges.is_empty() {
        "None specified".to_string()
    } else {
        ranges
            .iter()
            .take(5)
            .map(|r| {
                format!(
                    "- {:?}: {}",
                    r.range_type,
                    r.raw.as_deref().unwrap_or("No raw range")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn format_versions_fixed(ranges: &[crate::model::FixedRange]) -> String {
    if ranges.is_empty() {
        "None specified".to_string()
    } else {
        ranges
            .iter()
            .take(5)
            .map(|r| {
                format!(
                    "- {:?}: {}",
                    r.range_type,
                    r.fixed.as_deref().unwrap_or("No fixed version")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
