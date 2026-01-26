//! Prompts for vulnerability assessment

use crate::model::VulnerabilityIntel;

/// System prompt for vulnerability assessment
pub const ASSESSMENT_SYSTEM_PROMPT: &str = r#"You are a security vulnerability analyst.

Your role is to synthesize exploitability, impact, and limitations assessments
from pre-extracted vulnerability intelligence.

You must:
- Base conclusions strictly on provided claims and evidence
- Respect claim certainty and trust level
- Avoid speculation or invention
- Be conservative when evidence is weak or incomplete
- Explicitly acknowledge uncertainty and conflicts

Do not:
- Invent attack scenarios or impacts
- Generalize vendor-specific data beyond its scope
- Treat CVSS scores as proof of exploitability

Your output must be structured JSON only and conform to the requested schema."#;

/// Build the assessment prompt from vulnerability intelligence
pub fn build_assessment_prompt(cve_id: &str, intel: &VulnerabilityIntel) -> String {
    // Extract relevant claims by category
    let exploitability_claims: Vec<_> = intel
        .claims
        .iter()
        .filter(|c| matches!(c.reason, crate::model::SourceClaimReason::Exploitability))
        .collect();

    let impact_claims: Vec<_> = intel
        .claims
        .iter()
        .filter(|c| matches!(c.reason, crate::model::SourceClaimReason::Impact))
        .collect();

    // Extract CVSS info
    let cvss_info = intel
        .cve_identity
        .cvss_vectors
        .iter()
        .map(|v| format!("{:?}: {}", v.cvss_type, v.vector))
        .collect::<Vec<_>>()
        .join(", ");

    // Build detailed claims information
    let claims_details = if intel.claims.is_empty() {
        "No claims extracted from reference documents.".to_string()
    } else {
        let mut details = format!(
            "Total claims: {}\nExploitability claims: {}\nImpact claims: {}\n\n",
            intel.claims.len(),
            exploitability_claims.len(),
            impact_claims.len()
        );

        // Add exploitability claims
        if !exploitability_claims.is_empty() {
            details.push_str("### Exploitability Claims:\n");
            for (i, claim) in exploitability_claims.iter().enumerate() {
                let excerpt = claim
                    .evidence
                    .first()
                    .and_then(|e| e.excerpt.as_ref())
                    .map(|s| s.as_str())
                    .unwrap_or("No excerpt");
                let rationale = claim.rationale.as_deref().unwrap_or("No rationale");
                details.push_str(&format!(
                    "{}. Certainty: {:?}\n   Excerpt: {}\n   Rationale: {}\n\n",
                    i + 1,
                    claim.certainty,
                    excerpt,
                    rationale
                ));
            }
        }

        // Add impact claims
        if !impact_claims.is_empty() {
            details.push_str("### Impact Claims:\n");
            for (i, claim) in impact_claims.iter().enumerate() {
                let excerpt = claim
                    .evidence
                    .first()
                    .and_then(|e| e.excerpt.as_ref())
                    .map(|s| s.as_str())
                    .unwrap_or("No excerpt");
                let rationale = claim.rationale.as_deref().unwrap_or("No rationale");
                details.push_str(&format!(
                    "{}. Certainty: {:?}\n   Excerpt: {}\n   Rationale: {}\n\n",
                    i + 1,
                    claim.certainty,
                    excerpt,
                    rationale
                ));
            }
        }

        // Add identification and mitigation claims for context
        let other_claims: Vec<_> = intel
            .claims
            .iter()
            .filter(|c| {
                matches!(
                    c.reason,
                    crate::model::SourceClaimReason::Identification
                        | crate::model::SourceClaimReason::Mitigation
                )
            })
            .collect();

        if !other_claims.is_empty() {
            details.push_str("### Other Relevant Claims:\n");
            for (i, claim) in other_claims.iter().take(5).enumerate() {
                let excerpt = claim
                    .evidence
                    .first()
                    .and_then(|e| e.excerpt.as_ref())
                    .map(|s| s.as_str())
                    .unwrap_or("No excerpt");
                details.push_str(&format!(
                    "{}. {:?} - {}\n",
                    i + 1,
                    claim.reason,
                    excerpt.chars().take(100).collect::<String>()
                ));
            }
        }

        details
    };

    // Format vendor remediations
    let vendor_remediations = if intel.vendor_remediations.is_empty() {
        "No vendor remediations available.".to_string()
    } else {
        intel
            .vendor_remediations
            .iter()
            .map(|r| {
                format!(
                    "- Category: {:?}, Vendor: {}, Details: {}",
                    r.category,
                    r.vendor,
                    r.details.as_deref().unwrap_or("No details")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Format affected versions
    let affected_versions = if intel.affected_versions.is_empty() {
        "No affected versions specified.".to_string()
    } else {
        intel
            .affected_versions
            .iter()
            .map(|v| format!("- {:?}", v))
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Format fixed versions
    let fixed_versions = if intel.fixed_versions.is_empty() {
        "No fixed versions specified.".to_string()
    } else {
        intel
            .fixed_versions
            .iter()
            .map(|v| format!("- {:?}", v))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"Assess the vulnerability {cve_id} using only the information provided below.

You must base your assessment strictly on the extracted claims and referenced evidence.
Do NOT invent new facts, attack scenarios, or impacts that are not supported by claims.

## Vulnerability Description
{description}

## CVSS Information
{cvss_info}
Note: CVSS indicates severity, not real-world exploitability. Use it only as supporting context.

## Extracted Claims
{claims_details}
Claims include certainty levels and evidence sources.
Prefer higher-certainty and higher-trust claims.
If claims conflict, reflect this explicitly in limitations.

## Affected Versions
{affected_versions}

## Fixed Versions
{fixed_versions}

## Vendor Remediations
{vendor_remediations}
Vendor remediations may apply only to specific products or distributions.

---

### Required Output

Produce structured JSON containing:

### 1. Exploitability
- status: exploitable | conditionally_exploitable | not_exploitable | unknown
- certainty
- conditions (if applicable)
- notes (optional)
- supported_by: list of claim IDs

### 2. Impact
- severity: low | medium | high | critical | unknown
- confidentiality, integrity, availability
- notes (optional)
- supported_by: list of claim IDs

### 3. Limitations
- reason
- description
- supported_by (optional claim IDs)

Guidelines:
- If evidence is insufficient, use "unknown" and explain why
- Do not repeat CVSS text unless supported by claims
- Prefer concrete impacts over abstract severity language
- Do not include remediation recommendations

Output JSON only."#,
        cve_id = cve_id,
        description = intel.cve_identity.description,
        cvss_info = if cvss_info.is_empty() {
            "No CVSS information available"
        } else {
            &cvss_info
        },
        claims_details = claims_details,
        affected_versions = affected_versions,
        fixed_versions = fixed_versions,
        vendor_remediations = vendor_remediations
    )
}
