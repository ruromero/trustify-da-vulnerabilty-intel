//! Applicability determination logic
//!
//! Determines whether a vulnerability is applicable to a specific package version
//! using a priority-based approach:
//! 1. Trusted content (customer-provided VEX data) - highest priority
//! 2. Vendor remediation information (CSAF/VEX)
//! 3. Version-based analysis (semantic version comparison)

use crate::model::{
    ApplicabilityResult, ApplicabilitySourceType, ApplicabilityStatus, PackageIdentity,
    RemediationCategory, RemediationConfidenceLevel, RemediationPlanRequest, VendorRemediation,
    VulnerabilityAssessment, VulnerabilityIntel,
};
use crate::service::remediation::version::{version_in_fixed_range, version_in_range};

/// Determine applicability using priority-based checks
///
/// Priority order:
/// 1. Trusted content (customer VEX data)
/// 2. Vendor remediation (CSAF data)
/// 3. Version-based analysis
pub fn determine_applicability(
    request: &RemediationPlanRequest,
    assessment: &VulnerabilityAssessment,
) -> ApplicabilityResult {
    // Priority 1: Check trusted content (customer VEX data)
    if let Some(result) = check_trusted_content(request) {
        return result;
    }

    // Priority 2: Check vendor remediation
    if let Some(result) = check_vendor_remediation_applicability(
        &request.package,
        &assessment.intel.vendor_remediations,
    ) {
        return result;
    }

    // Priority 3: Check version-based applicability
    check_version_based_applicability(&request.package, &assessment.intel)
}

/// Check trusted content (Priority 1)
/// When a purl is provided, it is expected to indicate Fixed or NotAffected; justification is not used.
fn check_trusted_content(request: &RemediationPlanRequest) -> Option<ApplicabilityResult> {
    let purl = request.trusted_content.as_ref()?;

    let justification = "Vendor provided remediation".to_string();

    tracing::info!(
        cve = %request.cve,
        purl = %purl,
        "Applicability determined from trusted content (purl)"
    );

    // Presence of trusted purl means not required to be remediated (Fixed or NotAffected)
    let requires_action = ApplicabilityStatus::NotApplicable;

    Some(ApplicabilityResult {
        requires_action,
        justification,
        confidence: RemediationConfidenceLevel::High,
        sources: vec![ApplicabilitySourceType::Customer],
    })
}

/// Check vendor remediation applicability (Priority 2)
fn check_vendor_remediation_applicability(
    package: &PackageIdentity,
    vendor_remediations: &[VendorRemediation],
) -> Option<ApplicabilityResult> {
    for remediation in vendor_remediations {
        // Check if product matches (simplified - in production, match product_ids properly)
        let product_matches = remediation
            .product_ids
            .iter()
            .any(|pid| package.purl.as_str().contains(pid));

        if !product_matches {
            continue;
        }

        let requires_action = match remediation.category {
            RemediationCategory::VendorFix => ApplicabilityStatus::Applicable,
            RemediationCategory::NoneAvailable => ApplicabilityStatus::Applicable,
            RemediationCategory::NoFixPlanned => ApplicabilityStatus::NotApplicable,
            RemediationCategory::Workaround => ApplicabilityStatus::Applicable,
            RemediationCategory::Other => ApplicabilityStatus::Uncertain,
        };

        // Make explicit distinction for NotApplicable cases
        let justification = match requires_action {
            ApplicabilityStatus::NotApplicable => {
                format!(
                    "Not affected: vendor indicates no fix planned (vendor: {}). Product matching: {}",
                    remediation.vendor,
                    if product_matches {
                        "high confidence"
                    } else {
                        "low confidence"
                    }
                )
            }
            _ => {
                format!(
                    "Vendor remediation ({:?}) indicates {:?} for product matching purl. Product matching uncertainty: {}",
                    remediation.category,
                    requires_action,
                    if product_matches {
                        "high confidence"
                    } else {
                        "low confidence"
                    }
                )
            }
        };

        let confidence = if product_matches {
            RemediationConfidenceLevel::High
        } else {
            RemediationConfidenceLevel::Medium
        };

        return Some(ApplicabilityResult {
            requires_action,
            justification,
            confidence,
            sources: vec![ApplicabilitySourceType::Vendor],
        });
    }

    None
}

/// Check version-based applicability (Priority 3)
fn check_version_based_applicability(
    package: &PackageIdentity,
    intel: &VulnerabilityIntel,
) -> ApplicabilityResult {
    let package_version = extract_version_from_purl(&package.purl);

    if package_version.is_none() {
        return ApplicabilityResult {
            requires_action: ApplicabilityStatus::Uncertain,
            justification: "Cannot determine applicability: version not found in package URL"
                .to_string(),
            confidence: RemediationConfidenceLevel::Low,
            sources: vec![ApplicabilitySourceType::VersionCheck],
        };
    }

    let version = package_version.unwrap();
    let mut is_affected = false;
    let mut is_fixed = false;

    // Check if version is in affected ranges
    for range in &intel.affected_versions {
        if version_in_range(&version, range) {
            is_affected = true;
            break;
        }
    }

    // Check if version is in fixed ranges
    for range in &intel.fixed_versions {
        if version_in_fixed_range(&version, range) {
            is_fixed = true;
            break;
        }
    }

    let requires_action = if is_affected && !is_fixed {
        ApplicabilityStatus::Applicable
    } else if !is_affected {
        ApplicabilityStatus::NotApplicable
    } else {
        ApplicabilityStatus::Uncertain
    };

    // Make explicit distinction between "never vulnerable" and "already fixed"
    let justification = match (is_affected, is_fixed) {
        (false, _) => {
            format!(
                "Not affected: vulnerable code not present in version {} (version is outside affected range)",
                version
            )
        }
        (true, true) => {
            // Find the fixed version for clarity
            let fixed_version_info = intel
                .fixed_versions
                .iter()
                .find_map(|r| r.fixed.as_ref())
                .map(|fv| format!("version {}", fv))
                .unwrap_or_else(|| "a fixed version".to_string());

            format!(
                "Already fixed: vulnerability was present but has been remediated in {} (current version: {})",
                fixed_version_info, version
            )
        }
        (true, false) => {
            format!(
                "Version {} is within affected range and not yet fixed",
                version
            )
        }
    };

    tracing::info!(
        purl = %package.purl,
        version = %version,
        is_affected = is_affected,
        is_fixed = is_fixed,
        requires_action = ?requires_action,
        "Applicability determined from version check"
    );

    ApplicabilityResult {
        requires_action,
        justification,
        confidence: RemediationConfidenceLevel::Medium,
        sources: vec![ApplicabilitySourceType::VersionCheck],
    }
}

/// Extract version from purl string
///
/// PURL format: pkg:type/namespace/name@version?qualifiers#subpath
fn extract_version_from_purl(purl: &url::Url) -> Option<String> {
    let purl_str = purl.as_str();

    // PURLs typically have @version in them
    if let Some(at_pos) = purl_str.rfind('@') {
        let after_at = &purl_str[at_pos + 1..];
        // Version ends at ? or # or end of string
        let version_end = after_at
            .find('?')
            .or_else(|| after_at.find('#'))
            .unwrap_or(after_at.len());

        return Some(after_at[..version_end].to_string());
    }

    None
}
