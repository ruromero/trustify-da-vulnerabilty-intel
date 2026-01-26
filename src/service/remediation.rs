//! Remediation plan service
//!
//! Generates remediation plans based on vulnerability assessments.

use std::sync::Arc;

use crate::model::{
    AffectedRange, ApplicabilityResult, ApplicabilitySourceType, ApplicabilityStatus,
    ClaimCertainty, FixedRange, PackageIdentity, RemediationCategory, RemediationConfidenceLevel,
    RemediationKind, RemediationOption, RemediationPlan, RemediationPlanRequest, RemediationStatus,
    Scope, SourceClaimReason, VendorRemediation, VulnerabilityAssessment,
};

/// Service for generating remediation plans
pub struct RemediationService {
    vulnerability_service: Arc<crate::service::VulnerabilityService>,
}

impl RemediationService {
    /// Create a new remediation service
    pub fn new(vulnerability_service: Arc<crate::service::VulnerabilityService>) -> Self {
        Self {
            vulnerability_service,
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
        // First, get the vulnerability assessment
        let assessment = self
            .vulnerability_service
            .get_vulnerability_intel(&request.cve, &request.package)
            .await
            .map_err(|e| RemediationError::AssessmentFailed(e.to_string()))?;

        // Determine applicability using priority-based checks
        let applicability = self.determine_applicability(request, &assessment);

        // Generate remediation options (Phase 2)
        let options = self.generate_remediation_options(request, &assessment);

        // Build remediation plan based on applicability and options
        let plan = RemediationPlan {
            applicable: matches!(applicability.applicable, ApplicabilityStatus::Applicable),
            actions: vec![],
            options,
            safe_defaults: vec![],
            confirmation_risks: vec![applicability.justification],
        };

        Ok((plan, assessment))
    }

    /// Determine applicability using priority-based checks
    fn determine_applicability(
        &self,
        request: &RemediationPlanRequest,
        assessment: &VulnerabilityAssessment,
    ) -> ApplicabilityResult {
        if let Some(ref trusted) = request.trusted_content
            && matches!(
                trusted.status,
                RemediationStatus::NotAffected | RemediationStatus::Fixed
            )
        {
            let justification = trusted
                .justification
                .as_deref()
                .unwrap_or("no justification provided");
            let justification_message = format!(
                "Trusted content remediation indicates {} for this exact purl ({})",
                justification, trusted.purl
            );

            tracing::info!(
                cve = %request.cve,
                purl = %trusted.purl,
                status = ?trusted.status,
                "Applicability determined from trusted content"
            );

            // Both Fixed and NotAffected mean the vulnerability is not applicable:
            // - NotAffected: Package was never vulnerable (not applicable)
            // - Fixed: Package was vulnerable but is now fixed (no longer applicable)
            let applicable = ApplicabilityStatus::NotApplicable;

            return ApplicabilityResult {
                applicable,
                justification: justification_message,
                confidence: RemediationConfidenceLevel::High,
                sources: vec![ApplicabilitySourceType::Customer],
            };
        }

        if let Some(result) = self.check_vendor_remediation_applicability(
            &request.package,
            &assessment.intel.vendor_remediations,
        ) {
            return result;
        }

        self.check_version_based_applicability(&request.package, &assessment.intel)
    }

    /// Check applicability based on vendor remediation (VEX/CSAF)
    fn check_vendor_remediation_applicability(
        &self,
        package: &PackageIdentity,
        vendor_remediations: &[VendorRemediation],
    ) -> Option<ApplicabilityResult> {
        if vendor_remediations.is_empty() {
            return None;
        }

        // Check if any vendor remediation matches the product
        // For now, we'll check if product_ids match the purl (simplified matching)
        let purl_str = package.purl.as_str();
        let mut matching_remediation: Option<&VendorRemediation> = None;
        let mut product_match_confidence = RemediationConfidenceLevel::Low;

        for remediation in vendor_remediations {
            // Check if product_ids contain the purl or match it
            let matches = remediation
                .product_ids
                .iter()
                .any(|product_id| purl_str.contains(product_id) || product_id.contains(purl_str));

            if matches {
                matching_remediation = Some(remediation);
                product_match_confidence = RemediationConfidenceLevel::High;
                break;
            }
        }

        // If no exact match, use the first remediation but note uncertainty
        let remediation = matching_remediation.or_else(|| vendor_remediations.first())?;
        let confidence = if matching_remediation.is_some() {
            product_match_confidence
        } else {
            RemediationConfidenceLevel::Low
        };

        // According to requirements:
        // vendor_fix -> applicable=true (remediation plan is applicable)
        // none_available -> applicable=true (remediation plan is applicable)
        // no_fix_planned -> applicable=false (no remediation plan applicable)
        let (applicable, category_desc) = match remediation.category {
            RemediationCategory::VendorFix => {
                (ApplicabilityStatus::Applicable, "vendor fix available")
            }
            RemediationCategory::NoneAvailable => {
                (ApplicabilityStatus::Applicable, "no vendor fix available")
            }
            RemediationCategory::NoFixPlanned => (
                ApplicabilityStatus::NotApplicable,
                "no fix planned by vendor",
            ),
            RemediationCategory::Workaround => {
                (ApplicabilityStatus::Applicable, "workaround available")
            }
            RemediationCategory::Other => {
                (ApplicabilityStatus::Uncertain, "other remediation category")
            }
        };

        let mut justification = format!(
            "Vendor remediation ({}) indicates {}",
            remediation.vendor, category_desc
        );

        if confidence == RemediationConfidenceLevel::Low {
            justification.push_str(". Note: Product matching uncertainty - vendor remediation may not apply to this exact package.");
        }

        tracing::info!(
            purl = %package.purl,
            vendor = %remediation.vendor,
            category = ?remediation.category,
            confidence = ?confidence,
            "Applicability determined from vendor remediation"
        );

        Some(ApplicabilityResult {
            applicable,
            justification,
            confidence,
            sources: vec![ApplicabilitySourceType::Vendor],
        })
    }

    /// Check applicability based on version comparison with affected/fixed ranges
    fn check_version_based_applicability(
        &self,
        package: &PackageIdentity,
        intel: &crate::model::VulnerabilityIntel,
    ) -> ApplicabilityResult {
        // Extract version from purl
        let package_version = self.extract_version_from_purl(&package.purl);

        if package_version.is_none() {
            return ApplicabilityResult {
                applicable: ApplicabilityStatus::Uncertain,
                justification: "Cannot determine applicability: version not found in package URL"
                    .to_string(),
                confidence: RemediationConfidenceLevel::Low,
                sources: vec![ApplicabilitySourceType::VersionCheck],
            };
        }

        let version = package_version.unwrap();

        // Check if version is in affected ranges
        let is_affected = intel
            .affected_versions
            .iter()
            .any(|range| self.version_in_range(&version, range));

        // Check if version is in fixed ranges
        let is_fixed = intel
            .fixed_versions
            .iter()
            .any(|range| self.version_in_fixed_range(&version, range));

        let (applicable, justification) = if is_affected && !is_fixed {
            (
                ApplicabilityStatus::Applicable,
                format!(
                    "Package version {} is in affected range and not fixed",
                    version
                ),
            )
        } else if !is_affected {
            (
                ApplicabilityStatus::NotApplicable,
                format!("Package version {} is outside affected ranges", version),
            )
        } else {
            // is_fixed or uncertain
            (
                ApplicabilityStatus::Uncertain,
                format!(
                    "Package version {} status cannot be determined from version ranges",
                    version
                ),
            )
        };

        tracing::info!(
            purl = %package.purl,
            version = %version,
            is_affected = is_affected,
            is_fixed = is_fixed,
            applicable = ?applicable,
            "Applicability determined from version check"
        );

        ApplicabilityResult {
            applicable,
            justification,
            confidence: RemediationConfidenceLevel::Medium,
            sources: vec![ApplicabilitySourceType::VersionCheck],
        }
    }

    /// Extract version from purl string
    /// PURL format: pkg:type/namespace/name@version?qualifiers#subpath
    fn extract_version_from_purl(&self, purl: &url::Url) -> Option<String> {
        let purl_str = purl.as_str();

        // PURLs typically have @version in them
        if let Some(at_pos) = purl_str.rfind('@') {
            let after_at = &purl_str[at_pos + 1..];
            // Version ends at ? (qualifiers) or # (subpath) or end of string
            let version_end = after_at
                .find('?')
                .or_else(|| after_at.find('#'))
                .unwrap_or(after_at.len());

            let version = &after_at[..version_end];
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }

        None
    }

    /// Check if a version is within a range
    /// This is a simplified check - in production, you'd want proper semantic version comparison
    fn version_in_range(&self, version: &str, range: &AffectedRange) -> bool {
        // For now, check if the version matches the raw range string
        // or falls between introduced and last_affected
        if let Some(ref raw) = range.raw
            && raw.contains(version)
        {
            return true;
        }

        // Check if version is between introduced and last_affected
        if let (Some(introduced), Some(last_affected)) = (&range.introduced, &range.last_affected) {
            // Simplified: check if version string appears in the range
            // In production, use proper semantic version comparison
            return version >= introduced.as_str() && version <= last_affected.as_str();
        }

        // If we have introduced but no last_affected, check if version >= introduced
        if let Some(introduced) = &range.introduced {
            return version >= introduced.as_str();
        }

        // If we have last_affected but no introduced, check if version <= last_affected
        if let Some(last_affected) = &range.last_affected {
            return version <= last_affected.as_str();
        }

        false
    }

    /// Check if a version is in a fixed range
    fn version_in_fixed_range(&self, version: &str, range: &FixedRange) -> bool {
        // For fixed ranges, check if the version matches the fixed version
        if let Some(ref fixed) = range.fixed {
            if fixed == version {
                return true;
            }
            // Also check if version >= fixed (meaning it's fixed in this or later version)
            return version >= fixed.as_str();
        }

        // Check raw range string
        if let Some(ref raw) = range.raw {
            return raw.contains(version);
        }

        false
    }

    /// Generate remediation options based on static logic and intel
    /// Phase 2: Enumerate possible ways to address the issue
    fn generate_remediation_options(
        &self,
        request: &RemediationPlanRequest,
        assessment: &VulnerabilityAssessment,
    ) -> Vec<RemediationOption> {
        let mut options = Vec::new();

        // Check each option type based on rules
        if let Some(option) = self.check_patch_upgrade_option(&request.package, &assessment.intel) {
            options.push(option);
        }

        if let Some(option) = self.check_code_change_option(&assessment.intel) {
            options.push(option);
        }

        if let Some(option) = self.check_configuration_change_option(&assessment.intel) {
            options.push(option);
        }

        if let Some(option) = self.check_dependency_removal_option(&request.package) {
            options.push(option);
        }

        if let Some(option) = self.check_alternative_library_option(&assessment.intel) {
            options.push(option);
        }

        if let Some(option) = self.check_ignore_false_positive_option(request, &assessment.intel) {
            options.push(option);
        }

        tracing::info!(
            cve = %request.cve,
            options_count = options.len(),
            "Generated remediation options"
        );

        options
    }

    /// Check if PatchUpgrade option is applicable
    /// Rule: fixed_versions not empty AND ecosystem supports upgrades
    fn check_patch_upgrade_option(
        &self,
        package: &PackageIdentity,
        intel: &crate::model::VulnerabilityIntel,
    ) -> Option<RemediationOption> {
        if intel.fixed_versions.is_empty() {
            return None;
        }

        if !self.ecosystem_supports_upgrades(&package.purl) {
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

        // Check for configuration-related keywords
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
                || excerpt.contains("variable")
                || excerpt.contains("config")
                || excerpt.contains("setting")
                || excerpt.contains("parameter")
                || excerpt.contains("option")
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
    /// Rule: scope ≠ runtime OR dependency is optional
    fn check_dependency_removal_option(
        &self,
        package: &PackageIdentity,
    ) -> Option<RemediationOption> {
        let is_non_runtime = !matches!(package.scope, Scope::Runtime);

        // Note: We don't have information about whether dependency is optional
        // This would need to come from package metadata or dependency graph analysis
        if !is_non_runtime {
            return None;
        }

        Some(RemediationOption {
            kind: RemediationKind::DependencyRemoval,
            description: format!(
                "DependencyRemoval (Medium confidence, package scope): Package scope is {:?}, removal may be feasible",
                package.scope
            ),
            migration_guide: None,
            certainty: ClaimCertainty::Conditional,
        })
    }

    /// Check if AlternativeLibrary option is applicable
    /// Rule: no fix available OR vendor says no_fix_planned
    fn check_alternative_library_option(
        &self,
        intel: &crate::model::VulnerabilityIntel,
    ) -> Option<RemediationOption> {
        let has_no_fix = intel.vendor_remediations.iter().any(|r| {
            matches!(r.category, RemediationCategory::NoFixPlanned)
                || matches!(r.category, RemediationCategory::NoneAvailable)
        });

        let has_fixed_versions = !intel.fixed_versions.is_empty();

        // If there are fixed versions, alternative library is not needed
        if has_fixed_versions {
            return None;
        }

        if !has_no_fix {
            return None;
        }

        let vendor_info = intel
            .vendor_remediations
            .iter()
            .find(|r| {
                matches!(r.category, RemediationCategory::NoFixPlanned)
                    || matches!(r.category, RemediationCategory::NoneAvailable)
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
}

/// Error type for remediation plan generation
#[derive(Debug, thiserror::Error)]
pub enum RemediationError {
    #[error("Failed to get vulnerability assessment: {0}")]
    AssessmentFailed(String),
}
