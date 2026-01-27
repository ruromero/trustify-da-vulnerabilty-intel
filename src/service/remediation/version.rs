//! Version comparison utilities using semantic versioning

use crate::model::{AffectedRange, FixedRange, RangeType};
use semver::{Version, VersionReq};

/// Compare versions using semantic versioning when possible
pub fn version_in_range(version: &str, range: &AffectedRange) -> bool {
    // Try semantic version comparison first if range type is Semver
    if matches!(range.range_type, RangeType::Semver)
        && let Ok(ver) = Version::parse(version) {
            // Check introduced and last_affected with semver
            if let (Some(introduced), Some(last_affected)) =
                (&range.introduced, &range.last_affected)
                && let (Ok(intro_ver), Ok(last_ver)) =
                    (Version::parse(introduced), Version::parse(last_affected))
                {
                    return ver >= intro_ver && ver <= last_ver;
                }

            // Try parsing raw range as VersionReq
            if let Some(ref raw) = range.raw
                && let Ok(req) = VersionReq::parse(raw) {
                    return req.matches(&ver);
                }
        }

    // Fallback to string-based comparison for non-semver ranges
    if let Some(ref raw) = range.raw
        && raw.contains(version) {
            return true;
        }

    // Check introduced and last_affected with string comparison
    if let (Some(introduced), Some(last_affected)) = (&range.introduced, &range.last_affected) {
        version >= introduced.as_str() && version <= last_affected.as_str()
    } else {
        false
    }
}

/// Check if a version is in a fixed range
pub fn version_in_fixed_range(version: &str, range: &FixedRange) -> bool {
    // Try semantic version comparison first if range type is Semver
    if matches!(range.range_type, RangeType::Semver)
        && let Ok(ver) = Version::parse(version)
            && let Some(ref fixed) = range.fixed
                && let Ok(fixed_ver) = Version::parse(fixed) {
                    return ver >= fixed_ver;
                }

    // Fallback to string comparison
    if let Some(ref fixed) = range.fixed {
        version >= fixed.as_str()
    } else {
        false
    }
}

/// Select the optimal fixed version from a list of fixed ranges
/// Returns the lowest stable version that is greater than the affected range
pub fn select_optimal_fixed_version(
    fixed_ranges: &[FixedRange],
    affected_ranges: &[AffectedRange],
) -> Option<String> {
    let mut candidate_versions: Vec<Version> = Vec::new();

    // Collect all fixed versions that can be parsed as semver
    for range in fixed_ranges {
        if let Some(ref fixed) = range.fixed
            && let Ok(ver) = Version::parse(fixed) {
                // Prefer stable (non-pre-release) versions
                if ver.pre.is_empty() {
                    candidate_versions.push(ver);
                }
            }
    }

    if candidate_versions.is_empty() {
        // Fallback: return first fixed version as string
        return fixed_ranges
            .iter()
            .find_map(|r| r.fixed.clone());
    }

    // Find the highest affected version to compare against
    let mut max_affected: Option<Version> = None;
    for range in affected_ranges {
        if let Some(ref last_affected) = range.last_affected
            && let Ok(ver) = Version::parse(last_affected) {
                max_affected = Some(match max_affected {
                    Some(max) => {
                        if ver > max {
                            ver
                        } else {
                            max
                        }
                    }
                    None => ver,
                });
            }
    }

    // Filter to versions greater than max_affected, then select lowest
    if let Some(max_aff) = max_affected {
        candidate_versions.retain(|v| *v > max_aff);
    }

    if candidate_versions.is_empty() {
        // If no versions are greater than affected, return the lowest fixed version
        candidate_versions = fixed_ranges
            .iter()
            .filter_map(|r| r.fixed.as_ref().and_then(|s| Version::parse(s).ok()))
            .collect();
    }

    candidate_versions.sort();
    candidate_versions.first().map(|v| v.to_string())
}
