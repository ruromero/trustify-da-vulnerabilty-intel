//! Conversions between OSV API types and domain types

use chrono::{DateTime, Utc};
use url::Url;

use super::intel::{
    AffectedRange, CveIdentity, CveReference, CvssType, CvssVector, FixedRange, RangeType,
    SourceType,
};
use super::osv::{
    OsvAffected, OsvRange, OsvRangeType, OsvReference, OsvReferenceType, OsvSeverity,
    OsvVulnerability,
};

impl From<OsvVulnerability> for CveIdentity {
    fn from(osv: OsvVulnerability) -> Self {
        let published = parse_datetime(osv.published);
        let last_modified = parse_datetime(osv.modified);

        CveIdentity {
            cve: osv.id,
            description: osv.summary.unwrap_or_default(),
            aliases: osv.aliases,
            cvss_vectors: osv.severity.into_iter().map(Into::into).collect(),
            references: osv
                .references
                .into_iter()
                .filter_map(|r| r.try_into().ok())
                .collect(),
            published,
            last_modified,
        }
    }
}

impl From<OsvSeverity> for CvssVector {
    fn from(severity: OsvSeverity) -> Self {
        let cvss_type = match severity.severity_type.as_str() {
            "CVSS_V2" => CvssType::V2,
            "CVSS_V3" => CvssType::V3,
            "CVSS_V4" => CvssType::V4,
            _ => CvssType::Unknown,
        };
        CvssVector {
            cvss_type,
            vector: severity.score,
        }
    }
}

impl TryFrom<OsvReference> for CveReference {
    type Error = url::ParseError;

    fn try_from(reference: OsvReference) -> Result<Self, Self::Error> {
        Ok(CveReference {
            url: Url::parse(&reference.url)?,
            source_type: reference.ref_type.into(),
        })
    }
}

impl From<OsvReferenceType> for SourceType {
    fn from(ref_type: OsvReferenceType) -> Self {
        match ref_type {
            OsvReferenceType::Advisory => SourceType::Advisory,
            OsvReferenceType::Article => SourceType::Article,
            OsvReferenceType::Detection => SourceType::Detection,
            OsvReferenceType::Discussion => SourceType::Discussion,
            OsvReferenceType::Report => SourceType::Report,
            OsvReferenceType::Fix => SourceType::Fix,
            OsvReferenceType::Introduced => SourceType::Introduced,
            OsvReferenceType::Package => SourceType::Package,
            OsvReferenceType::Evidence => SourceType::Evidence,
            OsvReferenceType::Web => SourceType::Web,
            OsvReferenceType::Unknown => SourceType::Unknown,
        }
    }
}

fn parse_datetime(datetime: Option<String>) -> DateTime<Utc> {
    datetime
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now)
}

impl From<OsvRangeType> for RangeType {
    fn from(range_type: OsvRangeType) -> Self {
        match range_type {
            OsvRangeType::Semver => RangeType::Semver,
            OsvRangeType::Ecosystem => RangeType::Ecosystem,
            OsvRangeType::Git => RangeType::Git,
            OsvRangeType::Unknown => RangeType::Ecosystem, // Default to ecosystem
        }
    }
}

/// Extracted version information from OSV affected data
#[derive(Debug, Default)]
pub struct ExtractedVersions {
    pub affected: Vec<AffectedRange>,
    pub fixed: Vec<FixedRange>,
}

/// Extract affected and fixed version ranges from OSV affected entries
///
/// This function processes the OSV affected array and extracts:
/// - Affected versions: ranges where the vulnerability exists (introduced..fixed or introduced..last_affected)
/// - Fixed versions: specific versions where the vulnerability was fixed
pub fn extract_versions_from_affected(
    affected_entries: &[OsvAffected],
    purl: Option<&str>,
) -> ExtractedVersions {
    let mut result = ExtractedVersions::default();

    for affected in affected_entries {
        // If purl is provided, filter by matching package
        if let Some(purl) = purl
            && let Some(ref pkg) = affected.package
            && let Some(ref pkg_purl) = pkg.purl
            && pkg_purl != purl
        {
            continue;
        }

        // Process explicit versions list
        for version in &affected.versions {
            result.affected.push(AffectedRange {
                range_type: RangeType::Ecosystem,
                introduced: Some(version.clone()),
                last_affected: Some(version.clone()),
                raw: Some(version.clone()),
            });
        }

        // Process ranges
        for range in &affected.ranges {
            let range_versions = extract_from_range(range);
            result.affected.extend(range_versions.affected);
            result.fixed.extend(range_versions.fixed);
        }
    }

    result
}

/// Extract version ranges from a single OSV range
fn extract_from_range(range: &OsvRange) -> ExtractedVersions {
    let mut result = ExtractedVersions::default();

    // Process the main events (may be git commits or versions depending on range type)
    let main_range_type: RangeType = range.range_type.clone().into();
    let main_versions = extract_from_events(&range.events, main_range_type);
    result.affected.extend(main_versions.affected);
    result.fixed.extend(main_versions.fixed);

    // Process database_specific.versions if present (semantic versions for GIT ranges)
    if let Some(ref db_specific) = range.database_specific
        && !db_specific.versions.is_empty()
    {
        // These are semantic versions, use Semver type
        let semver_versions = extract_from_events(&db_specific.versions, RangeType::Semver);
        result.affected.extend(semver_versions.affected);
        result.fixed.extend(semver_versions.fixed);
    }

    result
}

/// Extract version ranges from a list of OSV events
fn extract_from_events(
    events: &[super::osv::OsvEvent],
    range_type: RangeType,
) -> ExtractedVersions {
    let mut result = ExtractedVersions::default();

    // Each "introduced" starts a vulnerable range, "fixed" or "last_affected" ends it
    let mut current_introduced: Option<String> = None;

    for event in events {
        if let Some(ref introduced) = event.introduced {
            // Start of a new vulnerable range
            current_introduced = Some(introduced.clone());
        }

        if let Some(ref fixed) = event.fixed {
            // End of vulnerable range with a fix
            result.affected.push(AffectedRange {
                range_type: range_type.clone(),
                introduced: current_introduced.clone(),
                last_affected: None,
                raw: None,
            });

            // Record the fixed version
            result.fixed.push(FixedRange {
                range_type: range_type.clone(),
                fixed: Some(fixed.clone()),
                raw: None,
            });

            current_introduced = None;
        }

        if let Some(ref last_affected) = event.last_affected {
            // End of vulnerable range at last_affected version
            result.affected.push(AffectedRange {
                range_type: range_type.clone(),
                introduced: current_introduced.clone(),
                last_affected: Some(last_affected.clone()),
                raw: None,
            });

            current_introduced = None;
        }
    }

    // If we still have an open introduced range with no end, it's still vulnerable
    if let Some(introduced) = current_introduced {
        result.affected.push(AffectedRange {
            range_type: range_type.clone(),
            introduced: Some(introduced),
            last_affected: None,
            raw: Some("No fix available".to_string()),
        });
    }

    result
}
