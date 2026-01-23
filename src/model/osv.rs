//! OSV.dev API response models
//!
//! Based on the OSV Schema: https://ossf.github.io/osv-schema/

use serde::{Deserialize, Serialize};

/// Vulnerability record from OSV.dev
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    /// The unique identifier for the vulnerability (e.g., "CVE-2021-44228", "GHSA-xxx")
    pub id: String,

    /// A brief summary of the vulnerability
    #[serde(default)]
    pub summary: Option<String>,

    /// Detailed description of the vulnerability
    #[serde(default)]
    pub details: Option<String>,

    /// Aliases for the vulnerability (e.g., CVE IDs, GHSA IDs)
    #[serde(default)]
    pub aliases: Vec<String>,

    /// Timestamp when the vulnerability was last modified
    #[serde(default)]
    pub modified: Option<String>,

    /// Timestamp when the vulnerability was first published
    #[serde(default)]
    pub published: Option<String>,

    /// Timestamp when the vulnerability was withdrawn (if applicable)
    #[serde(default)]
    pub withdrawn: Option<String>,

    /// Related vulnerability IDs
    #[serde(default)]
    pub related: Vec<String>,

    /// References related to the vulnerability
    #[serde(default)]
    pub references: Vec<OsvReference>,

    /// Affected packages and versions
    #[serde(default)]
    pub affected: Vec<OsvAffected>,

    /// Severity information
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,

    /// Credits for vulnerability discovery/reporting
    #[serde(default)]
    pub credits: Vec<OsvCredit>,

    /// Database-specific metadata
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,

    /// Schema version used
    #[serde(default)]
    pub schema_version: Option<String>,
}

/// Reference to external resources about the vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvReference {
    /// Type of reference (e.g., "ADVISORY", "WEB", "REPORT", "FIX", "PACKAGE")
    #[serde(rename = "type")]
    pub ref_type: OsvReferenceType,

    /// URL of the reference
    pub url: String,
}

/// Type of reference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OsvReferenceType {
    Advisory,
    Article,
    Detection,
    Discussion,
    Report,
    Fix,
    Introduced,
    Package,
    Evidence,
    Web,
    #[serde(other)]
    Unknown,
}

/// Affected package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAffected {
    /// Package information (optional - some CVE entries don't have this)
    #[serde(default)]
    pub package: Option<OsvPackage>,

    /// Severity specific to this affected entry
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,

    /// Version ranges affected
    #[serde(default)]
    pub ranges: Vec<OsvRange>,

    /// Specific affected versions
    #[serde(default)]
    pub versions: Vec<String>,

    /// Ecosystem-specific metadata
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,

    /// Database-specific metadata
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

/// Package identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackage {
    /// Package name
    pub name: String,

    /// Ecosystem (e.g., "npm", "PyPI", "Maven", "crates.io")
    pub ecosystem: String,

    /// Package URL (purl)
    #[serde(default)]
    pub purl: Option<String>,
}

/// Severity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    /// Scoring system type (e.g., "CVSS_V3", "CVSS_V2")
    #[serde(rename = "type")]
    pub severity_type: String,

    /// The score value (e.g., CVSS vector string)
    pub score: String,
}

/// Version range information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    /// Type of range (e.g., "SEMVER", "ECOSYSTEM", "GIT")
    #[serde(rename = "type")]
    pub range_type: OsvRangeType,

    /// Repository URL (for GIT type)
    #[serde(default)]
    pub repo: Option<String>,

    /// Events that describe the range
    #[serde(default)]
    pub events: Vec<OsvEvent>,

    /// Database-specific metadata (may contain semantic versions for GIT ranges)
    #[serde(default)]
    pub database_specific: Option<OsvRangeDatabaseSpecific>,
}

/// Database-specific metadata for a range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRangeDatabaseSpecific {
    /// Semantic version events (parallel to git commit events)
    #[serde(default)]
    pub versions: Vec<OsvEvent>,
}

/// Type of version range
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OsvRangeType {
    Semver,
    Ecosystem,
    Git,
    #[serde(other)]
    Unknown,
}

/// Event in a version range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvEvent {
    /// Version where vulnerability was introduced
    #[serde(default)]
    pub introduced: Option<String>,

    /// Version where vulnerability was fixed
    #[serde(default)]
    pub fixed: Option<String>,

    /// Last affected version
    #[serde(default)]
    pub last_affected: Option<String>,

    /// Limit version (exclusive upper bound)
    #[serde(default)]
    pub limit: Option<String>,
}

/// Credit for vulnerability discovery/reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvCredit {
    /// Name of the credited party
    pub name: String,

    /// Contact information
    #[serde(default)]
    pub contact: Vec<String>,

    /// Type of credit
    #[serde(rename = "type", default)]
    pub credit_type: Option<String>,
}
