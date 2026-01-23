use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use url::Url;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    High,
    Medium,
    Low,
}

// Describes a claim made about the vulnerability intelligence
// - reason: what we are claiming
// - certainty: how confident we are in the claim
// - evidence: why we believe the claim
// - rationale: Human/LLM Explanation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SourceClaim {
    pub reason: SourceClaimReason,
    pub certainty: ClaimCertainty,
    pub evidence: Vec<ClaimEvidence>,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClaimEvidence {
    pub reference_id: ReferenceId,
    pub trust_level: TrustLevel,
    pub excerpt: Option<String>,
    pub source_roles: Vec<SourceType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReferenceDocument {
    pub id: String,
    /// The actual URL used to retrieve the content (e.g., API URL)
    pub retrieved_from: Url,
    /// The original reference URL (e.g., web URL from vulnerability references)
    pub canonical_url: Url,
    pub domain_url: Option<Url>,
    pub retriever: RetrieverType,
    pub retrieved_at: DateTime<Utc>,
    pub published: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub raw_content: String,
    pub content_type: ContentType,
    pub normalized_content: Option<String>,
    pub content_hash: String,
    pub metadata: Option<ReferenceMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum RetrieverType {
    Nvd,
    GitCveV5,
    GitAdvisory,
    GitIssue,
    GitCommit,
    GitRelease,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReferenceMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub commit_message: Option<String>,
    pub authors: Vec<String>,
    pub tags: Vec<String>,
    pub labels: Vec<String>,
    pub issue_number: Option<u64>,
    pub repository: Option<Url>,
    pub file_changes: Vec<FileChange>,
    pub code_snippets: Vec<CodeSnippet>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CodeSnippet {
    /// Programming language (extracted from class="language-xxx" or inferred)
    pub language: Option<String>,
    /// The code content
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FileChange {
    pub filename: String,
    pub status: FileStatus,
    pub patch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Markdown,
    Html,
    Json,
    GitCommit,
    Issue,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReferenceId {
    pub source: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceClaimReason {
    Identification,
    Exploitability,
    Impact,
    Mitigation,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCertainty {
    Conditional,        // Vulnerability exists under certain conditions
    Strong,             // Vulnerability exists and is confirmed
    IdentificationOnly, // Vulnerability exists
    Indicative,         // Vulnerability may exist but is not confirmed
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SourceReference {
    pub source: String,
    pub url: Url,
    pub source_type: SourceType,
    pub trust_level: TrustLevel, // describes the trustworthiness of the source
    pub claims: Vec<SourceClaim>,
    pub published: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub generated_at: DateTime<Utc>,

    pub derived_from: Vec<ReferenceId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Runtime,
    Development,
    Build,
    Test,
    Unknown,
}

// Describes the package under investigation
// - purl: the package URL
// - dependency_graph: the parent dependencies of the package. Empty if it is a direct dependency.
// - scope: the scope of the package
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PackageIdentity {
    pub purl: Url,
    pub dependency_graph: Vec<Url>,
    pub scope: Scope,
}

impl fmt::Display for PackageIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.purl)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CvssType {
    V2,
    V3,
    V4,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CvssVector {
    pub cvss_type: CvssType,
    pub vector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
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
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CveReference {
    pub url: Url,
    pub source_type: SourceType,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CveIdentity {
    pub cve: String,
    pub description: String,
    pub aliases: Vec<String>,
    pub cvss_vectors: Vec<CvssVector>,
    pub references: Vec<CveReference>,
    pub published: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
}

// Describes how to exploit the vulnerability on the specific package
// - status: if the vulnerability is exploitable, conditionally exploitable, not exploitable, or unknown
// - certainty: the certainty of the exploitability assessment
// - conditions: the conditions under which the vulnerability is exploitable
// - notes: any additional notes about the exploitability assessment
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExploitabilityAssessment {
    pub status: ExploitabilityStatus,
    pub certainty: ClaimCertainty,
    pub conditions: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExploitabilityStatus {
    Exploitable,
    ConditionallyExploitable,
    NotExploitable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExploitCondition {
    pub description: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RangeType {
    Semver,
    Ecosystem,
    Git,
    Purl,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OverallConfidence {
    pub confidence_level: ConfidenceLevel,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LimitationReason {
    InsufficientData,
    RuntimeDependent,
    EnvironmentSpecific,
    ConflictingData,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Limitation {
    pub reason: LimitationReason,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemediationKind {
    PatchUpgrade,
    CodeChange,
    ConfigurationChange,
    DependencyRemoval,
    AlternativeLibrary,
    IgnoreFalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RemediationOption {
    pub kind: RemediationKind,
    pub description: String,
    pub migration_guide: Option<String>,
    pub certainty: ClaimCertainty,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImpactSeverity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}
// Describes how the vulnerability affects the specific package
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImpactAssessment {
    pub severity: ImpactSeverity,
    pub confidentiality: Option<ImpactLevel>,
    pub integrity: Option<ImpactLevel>,
    pub availability: Option<ImpactLevel>,
    pub notes: Option<String>,
}

// Describes the vulnerability intelligence for a specific package
// - cve_identity: the CVE identity of the vulnerability
// - package: package under investigation
// - affected_versions: when does the vulnerability affect the package
// - fixed_versions: when is the vulnerability fixed
// - exploitability: is it exploitable in the specific package
// - impact: how bad is if the vulnerability is exploited
// - confidence: how confident the system is in the vulnerability intelligence
// - claims: claims made about the vulnerability intelligence
// - limitations: what are the caveats
// - generated_at: when the information was produced
// - requested_at: when the the information was last fetched
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VulnerabilityIntel {
    pub cve_identity: CveIdentity,
    pub package_metadata: PackageMetadata,
    pub package_identity: PackageIdentity,
    pub affected_versions: Vec<AffectedRange>,
    pub fixed_versions: Vec<FixedRange>,
    pub exploitability: ExploitabilityAssessment,
    pub impact: ImpactAssessment,
    pub claims: Vec<SourceClaim>,
    pub confidence: OverallConfidence,
    pub limitations: Vec<Limitation>,
    /// IDs of retrieved reference documents (content hashes)
    pub reference_ids: Vec<String>,
    pub generated_at: DateTime<Utc>,
    pub retrieved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct PackageMetadata {
    pub source_repo: Option<Url>,
    pub homepage: Option<Url>,
    pub issue_tracker: Option<Url>,
    pub licenses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AffectedRange {
    pub range_type: RangeType,
    pub introduced: Option<String>,
    pub last_affected: Option<String>,
    pub raw: Option<String>,
} 

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FixedRange {
    pub range_type: RangeType,
    pub fixed: Option<String>,
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VulnerabilityIntelRequest {
    pub cve: String,
    pub package: PackageIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VulnerabilityIntelResponse {
    pub intel: VulnerabilityIntel,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RemediationPlanRequest {
    pub cve: String,
    pub package: PackageIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstructionDomain {
    Dependency,
    Code,
    Configuration,
    Build,
    Annotation,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RemediationInstruction {
    pub domain: InstructionDomain,
    pub action: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RemediationAction {
    pub kind: RemediationKind,
    pub description: String,
    pub language: Option<String>,
    pub instructions: Vec<RemediationInstruction>,
    pub preconditions: Vec<String>,
    pub confirmation_risks: Vec<String>,
    pub expected_outcomes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RemediationPlan {
    pub applicable: bool,
    pub actions: Vec<RemediationAction>,
    pub options: Vec<RemediationOption>,
    pub safe_defaults: Vec<RemediationAction>,
    pub confirmation_risks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RemediationPlanResponse {
    pub plan: RemediationPlan,
    pub intel: VulnerabilityIntel,
    pub request_id: String,
}
