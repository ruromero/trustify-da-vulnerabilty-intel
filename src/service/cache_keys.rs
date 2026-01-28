//! Utilities for generating cache keys for assessments and remediation plans

use sha2::{Digest, Sha256};
use serde::Serialize;

use crate::model::{PackageIdentity, VulnerabilityIntel, TrustedRemediation};
use crate::service::assessment::prompts::{ASSESSMENT_SYSTEM_PROMPT, build_assessment_prompt};
use crate::service::remediation::prompts::ACTION_GENERATION_SYSTEM_PROMPT;

/// Generate cache key hash for vulnerability assessment
/// 
/// The key is based on:
/// - cve_id
/// - sorted_reference_ids
/// - vendor_remediation_hash
/// - package_identity_hash
/// - prompt_version (hash of prompt content)
/// - model_id
pub fn generate_assessment_cache_key(
    cve_id: &str,
    intel: &VulnerabilityIntel,
    model_id: &str,
) -> String {
    // Sort reference IDs for consistent hashing
    let mut sorted_ref_ids: Vec<String> = intel
        .reference_ids
        .iter()
        .map(|id| id.to_string())
        .collect();
    sorted_ref_ids.sort();

    // Hash vendor remediations
    let vendor_remediation_hash = hash_serializable(&intel.vendor_remediations);

    // Hash package identity
    let package_identity_hash = hash_serializable(&intel.package_identity);

    // Hash prompt content (system prompt + assessment prompt)
    let assessment_prompt = build_assessment_prompt(cve_id, intel);
    let prompt_content = format!("{}\n{}", ASSESSMENT_SYSTEM_PROMPT, assessment_prompt);
    let prompt_version = hash_string(&prompt_content);

    // Combine all components
    let key_components = format!(
        "{}|{}|{}|{}|{}|{}",
        cve_id,
        sorted_ref_ids.join(","),
        vendor_remediation_hash,
        package_identity_hash,
        prompt_version,
        model_id
    );

    // Return the hash
    hash_string(&key_components)
}

/// Generate cache key hash for remediation plan
/// 
/// The key is based on:
/// - trusted_content hash
/// - package identity
/// - model
/// - vulnerability_assessment cache key
pub fn generate_remediation_cache_key(
    trusted_content: Option<&TrustedRemediation>,
    package: &PackageIdentity,
    model_id: &str,
    assessment_cache_key: &str,
) -> String {
    // Hash trusted content if present
    let trusted_content_hash = if let Some(tc) = trusted_content {
        hash_serializable(tc)
    } else {
        "none".to_string()
    };

    // Hash package identity
    let package_identity_hash = hash_serializable(package);

    // Hash remediation prompt system prompt (for prompt versioning)
    let prompt_version = hash_string(ACTION_GENERATION_SYSTEM_PROMPT);

    // Combine all components
    let key_components = format!(
        "{}|{}|{}|{}|{}",
        trusted_content_hash,
        package_identity_hash,
        model_id,
        assessment_cache_key,
        prompt_version
    );

    // Return the hash
    hash_string(&key_components)
}

/// Hash a serializable value to a hex string
fn hash_serializable<T: Serialize>(value: &T) -> String {
    let json = serde_json::to_string(value).unwrap_or_else(|_| "".to_string());
    hash_string(&json)
}

/// Hash a string to a hex string using SHA256
fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}
