//! Prompts for remediation action generation

use crate::model::{FixedRange, RangeType, RemediationOption, VulnerabilityIntel};

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
8. When generating dependency instructions, use a **package version number** (e.g. 1.2.3 for semver).
  If Fixed Versions list a git commit hash, do NOT use the commit as the version parameter.
  Instead, instruct to upgrade to the release that contains that fix (use version from claims/advisory if present).
  If multiple fixed versions exist, prefer the lowest stable version greater than the affected range.

Your output must be structured and actionable."#;

/// Returns true if the string looks like a git commit hash (e.g. 40 or 7+ hex chars).
pub fn looks_like_commit_hash(s: &str) -> bool {
    let s = s.trim();
    (s.len() == 40 || s.len() >= 7)
        && s.chars()
            .all(|c| c.is_ascii_hexdigit())
    // Short refs are often 7–12 chars
}

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
                    "- {:?}: {}",
                    c.reason,
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

## Required JSON Schema

You MUST return valid JSON conforming to this exact schema:

```json
{{
  "instructions": [
    {{
      "domain": "dependency" | "code" | "configuration" | "build" | "test" | "annotation",
      "action": "clear, actionable description (at least 10 characters)",
      "parameters": {{
        "package_name": "example-package",
        "version": "1.2.3",
        "file_path": "/path/to/file",
        "key": "value"
      }}
    }}
  ],
  "preconditions": [
    "Create backup of current state",
    "Verify test environment available"
  ],
  "expected_outcomes": [
    "Vulnerability CVE-2024-1234 is patched",
    "All existing tests pass"
  ],
  "confirmation_risks": [
    "This upgrade includes breaking API changes in feature X",
    "This configuration disables legacy authentication method"
  ],
  "reasoning": "Step-by-step explanation of the remediation strategy and version selection (optional but recommended)"
}}
```

Guidelines:
1. Instructions: Break down into domain-specific actions with specific parameters
2. Preconditions: What must be true before applying (backups, test environment, dependencies)
3. Expected Outcomes: What should happen after successful remediation
4. Confirmation Risks: User-facing decisions or breaking changes (NOT general warnings like "may cause issues")
5. Reasoning: Explain WHY this remediation works and why the recommended version was selected

CRITICAL: Return ONLY valid JSON. No explanations outside the JSON structure.

## Examples

### Example 1: Dependency Upgrade

**Context:**
- CVE: CVE-2024-1234 (buffer overflow in XML parser)
- Package: xml-parser @ 2.3.0
- Recommended Version: 3.24.1
- Ecosystem: npm

**Correct Output:**
```json
{{
  "instructions": [
    {{
      "domain": "dependency",
      "action": "Update xml-parser to version 3.24.1",
      "parameters": {{
        "package_name": "xml-parser",
        "old_version": "2.3.0",
        "new_version": "3.24.1",
        "ecosystem": "npm"
      }}
    }},
    {{
      "domain": "test",
      "action": "Run full test suite to verify compatibility",
      "parameters": {{
        "test_command": "npm test"
      }}
    }}
  ],
  "preconditions": [
    "Create backup of package.json and package-lock.json",
    "Verify Node.js version compatibility (requires >= 14.0.0)"
  ],
  "expected_outcomes": [
    "CVE-2024-1234 buffer overflow vulnerability is patched",
    "All existing tests pass without modification",
    "Application behavior remains unchanged"
  ],
  "confirmation_risks": [
    "This is a major version upgrade (2.x to 3.x) which may include breaking changes",
    "Parser API has been redesigned - custom error handlers may need updates"
  ],
  "reasoning": "Version 3.24.1 is the lowest fixed version that patches CVE-2024-1234. The vulnerability is a buffer overflow in the parser that was fixed through a complete rewrite. Major version change indicates potential breaking changes in the API."
}}
```

### Example 2: Configuration Change

**Context:**
- CVE: CVE-2024-5678 (XXE vulnerability)
- Package: xml-processor @ 1.5.0
- Remediation: Disable external entity processing
- No upgrade available

**Correct Output:**
```json
{{
  "instructions": [
    {{
      "domain": "configuration",
      "action": "Disable external entity processing in XML parser configuration",
      "parameters": {{
        "config_file": "config/xml-processor.yml",
        "setting": "allow_external_entities",
        "value": false
      }}
    }},
    {{
      "domain": "annotation",
      "action": "Document the security configuration in code comments",
      "parameters": {{
        "location": "src/xml-handler.js",
        "annotation": "External entities disabled to prevent CVE-2024-5678 XXE attacks"
      }}
    }}
  ],
  "preconditions": [
    "Backup current configuration file",
    "Verify application does not require external entity references"
  ],
  "expected_outcomes": [
    "CVE-2024-5678 XXE vulnerability is mitigated",
    "XML processing continues to work for internal documents",
    "External entity references are rejected with clear error messages"
  ],
  "confirmation_risks": [
    "This disables external entity references which may break XML documents that rely on external DTDs or entities"
  ],
  "reasoning": "CVE-2024-5678 is an XXE vulnerability exploitable when external entities are processed. Disabling external entity processing completely prevents the attack. This is a configuration-based mitigation since no patched version is available."
}}
```

### Example 3: Invalid - Vague Risks (DO NOT DO THIS)

**WRONG Output:**
```json
{{
  "instructions": [...],
  "preconditions": [...],
  "expected_outcomes": [...],
  "confirmation_risks": [
    "This upgrade may cause issues",
    "Breaking changes are possible",
    "Test thoroughly before deploying"
  ],
  "reasoning": "..."
}}
```

**Why it's wrong:** The confirmation risks are vague and non-specific.

**CORRECT Output:**
```json
{{
  "instructions": [...],
  "preconditions": [...],
  "expected_outcomes": [...],
  "confirmation_risks": [
    "This upgrade changes the default timeout from 30s to 5s which may cause failures for slow backends",
    "The deprecated connectWithRetry() method is removed - use connect() with retry option instead"
  ],
  "reasoning": "..."
}}
```

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
        recommended_fixed_version_line(optimal_fixed_version, &intel.fixed_versions),
    )
}

/// Recommended fixed version line for the prompt. When the value is a git commit, instruct
/// the LLM to use a package version from advisory/claims, not the commit hash.
fn recommended_fixed_version_line(
    optimal_fixed_version: Option<&str>,
    fixed_versions: &[FixedRange],
) -> String {
    let Some(v) = optimal_fixed_version else {
        return "See Fixed Versions above.".to_string();
    };
    let is_git_fix = fixed_versions
        .iter()
        .any(|r| r.fixed.as_deref() == Some(v) && matches!(r.range_type, RangeType::Git));
    let is_commit_like = looks_like_commit_hash(v);

    if is_git_fix || is_commit_like {
        format!(
            "Fix is identified by git commit {} — do NOT use this as the package version. \
             Use the package RELEASE VERSION that contains this fix (e.g. from claims or advisory above).",
            if v.len() > 12 { format!("{}…", &v[..12]) } else { v.to_string() }
        )
    } else {
        format!("Use version: {}", v)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FixedRange;

    #[test]
    fn test_looks_like_commit_hash() {
        assert!(looks_like_commit_hash("911c886bb170a6ee3db05fd3709221752213ec8a"));
        assert!(looks_like_commit_hash("911c886"));
        assert!(!looks_like_commit_hash("1.2.3"));
        assert!(!looks_like_commit_hash("7.5.4"));
    }

    #[test]
    fn test_recommended_fixed_version_line_commit() {
        let fixed = vec![FixedRange {
            range_type: RangeType::Git,
            fixed: Some("911c886bb170a6ee3db05fd3709221752213ec8a".to_string()),
            raw: None,
        }];
        let line = recommended_fixed_version_line(
            Some("911c886bb170a6ee3db05fd3709221752213ec8a"),
            &fixed,
        );
        assert!(line.contains("do NOT use"), "{}", line);
        assert!(line.contains("RELEASE VERSION"), "{}", line);
    }
}
