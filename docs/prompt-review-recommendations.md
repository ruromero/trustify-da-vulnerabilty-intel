# LLM Prompt Review & Recommendations

**Project**: Trustify DA Agents
**Date**: 2026-01-27
**Focus**: Reproducibility, Trustworthiness, Auditability, Grounding

---

## Executive Summary

The current prompts demonstrate **strong foundational practices** with clear constraints and explicit anti-hallucination guidance. However, there are significant opportunities to improve:

### ✅ Current Strengths
- **Evidence-based constraints**: All prompts emphasize grounding in provided data
- **Clear anti-hallucination rules**: Explicit instructions not to invent facts
- **Structured output**: All prompts request JSON responses
- **Certainty modeling**: Claims and assessments include confidence levels
- **Category separation**: Clear boundaries between extraction and assessment

### 🔧 Critical Improvements Needed

| Priority | Issue | Impact |
|----------|-------|--------|
| 🔴 **CRITICAL** | No JSON schemas provided | Low reproducibility, parsing failures |
| 🔴 **CRITICAL** | No temperature control | Non-deterministic outputs |
| 🟠 **HIGH** | No few-shot examples | Inconsistent output formatting |
| 🟠 **HIGH** | No chain-of-thought reasoning | Poor auditability of decisions |
| 🟠 **HIGH** | No explicit source citation format | Weak traceability |
| 🟡 **MEDIUM** | No model versioning strategy | Drift over time |
| 🟡 **MEDIUM** | No prompt versioning/tracking | Cannot compare changes |

---

## Core Principles for Trustworthy LLM Systems

### 1. Reproducibility
- **Use structured output modes** (JSON schema, not natural language)
- **Set temperature to 0** for deterministic tasks
- **Pin model versions** explicitly
- **Use seed parameters** when available

### 2. Grounding & Auditability
- **Request citations** for every claim (line numbers, excerpt IDs)
- **Chain-of-thought reasoning** makes decisions traceable
- **Source attribution** in structured format
- **Confidence scores** for every assertion

### 3. Trustworthiness
- **Explicit uncertainty handling** ("I don't know" is valid)
- **Conservative by default** (prefer "unknown" to speculation)
- **Evidence requirements** clearly stated
- **Validation steps** in the reasoning process

---

## Detailed Prompt Analysis

## 1. Claim Extraction Prompts

**File**: `src/service/claims/prompts.rs`

### Current State Assessment: **B+ (Good but needs structure)**

#### ✅ Strengths
1. **Excellent critical rules** with specific examples
2. **Strong guidance on rationale writing** (no meta-commentary)
3. **Clear certainty levels** (strong, conditional, indicative, identification_only)
4. **Good negative examples** (what NOT to extract)

#### ❌ Issues

##### 🔴 CRITICAL: No JSON Schema
**Current**: Natural language description of output format
```rust
"Return structured JSON with:
- reason: identification | exploitability | impact | mitigation
- certainty: strong | conditional | indicative | identification_only
- excerpt: verbatim text (1-3 sentences)
- rationale: direct, factual explanation"
```

**Problem**: LLM may format output inconsistently, leading to parsing failures.

**Recommendation**: Use explicit JSON schema with the rig extractor:

```rust
// In src/model/claims.rs - add schema documentation
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractedClaims {
    /// Array of security claims extracted from the document.
    /// Return empty array if no valid security claims exist.
    pub claims: Vec<ExtractedClaim>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractedClaim {
    /// Category of the claim
    #[schemars(description = "Must be one of: identification, exploitability, impact, mitigation")]
    pub reason: ExtractedReason,

    /// Confidence level of the claim
    #[schemars(description = "Must be one of: strong, conditional, indicative, identification_only")]
    pub certainty: ExtractedCertainty,

    /// Verbatim excerpt from the document (1-3 sentences) that directly supports this claim.
    /// Must contain security-related terminology.
    #[schemars(description = "Exact quote from document, 1-3 sentences")]
    #[schemars(min_length = 10, max_length = 500)]
    pub excerpt: String,

    /// Direct, factual explanation of why this is a security claim.
    /// Write as standalone statement without referencing "this excerpt" or "this statement".
    #[schemars(description = "Factual explanation without meta-commentary")]
    #[schemars(min_length = 20, max_length = 300)]
    pub rationale: String,

    /// Optional: Line numbers or excerpt ID from source document for traceability
    #[schemars(description = "Source location in document for auditability")]
    pub source_location: Option<String>,
}
```

**Update prompt template**:
```rust
pub const EXTRACTION_SYSTEM_PROMPT: &str = r#"You are a security vulnerability analyst.

[... existing rules ...]

## Output Format

You MUST return valid JSON that conforms to the following schema:
{
  "claims": [
    {
      "reason": "identification" | "exploitability" | "impact" | "mitigation",
      "certainty": "strong" | "conditional" | "indicative" | "identification_only",
      "excerpt": "verbatim text from document (1-3 sentences)",
      "rationale": "direct, factual explanation without meta-commentary",
      "source_location": "optional line number or section ID"
    }
  ]
}

Return {"claims": []} if no valid security claims exist.

CRITICAL: Your response must be valid JSON only. Do not include explanations outside the JSON structure.
"#;
```

##### 🔴 CRITICAL: No Temperature Setting
**Current**: Uses rig default (likely 1.0, which is high variance)

**Recommendation**: Set temperature to 0 for reproducible extraction:

```rust
// In src/service/claims/mod.rs
.extractor::<ExtractedClaims>(&self.model)
    .preamble(&prompts::EXTRACTION_SYSTEM_PROMPT)
    .prompt(&user_prompt)
    .temperature(0.0)  // <-- ADD THIS
    .extract(&self.llm_client.openai_client())
    .await
```

##### 🟠 HIGH: No Few-Shot Examples
**Problem**: LLM may misinterpret instructions without concrete examples.

**Recommendation**: Add 2-3 few-shot examples to system prompt:

```rust
pub const EXTRACTION_SYSTEM_PROMPT: &str = r#"
[... existing rules ...]

## Examples

### Example 1: Valid Mitigation Claim
Document excerpt: "CVE-2024-1234 can be mitigated by upgrading to version 3.24.1 or applying the security patch available at https://..."

Extracted claim:
{
  "reason": "mitigation",
  "certainty": "strong",
  "excerpt": "CVE-2024-1234 can be mitigated by upgrading to version 3.24.1 or applying the security patch.",
  "rationale": "Upgrading to version 3.24.1 fixes the vulnerability.",
  "source_location": "line 45"
}

### Example 2: Valid Exploitability Claim
Document excerpt: "The flaw allows an authenticated attacker to execute arbitrary code by sending a malformed XML payload to the /api/process endpoint."

Extracted claim:
{
  "reason": "exploitability",
  "certainty": "strong",
  "excerpt": "The flaw allows an authenticated attacker to execute arbitrary code by sending a malformed XML payload to the /api/process endpoint.",
  "rationale": "An authenticated attacker can achieve remote code execution by sending malformed XML to the /api/process endpoint.",
  "source_location": "line 12"
}

### Example 3: NOT a Valid Claim
Document excerpt: "Version bumps for Vert.x 4.5.16. Also include Mutiny and Netty alignments."

Extracted:
{
  "claims": []
}

Rationale: These are version bumps and dependency alignments without explicit security context. No security claims.

[... rest of prompt ...]
"#;
```

##### 🟠 HIGH: No Explicit Citation Format
**Current**: Excerpts are extracted but source locations aren't tracked.

**Recommendation**: Request line numbers or section IDs:

```rust
"## Required for Every Claim

1. **Excerpt**: Verbatim quote from document (1-3 sentences)
2. **Source Location**: Specify line number, paragraph number, or section ID
3. **Rationale**: Direct explanation without meta-commentary

This enables traceability and auditability of all extracted claims."
```

##### 🟡 MEDIUM: No Confidence Calibration
**Current**: Certainty levels defined but no calibration guidance.

**Recommendation**: Add calibration examples:

```rust
"## Certainty Level Calibration

- **strong**: Explicitly stated by authoritative source with clear evidence
  Example: 'CVE-2024-1234 affects all versions prior to 2.5.0'

- **conditional**: True only under specific stated conditions
  Example: 'Exploitable only if XML processing is enabled and untrusted input is accepted'

- **indicative**: Suggested but not definitively confirmed
  Example: 'This may allow privilege escalation in certain configurations'

- **identification_only**: Basic CVE/vulnerability identification without analysis
  Example: 'This commit addresses CVE-2024-1234'

When in doubt between two levels, choose the more conservative (lower certainty)."
```

---

## 2. Vulnerability Assessment Prompts

**File**: `src/service/assessment/prompts.rs`

### Current State Assessment: **B (Good foundation, needs structure)**

#### ✅ Strengths
1. **Strong anti-hallucination guidance** ("Base conclusions strictly on provided claims")
2. **Explicit uncertainty handling** ("use 'unknown' and explain why")
3. **Clear separation** between CVSS and real exploitability
4. **Claim-based reasoning** (supported_by references)

#### ❌ Issues

##### 🔴 CRITICAL: No JSON Schema
**Current**: Natural language description of output

**Recommendation**: Define strict JSON schema:

```rust
// In src/model/assessments.rs
use schemars::JsonSchema;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractedAssessment {
    /// Exploitability assessment based on provided claims
    pub exploitability: ExtractedExploitability,

    /// Impact assessment based on provided claims
    pub impact: ExtractedImpact,

    /// Limitations and uncertainties in the assessment
    pub limitations: Vec<ExtractedLimitation>,

    /// Chain-of-thought reasoning for auditability
    #[schemars(description = "Step-by-step reasoning process used to reach conclusions")]
    pub reasoning: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractedExploitability {
    /// Exploitability status based on evidence
    #[schemars(description = "Must be one of: exploitable, conditionally_exploitable, not_exploitable, unknown")]
    pub status: String,

    /// Certainty of the exploitability assessment
    #[schemars(description = "low | medium | high")]
    pub certainty: String,

    /// Conditions required for exploitation (if conditionally_exploitable)
    #[schemars(description = "Specific conditions required for exploitation")]
    pub conditions: Option<Vec<String>>,

    /// Additional notes explaining the assessment
    pub notes: Option<String>,

    /// List of claim IDs that support this assessment
    #[schemars(description = "Reference to claim excerpts that support this conclusion")]
    pub supported_by: Vec<String>,
}
```

**Update prompt**:
```rust
pub fn build_assessment_prompt(cve_id: &str, intel: &VulnerabilityIntel) -> String {
    format!(
        r#"
[... existing context ...]

---

### Required Output Format

You MUST return valid JSON conforming to this schema:

{{
  "exploitability": {{
    "status": "exploitable" | "conditionally_exploitable" | "not_exploitable" | "unknown",
    "certainty": "low" | "medium" | "high",
    "conditions": ["condition1", "condition2"],  // if conditionally_exploitable
    "notes": "brief explanation",
    "supported_by": ["claim_excerpt_1", "claim_excerpt_2"]  // verbatim claim excerpts
  }},
  "impact": {{
    "severity": "low" | "medium" | "high" | "critical" | "unknown",
    "confidentiality": "none" | "low" | "high",
    "integrity": "none" | "low" | "high",
    "availability": "none" | "low" | "high",
    "notes": "brief explanation",
    "supported_by": ["claim_excerpt_1"]
  }},
  "limitations": [
    {{
      "reason": "insufficient_evidence" | "conflicting_claims" | "vendor_specific" | "version_specific",
      "description": "explanation of the limitation",
      "supported_by": ["claim_excerpt"] // optional
    }}
  ],
  "reasoning": "optional step-by-step explanation of how you reached these conclusions"
}}

### Critical Rules
1. Every conclusion must reference supporting claims via supported_by
2. Use "unknown" when evidence is insufficient - do not speculate
3. When claims conflict, add a limitation explaining the conflict
4. The reasoning field should trace your decision-making process

RETURN ONLY VALID JSON. NO ADDITIONAL TEXT.
"#,
        [... existing args ...]
    )
}
```

##### 🔴 CRITICAL: No Temperature Setting
**Recommendation**: Set to 0 for reproducibility:

```rust
// In src/service/assessment/mod.rs
.extractor::<ExtractedAssessment>(&self.model)
    .preamble(&prompts::ASSESSMENT_SYSTEM_PROMPT)
    .prompt(&assessment_prompt)
    .temperature(0.0)  // <-- ADD THIS
    .extract(&self.llm_client.openai_client())
    .await
```

##### 🟠 HIGH: No Chain-of-Thought Reasoning
**Current**: Assessments are produced without explaining the reasoning process.

**Problem**: Cannot audit why a particular conclusion was reached.

**Recommendation**: Add reasoning field and request explicit chain-of-thought:

```rust
pub const ASSESSMENT_SYSTEM_PROMPT: &str = r#"
[... existing rules ...]

## Reasoning Process (Required)

Before generating your final assessment, you must:

1. **Identify relevant claims**: List all claims that discuss exploitability or impact
2. **Evaluate claim certainty**: Consider the certainty and trust level of each claim
3. **Synthesize evidence**: Combine claims that agree, note conflicts
4. **Apply conservative principle**: When evidence is weak or conflicting, choose "unknown"
5. **Document supporting evidence**: Link every conclusion to specific claim excerpts

Include your reasoning in the "reasoning" field for auditability.

Example reasoning:
"Three claims discuss exploitability:
1. 'Requires authenticated access' (strong certainty)
2. 'PoC available on GitHub' (strong certainty)
3. 'Affects only legacy API endpoint' (conditional certainty)

Conclusion: conditionally_exploitable because exploitation requires authentication (Claim 1) but a working PoC exists (Claim 2). Limited to legacy API (Claim 3)."
"#;
```

##### 🟠 HIGH: Weak Citation Mechanism
**Current**: `supported_by` mentioned but format not specified.

**Recommendation**: Require verbatim claim excerpts:

```rust
"## Citation Requirements

Every assessment field (exploitability, impact) MUST include supported_by with:
- Verbatim excerpts from claims (not paraphrased)
- At least one supporting claim for non-'unknown' conclusions
- Multiple claims when they corroborate the same conclusion

Example:
{
  \"status\": \"conditionally_exploitable\",
  \"supported_by\": [
    \"The flaw allows an authenticated attacker to execute arbitrary code\",
    \"Exploitation requires the XML parser feature to be enabled\"
  ]
}

This enables verification that conclusions are grounded in evidence."
```

##### 🟡 MEDIUM: CVSS Handling Could Be Stronger
**Current**: Warns that "CVSS indicates severity, not real-world exploitability"

**Improvement**: Make the constraint more explicit:

```rust
"## CVSS Information
{cvss_info}

CRITICAL: CVSS is a severity score, NOT proof of exploitability.
- DO NOT use CVSS as primary evidence for exploitability status
- DO NOT repeat CVSS metrics unless they're confirmed by claims
- DO use CVSS as weak supporting context only when claims are absent
- PREFER 'unknown' over relying solely on CVSS

If no claims discuss exploitability and only CVSS exists:
- Set status to 'unknown'
- Add limitation: 'insufficient_evidence'
- Note: 'Only CVSS score available, no real-world exploitability analysis found'"
```

---

## 3. Remediation Action Prompts

**File**: `src/service/remediation/prompts.rs`

### Current State Assessment: **B+ (Good, needs reproducibility)**

#### ✅ Strengths
1. **Clear scope**: "DO NOT decide applicability - focus on HOW"
2. **Specific version selection guidance**: Prefer lowest fixed version
3. **Structured output**: Instructions, preconditions, outcomes, risks
4. **Good risk guidance**: Must be user-facing decisions

#### ❌ Issues

##### 🔴 CRITICAL: No JSON Schema
**Recommendation**: Define strict action schema:

```rust
// In src/model/remediations/action_extraction.rs
use schemars::JsonSchema;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractedRemediationAction {
    /// Detailed step-by-step instructions grouped by domain
    pub instructions: Vec<ExtractedInstruction>,

    /// Prerequisites before applying remediation
    pub preconditions: Vec<String>,

    /// Expected outcomes after successful remediation
    pub expected_outcomes: Vec<String>,

    /// User-facing decisions or breaking changes requiring confirmation
    pub confirmation_risks: Vec<String>,

    /// Reasoning for why these steps are recommended
    #[schemars(description = "Explanation of remediation strategy")]
    pub reasoning: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractedInstruction {
    /// Type of action to perform
    #[schemars(description = "Must be one of: dependency, code, configuration, build, test, annotation")]
    pub instruction_type: String,

    /// Human-readable description of the step
    #[schemars(description = "Clear, actionable description")]
    pub description: String,

    /// Specific parameters for automation
    #[schemars(description = "Key-value pairs for automated execution")]
    pub parameters: Option<std::collections::HashMap<String, String>>,
}
```

**Update prompt**:
```rust
pub const ACTION_GENERATION_SYSTEM_PROMPT: &str = r#"
[... existing rules ...]

## Output Format (JSON Schema)

You MUST return valid JSON conforming to this schema:

{
  "instructions": [
    {
      "instruction_type": "dependency" | "code" | "configuration" | "build" | "test" | "annotation",
      "description": "Clear, actionable step",
      "parameters": {
        "package_name": "example",
        "version": "1.2.3",
        "ecosystem": "maven"
      }
    }
  ],
  "preconditions": [
    "Create backup of current deployment",
    "Verify test environment is available"
  ],
  "expected_outcomes": [
    "Vulnerability CVE-2024-1234 is patched",
    "All existing tests pass"
  ],
  "confirmation_risks": [
    "This upgrade includes breaking API changes in the authentication module",
    "This configuration change disables the legacy XML parser"
  ],
  "reasoning": "Step-by-step explanation of why these actions remediate the vulnerability"
}

RETURN ONLY VALID JSON.
"#;
```

##### 🔴 CRITICAL: No Temperature Setting
**Recommendation**:

```rust
// In src/service/remediation/mod.rs
.extractor::<ExtractedRemediationAction>(&self.model)
    .preamble(&prompts::ACTION_GENERATION_SYSTEM_PROMPT)
    .prompt(&action_prompt)
    .temperature(0.0)  // <-- ADD for reproducibility
    .extract(&self.llm_client.openai_client())
    .await
```

##### 🟠 HIGH: Version Selection Logic Not Auditable
**Current**: "Prefer lowest fixed version greater than affected range"

**Problem**: No way to verify LLM followed this rule.

**Recommendation**: Add reasoning requirement:

```rust
pub fn build_action_prompt(...) -> String {
    format!(
        r#"
[... existing context ...]

Recommended Fixed Version: {optimal_fixed_version}

CRITICAL: You MUST use the Recommended Fixed Version specified above for dependency instructions.
Do not select a different version unless you document why in the reasoning field.

In your reasoning field, explain:
1. Why the recommended version was selected
2. What makes this version optimal (lowest patched, stable, compatible)
3. Any trade-offs or considerations

Example reasoning:
"Selected version 3.24.1 because:
- It's the lowest version that fixes CVE-2024-1234 (per Fixed Versions)
- It's a stable release (not pre-release)
- It's a patch version bump, minimizing breaking changes
- Current version 3.23.0 is within the affected range"
"#,
        [... args ...]
        optimal_fixed_version = optimal_fixed_version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "NONE_AVAILABLE".to_string())
    )
}
```

##### 🟡 MEDIUM: Risk Guidance Could Be More Specific
**Current**: "Confirmation Risks must be user-facing decisions, not general warnings"

**Improvement**: Add calibration examples:

```rust
"## Confirmation Risk Calibration

Confirmation risks are BREAKING CHANGES or USER DECISIONS, not general warnings.

✅ VALID Confirmation Risks:
- 'This upgrade changes from Java 8 to Java 11, requiring JVM upgrade'
- 'This configuration disables the legacy v1 API endpoint'
- 'This removes support for deprecated authentication methods'

❌ INVALID Confirmation Risks (too vague):
- 'May cause issues'
- 'Test thoroughly before deploying'
- 'Review breaking changes'
- 'Could affect performance'

If there are no breaking changes or user decisions, set confirmation_risks to []."
```

---

## 4. Cross-Cutting Improvements

### 4.1 Model & Temperature Configuration

**Current State**:
- Models configurable via env vars (good)
- Temperature not set (defaults vary by model)
- No seed parameter for reproducibility

**Recommendation**: Add configuration module

```rust
// src/service/llm.rs - EXPAND

use serde::Deserialize;

/// LLM configuration for reproducible outputs
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// Model to use (e.g., "gpt-4o-mini")
    pub model: String,

    /// Temperature (0.0 = deterministic, 1.0 = creative)
    /// Use 0.0 for extraction/assessment, 0.3 for generation
    pub temperature: f32,

    /// Random seed for reproducibility (OpenAI supports this)
    pub seed: Option<u64>,

    /// Max tokens for response
    pub max_tokens: Option<u32>,
}

impl LlmConfig {
    /// Configuration for claim extraction (deterministic)
    pub fn claim_extraction() -> Self {
        Self {
            model: std::env::var("CLAIM_MODEL")
                .unwrap_or_else(|_| "gpt-4o-mini".to_string()),
            temperature: 0.0,  // Deterministic
            seed: Some(42),     // Reproducible
            max_tokens: Some(4096),
        }
    }

    /// Configuration for vulnerability assessment (deterministic)
    pub fn assessment() -> Self {
        Self {
            model: std::env::var("ASSESSMENT_MODEL")
                .unwrap_or_else(|_| "gpt-4o-mini".to_string()),
            temperature: 0.0,  // Deterministic
            seed: Some(42),
            max_tokens: Some(2048),
        }
    }

    /// Configuration for remediation action generation (slightly creative)
    pub fn remediation() -> Self {
        Self {
            model: std::env::var("REMEDIATION_MODEL")
                .unwrap_or_else(|_| "gpt-4o-mini".to_string()),
            temperature: 0.1,  // Slightly creative for action phrasing
            seed: Some(42),
            max_tokens: Some(3072),
        }
    }
}

// Update LlmClient to use configs
impl LlmClient {
    pub fn extractor_with_config<T>(&self, config: &LlmConfig) -> rig::extractor::Extractor<T> {
        let mut extractor = self.client.extractor::<T>(&config.model);

        extractor = extractor.temperature(config.temperature);

        if let Some(seed) = config.seed {
            extractor = extractor.seed(seed);
        }

        if let Some(max_tokens) = config.max_tokens {
            extractor = extractor.max_tokens(max_tokens);
        }

        extractor
    }
}
```

**Usage**:
```rust
// In claims/mod.rs
let config = LlmConfig::claim_extraction();
let result = self.llm_client
    .extractor_with_config::<ExtractedClaims>(&config)
    .preamble(&prompts::EXTRACTION_SYSTEM_PROMPT)
    .prompt(&user_prompt)
    .extract(&self.llm_client.openai_client())
    .await?;
```

### 4.2 Prompt Versioning & Tracking

**Problem**: No way to track prompt changes or A/B test improvements.

**Recommendation**: Add version metadata:

```rust
// In each prompts.rs file
pub const EXTRACTION_PROMPT_VERSION: &str = "2.0.0";
pub const EXTRACTION_PROMPT_DATE: &str = "2026-01-27";

pub const EXTRACTION_SYSTEM_PROMPT: &str = r#"Version: 2.0.0
Last Updated: 2026-01-27
Changelog: Added JSON schema, few-shot examples, explicit citation requirements

You are a security vulnerability analyst...
"#;
```

**Track in logs**:
```rust
tracing::info!(
    prompt_version = prompts::EXTRACTION_PROMPT_VERSION,
    model = %self.model,
    temperature = 0.0,
    "Extracting claims with versioned prompt"
);
```

**Store in database for auditing**:
```sql
-- Add to reference_documents or create audit table
ALTER TABLE reference_documents ADD COLUMN extraction_prompt_version VARCHAR(10);
ALTER TABLE reference_documents ADD COLUMN extraction_model VARCHAR(50);
ALTER TABLE reference_documents ADD COLUMN extraction_temperature FLOAT;
```

### 4.3 Output Validation & Quality Checks

**Problem**: No validation that LLM followed instructions.

**Recommendation**: Add post-extraction validation:

```rust
// src/service/claims/validation.rs (NEW)

use crate::model::claims::ExtractedClaims;

pub struct ClaimValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn validate_extracted_claims(
    extracted: &ExtractedClaims,
    document_content: &str,
) -> ClaimValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    for (i, claim) in extracted.claims.iter().enumerate() {
        // 1. Verify excerpt exists in document (grounding check)
        if !document_content.contains(&claim.excerpt) {
            errors.push(format!(
                "Claim {} excerpt not found in document: '{}'",
                i, claim.excerpt
            ));
        }

        // 2. Verify excerpt contains security keywords
        let security_keywords = [
            "vulnerability", "CVE", "exploit", "attack", "injection",
            "overflow", "XSS", "SQL", "RCE", "DoS", "security", "patch",
        ];

        let has_security_keyword = security_keywords.iter().any(|kw| {
            claim.excerpt.to_lowercase().contains(&kw.to_lowercase())
        });

        if !has_security_keyword {
            warnings.push(format!(
                "Claim {} excerpt may not be security-related: '{}'",
                i, claim.excerpt
            ));
        }

        // 3. Verify rationale doesn't contain meta-commentary
        let meta_phrases = [
            "this excerpt", "this statement", "this suggests",
            "the excerpt", "the statement",
        ];

        for phrase in &meta_phrases {
            if claim.rationale.to_lowercase().contains(phrase) {
                warnings.push(format!(
                    "Claim {} rationale contains meta-commentary: '{}'",
                    i, claim.rationale
                ));
            }
        }

        // 4. Verify rationale is substantive
        if claim.rationale.len() < 20 {
            warnings.push(format!(
                "Claim {} rationale is too short: '{}'",
                i, claim.rationale
            ));
        }
    }

    ClaimValidationResult {
        is_valid: errors.is_empty(),
        errors,
        warnings,
    }
}
```

**Use in extraction service**:
```rust
// In claims/mod.rs, after extraction
let validation = validation::validate_extracted_claims(&result, &doc.normalized_content);

if !validation.is_valid {
    tracing::error!(
        errors = ?validation.errors,
        "Claim extraction validation failed"
    );
    return Err(ClaimExtractionError::ValidationFailed(validation.errors));
}

if !validation.warnings.is_empty() {
    tracing::warn!(
        warnings = ?validation.warnings,
        "Claim extraction produced warnings"
    );
}
```

### 4.4 Monitoring & Quality Metrics

**Recommendation**: Track LLM quality metrics:

```rust
// src/service/metrics.rs (NEW)

use prometheus::{IntCounter, Histogram};

lazy_static! {
    // Extraction metrics
    static ref CLAIMS_EXTRACTED_TOTAL: IntCounter =
        IntCounter::new("claims_extracted_total", "Total claims extracted").unwrap();

    static ref CLAIMS_VALIDATION_FAILURES: IntCounter =
        IntCounter::new("claims_validation_failures", "Claims that failed validation").unwrap();

    static ref CLAIM_EXTRACTION_LATENCY: Histogram =
        Histogram::new("claim_extraction_latency_seconds", "Claim extraction latency").unwrap();

    // Assessment metrics
    static ref ASSESSMENTS_UNKNOWN_TOTAL: IntCounter =
        IntCounter::new("assessments_unknown_total", "Assessments with 'unknown' status").unwrap();

    static ref ASSESSMENTS_WITH_LIMITATIONS: IntCounter =
        IntCounter::new("assessments_with_limitations", "Assessments with limitations").unwrap();

    // Remediation metrics
    static ref REMEDIATION_ACTIONS_GENERATED: IntCounter =
        IntCounter::new("remediation_actions_generated", "Remediation actions generated").unwrap();
}
```

**Dashboard queries**:
```promql
# Percentage of assessments that are "unknown" (higher = less confident)
rate(assessments_unknown_total[5m]) / rate(assessments_total[5m])

# Average claims per document (lower might indicate quality issues)
rate(claims_extracted_total[5m]) / rate(documents_processed[5m])

# Validation failure rate (should be near zero)
rate(claims_validation_failures[5m]) / rate(claims_extracted_total[5m])
```

---

## 5. Implementation Roadmap

### Phase 1: Critical Reproducibility Fixes (1-2 days)

**Priority**: 🔴 CRITICAL

1. **Add temperature=0.0 to all extractors**
   - `src/service/claims/mod.rs` - claim extraction
   - `src/service/assessment/mod.rs` - vulnerability assessment
   - `src/service/remediation/mod.rs` - action generation

2. **Add JSON schemas to all models**
   - Use `schemars` crate for schema generation
   - Update `ExtractedClaims`, `ExtractedAssessment`, `ExtractedRemediationAction`
   - Add schema validation

3. **Add seed parameter for reproducibility**
   - Use `seed: Some(42)` consistently
   - Document in configuration guide

**Expected Impact**: Significantly improved reproducibility (same input → same output)

### Phase 2: Grounding & Auditability (2-3 days)

**Priority**: 🟠 HIGH

1. **Add chain-of-thought reasoning fields**
   - Update all schemas with `reasoning: Option<String>`
   - Update prompts to request step-by-step reasoning
   - Log reasoning for manual review

2. **Improve citation mechanisms**
   - Add `source_location` to claims (line numbers)
   - Require verbatim excerpts in `supported_by` fields
   - Validate citations against source documents

3. **Add output validation**
   - Create validation module for each service
   - Verify excerpts exist in source documents
   - Check for meta-commentary in rationales
   - Validate security keyword presence

**Expected Impact**: Better traceability, easier debugging of LLM decisions

### Phase 3: Quality & Consistency (3-4 days)

**Priority**: 🟠 HIGH

1. **Add few-shot examples to all prompts**
   - 2-3 examples per prompt showing ideal outputs
   - Include edge cases (unknown, conflicting claims)
   - Show both valid and invalid examples

2. **Create LlmConfig abstraction**
   - Centralize temperature, model, seed settings
   - Different configs for extraction vs generation
   - Environment variable configuration

3. **Add prompt versioning**
   - Version all prompts (semantic versioning)
   - Track in logs and database
   - Enable A/B testing of prompt changes

**Expected Impact**: More consistent outputs, easier prompt iteration

### Phase 4: Monitoring & Continuous Improvement (2-3 days)

**Priority**: 🟡 MEDIUM

1. **Add quality metrics**
   - Prometheus metrics for LLM quality
   - Track "unknown" rates, validation failures
   - Dashboard for monitoring drift

2. **Create evaluation dataset**
   - Curate 50-100 test cases with ground truth
   - Run regression tests on prompt changes
   - Measure precision/recall of extractions

3. **Add human-in-the-loop feedback**
   - API endpoint for users to flag bad extractions
   - Store feedback for prompt tuning
   - Periodic manual review of edge cases

**Expected Impact**: Continuous quality improvement, early detection of regressions

---

## 6. Specific Code Changes

### 6.1 Update Claims Extraction (HIGH PRIORITY)

```rust
// src/service/claims/mod.rs

// Add temperature and seed
let result = self.llm_client
    .openai_client()
    .extractor::<ExtractedClaims>(&self.model)
    .preamble(&prompts::EXTRACTION_SYSTEM_PROMPT)
    .prompt(&extraction_prompt)
    .temperature(0.0)      // <-- ADD: Deterministic
    .seed(Some(42))        // <-- ADD: Reproducible
    .extract(&self.llm_client.openai_client())
    .await
    .map_err(|e| ClaimExtractionError::LlmFailed(e.to_string()))?;

// Add validation
let validation = validation::validate_extracted_claims(&result, &doc.normalized_content);
if !validation.is_valid {
    tracing::error!(
        document_id = %doc.id,
        errors = ?validation.errors,
        "Claim extraction produced invalid output"
    );
    // Option 1: Fail hard
    return Err(ClaimExtractionError::ValidationFailed(validation.errors));

    // Option 2: Filter invalid claims (more graceful)
    // result.claims.retain(|c| is_valid_claim(c, &doc.normalized_content));
}

if !validation.warnings.is_empty() {
    tracing::warn!(
        document_id = %doc.id,
        warnings = ?validation.warnings,
        "Claim extraction produced warnings"
    );
}

// Log prompt version for tracking
tracing::info!(
    document_id = %doc.id,
    claims_count = result.claims.len(),
    prompt_version = prompts::EXTRACTION_PROMPT_VERSION,
    model = %self.model,
    temperature = 0.0,
    "Successfully extracted claims"
);
```

### 6.2 Update Assessment (HIGH PRIORITY)

```rust
// src/service/assessment/mod.rs

let result = self.llm_client
    .openai_client()
    .extractor::<ExtractedAssessment>(&self.model)
    .preamble(&prompts::ASSESSMENT_SYSTEM_PROMPT)
    .prompt(&assessment_prompt)
    .temperature(0.0)      // <-- ADD
    .seed(Some(42))        // <-- ADD
    .extract(&self.llm_client.openai_client())
    .await
    .map_err(|e| AssessmentError::LlmFailed(e.to_string()))?;

// Validate that supported_by references are not empty
if result.exploitability.status != "unknown"
    && result.exploitability.supported_by.is_empty() {
    tracing::warn!(
        cve = %cve_id,
        status = %result.exploitability.status,
        "Exploitability assessment lacks supporting evidence"
    );
}

// Log reasoning for audit trail
if let Some(ref reasoning) = result.reasoning {
    tracing::debug!(
        cve = %cve_id,
        reasoning = %reasoning,
        "Assessment reasoning"
    );
}
```

### 6.3 Update Remediation (HIGH PRIORITY)

```rust
// src/service/remediation/mod.rs

let result = self.llm_client
    .openai_client()
    .extractor::<ExtractedRemediationAction>(&self.model)
    .preamble(&prompts::ACTION_GENERATION_SYSTEM_PROMPT)
    .prompt(&action_prompt)
    .temperature(0.1)      // <-- ADD: Slightly creative for phrasing
    .seed(Some(42))        // <-- ADD
    .extract(&self.llm_client.openai_client())
    .await
    .map_err(|e| RemediationError::ActionGenerationFailed(e.to_string()))?;

// Validate that recommended version was used
if let Some(optimal_version) = optimal_fixed_version {
    let version_used = result.instructions
        .iter()
        .find(|i| i.instruction_type == "dependency")
        .and_then(|i| i.parameters.as_ref()?.get("version"));

    if let Some(used) = version_used {
        if used != optimal_version {
            tracing::warn!(
                recommended = optimal_version,
                used = used,
                "LLM selected different version than recommended"
            );
        }
    }
}

// Log reasoning
if let Some(ref reasoning) = result.reasoning {
    tracing::debug!(
        cve = %cve_id,
        reasoning = %reasoning,
        "Remediation action reasoning"
    );
}
```

---

## 7. Testing & Validation

### 7.1 Create Evaluation Dataset

**File**: `tests/llm_evaluation/mod.rs`

```rust
//! Regression tests for LLM prompt quality

use crate::model::claims::ExtractedClaims;
use crate::service::claims::ClaimExtractionService;

#[tokio::test]
async fn test_claim_extraction_reproducibility() {
    // Given: Same document processed twice
    let service = create_test_service();
    let doc = create_test_document();

    // When: Extracting claims twice
    let result1 = service.extract_claims(&doc).await.unwrap();
    let result2 = service.extract_claims(&doc).await.unwrap();

    // Then: Results should be identical (with temperature=0 and seed)
    assert_eq!(result1.claims.len(), result2.claims.len());
    for (claim1, claim2) in result1.claims.iter().zip(result2.claims.iter()) {
        assert_eq!(claim1.excerpt, claim2.excerpt);
        assert_eq!(claim1.rationale, claim2.rationale);
        assert_eq!(claim1.reason, claim2.reason);
    }
}

#[tokio::test]
async fn test_claim_extraction_no_meta_commentary() {
    let service = create_test_service();
    let doc = create_test_document();

    let result = service.extract_claims(&doc).await.unwrap();

    // Verify no meta-commentary in rationales
    let meta_phrases = ["this excerpt", "this statement", "the excerpt"];
    for claim in &result.claims {
        for phrase in &meta_phrases {
            assert!(
                !claim.rationale.to_lowercase().contains(phrase),
                "Claim rationale contains meta-commentary '{}': {}",
                phrase,
                claim.rationale
            );
        }
    }
}

#[tokio::test]
async fn test_assessment_grounding() {
    let service = create_test_assessment_service();
    let intel = create_test_intel();

    let result = service.assess(&intel).await.unwrap();

    // Verify non-unknown status has supporting evidence
    if result.exploitability.status != "unknown" {
        assert!(
            !result.exploitability.supported_by.is_empty(),
            "Exploitability assessment lacks supporting evidence"
        );
    }

    // Verify supported_by references exist in claims
    for evidence in &result.exploitability.supported_by {
        let found = intel.claims.iter().any(|c| {
            c.evidence.iter().any(|e| {
                e.excerpt.as_ref().map_or(false, |ex| ex.contains(evidence))
            })
        });
        assert!(found, "Evidence '{}' not found in claims", evidence);
    }
}
```

### 7.2 Prompt A/B Testing Framework

```rust
// tests/prompt_comparison.rs

/// Compare two prompt versions on same dataset
pub async fn compare_prompts(
    prompt_v1: &str,
    prompt_v2: &str,
    test_cases: &[TestCase],
) -> PromptComparisonResult {
    let mut v1_results = Vec::new();
    let mut v2_results = Vec::new();

    for test_case in test_cases {
        let r1 = run_extraction(prompt_v1, test_case).await;
        let r2 = run_extraction(prompt_v2, test_case).await;

        v1_results.push(r1);
        v2_results.push(r2);
    }

    PromptComparisonResult {
        v1_precision: calculate_precision(&v1_results),
        v2_precision: calculate_precision(&v2_results),
        v1_recall: calculate_recall(&v1_results),
        v2_recall: calculate_recall(&v2_results),
        // ... other metrics
    }
}
```

---

## 8. Summary & Recommendations

### Critical Actions (Do First)

1. **Set temperature=0.0 and seed=42** on all extractors (30 minutes)
   - Immediate improvement in reproducibility
   - No prompt changes needed

2. **Add JSON schemas** to all extraction models (2-3 hours)
   - Use `schemars` crate
   - Significantly reduces parsing errors

3. **Add output validation** for claims extraction (2-3 hours)
   - Verify excerpts exist in documents
   - Check for meta-commentary
   - Ensure security keywords present

### High-Value Improvements (Next Week)

4. **Add chain-of-thought reasoning** to all prompts (1 day)
   - Request step-by-step reasoning
   - Log for audit trail
   - Improves transparency

5. **Add few-shot examples** to all prompts (1 day)
   - 2-3 examples per prompt
   - Show edge cases
   - Improves consistency

6. **Create LlmConfig abstraction** (1 day)
   - Centralize temperature, model, seed
   - Environment-based configuration
   - Easier to tune

### Long-Term Improvements (Next Month)

7. **Build evaluation dataset** (1 week)
   - 50-100 curated test cases
   - Ground truth labels
   - Regression testing

8. **Add quality monitoring** (3-4 days)
   - Prometheus metrics
   - Quality dashboard
   - Alerting on degradation

9. **Prompt versioning system** (2-3 days)
   - Semantic versioning
   - A/B testing framework
   - Track in database

### Expected Impact

| Improvement | Reproducibility | Trustworthiness | Auditability |
|-------------|-----------------|-----------------|--------------|
| Temperature=0, seed | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| JSON schemas | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| Output validation | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| Chain-of-thought | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Few-shot examples | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| Evaluation dataset | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

---

## Conclusion

The current prompts have a **solid foundation** but lack the **reproducibility and auditability mechanisms** needed for a trustworthy AI system handling security decisions.

**Priority order**:
1. 🔴 Add temperature=0 and seed (immediate reproducibility boost)
2. 🔴 Add JSON schemas (prevent parsing failures)
3. 🟠 Add output validation (ensure grounding)
4. 🟠 Add chain-of-thought reasoning (enable auditing)
5. 🟡 Add few-shot examples (improve consistency)
6. 🟡 Build evaluation framework (measure quality over time)

These improvements will transform the system from "good LLM usage" to "production-grade, auditable AI system."
