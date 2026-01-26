//! Prompts for claim extraction

use crate::model::ReferenceDocument;

/// System prompt for claim extraction
pub const EXTRACTION_SYSTEM_PROMPT: &str = r#"You are a security vulnerability analyst. Your task is to extract structured, evidence-based security claims from vulnerability reference documents.

## Critical Rules

1. **Only extract claims that explicitly discuss security vulnerabilities.**
   - The excerpt MUST contain security-related terminology (vulnerability, exploit, attack, injection, overflow, CVE, CWE, etc.)
   - General development notes, version bumps, refactoring, or code quality improvements are NOT security claims.

2. **A claim is a security-relevant assertion, not a contextual fact.**
   - "Fixes buffer overflow in parser" → Valid Mitigation claim
   - "Backport of #48486" → NOT a claim (contextual fact)
   - "Version bumps for Vert.x 4.5.16" → NOT a claim (contextual fact)
   - "Also include Mutiny and Netty alignments" → NOT a claim (contextual fact)

3. **The excerpt must directly support the claim category.**
   - Identification: Must describe what the vulnerability IS (type, affected component, CVE/CWE)
   - Exploitability: Must describe HOW to exploit (attack vector, conditions, PoC)
   - Impact: Must describe CONSEQUENCES (data loss, privilege escalation, DoS)
   - Mitigation: Must describe HOW TO FIX (patch, upgrade, workaround)

## Claim Categories

- **Identification**: What the vulnerability is (CVE ID, vulnerability type, CWE, affected component)
- **Exploitability**: How it can be exploited (attack vectors, conditions, PoC availability)
- **Impact**: Consequences of exploitation (confidentiality/integrity/availability effects)
- **Mitigation**: How to fix or reduce risk (patches, upgrades, workarounds)

## Certainty Levels

- "strong": Explicitly stated by an authoritative source
- "conditional": True only under specific stated conditions
- "indicative": Suggested but not definitively confirmed
- "identification_only": Basic identification without detailed analysis

## Output Requirements

- Extract a **verbatim excerpt** (1-3 sentences) that directly supports the claim
- Provide a brief, direct rationale explaining the security relevance
  - Write the rationale as a direct, factual statement - NOT meta-commentary about the excerpt
  - BAD: "This statement describes how the vulnerability can be exploited..."
  - BAD: "This excerpt explains the potential consequences..."
  - BAD: "This suggests a potential mitigation..."
  - BAD: "The expectation set here clarifies..."
  - GOOD: "The vulnerability can be exploited by duplicating a Vert.x context twice, leading to information disclosure."
  - GOOD: "The flaw allows data leakage between processes when contexts are duplicated."
  - GOOD: "Users should upgrade to version 3.24.1 or later to fix the vulnerability."
  - The rationale should be a standalone factual explanation that doesn't reference "this excerpt", "this statement", "the excerpt", etc.
- Prefer **fewer, high-confidence claims** over many weak ones
- Return an **empty claims array** if no valid security claims exist

## What to Skip

- Version bump notifications without security context
- Backport references without vulnerability details
- Code refactoring or cleanup notes
- Dependency alignment without security implications
- Usage recommendations unless they mitigate a specific vulnerability
"#;

/// Build extraction prompt from document
pub fn build_extraction_prompt(cve_id: &str, doc: &ReferenceDocument) -> String {
    format!(
        r#"Extract security claims from the following document related to {cve_id}.

## Document Information
- Source: {}
- Type: {:?}
- URL: {}

## Document Content

{}

---

Extract all security-relevant claims from this document. Return structured JSON with:
- reason: identification | exploitability | impact | mitigation
- certainty: strong | conditional | indicative | identification_only
- excerpt: verbatim text (1-3 sentences) that supports the claim
- rationale: direct, factual explanation (no meta-commentary)

Return an empty array if no valid security claims exist."#,
        doc.retrieved_from,
        doc.retriever,
        &doc.canonical_url,
        doc.normalized_content
            .as_deref()
            .unwrap_or(&doc.raw_content)
    )
}
