# Remediation Plan

The Remediation Plan endpoint generates actionable remediation plans with applicability determination and step-by-step instructions.

## Endpoint

**POST** `/v1/vulnerability/remediation_plan`

## Overview

The remediation plan generation process:

1. **Vulnerability Assessment**: Generates full vulnerability assessment (see [Vulnerability Assessment](vulnerability-assessment.md))
2. **Applicability Determination**: Determines if remediation is required using priority-based checks
3. **Option Generation**: Enumerates possible remediation options
4. **Action Generation**: Uses LLM to generate detailed remediation actions from options
5. **Action Classification**: Separates safe defaults from actions requiring confirmation

## Request

```json
{
  "cve": "CVE-2024-12345",
  "package": {
    "purl": "pkg:npm/example@1.2.3",
    "dependency_graph": [],
    "scope": "runtime"
  },
  "trusted_content": {
    "purl": "pkg:npm/example@1.2.3",
    "status": "not_affected",
    "justification": "Custom build without vulnerable component"
  }
}
```

### Request Fields

- **`cve`** (string, required): CVE identifier
- **`package`** (object, required): Package identity (same as vulnerability assessment)
- **`trusted_content`** (object, optional): Customer-provided remediation status
  - **`purl`** (string, required): Package URL
  - **`status`** (enum, required): `not_affected`, `affected`, `fixed`, `under_investigation`
  - **`justification`** (string, optional): Customer justification

## Response

The response structure depends on whether the vulnerability is applicable:

### When Applicable (`applicable: true`)

```json
{
  "plan": {
    "applicable": true,
    "actions": [
      {
        "kind": "patch_upgrade",
        "description": "PatchUpgrade (High confidence, vendor advisory): Upgrade to fixed version(s): 1.2.3",
        "language": "JavaScript",
        "instructions": [
          {
            "domain": "dependency",
            "action": "update_package",
            "parameters": {
              "package": "example",
              "version": "1.2.3",
              "ecosystem": "npm"
            }
          }
        ],
        "preconditions": [
          "Backup current package.json",
          "Ensure test environment is available"
        ],
        "confirmation_risks": [
          "This upgrade introduces a patch version change"
        ],
        "expected_outcomes": [
          "Vulnerability patched",
          "No breaking changes expected"
        ]
      }
    ],
    "options": [
      {
        "kind": "patch_upgrade",
        "description": "PatchUpgrade (High confidence, vendor advisory): Upgrade to fixed version(s): 1.2.3",
        "migration_guide": null,
        "certainty": "strong"
      },
      {
        "kind": "code_change",
        "description": "CodeChange (High confidence, GitHub advisory): Code changes or workarounds suggested",
        "migration_guide": null,
        "certainty": "strong"
      }
    ],
    "safe_defaults": [
      {
        "kind": "patch_upgrade",
        "description": "PatchUpgrade (High confidence, vendor advisory): Upgrade to fixed version(s): 1.2.3",
        "language": "JavaScript",
        "instructions": [...],
        "preconditions": [...],
        "confirmation_risks": [],
        "expected_outcomes": [...]
      }
    ],
    "confirmation_risks": [
      "Version 1.2.3 is within affected range and not yet fixed"
    ]
  },
  "intel": {
    // Full VulnerabilityAssessment (see vulnerability-assessment.md)
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### When Not Applicable (`applicable: false`)

When the vulnerability is not applicable (e.g., version is outside affected range, already fixed, or customer indicates not affected), **no actions are generated** - only options are provided:

```json
{
  "plan": {
    "applicable": false,
    "actions": [],
    "options": [
      {
        "kind": "patch_upgrade",
        "description": "PatchUpgrade (High confidence, vendor advisory): Upgrade to fixed version(s): 1.2.3",
        "migration_guide": null,
        "certainty": "strong"
      },
      {
        "kind": "code_change",
        "description": "CodeChange (High confidence, GitHub advisory): Code changes or workarounds suggested",
        "migration_guide": null,
        "certainty": "strong"
      }
    ],
    "safe_defaults": [],
    "confirmation_risks": [
      "Not affected: vulnerable code not present in version 1.0.0 (version is outside affected range)"
    ]
  },
  "intel": {
    // Full VulnerabilityAssessment (see vulnerability-assessment.md)
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Note**: When `applicable: false`, the system follows the rule: "If applicable = false → no actions, only options". This means:
- `actions` will be an empty array
- `safe_defaults` will be an empty array
- `options` will still contain all possible remediation options (for informational purposes)
- `confirmation_risks` will contain the explicit justification for why no action is required

## Response Fields

### `plan` - Remediation Plan

- **`applicable`** (boolean): Whether remediation is required
  - `true`: Vulnerability is applicable, actions will be generated
  - `false`: Vulnerability is not applicable, only options provided (no actions)
- **`actions`** (array): Actions requiring user confirmation (empty if `applicable: false`)
- **`options`** (array): All available remediation options (always populated for informational purposes)
- **`safe_defaults`** (array): Low-risk actions that can be applied automatically (empty if `applicable: false`)
- **`confirmation_risks`** (array): Global risks requiring confirmation, includes explicit justification for `applicable: false` cases

### `actions` and `safe_defaults` - Remediation Actions

Each action includes:

- **`kind`**: `patch_upgrade`, `code_change`, `configuration_change`, `dependency_removal`, `alternative_library`, `ignore_false_positive`
- **`description`**: Human-readable description with confidence and source
- **`language`**: Programming language (if applicable)
- **`instructions`**: Step-by-step instructions by domain
  - **`domain`**: `dependency`, `code`, `configuration`, `build`, `annotation`
  - **`action`**: Specific action to perform
  - **`parameters`**: Action parameters (key-value pairs)
- **`preconditions`**: Requirements before applying (e.g., backups, test environment)
- **`confirmation_risks`**: User-facing risks requiring confirmation
- **`expected_outcomes`**: Expected results after successful remediation

## Applicability Determination

Applicability is determined using a priority-based system:

### Priority 1: Trusted Content (Customer)

If `trusted_content` is provided:

- **`not_affected`** → `NotApplicable`: "Not affected: vulnerable code not present. Customer indicates: ..."
- **`fixed`** → `NotApplicable`: "Already fixed: vulnerability was present but has been remediated. Customer indicates: ..."
- **`affected`** → `Applicable`
- **`under_investigation`** → `Uncertain`

**Justification**: Explicit distinction between "never vulnerable" and "already fixed" for auditability.

### Priority 2: Vendor Remediation (VEX/CSAF)

If vendor remediations match the product:

- **`vendor_fix`** → `Applicable`
- **`none_available`** → `Applicable`
- **`no_fix_planned`** → `NotApplicable`: "Not affected: vendor indicates no fix planned"
- **`workaround`** → `Applicable`
- **`other`** → `Uncertain`

**Justification**: Includes product matching confidence level.

### Priority 3: Version-Based Check

Compares package version with affected/fixed ranges using semantic versioning:

- **Inside affected & not fixed** → `Applicable`
- **Outside affected** → `NotApplicable`: "Not affected: vulnerable code not present in version X"
- **Already fixed** → `NotApplicable`: "Already fixed: vulnerability was present but has been remediated in version X"
- **Cannot determine** → `Uncertain`

**Justification**: Explicit version information and range comparison results.

## Remediation Options

Options are generated using static logic based on:

- **Fixed versions**: Patch upgrade option
- **Mitigation claims**: Code change or configuration change options
- **Package scope**: Dependency removal option
- **Vendor status**: Alternative library or ignore false positive options

Each option includes:
- **`kind`**: Type of remediation
- **`description`**: Confidence level and source
- **`certainty`**: Claim certainty level

## Action Generation

**Important**: Actions are only generated when `applicable: true`. When `applicable: false`, the system follows the rule: "If applicable = false → no actions, only options".

For each applicable option (when `applicable: true`), the LLM generates:

1. **Instructions**: Domain-specific actions with parameters
2. **Preconditions**: Requirements before applying
3. **Expected Outcomes**: Success criteria
4. **Confirmation Risks**: User-facing decisions (not vague warnings)

### LLM Prompt Includes

- Package information (PURL, ecosystem, language)
- Selected remediation option
- Vulnerability context (CVE, description)
- Relevant claims (sample)
- Affected and fixed versions
- **Recommended fixed version** (for patch upgrades, selected using semantic versioning)

### Action Classification

Actions are classified into:

- **`safe_defaults`**: Low-risk actions
  - Patch upgrade within same minor version
  - Ignore false positive with justification
- **`actions`**: Everything else (require confirmation)

## Data Persistence & Traceability

### Full Assessment Stored

The complete `VulnerabilityAssessment` is included in the response, providing:

- **Complete Traceability**: All reference documents, claims, and assessments
- **Reproducibility**: Can regenerate plan from stored assessment
- **Audit Trail**: Full history of how plan was generated

### LLM Call Logging

All LLM action generation calls are logged with:

- Model used
- Prompt length
- Response time
- Success/failure status
- Retry attempts (if any)

### Version Selection

For patch upgrades, the system:

1. Parses fixed versions using semantic versioning
2. Selects lowest stable version greater than affected range
3. Passes selected version to LLM for instruction generation

This ensures consistent, optimal version recommendations.

## Error Handling

- **500**: Internal server error
  - LLM generation failure (with retry logic)
  - Assessment generation failure
  - Database errors

All errors include a `request_id` for traceability.

## Performance Considerations

- **Parallel Action Generation**: All actions generated in parallel using `futures::join_all`
- **Retry Logic**: Exponential backoff (500ms, 1s, 2s) for transient LLM failures
- **Caching**: Vulnerability assessment cached, claims cached per document
- **Semantic Versioning**: Proper version comparison for accurate applicability

## Example Use Cases

1. **Automated Remediation**: Apply `safe_defaults` automatically
2. **Manual Review**: Review `actions` and `confirmation_risks` before applying
3. **Compliance Auditing**: Use explicit justifications for "not applicable" decisions
4. **CI/CD Integration**: Generate plans in build pipelines for dependency updates

## Justification Examples

### Not Applicable - Never Vulnerable

```
"Not affected: vulnerable code not present in version 1.0.0 (version is outside affected range)"
```

### Not Applicable - Already Fixed

```
"Already fixed: vulnerability was present but has been remediated in version 1.2.3 (current version: 1.2.3)"
```

### Not Applicable - Customer Indication

```
"Not affected: vulnerable code not present. Customer indicates: Custom build without vulnerable component (purl: pkg:npm/example@1.2.3)"
```

These explicit justifications provide clear audit trails for compliance and security reviews.
