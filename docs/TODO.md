# Trustify Vulnerability Intelligence - Remaining Improvements

**Last Updated**: 2026-01-27
**Status**: Production-ready, these are nice-to-have improvements

---

## Summary of Completed Work

✅ **Phases 1-3 Complete** (Commits: 72cda0d, a4fba6e, 33e27cf):
- Unified API error handling with `ApiError`
- Code organization with `AppState` pattern
- Kubernetes health check endpoints
- LLM reproducibility (temperature=0, seed=42)
- LLM validation modules (grounding, quality checks)
- Comprehensive documentation (architecture, configuration, prompts)

**See**: `docs/CHANGELOG.md` for full implementation details

---

## Priority Levels

- 🔴 **CRITICAL**: Security issues, data loss risks, blocking bugs
- 🟠 **HIGH**: Maintainability, consistency, developer experience
- 🟡 **MEDIUM**: Code quality, performance, best practices
- 🟢 **LOW**: Nice-to-haves, future enhancements

---

## 1. Testing & Quality Assurance

### 🟠 HIGH: Add Unit Tests for Business Logic

**Goal**: 70% test coverage on service layer

**Tasks**:
1. Add tests for version comparison logic
   - File: `src/service/remediation/version.rs`
   - Test: `version_in_range()`, `select_optimal_fixed_version()`

2. Add tests for confidence computation
   - File: `src/service/assessment/confidence.rs`
   - Test: All confidence calculation functions

3. Add tests for applicability determination
   - File: `src/service/remediation/applicability.rs`
   - Test: Priority-based applicability logic

**Dependencies**: None (validation tests already exist)

**Effort**: 2-3 days

**Tools**:
```toml
# Cargo.toml - already present
[dev-dependencies]
```

---

### 🟡 MEDIUM: Add Integration Tests for API Endpoints

**Goal**: End-to-end testing of API flows

**Tasks**:
```rust
// tests/api_integration.rs (new file)
use actix_web::test;

#[actix_web::test]
async fn test_vulnerability_assessment_flow() {
    // Test full flow: request → assessment → response
}

#[actix_web::test]
async fn test_remediation_plan_generation() {
    // Test full remediation flow
}

#[actix_web::test]
async fn test_error_handling() {
    // Test ApiError responses
}
```

**Dependencies**: None

**Effort**: 1-2 days

---

### 🟢 LOW: Set Up Coverage Reporting

**Goal**: Track test coverage over time

**Tasks**:
```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Run coverage
cargo tarpaulin --out Html

# Add to CI/CD
```

**Dependencies**: Unit tests implemented

**Effort**: 2-3 hours

---

## 2. LLM Prompt Improvements

### 🟠 HIGH: Update Prompts with Explicit JSON Schemas

**Goal**: Further improve output consistency

**Current**: Prompts use natural language to describe output format
**Target**: Explicit JSON schema examples in prompt strings

**Tasks**:

1. **Claims Extraction** (`src/service/claims/prompts.rs`):
```rust
pub const EXTRACTION_SYSTEM_PROMPT: &str = r#"
[... existing rules ...]

## Required Output Format

You MUST return valid JSON conforming to this exact schema:

{
  "claims": [
    {
      "reason": "identification" | "exploitability" | "impact" | "mitigation",
      "certainty": "strong" | "conditional" | "indicative" | "identification_only",
      "excerpt": "verbatim quote from document (1-3 sentences)",
      "rationale": "factual explanation without meta-commentary"
    }
  ]
}

Return {"claims": []} if no valid security claims exist.

CRITICAL: Return ONLY valid JSON. No explanations outside the JSON structure.
"#;
```

2. **Vulnerability Assessment** (`src/service/assessment/prompts.rs`):
   - Add `supported_by` and `reasoning` to output format description
   - Emphasize that every conclusion must reference supporting claims

3. **Remediation Actions** (`src/service/remediation/prompts.rs`):
   - Add `reasoning` to output format description
   - Emphasize version selection justification

**Dependencies**: None (schemas already exist in models)

**Effort**: 2-3 hours

**Expected Impact**: ⭐⭐⭐⭐ - 10-15% further improvement in consistency

---

### 🟡 MEDIUM: Add Few-Shot Examples to Prompts

**Goal**: Show LLM concrete examples of ideal outputs

**Tasks**:

Add 2-3 examples to each prompt showing:
- Valid outputs (with proper format)
- Edge cases (unknown status, conflicting claims)
- Invalid outputs that should be avoided

**Example**:
```rust
pub const EXTRACTION_SYSTEM_PROMPT: &str = r#"
[... existing rules ...]

## Examples

### Example 1: Valid Mitigation Claim
Document: "CVE-2024-1234 can be mitigated by upgrading to version 3.24.1"

Correct Output:
{
  "claims": [{
    "reason": "mitigation",
    "certainty": "strong",
    "excerpt": "CVE-2024-1234 can be mitigated by upgrading to version 3.24.1",
    "rationale": "Upgrading to version 3.24.1 fixes the vulnerability"
  }]
}

### Example 2: No Security Claims
Document: "Version bump to 1.2.3. Also include Mutiny and Netty alignments."

Correct Output:
{
  "claims": []
}

Explanation: These are version bumps without explicit security context.

[... rest of prompt ...]
"#;
```

**Dependencies**: JSON schema updates (task 2.1)

**Effort**: 1 day

**Expected Impact**: ⭐⭐⭐⭐ - Significant improvement in edge case handling

---

### 🟡 MEDIUM: Add Prompt Versioning

**Goal**: Track prompt changes for A/B testing and regression detection

**Tasks**:

1. Add version metadata to prompts:
```rust
// src/service/claims/prompts.rs
pub const EXTRACTION_PROMPT_VERSION: &str = "2.0.0";
pub const EXTRACTION_PROMPT_DATE: &str = "2026-01-27";

pub const EXTRACTION_SYSTEM_PROMPT: &str = r#"Version: 2.0.0
Last Updated: 2026-01-27
Changelog: Added explicit JSON schemas and few-shot examples

[... prompt content ...]
"#;
```

2. Log prompt version:
```rust
tracing::info!(
    prompt_version = prompts::EXTRACTION_PROMPT_VERSION,
    model = %self.model,
    "Extracting claims with versioned prompt"
);
```

3. Store in database (optional):
```sql
ALTER TABLE reference_documents
ADD COLUMN extraction_prompt_version VARCHAR(10),
ADD COLUMN extraction_model VARCHAR(50);
```

**Dependencies**: None

**Effort**: 2-3 hours

**Expected Impact**: ⭐⭐⭐ - Enables tracking prompt performance over time

---

## 3. Configuration Management

### 🟡 MEDIUM: Consolidate Environment Variables

**Current**: 15+ environment variables scattered across files

**Goal**: Single configuration source with hierarchical overrides

**Tasks**:

1. Add `config` crate:
```toml
# Cargo.toml
[dependencies]
config = "0.13"
```

2. Create unified config structure:
```rust
// src/config.rs (expand existing)
#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
    pub llm: LlmConfig,
    pub integrations: IntegrationsConfig,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        ConfigBuilder::builder()
            .add_source(File::with_name("config").required(false))
            .add_source(Environment::with_prefix("DA_AGENT").separator("__"))
            .build()?
            .try_deserialize()
    }
}
```

3. Create example configs:
   - `config.yaml.example` - Development
   - `config.prod.yaml.example` - Production
   - `config.test.yaml.example` - Testing

**Dependencies**: None

**Effort**: 1 day

**Expected Impact**: ⭐⭐⭐ - Easier configuration management

---

## 4. Database Schema Management

### 🟡 MEDIUM: Migrate to SQLx Migrations

**Current**: Schema created with `init_schema()` function

**Goal**: Version-controlled, reproducible schema migrations

**Tasks**:

1. Install sqlx-cli:
```bash
cargo install sqlx-cli --no-default-features --features postgres
```

2. Create initial migration:
```bash
sqlx migrate add initial_schema
```

3. Move schema from `src/db/mod.rs:init_schema()` to migration:
```sql
-- migrations/20260127000001_initial_schema.sql
CREATE TABLE IF NOT EXISTS reference_documents (
    id VARCHAR(64) PRIMARY KEY,
    retrieved_from TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    -- ... rest of schema
);

CREATE INDEX IF NOT EXISTS idx_reference_documents_retriever_type
    ON reference_documents(retriever_type);
```

4. Update initialization code:
```rust
// src/db/mod.rs
pub async fn run_migrations(pool: &PgPool) -> Result<(), DbError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await?;
    Ok(())
}
```

**Dependencies**: None

**Effort**: 3-4 hours

**Expected Impact**: ⭐⭐⭐⭐ - Better schema change management

---

## 5. API Validation

### 🟢 LOW: Add Request Validation

**Goal**: Validate request bodies before processing

**Tasks**:

1. Add validator crate:
```toml
# Cargo.toml
[dependencies]
validator = { version = "0.16", features = ["derive"] }
```

2. Add validation rules:
```rust
// src/model/intel.rs
use validator::Validate;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct VulnerabilityAssessmentRequest {
    #[validate(regex = "CVE-[0-9]{4}-[0-9]{4,}")]
    pub cve: String,

    #[validate]
    pub package: PackageIdentity,
}
```

3. Use in endpoints:
```rust
pub async fn get_vulnerability_assessment(
    request: web::Json<VulnerabilityAssessmentRequest>,
) -> Result<impl Responder, ApiError> {
    request.validate()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // ... process
}
```

**Dependencies**: None (ApiError::BadRequest already exists)

**Effort**: 2-3 hours

**Expected Impact**: ⭐⭐ - Better error messages for invalid requests

---

## 6. Documentation

### 🟢 LOW: Create Deployment Guide

**Goal**: Complete K8s deployment documentation

**Tasks**:

Create `docs/deployment.md` with:
- Kubernetes manifests
- Helm charts (optional)
- Environment variable configuration
- Scaling recommendations
- Monitoring setup
- Troubleshooting guide

**Dependencies**: None

**Effort**: 1 day

---

### 🟢 LOW: Add Contributing Guide

**Goal**: Help external contributors

**Tasks**:

Create `CONTRIBUTING.md` with:
- Development setup
- Code style guidelines
- Testing requirements
- PR process
- Commit message conventions

**Dependencies**: None

**Effort**: 2-3 hours

---

## 7. Monitoring & Observability

### 🟢 LOW: Add LLM Quality Metrics

**Goal**: Track LLM output quality over time

**Tasks**:

1. Add Prometheus metrics:
```rust
// src/service/metrics.rs (new)
use prometheus::{IntCounter, Histogram};

lazy_static! {
    static ref CLAIMS_EXTRACTED_TOTAL: IntCounter =
        IntCounter::new("claims_extracted_total", "Total claims extracted").unwrap();

    static ref CLAIMS_VALIDATION_FAILURES: IntCounter =
        IntCounter::new("claims_validation_failures", "Claims validation failures").unwrap();

    static ref ASSESSMENTS_UNKNOWN_TOTAL: IntCounter =
        IntCounter::new("assessments_unknown_total", "Assessments with unknown status").unwrap();
}
```

2. Track metrics in services

3. Create Grafana dashboard

**Dependencies**: Prometheus setup in deployment

**Effort**: 1 day

**Expected Impact**: ⭐⭐⭐⭐ - Early detection of quality regressions

---

### 🟢 LOW: Create Evaluation Dataset

**Goal**: Regression testing for prompt changes

**Tasks**:

1. Curate 50-100 test cases with ground truth:
   - Real vulnerability documents
   - Expected claims/assessments
   - Edge cases

2. Create evaluation script:
```rust
// tests/llm_evaluation.rs
#[tokio::test]
async fn test_claim_extraction_quality() {
    for test_case in load_test_cases() {
        let result = extract_claims(&test_case.document).await;
        assert_precision(&result, &test_case.expected);
        assert_recall(&result, &test_case.expected);
    }
}
```

3. Run before merging prompt changes

**Dependencies**: None

**Effort**: 1 week

**Expected Impact**: ⭐⭐⭐⭐⭐ - Prevents prompt regressions

---

## Implementation Priority

### Immediate (Do Next)
1. 🟠 Update prompts with JSON schemas (2-3 hours) - Quick win
2. 🟠 Add unit tests for business logic (2-3 days) - High value

### Short-term (This Sprint)
3. 🟡 Add few-shot examples to prompts (1 day) - High impact
4. 🟡 Migrate to SQLx migrations (3-4 hours) - Best practices
5. 🟡 Consolidate configuration (1 day) - Maintainability

### Medium-term (Next Sprint)
6. 🟡 Add prompt versioning (2-3 hours) - Enables tracking
7. 🟡 Add integration tests (1-2 days) - Quality assurance
8. 🟢 Add request validation (2-3 hours) - Better UX

### Long-term (Nice to Have)
9. 🟢 Add LLM quality metrics (1 day) - Monitoring
10. 🟢 Create evaluation dataset (1 week) - Regression prevention
11. 🟢 Write deployment guide (1 day) - Documentation
12. 🟢 Add contributing guide (2-3 hours) - Documentation

---

## Estimated Total Effort

- **Critical/High**: ~1 week
- **Medium**: ~1 week
- **Low**: ~2 weeks

**Total**: ~1 month for all improvements

---

## Notes

- All critical improvements are **already completed**
- System is **production-ready** as-is
- These are **quality-of-life improvements** and **best practices**
- Prioritize based on your team's needs and bandwidth

For details on completed work, see:
- `docs/CHANGELOG.md` - Full implementation history
- `docs/architecture.md` - System design
- `docs/configuration.md` - Configuration guide
