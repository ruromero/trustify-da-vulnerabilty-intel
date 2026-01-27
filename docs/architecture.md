# Architecture Documentation

## Overview

Trustify DA Agents is a vulnerability intelligence REST service designed to help AI-assisted IDEs provide actionable remediation guidance for security vulnerabilities in project dependencies. Built with Rust and Actix-web, it aggregates vulnerability data from multiple authoritative sources and uses LLM-powered analysis to generate comprehensive assessments and remediation plans.

## Use Case

This service acts as a backend for MCP (Model Context Protocol) servers that integrate with AI-assisted IDEs. When developers encounter vulnerabilities in their dependencies, the IDE can query this service to get:

1. **Comprehensive Assessment**: Exploitability analysis, impact evaluation, and confidence scoring
2. **Actionable Remediation Plans**: Step-by-step instructions for fixing vulnerabilities
3. **Trusted Intelligence**: Claims extracted from official sources (NVD, GitHub advisories, vendor documentation)

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Client (MCP Server / IDE)                 │
└─────────────────────────────────────────────────────────────┘
                         │ HTTPS/REST
┌─────────────────────────────────────────────────────────────┐
│                   REST API (Actix Web)                      │
│                                                             │
│  POST /v1/vulnerability/assessment                         │
│  POST /v1/vulnerability/remediation_plan                   │
│  GET  /v1/documents                                        │
│  GET  /health/ready, /health/live                          │
└─────────────────────────────────────────────────────────────┘
                         │
┌─────────────────────────────────────────────────────────────┐
│                     Service Layer                           │
│  ┌───────────────────────────────────────────────────┐     │
│  │ VulnerabilityService (Orchestration)              │     │
│  │   ├─→ ClaimExtractionService (LLM)               │     │
│  │   ├─→ AssessmentService (LLM)                    │     │
│  │   └─→ DocumentService (Retrieval & Persistence)  │     │
│  └───────────────────────────────────────────────────┘     │
│  ┌───────────────────────────────────────────────────┐     │
│  │ RemediationService                                │     │
│  │   ├─→ Applicability Determination                │     │
│  │   ├─→ Remediation Options Generation             │     │
│  │   └─→ Action Generation (LLM)                    │     │
│  └───────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                         │
┌─────────────────────────────────────────────────────────────┐
│                   Data Access Layer                         │
│  ┌──────────────────────┐  ┌──────────────────────┐        │
│  │ RetrieverDispatcher  │  │ ReferenceDocument    │        │
│  │ (Strategy Pattern)   │  │ Repository           │        │
│  ├──────────────────────┤  │ (PostgreSQL)         │        │
│  │ • NVD                │  └──────────────────────┘        │
│  │ • CVE.org            │                                   │
│  │ • GitHub (Advisory,  │  ┌──────────────────────┐        │
│  │   Issue, Commit)     │  │ VulnerabilityCache   │        │
│  │ • Red Hat CSAF       │  │ (Redis)              │        │
│  │ • Bugzilla           │  └──────────────────────┘        │
│  │ • Generic Web        │                                   │
│  └──────────────────────┘                                   │
└─────────────────────────────────────────────────────────────┘
                         │
┌─────────────────────────────────────────────────────────────┐
│              External Dependencies                          │
│                                                             │
│  PostgreSQL 18+    Redis 8+       OpenAI API              │
│  (Documents)       (Cache)        (LLM Analysis)           │
│                                                             │
│  OSV.dev   NVD   GitHub   Red Hat CSAF   Deps.dev         │
│  (Vulnerability Data Sources)                              │
└─────────────────────────────────────────────────────────────┘
```

## Module Structure

### API Layer (`src/api/`)

**Purpose**: HTTP request/response handling, input validation, error conversion

- **vulnerability.rs**: Core endpoints for vulnerability assessment and remediation
- **document.rs**: CRUD operations for reference documents
- **openapi.rs**: OpenAPI/Swagger specification and UI

**Key Patterns**:
- Uses `actix-web` handlers with dependency injection via `web::Data`
- OpenAPI documentation via `utoipa` attributes
- Error handling via manual conversion (to be unified - see recommendations)

### Service Layer (`src/service/`)

**Purpose**: Business logic, orchestration, LLM integration

#### VulnerabilityService (`vulnerability.rs`)
**Responsibilities**:
- Orchestrates vulnerability intelligence gathering
- Coordinates parallel data fetching (OSV, CSAF, deps.dev)
- Manages document retrieval and persistence
- Coordinates claim extraction and assessment

**Dependencies**:
- `OsvClient`: Fetches vulnerability data from OSV.dev
- `DepsDevClient`: Fetches package metadata
- `RedHatCsafClient`: Fetches Red Hat vendor advisories
- `DocumentService`: Retrieves and persists reference documents
- `ClaimExtractionService`: Extracts structured claims from documents
- `VulnerabilityAssessmentService`: LLM-based exploitability/impact analysis
- `VulnerabilityCache`: Redis caching layer

#### ClaimExtractionService (`claims/mod.rs`)
**Responsibilities**:
- Extracts structured security claims from unstructured documents
- Filters weak/irrelevant claims
- Synthesizes and deduplicates claims across documents

**Submodules**:
- `filters.rs`: Claim quality filtering
- `synthesis.rs`: Claim deduplication and merging
- `prompts.rs`: LLM prompt engineering
- `error.rs`: Error types

**LLM Integration**: Uses OpenAI GPT-4o-mini (configurable) for structured extraction

#### VulnerabilityAssessmentService (`assessment/mod.rs`)
**Responsibilities**:
- Assesses exploitability status (exploited, likely, unlikely, unknown)
- Evaluates impact (confidentiality, integrity, availability)
- Identifies limitations and edge cases
- Computes overall confidence

**Submodules**:
- `confidence.rs`: Rule-based confidence scoring
- `converters.rs`: Data transformations
- `prompts.rs`: LLM prompt templates
- `error.rs`: Error types

**LLM Integration**: Uses OpenAI GPT-4o-mini (configurable) for assessment generation

#### RemediationService (`remediation/mod.rs`)
**Responsibilities**:
- Determines vulnerability applicability to user's package
- Generates remediation options (upgrade, workaround, backport, ignore)
- Generates detailed remediation actions with step-by-step instructions

**Submodules**:
- `converters.rs`: Data transformations
- `prompts.rs`: LLM prompt templates for action generation
- `version.rs`: Semantic version comparison and optimal version selection

**LLM Integration**: Uses OpenAI GPT-4o-mini (configurable) for action generation

#### DocumentService (`document.rs`)
**Responsibilities**:
- Retrieves documents from multiple sources via RetrieverDispatcher
- Persists documents to PostgreSQL with deduplication
- Provides CRUD operations for reference documents

**Deduplication**: Uses SHA256 hash of (canonical_url + raw_content)

#### Infrastructure Services
- **cache.rs**: Redis cache implementation with cache-aside pattern
- **llm.rs**: LLM client wrapper around OpenAI API (rig-core)
- **osv.rs**: OSV.dev API client
- **depsdev.rs**: Deps.dev API client
- **redhat_csaf.rs**: Red Hat CSAF API client

### Data Access Layer

#### Retriever System (`src/retriever/`)

**Purpose**: Specialized document retrievers for different sources

**Design Pattern**: Strategy pattern with `DocumentRetriever` trait

**Trait Definition**:
```rust
#[async_trait]
pub trait DocumentRetriever: Send + Sync {
    fn can_handle(&self, url: &Url) -> bool;
    async fn retrieve(&self, url: &Url) -> Result<RetrievedDocument, RetrieverError>;
    fn retriever_type(&self) -> RetrieverType;
}
```

**Retrievers**:
- **NvdRetriever**: National Vulnerability Database
- **CveOrgRetriever**: MITRE CVE API
- **GitHubCveRetriever**: CVEProject/cvelistV5 repository
- **GitHubAdvisoryRetriever**: GitHub Security Advisories
- **GitHubIssueRetriever**: GitHub issues (with comments)
- **GitHubCommitRetriever**: GitHub commits (with file diffs)
- **GitHubReleaseRetriever**: GitHub releases
- **BugzillaRetriever**: Bugzilla bug reports
- **RedHatCsafRetriever**: Red Hat CSAF/VEX documents
- **GenericWebRetriever**: Fallback for any web URL

**RetrieverDispatcher**:
- Selects appropriate retriever based on URL pattern
- Checks allow/deny lists from configuration
- Falls back to GenericWebRetriever if no specific retriever matches

#### Database Layer (`src/db/`)

**Purpose**: PostgreSQL persistence with repository pattern

- **repository.rs**: ReferenceDocumentRepository (CRUD operations)
- **models.rs**: Database row models and query builders
- **mod.rs**: Connection pooling and schema initialization

**Schema**: Single table `reference_documents` with indexes on:
- `retriever_type`
- `domain_url`
- `retrieved_at`

### Models (`src/model/`)

**Purpose**: Domain models, DTOs, and type definitions

- **intel.rs**: Core domain models (VulnerabilityAssessment, Claims, etc.)
- **osv.rs**: OSV.dev API response models
- **redhat_csaf.rs**: Red Hat CSAF response models
- **claims.rs**: Claim extraction models
- **assessments.rs**: Assessment extraction models
- **remediations/**: Remediation models and action extraction
- **config.rs**: Application configuration
- **convert.rs**: Conversion utilities

## Data Flow

### 1. Vulnerability Assessment Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. API Request                                          │
│    POST /v1/vulnerability/assessment                   │
│    {                                                   │
│      "cve": "CVE-2024-1234",                          │
│      "package": {                                      │
│        "purl": "pkg:npm/example@1.0.0",              │
│        "scope": "runtime"                             │
│      }                                                 │
│    }                                                   │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 2. Parallel Data Fetching (tokio::join!)              │
│    ├─→ OSV.dev API (cached in Redis)                  │
│    ├─→ Red Hat CSAF API (cached in Redis)             │
│    └─→ Deps.dev API (cached in Redis)                 │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 3. Extract Reference URLs                              │
│    - From OSV vulnerability.references[]               │
│    - From Red Hat CSAF references[]                    │
│    Total: ~5-20 URLs per vulnerability                 │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 4. Parallel Document Retrieval                         │
│    (futures::join_all)                                 │
│    ├─→ RetrieverDispatcher selects retriever          │
│    ├─→ Check URL allow/deny lists                     │
│    ├─→ Retrieve document (HTML, JSON, etc.)           │
│    ├─→ Convert to Markdown (if HTML)                  │
│    └─→ Extract metadata (title, authors, code, etc.)  │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 5. Document Persistence                                │
│    - Compute SHA256 hash (URL + content)              │
│    - Check if exists in PostgreSQL                     │
│    - Upsert to reference_documents table              │
│    - Return document IDs                               │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 6. Claim Extraction (LLM)                              │
│    For each document:                                  │
│    ├─→ Check Redis cache (claims:{doc_id})            │
│    ├─→ On miss: Fetch from PostgreSQL                 │
│    ├─→ LLM extraction (OpenAI GPT-4o-mini)            │
│    │   • Identification claims                        │
│    │   • Exploitability claims                        │
│    │   • Impact claims                                │
│    │   • Mitigation claims                            │
│    ├─→ Filter weak claims                             │
│    ├─→ Cache extracted claims                         │
│    └─→ Synthesize & deduplicate across docs           │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 7. Build VulnerabilityIntel                            │
│    - CVE metadata                                      │
│    - Package metadata                                  │
│    - Affected/fixed versions                           │
│    - Vendor remediations (from CSAF)                   │
│    - Extracted claims                                  │
│    - Reference document IDs                            │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 8. LLM Assessment                                       │
│    (VulnerabilityAssessmentService)                    │
│    ├─→ Assess exploitability                          │
│    │   • Status: exploited, likely, unlikely, unknown │
│    │   • Conditions required                          │
│    ├─→ Assess impact                                  │
│    │   • Severity: critical, high, medium, low        │
│    │   • CIA triad analysis                           │
│    └─→ Identify limitations                           │
│        • Version-specific limitations                 │
│        • Configuration dependencies                   │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 9. Confidence Computation                               │
│    Rule-based scoring:                                 │
│    - Claim quality and quantity                        │
│    - Source trust levels                               │
│    - Exploitability certainty                          │
│    - Number of limitations                             │
│    → Level: high, medium, low, very_low                │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 10. API Response                                        │
│     {                                                  │
│       "assessment": {                                  │
│         "intel": { ... },                             │
│         "exploitability": { ... },                    │
│         "impact": { ... },                            │
│         "confidence": { "level": "high", ... },       │
│         "limitations": [ ... ],                       │
│         "generated_at": "2024-01-27T...",            │
│         "retrieved_at": "2024-01-27T..."             │
│       },                                              │
│       "request_id": "uuid"                            │
│     }                                                  │
└─────────────────────────────────────────────────────────┘
```

**Performance Characteristics**:
- **Parallel I/O**: OSV, CSAF, and deps.dev fetched concurrently
- **Parallel Document Retrieval**: All reference URLs fetched in parallel
- **Caching**: Reduces redundant API calls and LLM costs
- **Typical Response Time**: 5-15 seconds (first request), 1-3 seconds (cached)

### 2. Remediation Plan Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. API Request                                          │
│    POST /v1/vulnerability/remediation_plan             │
│    {                                                   │
│      "cve": "CVE-2024-1234",                          │
│      "package": { "purl": "pkg:npm/example@1.0.0" },  │
│      "trusted_content": {                             │
│        "status": "not_affected",                      │
│        "justification": "Custom build"                │
│      }                                                 │
│    }                                                   │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 2. Get Vulnerability Assessment                         │
│    (Reuses VulnerabilityService)                       │
│    - All steps from assessment flow                    │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 3. Determine Applicability                             │
│    ├─→ Check trusted content (VEX data)                │
│    ├─→ Version range analysis                          │
│    │   • Package version vs affected ranges            │
│    │   • Semantic version comparison                   │
│    ├─→ CSAF remediation applicability                  │
│    └─→ Result: applicable, not_applicable, unknown     │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 4. Generate Remediation Options                        │
│    Based on applicability and available data:          │
│    ├─→ UPGRADE: Fixed version available                │
│    │   • Select optimal version (closest patch)        │
│    │   • Include breaking change warnings              │
│    ├─→ BACKPORT: Vendor provides backport             │
│    │   • From CSAF remediation data                    │
│    ├─→ WORKAROUND: Mitigation without upgrade         │
│    │   • From claims or CSAF                           │
│    ├─→ IGNORE: Not applicable or low risk             │
│    │   • Based on applicability result                │
│    └─→ Priority ranking                                │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 5. Select Options for Action Generation                │
│    Filter options based on:                            │
│    - Applicability status                              │
│    - Option priority                                   │
│    - User preferences                                  │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 6. Parallel Action Generation (LLM)                    │
│    For each selected option:                           │
│    ├─→ Build LLM prompt with:                          │
│    │   • Vulnerability intel                           │
│    │   • Remediation option details                    │
│    │   • Package context                               │
│    ├─→ LLM generates:                                  │
│    │   • Step-by-step instructions                     │
│    │   • Preconditions                                 │
│    │   • Verification steps                            │
│    │   • Rollback plan                                 │
│    │   • Risk assessment                               │
│    └─→ With retry logic (up to 3 attempts)             │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 7. Build RemediationPlan                                │
│    {                                                   │
│      "applicability": { ... },                        │
│      "options": [ ... ],                              │
│      "actions": [                                      │
│        {                                               │
│          "kind": "upgrade",                           │
│          "priority": 1,                               │
│          "instructions": [ ... ],                     │
│          "preconditions": [ ... ],                    │
│          "verification": [ ... ],                     │
│          "risks": [ ... ]                             │
│        }                                               │
│      ],                                                │
│      "status": "actionable"                           │
│    }                                                   │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 8. API Response                                         │
│    {                                                   │
│      "plan": { ... },                                 │
│      "intel": { ... },  // Full assessment            │
│      "request_id": "uuid"                             │
│    }                                                   │
└─────────────────────────────────────────────────────────┘
```

## Caching Strategy

### Redis Cache (Cache-Aside Pattern)

**Cache Keys**:
- `vuln:{cve}` - OSV vulnerability data
- `pkg:{purl}` - Deps.dev package metadata
- `csaf:{cve}` - Red Hat CSAF data
- `claims:{doc_id}` - Extracted claims per document

**TTL**: 1 hour (configurable via `DA_AGENT_CACHE_TTL`)

**Pattern**:
```rust
1. Check cache
2. If hit: return cached data
3. If miss: fetch from source
4. Cache the result (with TTL)
5. Return data
```

**Graceful Degradation**:
- If Redis is unavailable, service continues without cache
- Cache errors are logged but don't fail requests
- Transparent to API consumers

### PostgreSQL Storage

**Purpose**: Permanent storage with audit trail

**Documents Stored**:
- All reference documents retrieved
- Raw content (original HTML/JSON)
- Normalized content (Markdown conversion)
- Extracted metadata (title, authors, code snippets, etc.)
- Retrieval metadata (timestamp, source URL)

**Deduplication**: SHA256 hash of (canonical_url + raw_content)

**Benefits**:
- Complete audit trail
- Reproducible assessments
- Historical record for compliance

## Error Handling

### Error Flow

```
Service Error → API Error → HTTP Response
```

### Error Types by Layer

| Layer | Error Type | Purpose |
|-------|-----------|---------|
| DB | `DbError` | Database operations |
| Retriever | `RetrieverError` | Document retrieval |
| Cache | `CacheError` | Redis operations |
| Service (Vuln) | `VulnerabilityServiceError` | Business logic |
| Service (Claims) | `ClaimExtractionError` | LLM extraction |
| Service (Assessment) | `AssessmentError` | LLM assessment |
| Service (Document) | `DocumentServiceError` | Document ops |
| Service (Remediation) | `RemediationError` | Remediation generation |

### Error Handling Patterns

1. **Error Propagation**: `?` operator for bubbling errors
2. **Error Conversion**: `#[from]` for automatic conversions
3. **Graceful Degradation**: Cache failures, missing metadata
4. **Structured Logging**: `tracing` crate for context

**Current State**: Manual error conversion in API handlers (see recommendations for improvements)

## Dependencies

### Required
- **PostgreSQL 18+**: Document persistence
- **OpenAI API Key**: LLM-powered analysis

### Optional
- **Redis 8+**: Caching (recommended for production)
- **GitHub Token**: Higher API rate limits

### External APIs
- **OSV.dev**: Open Source Vulnerabilities database
- **NVD**: National Vulnerability Database
- **CVE.org**: MITRE CVE API
- **GitHub**: Security advisories, commits, issues
- **Red Hat CSAF**: Vendor security advisories
- **Bugzilla**: Bug tracking data
- **Deps.dev**: Package metadata

## Configuration

See [Configuration Guide](configuration.md) for detailed configuration options.

**Configuration Sources** (priority order):
1. Environment variables: `DA_AGENT_*`
2. Config file: `config.yaml`
3. Hardcoded defaults

## Security Considerations

1. **API Key Management**: Store `OPENAI_API_KEY` in secrets (K8s, etc.)
2. **Database Credentials**: Use secure credential management
3. **Input Validation**: CVE IDs and PURLs validated
4. **URL Filtering**: Allow/deny lists prevent SSRF
5. **Rate Limiting**: Consider adding rate limiting middleware
6. **Data Sanitization**: HTML converted to Markdown, scripts removed

## Performance Characteristics

- **Parallel I/O**: Document retrieval uses `futures::join_all`
- **Concurrent Requests**: Actix-web handles concurrent requests efficiently
- **Caching**: Reduces redundant API calls and LLM costs
- **Database Connection Pooling**: Max 10 connections (configurable)
- **LLM Costs**: Approximately $0.01-0.05 per assessment (first request)

**Typical Response Times**:
- **First request**: 5-15 seconds (fetches all data, LLM processing)
- **Cached request**: 1-3 seconds (cache hits, no LLM calls)

## Deployment

### Kubernetes Deployment

**Health Probes**:
- Liveness: `/health/live` (always returns 200)
- Readiness: `/health/ready` (checks database connection)

**Resource Requirements** (recommended):
```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

**Environment Variables**:
- `DA_AGENT_POSTGRES_*`: Database configuration
- `DA_AGENT_REDIS_*`: Redis configuration
- `OPENAI_API_KEY`: Required for LLM features
- `GITHUB_TOKEN`: Optional, for higher rate limits

See [Deployment Guide](deployment.md) for complete deployment instructions.

## Future Improvements

See [Code Review Recommendations](code-review-recommendations.md) for detailed improvement suggestions.

**Key Areas**:
1. Unified API error handling with `ResponseError` trait
2. Split large modules (remediation service)
3. Add comprehensive unit and integration tests
4. Consolidate configuration with `config` crate
5. Add observability (metrics, distributed tracing)
6. Add request validation with `validator` crate
