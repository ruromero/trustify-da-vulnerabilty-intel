# Trustify DA Agents

A Rust-based vulnerability intelligence service that aggregates, enriches, and analyzes security vulnerability data from multiple sources using LLM-powered reasoning.

## Purpose

Trustify DA Agents provides a unified API for:

- **Vulnerability Assessment**: Comprehensive vulnerability intelligence with LLM-powered claim extraction and exploitability/impact assessment
- **Remediation Planning**: Actionable remediation plans with applicability determination and step-by-step instructions
- **Reference Document Retrieval**: Automatically fetch and parse security advisories, commit details, and related documentation from various sources
- **Data Enrichment**: Extract structured metadata and security claims from vulnerability references

## Key Features

### LLM-Powered Intelligence

- **Claim Extraction**: Automatically extract structured security claims from reference documents using LLM reasoning
- **Vulnerability Assessment**: Synthesize exploitability, impact, and limitations from extracted claims
- **Remediation Action Generation**: Generate detailed, actionable remediation instructions with preconditions and risk assessments
- **Confidence Scoring**: Rule-based confidence computation with LLM-assisted reasoning explanations

### Multi-Source Data Aggregation

- **OSV.dev Integration**: Fetches vulnerability data from OSV.dev API
- **Deps.dev Integration**: Enriches with package metadata (licenses, source repos, issue trackers)
- **Red Hat CSAF/VEX**: Retrieves vendor-specific remediation information
- **GitHub Integration**: Fetches advisories, issues, commits, and releases (with authentication support)
- **NVD & CVE.org**: Retrieves official CVE descriptions and metadata
- **Bugzilla**: Fetches bug details and comments

### Intelligent Document Retrieval

Specialized retrievers for:
- NVD (National Vulnerability Database)
- CVE.org (MITRE CVE API)
- GitHub CVE (CVEProject/cvelistV5)
- GitHub Security Advisories
- GitHub Issues and Pull Requests
- GitHub Commits (with file change extraction)
- GitHub Releases
- Red Hat CSAF/VEX documents
- Bugzilla bugs
- Generic web pages (with meta tag and code snippet extraction)

### Data Persistence & Caching

- **PostgreSQL**: Persistent storage for all reference documents with full audit trail
- **Redis**: High-performance caching for vulnerability data, package metadata, and LLM-extracted claims
- **Content Deduplication**: Documents identified by content hash to avoid duplicate storage
- **Full Traceability**: Every document includes retrieval timestamp, source URL, and metadata

### Auditability & Traceability

- **Complete Audit Trail**: All reference documents stored with timestamps, source URLs, and retrieval metadata
- **Claim Provenance**: Every extracted claim includes source document ID and evidence excerpts
- **Assessment Traceability**: Vulnerability assessments include reference IDs linking back to source documents
- **LLM Call Logging**: All LLM interactions logged with timing, token usage, and model information
- **Version Tracking**: Semantic version comparison for accurate applicability determination

## Prerequisites

- Rust 2024 edition
- PostgreSQL 18+
- Redis 8+
- Docker & Docker Compose (for local development)
- OpenAI API key (required for LLM features)

## Quick Start

### 1. Start Infrastructure

```bash
cd etc/deploy/compose
docker compose up -d
```

This starts PostgreSQL and Redis containers.

### 2. Configure Environment

Create a `.env` file in the project root:

```env
# Database
DA_AGENT_DB_HOST=localhost
DA_AGENT_DB_PORT=5432
DA_AGENT_DB_USER=da_agent
DA_AGENT_DB_PASSWORD=da_agent
DA_AGENT_DB_NAME=da_agent

# Redis
DA_AGENT_REDIS_HOST=localhost
DA_AGENT_REDIS_PORT=6379

# LLM (Required)
OPENAI_API_KEY=your_openai_api_key

# Optional: Use different models
# CLAIM_EXTRACTION_MODEL=gpt-4o-mini
# ASSESSMENT_MODEL=gpt-4o-mini
# REMEDIATION_MODEL=gpt-4o-mini

# GitHub API (optional, but recommended for higher rate limits)
GITHUB_TOKEN=your_github_token

# OSV API (optional)
OSV_BASE_URL=https://api.osv.dev

# Logging
RUST_LOG=info
```

### 3. Run the Service

```bash
cargo run
```

The service starts on `http://localhost:8080`.

## API Reference

### Vulnerability Assessment

**POST** `/v1/vulnerability/assessment`

Generate a comprehensive vulnerability assessment with LLM-powered claim extraction and analysis.

See [Vulnerability Assessment Documentation](docs/vulnerability-assessment.md) for detailed information.

**Request:**
```json
{
  "cve": "CVE-2024-12345",
  "package": {
    "purl": "pkg:npm/example@1.2.3",
    "dependency_graph": [],
    "scope": "runtime"
  }
}
```

**Response:** See [Vulnerability Assessment Documentation](docs/vulnerability-assessment.md) for response structure.

---

### Remediation Plan

**POST** `/v1/vulnerability/remediation_plan`

Generate an actionable remediation plan with applicability determination and step-by-step instructions.

See [Remediation Plan Documentation](docs/remediation-plan.md) for detailed information.

**Request:**
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

**Response:** See [Remediation Plan Documentation](docs/remediation-plan.md) for response structure.

---

### Reference Documents

#### GET `/v1/documents`

List reference documents with pagination and filtering.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number (1-indexed) |
| `page_size` | integer | 20 | Items per page (max: 100) |
| `retriever_type` | string | - | Filter by type: `nvd`, `cve_org`, `git_cve_v5`, `git_advisory`, `git_issue`, `git_commit`, `git_release`, `bugzilla`, `redhat_csaf`, `generic` |
| `domain_url` | string | - | Filter by domain URL |

**Response:**
```json
{
  "documents": [
    {
      "id": "abc123...",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
      "retriever_type": "nvd",
      "title": "NVD - CVE-2024-12345",
      "retrieved_at": "2024-01-15T10:30:00Z"
    }
  ],
  "page": 1,
  "page_size": 20,
  "total_count": 42,
  "total_pages": 3
}
```

---

#### GET `/v1/documents/{id}`

Retrieve a specific reference document by ID.

**Response:** Full document including:
- `retrieved_from`: API URL used for fetching
- `canonical_url`: Original reference URL
- `raw_content`: Original content (HTML/JSON)
- `normalized_content`: Markdown-converted content
- `metadata`: Extracted metadata (title, authors, tags, code snippets, etc.)

---

#### DELETE `/v1/documents/{id}`

Delete a reference document.

**Response:** `204 No Content` on success

---

### OpenAPI Documentation

The API documentation is available at:
- **Swagger UI**: `/swagger-ui/`
- **OpenAPI JSON**: `/openapi.json`
- **OpenAPI YAML**: `/openapi.yaml`

## Data Persistence & Auditability

### PostgreSQL Storage

**Reference Documents** are permanently stored in PostgreSQL with:

- **Content Hash ID**: SHA256 hash of (canonical_url + raw_content) for deduplication
- **Retrieval Metadata**: `retrieved_at`, `retrieved_from`, `canonical_url`, `domain_url`
- **Content**: Both `raw_content` (original) and `normalized_content` (markdown)
- **Metadata**: Extracted metadata as JSON (title, authors, tags, code snippets)
- **Timestamps**: `published`, `last_modified` from source when available

**Why Persist:**
- **Audit Trail**: Complete record of all documents retrieved for a vulnerability
- **Reproducibility**: Can regenerate assessments from stored documents
- **Traceability**: Link claims and assessments back to source documents
- **Compliance**: Historical record for security audits

### Redis Caching

**Cached Data** (with TTL, default 1 hour):

- **Vulnerability Data**: OSV.dev responses keyed by CVE ID
- **Package Metadata**: Deps.dev responses keyed by PURL
- **CSAF/VEX Data**: Red Hat CSAF responses keyed by CVE ID
- **Extracted Claims**: LLM-extracted claims keyed by `(reference_id + content_hash)`

**Why Cache:**
- **Performance**: Avoid redundant API calls and LLM extractions
- **Cost Optimization**: Reduce LLM API costs by caching claim extractions
- **Rate Limiting**: Reduce load on external APIs

**Cache Keys:**
- `vuln:{cve_id}` - Vulnerability data
- `pkg:{purl}` - Package metadata
- `csaf:{cve_id}` - CSAF data
- `claims:{reference_id}:{content_hash}` - Extracted claims

### Traceability Features

1. **Reference IDs**: Every assessment includes `reference_ids` array linking to stored documents
2. **Claim Evidence**: Each extracted claim includes `reference_id` and `excerpt` from source
3. **Assessment Timestamps**: `retrieved_at` (when data fetched) and `generated_at` (when assessment computed)
4. **LLM Call Logging**: All LLM interactions logged with:
   - Model used
   - Prompt length
   - Response time
   - Success/failure status

## Configuration

### URL Filtering

Create a `config.yaml` file (or set `DA_AGENT_CONFIG_PATH` to a custom path):

```yaml
retriever:
  allow:
    - github.com
    - nvd.nist.gov
    - security.example.com
  deny:
    - internal.example.com
    - blocked-domain.com
```

- If `allow` is empty, all URLs are allowed (except denied ones)
- If `allow` has entries, only matching domains are processed
- `deny` always takes precedence

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      REST API (Actix Web)                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐    ┌─────────────────────────────┐    │
│  │ Vulnerability   │    │    Document Service         │    │
│  │ Service         │    │                             │    │
│  │                 │    │  ┌─────────────────────┐    │    │
│  │  ┌───────────┐  │    │  │ Retriever Dispatcher│    │    │
│  │  │ OSV.dev   │  │    │  ├─────────────────────┤    │    │
│  │  │ Client    │  │    │  │ • NVD Retriever     │    │    │
│  │  └───────────┘  │    │  │ • CVE.org           │    │    │
│  │  ┌───────────┐  │    │  │ • GitHub CVE        │    │    │
│  │  │ Deps.dev  │  │    │  │ • GitHub Advisory   │    │    │
│  │  │ Client    │  │    │  │ • GitHub Issue      │    │    │
│  │  └───────────┘  │    │  │ • GitHub Commit     │    │    │
│  │  ┌───────────┐  │    │  │ • GitHub Release│    │    │
│  │  │ Red Hat   │  │    │  │ • Bugzilla         │    │    │
│  │  │ CSAF      │  │    │  │ • Red Hat CSAF      │    │    │
│  │  │ Client    │  │    │  │ • Generic Web       │    │    │
│  │  └───────────┘  │    │  └─────────────────────┘    │    │
│  │  ┌───────────┐  │    └──────────────┬──────────────┘    │
│  │  │ Claim     │  │                   │                   │
│  │  │ Extraction│  │                   │                   │
│  │  │ Service   │  │                   │                   │
│  │  │ (LLM)     │  │                   │                   │
│  │  └───────────┘  │                   │                   │
│  │  ┌───────────┐  │                   │                   │
│  │  │ Assessment│  │                   │                   │
│  │  │ Service   │  │                   │                   │
│  │  │ (LLM)     │  │                   │                   │
│  │  └───────────┘  │                   │                   │
│  │  ┌───────────┐  │                   │                   │
│  │  │ Remediation│ │                   │                   │
│  │  │ Service   │  │                   │                   │
│  │  │ (LLM)     │  │                   │                   │
│  │  └───────────┘  │                   │                   │
│  └────────┬────────┘                   │                   │
│           │                            │                   │
├───────────┴────────────────────────────┴───────────────────┤
│                                                            │
│  ┌─────────────────┐           ┌─────────────────────┐     │
│  │     Redis       │           │    PostgreSQL      │     │
│  │  (Caching)      │           │  (Documents)       │     │
│  │                 │           │  (Audit Trail)     │     │
│  └─────────────────┘           └─────────────────────┘     │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

## Development

### Running Tests

```bash
cargo test
```

### Building for Production

```bash
cargo build --release
```

## Documentation

- [Vulnerability Assessment](docs/vulnerability-assessment.md) - Detailed guide to vulnerability assessment generation
- [Remediation Plan](docs/remediation-plan.md) - Detailed guide to remediation plan generation

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
