# Trustify Vulnerability Intelligence

A Rust-based vulnerability intelligence service that helps AI-assisted IDEs provide actionable remediation guidance for security vulnerabilities in project dependencies.

## What is this?

Trustify Vulnerability Intelligence is a REST service designed as a backend for MCP (Model Context Protocol) servers integrated with AI-assisted IDEs. When developers discover vulnerabilities in their dependencies, this service provides:

- **Comprehensive Vulnerability Assessments**: LLM-powered analysis of exploitability, impact, and confidence
- **Actionable Remediation Plans**: Step-by-step instructions for fixing vulnerabilities
- **Trusted Intelligence**: Claims extracted from authoritative sources (NVD, GitHub, Red Hat, etc.)
- **Complete Audit Trail**: Full traceability of all data sources and LLM reasoning

## Documentation

- **[Architecture Overview](docs/architecture.md)** - System design, data flow, and component details
- **[Configuration Guide](docs/configuration.md)** - Environment variables and config file options
- **[Vulnerability Assessment API](docs/vulnerability-assessment.md)** - Detailed API documentation
- **[Remediation Plan API](docs/remediation-plan.md)** - Detailed API documentation
- **[Code Review & Recommendations](docs/code-review-recommendations.md)** - Best practices and improvement suggestions

## Key Features

- **Multi-Source Data Aggregation**: OSV.dev, NVD, GitHub, Red Hat CSAF, Bugzilla, and more
- **LLM-Powered Analysis**: Automatic claim extraction, exploitability assessment, and remediation generation
- **PostgreSQL Storage**: Persistent storage with full audit trail and content deduplication
- **Redis Caching**: High-performance caching to reduce costs and improve response times
- **Kubernetes Ready**: Health checks, env-based configuration, production-ready deployment

For detailed feature information, see the [Architecture Documentation](docs/architecture.md).

## Prerequisites

**Required**:
- Rust 2024 edition
- PostgreSQL 18+
- OpenAI API key

**Optional**:
- Redis 8+ (recommended for production)
- GitHub token (for higher API rate limits)
- Docker & Docker Compose (for local development)

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
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run integration tests only
cargo test --test '*'
```

**Note**: Some tests require network access and are marked with `#[ignore]`. Run with:
```bash
cargo test -- --ignored
```

### Building for Production

```bash
# Build optimized release binary
cargo build --release

# Binary location
./target/release/trustify-vulnerability-intel
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint with clippy
cargo clippy -- -D warnings

# Check for issues
cargo check
```

## Troubleshooting

### Database Connection Issues

**Error**: `Failed to create database pool`

**Solutions**:
1. Check PostgreSQL is running: `pg_isready -h localhost`
2. Verify credentials in `.env` file
3. Test connection: `psql -h localhost -U da_agent -d da_agent`

### Redis Connection Issues

**Warning**: `Redis cache unavailable, running without cache`

**Solution**: This is non-critical. The service will work without Redis but with reduced performance. To enable Redis:
1. Check Redis is running: `redis-cli ping`
2. Verify Redis configuration in `.env`

### LLM API Issues

**Error**: `Failed to create LLM client: invalid OPENAI_API_KEY`

**Solutions**:
1. Check `OPENAI_API_KEY` is set correctly
2. Verify API key at https://platform.openai.com/api-keys
3. Ensure API key has sufficient credits

**Error**: `LLM assessment failed: rate limit exceeded`

**Solutions**:
1. Upgrade OpenAI plan for higher rate limits
2. Increase cache TTL to reduce LLM calls: `DA_AGENT_CACHE_TTL=7200`

### GitHub Rate Limiting

**Warning**: `Rate limited while retrieving document`

**Solution**: Add GitHub token for higher rate limits:
- Without token: 60 requests/hour
- With token: 5,000 requests/hour

```bash
export GITHUB_TOKEN="ghp_..."
```

For more detailed troubleshooting, see the [Configuration Guide](docs/configuration.md).

## API Documentation

API documentation is available at:
- **Swagger UI**: http://localhost:8080/swagger-ui/
- **OpenAPI JSON**: http://localhost:8080/openapi.json
- **OpenAPI YAML**: http://localhost:8080/openapi.yaml

## Contributing

Contributions are welcome! Please see:
- [Code Review Recommendations](docs/code-review-recommendations.md) for coding standards
- [Architecture Documentation](docs/architecture.md) for system design

**Before submitting a PR**:
1. Run tests: `cargo test`
2. Format code: `cargo fmt`
3. Check lints: `cargo clippy`
4. Update documentation if needed

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
