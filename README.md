# Trustify DA Agents

A Rust-based vulnerability intelligence service that aggregates and enriches security vulnerability data from multiple sources.

## Purpose

Trustify DA Agents provides a unified API for:

- **Vulnerability Intelligence**: Retrieve comprehensive vulnerability data for a given CVE and package combination
- **Reference Document Retrieval**: Automatically fetch and parse security advisories, commit details, and related documentation from various sources
- **Data Enrichment**: Extract structured metadata from vulnerability references including NVD, GitHub advisories, issues, commits, and releases

## Features

- **Multi-source Data Aggregation**: Fetches vulnerability data from OSV.dev and enriches with package metadata from deps.dev
- **Intelligent Document Retrieval**: Automatically retrieves and parses reference URLs with specialized retrievers for:
  - NVD (National Vulnerability Database)
  - GitHub CVE (CVEProject/cvelistV5)
  - GitHub Security Advisories
  - GitHub Issues and Pull Requests
  - GitHub Commits (with file change extraction)
  - GitHub Releases
  - Generic web pages (with meta tag and code snippet extraction)
- **Caching**: Redis-based caching for vulnerability and package data
- **Persistence**: PostgreSQL storage for reference documents
- **Configurable URL Filtering**: Allow/deny list for reference URL retrieval

## Prerequisites

- Rust 2024 edition
- PostgreSQL 18+
- Redis 8+
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

# GitHub API (optional, but recommended for higher rate limits)
GITHUB_TOKEN=your_github_token

# OSV API (optional)
OSV_BASE_URL=https://api.osv.dev

# Logging
RUST_LOG=debug
```

### 3. Run the Service

```bash
cargo run
```

The service starts on `http://localhost:8080`.

## API Reference

### Vulnerability Intelligence

#### POST `/v1/vulnerability/intel`

Retrieve vulnerability intelligence for a package and CVE combination.

**Request Body:**
```json
{
  "package": "pkg:maven/io.quarkus/quarkus-rest@3.20.4",
  "cve": "CVE-2024-12345"
}
```

**Response:** Comprehensive vulnerability intel including:
- CVE identity and severity scores
- Affected/fixed version ranges
- Exploitability assessment
- Impact assessment
- Remediation options
- Reference document IDs

---

### Reference Documents

#### GET `/v1/documents`

List reference documents with pagination and filtering.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number (1-indexed) |
| `page_size` | integer | 20 | Items per page (max: 100) |
| `retriever_type` | string | - | Filter by type: `nvd`, `git_cve_v5`, `git_advisory`, `git_issue`, `git_commit`, `git_release`, `generic` |
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

The API documentation is available at `/swagger-ui/` when the service is running.

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
│  │  └───────────┘  │    │  │ • GitHub CVE        │    │    │
│  │  ┌───────────┐  │    │  │ • GitHub Advisory   │    │    │
│  │  │ Deps.dev  │  │    │  │ • GitHub Issue      │    │    │
│  │  │ Client    │  │    │  │ • GitHub Commit     │    │    │
│  │  └───────────┘  │    │  │ • GitHub Release    │    │    │
│  └────────┬────────┘    │  │ • Generic Web       │    │    │
│           │             │  └─────────────────────┘    │    │
│           │             └──────────────┬──────────────┘    │
│           │                            │                   │
├───────────┴────────────────────────────┴───────────────────┤
│                                                            │
│  ┌─────────────────┐           ┌─────────────────────┐     │
│  │     Redis       │           │    PostgreSQL       │     │
│  │  (Caching)      │           │  (Documents)        │     │
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

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
