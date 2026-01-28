# Configuration Guide

This guide covers all configuration options for Trustify Vulnerability Intelligence.

## Configuration Sources

Configuration is loaded from multiple sources in the following priority order (highest to lowest):

1. **Environment Variables**: `DA_INTEL_*` prefix
2. **Config File**: `config.yaml` (default) or path in `DA_INTEL_CONFIG_PATH`
3. **Hardcoded Defaults**: Built-in fallback values

## Environment Variables

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | HTTP server bind address |
| `PORT` | `8080` | HTTP server port |

**Example**:
```bash
export HOST="0.0.0.0"
export PORT="8080"
```

### Database Configuration (PostgreSQL)

| Variable | Default | Description |
|----------|---------|-------------|
| `DA_INTEL_POSTGRES_HOST` | `127.0.0.1` | PostgreSQL hostname |
| `DA_INTEL_POSTGRES_PORT` | `5432` | PostgreSQL port |
| `DA_INTEL_POSTGRES_USER` | `da_intel` | Database user |
| `DA_INTEL_POSTGRES_PASSWORD` | `da_intel` | Database password |
| `DA_INTEL_POSTGRES_DB` | `da_intel` | Database name |

**Example**:
```bash
export DA_INTEL_POSTGRES_HOST="postgres.example.com"
export DA_INTEL_POSTGRES_PORT="5432"
export DA_INTEL_POSTGRES_USER="da_intel"
export DA_INTEL_POSTGRES_PASSWORD="secure_password"
export DA_INTEL_POSTGRES_DB="da_intel"
```

**Connection String Format**:
```
postgres://{user}:{password}@{host}:{port}/{database}
```

### Cache Configuration (Redis)

| Variable | Default | Description |
|----------|---------|-------------|
| `DA_INTEL_REDIS_HOST` | `127.0.0.1` | Redis hostname |
| `DA_INTEL_REDIS_PORT` | `6379` | Redis port |
| `DA_INTEL_REDIS_PASSWORD` | _(none)_ | Redis password (optional) |
| `DA_INTEL_REDIS_DB` | `0` | Redis database number |
| `DA_INTEL_CACHE_TTL` | `3600` | Cache TTL in seconds (1 hour) |

**Example**:
```bash
export DA_INTEL_REDIS_HOST="redis.example.com"
export DA_INTEL_REDIS_PORT="6379"
export DA_INTEL_REDIS_PASSWORD="secure_redis_password"
export DA_INTEL_REDIS_DB="0"
export DA_INTEL_CACHE_TTL="7200"  # 2 hours
```

**Redis URL Format** (internal):
```
redis://[:password@]host:port/db
```

**Note**: Redis is **optional**. If Redis is unavailable, the service will run without caching (reduced performance, higher LLM costs).

### LLM Configuration (OpenAI)

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | _(required)_ | OpenAI API key |
| `CLAIM_EXTRACTION_MODEL` | `gpt-4o-mini` | Model for claim extraction |
| `ASSESSMENT_MODEL` | `gpt-4o-mini` | Model for vulnerability assessment |
| `REMEDIATION_MODEL` | `gpt-4o-mini` | Model for remediation action generation |

**Example**:
```bash
export OPENAI_API_KEY="sk-..."
export CLAIM_EXTRACTION_MODEL="gpt-4o-mini"
export ASSESSMENT_MODEL="gpt-4o"
export REMEDIATION_MODEL="gpt-4o-mini"
```

**Model Options**:
- `gpt-4o-mini`: Fast and cost-effective (recommended)
- `gpt-4o`: More accurate but slower and more expensive
- `gpt-4-turbo`: Older model (not recommended)

**Cost Estimates** (per assessment, first request):
- With `gpt-4o-mini`: ~$0.01-0.03
- With `gpt-4o`: ~$0.05-0.15

### Integration Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | _(none)_ | GitHub personal access token (optional) |
| `OSV_BASE_URL` | `https://api.osv.dev/v1` | OSV.dev API base URL |

**Example**:
```bash
export GITHUB_TOKEN="ghp_..."  # Optional, for higher rate limits
export OSV_BASE_URL="https://api.osv.dev/v1"
```

**GitHub Token Benefits**:
- **Without token**: 60 requests/hour per IP
- **With token**: 5,000 requests/hour

**Scopes Required**: No special scopes needed (public read-only access)

### Logging Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level filter |

**Example**:
```bash
export RUST_LOG="info"
```

**Log Levels** (from most to least verbose):
- `trace`: Very detailed, including internal library logs
- `debug`: Detailed application logs (cache hits, API calls)
- `info`: General operational logs (recommended for production)
- `warn`: Warning messages
- `error`: Error messages only

**Module-Specific Logging**:
```bash
# Enable debug logs for specific modules
export RUST_LOG="trustify_vulnerability_intel=debug,sqlx=warn,actix_web=info"

# Enable trace for specific service
export RUST_LOG="trustify_vulnerability_intel::service::vulnerability=trace"
```

## Config File

Create a `config.yaml` file in the project root (or specify path via `DA_INTEL_CONFIG_PATH`).

### Example config.yaml

```yaml
# Retriever URL filtering
retriever:
  # Allow only these domains (empty = allow all)
  allow:
    - github.com
    - nvd.nist.gov
    - cve.org
    - bugzilla.redhat.com
    - access.redhat.com

  # Block these domains (takes precedence over allow)
  deny:
    - internal.example.com
    - localhost
```

### Retriever Filtering

**Purpose**: Prevent SSRF attacks by controlling which URLs can be fetched.

**Rules**:
1. If `allow` is empty: all URLs are allowed (except denied ones)
2. If `allow` has entries: only matching domains are fetched
3. `deny` always takes precedence over `allow`

**Example Use Cases**:

**1. Allow Only Trusted Sources**:
```yaml
retriever:
  allow:
    - github.com
    - nvd.nist.gov
    - cve.org
  deny: []
```

**2. Block Internal Networks**:
```yaml
retriever:
  allow: []  # Allow all
  deny:
    - localhost
    - 127.0.0.1
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - internal.example.com
```

**3. Strict Whitelist**:
```yaml
retriever:
  allow:
    - github.com
    - nvd.nist.gov
    - cve.org
    - bugzilla.redhat.com
    - access.redhat.com
    - www.openwall.org
  deny: []
```

## Configuration Examples

### Development Environment

**.env file**:
```bash
# Server
HOST="0.0.0.0"
PORT="8080"

# Database (local PostgreSQL)
DA_INTEL_POSTGRES_HOST="localhost"
DA_INTEL_POSTGRES_PORT="5432"
DA_INTEL_POSTGRES_USER="da_intel"
DA_INTEL_POSTGRES_PASSWORD="da_intel"
DA_INTEL_POSTGRES_DB="da_intel"

# Cache (local Redis)
DA_INTEL_REDIS_HOST="localhost"
DA_INTEL_REDIS_PORT="6379"
DA_INTEL_CACHE_TTL="3600"

# LLM
OPENAI_API_KEY="sk-..."
CLAIM_EXTRACTION_MODEL="gpt-4o-mini"
ASSESSMENT_MODEL="gpt-4o-mini"
REMEDIATION_MODEL="gpt-4o-mini"

# Integrations
GITHUB_TOKEN="ghp_..."  # Optional

# Logging
RUST_LOG="debug"
```

**config.yaml**:
```yaml
retriever:
  allow: []  # Allow all
  deny:
    - localhost
    - 127.0.0.1
```

### Production Environment (Kubernetes)

**ConfigMap**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: trustify-vulnerability-intel-config
data:
  config.yaml: |
    retriever:
      allow:
        - github.com
        - nvd.nist.gov
        - cve.org
        - bugzilla.redhat.com
        - access.redhat.com
      deny:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - localhost
```

**Secret**:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: trustify-vulnerability-intel-secrets
type: Opaque
stringData:
  OPENAI_API_KEY: "sk-..."
  GITHUB_TOKEN: "ghp_..."
  DA_INTEL_POSTGRES_PASSWORD: "secure_password"
  DA_INTEL_REDIS_PASSWORD: "secure_redis_password"
```

**Deployment**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: trustify-vulnerability-intel
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: trustify-vulnerability-intel
        image: trustify-vulnerability-intel:latest
        env:
        # Server
        - name: HOST
          value: "0.0.0.0"
        - name: PORT
          value: "8080"
        # Database
        - name: DA_INTEL_POSTGRES_HOST
          value: "postgres-service"
        - name: DA_INTEL_POSTGRES_PORT
          value: "5432"
        - name: DA_INTEL_POSTGRES_USER
          value: "da_intel"
        - name: DA_INTEL_POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: trustify-vulnerability-intel-secrets
              key: DA_INTEL_POSTGRES_PASSWORD
        - name: DA_INTEL_POSTGRES_DB
          value: "da_intel"
        # Redis
        - name: DA_INTEL_REDIS_HOST
          value: "redis-service"
        - name: DA_INTEL_REDIS_PORT
          value: "6379"
        - name: DA_INTEL_REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: trustify-vulnerability-intel-secrets
              key: DA_INTEL_REDIS_PASSWORD
        - name: DA_INTEL_CACHE_TTL
          value: "7200"  # 2 hours in production
        # LLM
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: trustify-vulnerability-intel-secrets
              key: OPENAI_API_KEY
        - name: ASSESSMENT_MODEL
          value: "gpt-4o-mini"
        # Integrations
        - name: GITHUB_TOKEN
          valueFrom:
            secretKeyRef:
              name: trustify-vulnerability-intel-secrets
              key: GITHUB_TOKEN
        # Logging
        - name: RUST_LOG
          value: "info"
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
      volumes:
      - name: config
        configMap:
          name: trustify-vulnerability-intel-config
```

## Validation

### Check Configuration

```bash
# Verify environment variables are set
env | grep DA_INTEL

# Test database connection
psql -h $DA_INTEL_POSTGRES_HOST -U $DA_INTEL_POSTGRES_USER -d $DA_INTEL_POSTGRES_DB -c "SELECT 1"

# Test Redis connection
redis-cli -h $DA_INTEL_REDIS_HOST -p $DA_INTEL_REDIS_PORT PING

# Test OpenAI API key
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

### Startup Logs

When the service starts, check logs for configuration confirmation:

```
INFO trustify_vulnerability_intel: Connecting to PostgreSQL host=localhost port=5432
INFO trustify_vulnerability_intel: PostgreSQL connection established
INFO trustify_vulnerability_intel: Connecting to Redis host=localhost port=6379
INFO trustify_vulnerability_intel: Redis connection established
INFO trustify_vulnerability_intel::service::remediation: Remediation service initialized model=gpt-4o-mini
INFO trustify_vulnerability_intel: Starting Trustify Vulnerability Intelligence server on 0.0.0.0:8080
```

**Warning Messages** (non-critical):
```
WARN trustify_vulnerability_intel: Redis cache unavailable, running without cache
```
This is OK - the service will work without Redis, just with reduced performance.

## Troubleshooting

### Database Connection Issues

**Error**:
```
Error: Failed to create database pool
```

**Solutions**:
1. Check PostgreSQL is running: `pg_isready -h $DA_INTEL_POSTGRES_HOST`
2. Verify credentials are correct
3. Check network connectivity: `telnet $DA_INTEL_POSTGRES_HOST 5432`
4. Check database exists: `psql -l`

### Redis Connection Issues

**Warning**:
```
WARN: Redis cache unavailable, running without cache
```

**Solutions**:
- This is non-critical - the service will run without Redis
- To enable Redis: check Redis is running and credentials are correct
- Test connection: `redis-cli -h $DA_INTEL_REDIS_HOST PING`

### LLM API Issues

**Error**:
```
Error: Failed to create LLM client: invalid OPENAI_API_KEY
```

**Solutions**:
1. Check API key is set: `echo $OPENAI_API_KEY`
2. Verify API key is valid: Test at https://platform.openai.com/api-keys
3. Check API key has sufficient credits

**Error**:
```
Error: LLM assessment failed: rate limit exceeded
```

**Solutions**:
1. Upgrade OpenAI plan for higher rate limits
2. Increase cache TTL to reduce LLM calls
3. Add retry logic with backoff (already implemented for action generation)

### GitHub Rate Limiting

**Warning**:
```
WARN: Rate limited while retrieving document, skipping
```

**Solutions**:
1. Add `GITHUB_TOKEN` environment variable
2. Rate limits:
   - Without token: 60 requests/hour
   - With token: 5,000 requests/hour

## Performance Tuning

### Cache TTL

**Default**: 1 hour (3600 seconds)

**Recommendations**:
- **Development**: 300 seconds (5 minutes) - faster iteration
- **Production**: 7200 seconds (2 hours) - reduce LLM costs
- **High-traffic**: 14400 seconds (4 hours) - maximize cache hits

**Trade-offs**:
- Longer TTL = Lower cost, potentially stale data
- Shorter TTL = Fresher data, higher LLM costs

### Database Connection Pool

**Default**: 10 connections

**Recommendations** (based on expected traffic):
- **Low traffic** (<10 req/s): 5 connections
- **Medium traffic** (10-50 req/s): 10-20 connections
- **High traffic** (>50 req/s): 20-50 connections

**Note**: This requires code change (see recommendations document for future improvements)

### LLM Model Selection

**Cost vs Quality Trade-off**:

| Model | Speed | Cost | Quality |
|-------|-------|------|---------|
| gpt-4o-mini | Fast | $0.01 | Good |
| gpt-4o | Medium | $0.05 | Better |
| gpt-4-turbo | Slow | $0.10 | Best |

**Recommendations**:
- **Development**: `gpt-4o-mini` (fast, cheap)
- **Production**: `gpt-4o-mini` for most workloads
- **High-accuracy**: `gpt-4o` for critical assessments

## Security Best Practices

1. **Never commit secrets** to version control
2. **Use environment variables** or secrets management for:
   - `OPENAI_API_KEY`
   - `DA_INTEL_POSTGRES_PASSWORD`
   - `DA_INTEL_REDIS_PASSWORD`
   - `GITHUB_TOKEN`
3. **Configure URL filtering** to prevent SSRF:
   - Whitelist trusted domains
   - Blacklist internal networks
4. **Use TLS** for database and Redis connections in production
5. **Rotate API keys** regularly
6. **Monitor API usage** to detect anomalies

## Migration Notes

### From Old Configuration Format

If you're using individual environment variables, no changes needed - they're still supported.

### Future Configuration Format

Future versions may consolidate configuration using the `config` crate. See [Code Review Recommendations](code-review-recommendations.md) for details.

Expected format:
```yaml
server:
  host: "0.0.0.0"
  port: 8080

database:
  host: "localhost"
  port: 5432
  user: "da_intel"
  password: "${DA_INTEL_POSTGRES_PASSWORD}"
  database: "da_intel"

cache:
  host: "localhost"
  port: 6379
  ttl_seconds: 3600

llm:
  openai_api_key: "${OPENAI_API_KEY}"
  assessment_model: "gpt-4o-mini"

integrations:
  github_token: "${GITHUB_TOKEN}"

retrievers:
  allow: []
  deny: []
```
