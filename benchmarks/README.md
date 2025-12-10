# FlashAuth Benchmarks

This directory contains benchmarking tools for FlashAuth performance testing.

## Available Benchmarks

### 1. Token Operations Benchmark (`token-operations.ts`)

Comprehensive in-process benchmarks for token operations:
- Token creation (simple, complex, with roles, etc.)
- Token validation (cached vs uncached)
- Permission checks
- Token revocation

**Run:**
```bash
bun run benchmark
```

### 2. HTTP Benchmark Server (`benchmark-server.ts`)

A simple ElysiaJS HTTP server for benchmarking FlashAuth operations via HTTP requests. This allows you to use standard HTTP benchmarking tools like `wrk`, `autocannon`, or `ab`.

**Run:**
```bash
bun run benchmark:server
```

The server starts on `http://localhost:3001`

## HTTP Benchmark Endpoints

### Baseline Endpoints (No Auth)
These endpoints help measure server overhead without FlashAuth:

- `GET /ping` - Simple ping/pong response
- `GET /health` - Health check with timestamp and uptime
- `GET /` - Server info and documentation

### Token Generation Endpoints

**Uncached (no caching layer):**
- `POST /token/generate/uncached` - Generate simple token
- `POST /token/generate/uncached/complex` - Generate complex token with custom claims

**Cached (with LRU cache enabled):**
- `POST /token/generate/cached` - Generate simple token with roles
- `POST /token/generate/cached/complex` - Generate complex token with roles and custom claims

### Token Verification Endpoints

- `POST /token/verify/uncached` - Verify token without caching
- `POST /token/verify/cached` - Verify token with caching enabled

## Example Usage

### Using curl

```bash
# Ping endpoint (baseline)
curl http://localhost:3001/ping

# Generate a simple uncached token
curl -X POST http://localhost:3001/token/generate/uncached \
  -H "Content-Type: application/json" \
  -d '{"userId":"user:123"}'

# Generate a cached token with custom roles
curl -X POST http://localhost:3001/token/generate/cached \
  -H "Content-Type: application/json" \
  -d '{"userId":"user:123","roles":["user","moderator"]}'

# Generate and verify a token
TOKEN=$(curl -s -X POST http://localhost:3001/token/generate/cached \
  -H "Content-Type: application/json" \
  -d '{"userId":"user:123"}' | jq -r '.token')

curl -X POST http://localhost:3001/token/verify/cached \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}"
```

### Using wrk

```bash
# Baseline benchmark (measure server overhead)
wrk -t4 -c100 -d30s http://localhost:3001/ping

# Token generation benchmark (save this as post-generate.lua)
cat > post-generate.lua << 'EOF'
wrk.method = "POST"
wrk.body = '{"userId":"user:123"}'
wrk.headers["Content-Type"] = "application/json"
EOF

wrk -t4 -c100 -d30s -s post-generate.lua http://localhost:3001/token/generate/cached

# Token verification benchmark
# First, generate a token
TOKEN=$(curl -s -X POST http://localhost:3001/token/generate/cached \
  -H "Content-Type: application/json" \
  -d '{"userId":"user:123"}' | jq -r '.token')

# Then create a Lua script for verification
cat > post-verify.lua << EOF
wrk.method = "POST"
wrk.body = '{"token":"'$TOKEN'"}'
wrk.headers["Content-Type"] = "application/json"
EOF

wrk -t4 -c100 -d30s -s post-verify.lua http://localhost:3001/token/verify/cached
```

### Using autocannon

```bash
# Install autocannon if needed
npm install -g autocannon

# Baseline benchmark
autocannon -c 100 -d 30 http://localhost:3001/ping

# Token generation benchmark
autocannon -c 100 -d 30 -m POST \
  -H "Content-Type: application/json" \
  -b '{"userId":"user:123"}' \
  http://localhost:3001/token/generate/cached

# Token verification benchmark
TOKEN=$(curl -s -X POST http://localhost:3001/token/generate/cached \
  -H "Content-Type: application/json" \
  -d '{"userId":"user:123"}' | jq -r '.token')

autocannon -c 100 -d 30 -m POST \
  -H "Content-Type: application/json" \
  -b "{\"token\":\"$TOKEN\"}" \
  http://localhost:3001/token/verify/cached
```

## Benchmark Comparisons

To understand FlashAuth's performance characteristics, compare:

1. **Server Overhead**: Compare `/ping` vs `/token/generate/uncached` to see the overhead of token generation
2. **Cache Benefit**: Compare `/token/verify/uncached` vs `/token/verify/cached` to measure cache performance
3. **Complexity Impact**: Compare simple vs complex token generation to see the impact of additional claims
4. **Concurrency**: Use different connection counts (`-c` flag) to test under various load conditions

## Interpreting Results

- **Requests/sec**: Higher is better - shows throughput capacity
- **Latency (p50, p95, p99)**: Lower is better - shows response time consistency
- **Baseline vs Auth**: The difference shows FlashAuth's overhead
- **Cached vs Uncached**: The difference shows cache effectiveness

## System Requirements

- Bun 1.1+
- Elysia 1.4+
- For HTTP benchmarking: `wrk`, `autocannon`, or `ab` (Apache Bench)
