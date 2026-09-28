# Cloudflare Worker — Production-Grade Country-Based Auto Guard

A production-grade, zero-external-backend automated IP threat detection and mitigation system built entirely on Cloudflare edge primitives (**Cloudflare Workers**, **Sharded Durable Objects**, **Cloudflare KV**, **Lists API**, and **Cloudflare WAF**).

---

## 🚀 Overview

High-frequency malicious traffic and DDoS probes often display distinct geographic patterns. **Auto Guard** continuously monitors inbound traffic, calculates sliding time-window metrics across IP addresses, and applies dynamic country-specific security policies stored in Cloudflare KV. 

When an IP crosses a configured request threshold within the sliding window and ranks within the Top-N candidate set, Auto Guard automatically registers the offending IP into a Cloudflare IP List for immediate WAF-level mitigation.

### Key Highlights
* **Zero External Dependencies**: No Redis, PostgreSQL, Node.js VPS, Docker containers, or third-party servers required. Everything runs natively within Cloudflare.
* **Sharded Durable Objects**: Distributed state storage partitioned by IP hash to prevent serialization bottlenecks and scale horizontally.
* **Distributed Top-N Aggregation**: Shards compute local Top-N candidates and stream only high-volume candidates to the global merge stage. Raw traffic records never choke a central node.
* **Runtime Dynamic Policies**: Policies are stored in Cloudflare KV (`guard:policy`). Thresholds, country rules, and time windows can be updated instantaneously **without redeploying Worker code**.
* **Failure Isolation**: If the Cloudflare Lists API or DO storage experiences an anomaly, legitimate user traffic is never interrupted or blocked.
* **Dry-Run Mode**: Full audit trail of block decisions (`WOULD_BLOCK`) without calling the mutation API for safe staging validation.
* **Idempotency & Deduplication**: Prevents duplicate Cloudflare API calls for IPs already present in the block list.

---

## 🏛️ Architecture

```text
                    INCOMING REQUEST
                           │
                           ▼
                   CLOUDFLARE WORKER
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
      IP & Country Metadata         Policy KV
              │                         │
              ▼                         │
      Traffic Collector                 │
              │                         │
              ▼                         │
    Durable Object Shards               │
      (sliding buckets)                 │
              │                         │
              ▼                         │
     Distributed Top-N                  │
              │                         │
              └────────────┬────────────┘
                           ▼
                    Policy Resolver
              (Country Override + Default)
                           │
                           ▼
                    Decision Engine
              (Deterministic Precedence)
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
             IGNORE                 BLOCK
                                      │
                                      ▼
                             Cloudflare Lists API
                                      │
                                      ▼
                                Cloudflare WAF
                             (ip.src in $LIST -> BLOCK)
```

---

## ⚙️ Configuration & Policy Schema

Policies are stored as JSON in Cloudflare KV under the key `guard:policy` in the `POLICY_KV` namespace.

### KV Policy Example

```json
{
  "enabled": true,
  "windowSeconds": 300,
  "topN": 100,
  "default": {
    "enabled": true,
    "threshold": 10000,
    "action": "block"
  },
  "allowlist": [
    "1.1.1.1",
    "8.8.8.8",
    "192.168.0.0/16"
  ],
  "countries": {
    "TR": {
      "enabled": false
    },
    "US": {
      "enabled": true,
      "threshold": 2000,
      "action": "block"
    },
    "DE": {
      "enabled": true,
      "threshold": 5000,
      "action": "block"
    },
    "NL": {
      "enabled": true,
      "threshold": 3000,
      "action": "block"
    },
    "GB": {
      "enabled": true,
      "threshold": 4000,
      "action": "block"
    }
  }
}
```

### Policy Precedence Rules
1. **Global Enablement**: If `enabled: false`, all guard evaluations return `IGNORE` (`GLOBAL_DISABLED`).
2. **IP Validation**: Malformed or missing IP headers return `IGNORE` (`INVALID_IP`).
3. **Allowlist**: If the IP matches any allowlist IP or CIDR block, it is immediately permitted (`ALLOWLISTED`).
4. **Country Override**: If the country policy is explicitly set to `enabled: false` (e.g., `TR`), it is ignored (`COUNTRY_DISABLED`).
5. **Top-N Filter**: If an IP rank is outside the active Top-N window, it returns `IGNORE` (`OUTSIDE_TOP_N`).
6. **Threshold Check**: If request volume in the sliding window is below the resolved country or default threshold, it returns `IGNORE` (`BELOW_THRESHOLD`).
7. **Idempotency**: If the IP is already present in the block list cache, it returns `IGNORE` (`ALREADY_BLOCKED`).
8. **Action**: If `dryRun: true`, the decision logs `WOULD_BLOCK` without mutating the Cloudflare List. Otherwise, the IP is added to the Cloudflare List.

---

## 📁 Project Directory Structure

```text
cloudflare-auto-guard/
│
├── index.ts                     # Worker entry point and Durable Object definition
│
├── config/
│   ├── config-loader.ts         # Loads KV policies and environment variables
│   ├── policy-schema.ts         # Zod schema validation for runtime policies
│   └── defaults.ts              # Fallback fail-safe default policy
│
├── domain/
│   ├── models/                  # IP, traffic, policy, and decision domain models
│   └── policies/                # Country, Top-N, threshold, and global policies
│
├── guard/
│   ├── collector.ts             # Captures request metadata
│   ├── aggregator.ts            # Sliding bucket aggregator
│   ├── evaluator.ts             # Evaluates candidate IPs against policies
│   ├── decision-engine.ts       # Deterministic decision pipeline
│   └── blocker.ts               # Executes IP block mutations
│
├── storage/
│   ├── durable-object.ts        # Sharded Durable Object traffic storage
│   ├── traffic-repository.ts    # Storage adapter for metrics
│   └── policy-cache.ts          # In-memory TTL cache for KV policies
│
├── cloudflare/
│   ├── client.ts                # Cloudflare API client with exponential backoff
│   ├── lists.ts                 # Cloudflare Lists API operations
│   └── types.ts                 # API response and request type definitions
│
├── security/
│   ├── ip-validator.ts          # IPv4 and IPv6 format validator
│   ├── ip-normalizer.ts         # Normalized representation for comparisons
│   └── allowlist.ts             # Exact IP and CIDR subnet matcher
│
├── observability/
│   ├── logger.ts                # Structured JSON logging
│   ├── metrics.ts               # Runtime metrics collector
│   └── audit.ts                 # Block decision audit recorder
│
├── shared/
│   ├── errors.ts                # Domain and infrastructure error definitions
│   ├── retry.ts                 # Exponential backoff and retry helper
│   └── utils.ts                 # Hashing and date-time utilities
│
├── test/
│   ├── unit/                    # Unit tests for policy, validator, and engine
│   ├── integration/             # Integration tests with mocked KV and Lists API
│   └── fixtures/                # Mock policies and request payloads
│
├── wrangler.jsonc               # Cloudflare Workers configuration
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── .dev.vars.example
├── .gitignore
└── README.md
```

---

## 🛡️ Cloudflare WAF Configuration

Once Auto Guard registers an IP to the configured Cloudflare List (e.g., `AUTO_GUARD_BLOCK`), configure a Cloudflare WAF Custom Rule in your zone dashboard:

* **Rule Name**: `Auto Guard IP Block Rule`
* **Expression**:
  ```text
  ip.src in $AUTO_GUARD_BLOCK
  ```
* **Action**: `Block`

Any IP listed by the Worker will immediately be dropped at the Cloudflare edge before reaching origin infrastructure.

---

## 🛠️ Getting Started & Local Development

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment Variables
Copy `.dev.vars.example` to `.dev.vars`:
```bash
cp .dev.vars.example .dev.vars
```
Fill in your Cloudflare credentials:
```ini
CF_API_TOKEN=your_cloudflare_api_token
CF_ACCOUNT_ID=your_cloudflare_account_id
CF_LIST_ID=your_cloudflare_list_id
DRY_RUN=true
```

### 3. Run Locally
```bash
npm run dev
```

### 4. Run Unit & Integration Tests
```bash
npm test
```

---

## 🚢 Production Deployment

```bash
# 1. Typecheck the codebase
npm run typecheck

# 2. Deploy to Cloudflare
npm run deploy
```

---

## 👨‍💻 Author & Vision

**Can Ugur**  
*Full-stack Architect & Open Source Craftsman*  

[![GitHub](https://img.shields.io/badge/GitHub-Profile-181717?style=flat&logo=github)](https://github.com/imcanugur) 
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/can-ugur)

> *"Stop configuring. Start building."*

---

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for more information.

---

<p align="center">
  <i>Mastering the local network, one port at a time.</i><br>
  <i>Made with ☕ and passion in the dev cave.</i>
</p>
