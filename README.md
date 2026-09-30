# 🛡️ Cloudflare Auto Guard

A production-grade, zero-external-backend automated IP threat detection and mitigation system built entirely on Cloudflare edge primitives (**Cloudflare Workers**, **GraphQL Zone Analytics**, **Rules Lists API**, **Cloudflare KV**, and **Cloudflare WAF**).

---

## 🚀 Overview

High-frequency malicious traffic, DDoS probes, and scrapers often display distinct geographic patterns. **Auto Guard** continuously monitors real edge traffic directly from **Cloudflare GraphQL Zone Analytics**, evaluates candidates against dynamic country-based policies, and automatically mitigates offending IPs via Cloudflare IP Lists and WAF rules.

### Key Highlights
* **Zero External Dependencies**: No Redis, PostgreSQL, Node.js VPS, Docker containers, or third-party servers required. Everything runs 100% natively on Cloudflare.
* **Edge GraphQL Analytics**: Queries live edge traffic directly via Cloudflare Analytics API (`httpRequestsAdaptiveGroups`).
* **High-Performance Bulk Batching**: Applies bans in a single bulk API call (up to 1,000 IPs per request), completely preventing subrequest limit errors.
* **Automated Unban (TTL & 10k Limit Protection)**: Automatically expires and prunes old bans after a configurable TTL (e.g., 24 hours) and applies FIFO pruning when approaching Cloudflare's 10,000 list item limit.
* **Runtime Dynamic Policies**: Policies are stored in Cloudflare KV (`POLICY_KV`). Rules, thresholds, and time windows can be updated instantaneously via cURL or Postman **without redeploying code**.
* **Detailed Audit Trail**: Enriches banned IPs with metadata comments including Country, Request count, Rule threshold, Time window, Traffic rank, and UTC timestamp.
* **Failure Isolation**: If the Cloudflare Lists API experiences an anomaly, legitimate user traffic is never interrupted.
* **Dry-Run Mode**: Full audit trail of block decisions (`WOULD_BLOCK`) without calling the mutation API for safe staging validation.
* **100% Idempotent**: Prevents duplicate Cloudflare API calls by checking existing list items before evaluation.

---

## 🏛️ Architecture

```text
                     EDGE TRAFFIC
                          │
                          ▼
            CLOUDFLARE ZONE ANALYTICS
        (httpRequestsAdaptiveGroups GraphQL)
                          │
                          ▼
            AUTO GUARD CRON / API WORKER
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
      Active Policy KV           Existing WAF List
       (guard:policy)         (syncExistingList / TTL Pruning)
             │                         │
             └────────────┬────────────┘
                          ▼
                   Decision Engine
             (Candidate IP Evaluation)
                          │
               ┌──────────┴──────────┐
               ▼                     ▼
            IGNORE                 BLOCK
                                     │
                                     ▼
                          Bulk Batch Mutations
                          (Cloudflare Lists API)
                                     │
                                     ▼
                               Cloudflare WAF
                         (ip.src in $auto_guard_block)
```

---

## ⚙️ Configuration & Policy Schema

Policies can be updated at runtime via `POST /__guard/policy` and are persisted in Cloudflare KV.

### Policy Configuration Template (`policy.example.json`)

```json
{
  "enabled": true,
  "windowSeconds": 3600,
  "topN": 100,
  "default": {
    "enabled": true,
    "threshold": 1000,
    "action": "block"
  },
  "allowlist": [
    "1.1.1.1",
    "8.8.8.8"
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
      "threshold": 1500,
      "action": "block"
    },
    "NL": {
      "enabled": true,
      "threshold": 1000,
      "action": "block"
    }
  },
  "unban": {
    "enabled": true,
    "ttlSeconds": 86400,
    "maxListSize": 9000
  }
}
```

### Policy Precedence Rules
1. **Global Enablement**: If `enabled: false`, all guard evaluations return `IGNORE` (`GLOBAL_DISABLED`).
2. **IP Validation**: Malformed or private IP headers return `IGNORE` (`INVALID_IP`).
3. **Allowlist**: If the IP matches any allowlist IP or CIDR block, it is immediately permitted (`ALLOWLISTED`).
4. **Country Override**: If the country policy is explicitly set to `enabled: false` (e.g., `TR`), it is ignored (`COUNTRY_DISABLED`).
5. **Top-N Filter**: If an IP rank is outside the active Top-N window, it returns `IGNORE` (`OUTSIDE_TOP_N`).
6. **Threshold Check**: If request volume in the sliding window is below the resolved country or default threshold, it returns `IGNORE` (`BELOW_THRESHOLD`).
7. **Idempotency**: If the IP is already present in the block list, it returns `IGNORE` (`ALREADY_BLOCKED`).
8. **Action**: If `dryRun: true`, the decision logs `WOULD_BLOCK` without mutating the Cloudflare List. Otherwise, the IP is added in bulk to the Cloudflare List.

---

## 🛠️ Step-by-Step Installation & Setup

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/imcanugur/cloudflare-auto-guard.git
cd cloudflare-auto-guard
npm install
```

### 2. Configure Cloudflare Secrets
Set your credentials directly into Cloudflare's encrypted vault:

```bash
# Zone ID of the website you want to protect
npx wrangler secret put CF_ZONE_ID

# Your Cloudflare Account ID
npx wrangler secret put CF_ACCOUNT_ID

# Cloudflare API Token (Requires Zone:Analytics:Read, Zone:Zone:Read, Account:Lists:Edit)
npx wrangler secret put CF_API_TOKEN

# Cloudflare Rules List ID for 'auto_guard_block'
npx wrangler secret put CF_LIST_ID

# Optional: Admin Secret Token to protect /__guard/* routes
npx wrangler secret put GUARD_ADMIN_TOKEN
```

### 3. Bind KV Namespace (in Cloudflare Dashboard)
1. Go to **Cloudflare Dashboard** ➔ **Workers & Pages** ➔ `cloudflare-auto-guard` ➔ **Settings** ➔ **Bindings**.
2. Click **Add binding** ➔ **KV Namespace**:
   * **Variable name**: `POLICY_KV`
   * **KV namespace**: Select your KV namespace (e.g., `AutoBanner`).
3. Click **Deploy**.

### 4. Create Cloudflare WAF Custom Rule
In your Cloudflare Zone dashboard under **Security** ➔ **WAF** ➔ **Custom Rules**:
* **Rule Name**: `Auto Guard WAF Block`
* **Expression**:
  ```text
  ip.src in $auto_guard_block
  ```
* **Action**: `Block`

### 5. Deploy Worker
```bash
npx wrangler deploy
```

---

## 📡 API & cURL Administration Guide

All management routes are pure headless JSON API. If `GUARD_ADMIN_TOKEN` is configured, pass `-H "X-Guard-Token: <token>"`.

### 1. View Active Policy
```bash
curl https://cloudflare-auto-guard.<subdomain>.workers.dev/__guard/policy \
  -H "X-Guard-Token: your_secret_token"
```

### 2. Update Policy in Real-Time (Persists to KV)
```bash
curl -X POST https://cloudflare-auto-guard.<subdomain>.workers.dev/__guard/policy \
  -H "Content-Type: application/json" \
  -H "X-Guard-Token: your_secret_token" \
  -d @policy.json
```

### 3. Trigger Instant Threat Evaluation
```bash
curl -X POST https://cloudflare-auto-guard.<subdomain>.workers.dev/__guard/evaluate \
  -H "X-Guard-Token: your_secret_token"
```

### 4. Health & Diagnostics
```bash
# Health Check
curl https://cloudflare-auto-guard.<subdomain>.workers.dev/health

# Environment Diagnostic Check
curl https://cloudflare-auto-guard.<subdomain>.workers.dev/_debug
```

---

## 🤖 Telegram Bot Control Center & Real-Time Alerts

Manage, monitor, and unban IPs directly from your phone or desktop via a secure, two-way Telegram Bot integrated directly into Cloudflare Workers!

### 📱 1. Interactive Bot Commands

| Command | Description | Example |
| :--- | :--- | :--- |
| `/status` | Live system health, active policy summary, and current banned IP count | `/status` |
| `/evaluate` | Instantly queries GraphQL Analytics and evaluates live edge traffic | `/evaluate` |
| `/list` | Shows currently active banned IPs in Cloudflare WAF with unban buttons | `/list` |
| `/ban <ip> [reason]` | Manually adds an IP to Cloudflare Rules List in real-time | `/ban 198.51.100.4 Scraper bot` |
| `/unban <ip>` | Removes an IP from Cloudflare Rules List and clears local cache | `/unban 198.51.100.4` |
| `/policy` | Displays the active protection policy JSON in formatted code | `/policy` |
| `/help` | Interactive control panel with instant action buttons | `/help` |

---

### 🚨 2. Real-Time Push Alerts with 1-Click Unban

Whenever the automated cron detects high-frequency attacks or policy violations, it instantly pushes a card directly to your Telegram chat:

```text
🚨 Auto Guard: Threat Detected & Mitigated!
━━━━━━━━━━━━━━━━━━━━
🌐 IP: 185.220.101.5
🏳️ Country: Russia (RU)
📊 Traffic: 1,420 requests (Threshold: 300)
🏷️ Rank: #1
📝 Reason: Exceeded country RU limit of 300 requests
━━━━━━━━━━━━━━━━━━━━
⏰ 2026-09-30 15:20:00 UTC

[ 🔓 Unban (185.220.101.5) ]  <-- (Interactive Inline Button)
```

> **Single-Click Unban**: Tapping the **[ 🔓 Unban ]** button immediately invokes the Cloudflare Rules Lists API, deletes the IP, purges the local cache, and edits the Telegram card to:  
> `✅ [UNBANNED] (by @admin_username)`.

---

### 🛠️ 3. Telegram Bot Setup (in 3 Simple Steps)

#### Step 1: Create Your Bot & Obtain Chat ID
1. Open Telegram and search for **[@BotFather](https://t.me/BotFather)**. Send `/newbot`, name your bot, and copy the provided `HTTP API Token`.
2. Search for **[@userinfobot](https://t.me/userinfobot)** in Telegram to retrieve your numeric `Id` (used as `TELEGRAM_ADMIN_CHAT_ID` to restrict bot access exclusively to you).

#### Step 2: Store Secrets in Cloudflare
```bash
# Save your Telegram Bot Token
npx wrangler secret put TELEGRAM_BOT_TOKEN
# Paste your BotFather token when prompted

# Save your Telegram Admin Chat ID (comma-separated for multiple admins: 12345,67890)
npx wrangler secret put TELEGRAM_ADMIN_CHAT_ID
# Paste your user ID when prompted

# Deploy your Worker
npx wrangler deploy
```

#### Step 3: Register Webhook in One Click
Open the setup endpoint in your browser or curl:
```bash
curl https://cloudflare-auto-guard.<subdomain>.workers.dev/__guard/telegram/setup
```
*Done!* Your Telegram Bot is now registered and active on Cloudflare Edge with two-way communication.

---

## 📁 Project Directory Structure

```text
cloudflare-auto-guard/
│
├── index.ts                     # Worker entry point (Fetch, Cron, REST API & Telegram Webhook)
│
├── telegram/                    # Telegram Bot Subsystem (Edge-Native)
│   ├── bot.ts                   # Command router, interactive callbacks & alert dispatcher
│   ├── client.ts                # Telegram Bot HTTP API client (sendMessage, setWebhook, etc.)
│   └── types.ts                 # Telegram Update, Message & Keyboard contract types
│
├── config/
│   ├── config-loader.ts         # Runtime policy loader with fail-safe defaults
│   ├── policy-schema.ts         # Zod schema validation for runtime policies
│   └── defaults.ts              # Fallback fail-safe default policy
│
├── domain/
│   ├── models/                  # IP, traffic, policy, and decision domain models
│   └── policies/                # Country, Top-N, threshold, and global policies
│
├── guard/
│   ├── evaluator.ts             # Deterministic candidate IP evaluator
│   ├── decision-engine.ts       # Main coordination pipeline
│   └── blocker.ts               # Bulk batch list execution & auto-unban pruning
│
├── cloudflare/
│   ├── client.ts                # Resilient Cloudflare API client (REST & GraphQL)
│   ├── analytics.ts             # Cloudflare GraphQL Zone Analytics service
│   ├── lists.ts                 # Rules Lists bulk batch and delete operations
│   └── types.ts                 # API response and request type definitions
│
├── security/
│   ├── ip-validator.ts          # IPv4 and IPv6 format validator
│   ├── ip-normalizer.ts         # Canonical IP representation
│   └── allowlist.ts             # CIDR subnet and exact IP matcher
│
├── observability/
│   ├── logger.ts                # Structured JSON logging
│   └── metrics.ts               # Runtime metrics collector
│
├── wrangler.jsonc               # Cloudflare Workers configuration
├── policy.example.json          # Open-source policy template
├── package.json
├── tsconfig.json
├── .dev.vars.example
├── .gitignore
└── README.md
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

<p align="center">
  <i>Made with ☕ and passion in the dev cave.</i>
</p>