# 🛡️ Cloudflare Auto Guard

A production-grade, zero-external-backend automated IP threat detection and mitigation system built entirely on Cloudflare edge primitives (**Cloudflare Workers**, **GraphQL Zone Analytics**, **Rules Lists API**, **Cloudflare KV**, and **Cloudflare WAF**).

---

## 🚀 Overview

High-frequency malicious traffic, DDoS probes, and scrapers often display distinct geographic patterns. **Auto Guard** continuously monitors real edge traffic directly from **Cloudflare GraphQL Zone Analytics**, evaluates candidates against dynamic country-based policies, and automatically mitigates offending IPs via Cloudflare IP Lists and WAF rules.

### Key Highlights
* **Zero External Dependencies**: No Redis, PostgreSQL, Node.js VPS, Docker containers, or third-party servers required. Everything runs 100% natively on Cloudflare.
* **Multi-Zone Protection on Shared List**: Protect 1 or dozens of domains simultaneously (`CF_ZONES="domain1.com:id1 | domain2.com:id2"`) using a single, unified 10,000-item edge IP list.
* **Edge GraphQL Analytics**: Queries live edge traffic directly via Cloudflare Analytics API (`httpRequestsAdaptiveGroups`) per protected zone.
* **High-Performance Bulk Batching**: Applies bans in a single bulk API call (up to 1,000 IPs per request), completely preventing subrequest limit errors.
* **Automated Unban (TTL & 10k Limit Protection)**: Automatically expires and prunes old bans after a configurable TTL (e.g., 24 hours) and applies FIFO pruning when approaching Cloudflare's 10,000 list item limit.
* **Runtime Dynamic Policies**: Policies are stored in Cloudflare KV (`POLICY_KV`). Rules, thresholds, and time windows can be updated instantaneously via cURL, Postman, or Telegram **without redeploying code**.
* **Detailed Audit Trail**: Enriches banned IPs with metadata comments including Target Zone, Country, Request count, Rule threshold, Time window, Traffic rank, and UTC timestamp.
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

### 2. Configure Cloudflare Secrets & Multi-Zone Support
Set your credentials directly into Cloudflare's encrypted vault:

```bash
# Your Cloudflare Account ID & API Token
npx wrangler secret put CF_ACCOUNT_ID
npx wrangler secret put CF_API_TOKEN

# Cloudflare Rules List ID for 'auto_guard_block' (Shared across all your zones)
npx wrangler secret put CF_LIST_ID

# Cloudflare Protected Zones (Single or multiple domains on 1 shared WAF list)
# Format: "domain1.com:zone_id_1" OR "domain1.com:zone_id_1 | domain2.com:zone_id_2"
npx wrangler secret put CF_ZONES

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
| `/flush` | Wipes and unbans all currently blocked IPs in 1 bulk request | `/flush` |
| `/ban <ip> [reason]` | Manually adds an IP to Cloudflare Rules List in real-time | `/ban 198.51.100.4 Scraper bot` |
| `/unban <ip1> [ip2]` | Removes one or multiple IPs from blocklist in 1 batch | `/unban 198.51.100.4 203.0.113.8` |
| `/policy` | Displays active policy with 1-click preset buttons | `/policy` |
| `/set_threshold <n>` | Updates default request limit threshold | `/set_threshold 300` |
| `/set_window <sec>` | Updates inspection timeframe window | `/set_window 900` |
| `/set_topn <n>` | Updates Top-N candidate sample size | `/set_topn 50` |
| `/set_country <C> <n>` | Configures country-specific threshold | `/set_country RU 100` |
| `/remove_country <C>` | Deletes country override rule | `/remove_country RU` |
| `/allow <ip/cidr>` | Whitelists an IP or CIDR subnet | `/allow 1.1.1.1` |
| `/disallow <ip/cidr>` | Removes an IP or CIDR from allowlist | `/disallow 1.1.1.1` |
| `/set_ttl <hours>` | Updates automated unban TTL | `/set_ttl 24h` |
| `/set_policy <json>` | Directly sets the full JSON policy | `/set_policy {...}` |
| `/admins` | Lists all authorized administrator IDs and groups | `/admins` |
| `/help` | Interactive control panel with instant action buttons | `/help` |

---

### 🚨 2. Real-Time Push Alerts with 1-Click Unban

Whenever the automated cron detects high-frequency attacks or policy violations, it instantly pushes a card directly to your Telegram chat:

```text
🚨 Auto Guard: Threat Detected & Mitigated!
━━━━━━━━━━━━━━━━━━━━
🌐 Target Zone: example.com
🏴‍☠️ Attacker IP: 185.220.101.5
🏳️ Country: Russia (RU)
📊 Traffic: 1,420 requests (Threshold: 300)
🏷️ Rank: #1
📝 Reason: Exceeded country RU limit of 300 requests
━━━━━━━━━━━━━━━━━━━━
⏰ 2026-10-02 15:20:00 UTC

[ 🔓 Unban (185.220.101.5) ]  <-- (Interactive Inline Button)
```

> **Single-Click Unban**: Tapping the **[ 🔓 Unban ]** button immediately invokes the Cloudflare Rules Lists API, deletes the IP, purges the local cache, and edits the Telegram card to:  
> `✅ [UNBANNED] (by @admin_username)`.

---

### 🔓 3. Real-Time Auto-Unban Notifications

Whenever an IP is automatically unbanned (either through TTL expiration e.g., 24 hours or FIFO list limit pruning), all configured administrators receive an instant push notification with a 1-click **[ 🚫 Re-Ban ]** button:

```text
🔓 Auto Guard: IP Unbanned
━━━━━━━━━━━━━━━━━━━━
🌐 IP: 185.220.101.5
📋 Reason: ⏳ TTL Expired (Automatic ban expiration)
💬 Original Ban: Auto Guard: RU | Req: 1420 (Limit: 300/1h) | Rank: #1
📅 Banned At: 2026-09-30T15:20:00Z
━━━━━━━━━━━━━━━━━━━━
⏰ 2026-10-01 15:20:00 UTC

[ 🚫 Re-Ban (185.220.101.5) ]  <-- (Instant Re-ban Button)
```

For large unban batches (> 5 IPs), a consolidated summary card is broadcasted to keep administrators fully informed without hitting Telegram message rate limits.

---

### 🛠️ 4. Telegram Bot Setup (in 3 Simple Steps)

#### Step 1: Create Your Bot & Obtain Chat ID
1. Open Telegram and search for **[@BotFather](https://t.me/BotFather)**. Send `/newbot`, name your bot, and copy the provided `HTTP API Token`.
2. Search for **[@userinfobot](https://t.me/userinfobot)** in Telegram to retrieve your numeric `Id` (used as `TELEGRAM_ADMIN_CHAT_ID` to restrict bot access exclusively to you).

#### Step 2: Store Secrets in Cloudflare
```bash
# Save your Telegram Bot Token
npx wrangler secret put TELEGRAM_BOT_TOKEN
# Paste your BotFather token when prompted

# Save your Telegram Admin Chat IDs (supports multiple user IDs and group IDs)
# Format: separated by | (or comma/space): "12345678 | 87654321 | -1001234567890"
npx wrangler secret put TELEGRAM_ADMIN_CHAT_ID
# Paste your user/group IDs when prompted

# Deploy your Worker
npx wrangler deploy
```

> **Multi-Admin & Group Support**:  
> You can pass multiple individual user IDs separated by pipe (e.g. `11111 | 22222`) or an entire **Telegram Group / Channel ID** (e.g. `-1001234567890`). All admins receive real-time alerts simultaneously, and any authorized admin can run commands or click the inline unban button.

#### Step 3: Register Webhook & Autocomplete Commands
Open the setup endpoint in your browser or curl:
```bash
curl https://cloudflare-auto-guard.<subdomain>.workers.dev/__guard/telegram/setup
```
*Done!* Your Telegram Bot is now registered and active on Cloudflare Edge with two-way communication. This endpoint automatically registers both the **Webhook URL** and the **Autocomplete Slash Commands** via Telegram's `setMyCommands` API!

---

#### 💡 Optional: BotFather `/setcommands` (Manual Menu Setup)
If you prefer to configure the command menu manually in **[@BotFather](https://t.me/BotFather)**, send `/setcommands`, choose your bot, and copy-paste this block:

```text
status - System health and active banned IP count
evaluate - Trigger edge traffic evaluation now
list - View currently banned IPs in Cloudflare WAF
flush - Flush and unban all currently blocked IPs
ban - Manually block an IP: /ban <ip> [reason]
unban - Remove IP(s) from blocklist: /unban <ip1> [ip2]
policy - View active threshold and protection policy
admins - List authorized administrator accounts
help - Show interactive control panel and menu
```

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