# ASH Cloud Dashboard - Complete Guide

## The Relationship: ASH Core vs ASH Cloud

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           YOUR USERS                                     │
│                              │                                           │
│                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    YOUR APPLICATION                              │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │   │
│  │  │   Frontend  │───▶│ ASH Client  │───▶│    Your Backend     │ │   │
│  │  │   (React)   │    │   (SDK)     │    │  + ASH Middleware   │ │   │
│  │  └─────────────┘    └─────────────┘    └──────────┬──────────┘ │   │
│  └───────────────────────────────────────────────────┼─────────────┘   │
│                                                      │                  │
│                                          (optional webhook)             │
│                                                      │                  │
│  ┌───────────────────────────────────────────────────▼─────────────┐   │
│  │                      ASH CLOUD (SaaS)                            │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │   │
│  │  │  Dashboard  │◀───│   ASH API   │◀───│  Analytics Engine   │ │   │
│  │  │    (UI)     │    │  (Webhooks) │    │   (TimescaleDB)     │ │   │
│  │  └─────────────┘    └─────────────┘    └─────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## What Each Part Does

| Component | What It Is | Who Owns It |
|-----------|------------|-------------|
| **ASH Core** | The security library (PHP, Node, etc.) | You (open source) |
| **ASH Client SDK** | JavaScript for browsers | You (open source) |
| **ASH Middleware** | Server-side verification | You (open source) |
| **ASH Cloud API** | Receives analytics webhooks | You (SaaS) |
| **ASH Dashboard** | Web UI to view analytics | You (SaaS) |

## The Value Proposition

**ASH Core (Free):**
- Protects requests ✓
- Works completely offline ✓
- No data sent anywhere ✓

**ASH Cloud (Paid):**
- See HOW your ASH protection is working
- Track rejection rates (how many attacks blocked)
- Geographic distribution of requests
- Anomaly detection (sudden spike = attack?)
- Compliance reports for audits

---

## Dashboard Architecture

### Option A: Simple (Recommended to Start)

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Your App with   │────▶│   ASH Cloud      │────▶│    Dashboard     │
│  ASH Middleware  │     │   REST API       │     │   (Next.js)      │
│                  │     │   (Node/PHP)     │     │                  │
│  Sends webhook   │     │   Stores in DB   │     │   Shows charts   │
│  on verify       │     │                  │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

**Tech Stack (Simple):**
- **Dashboard:** Next.js + Tailwind + shadcn/ui
- **API:** Node.js (Express) or PHP (Laravel)
- **Database:** PostgreSQL or MySQL
- **Hosting:** Vercel (dashboard) + Railway/DigitalOcean (API)
- **Cost:** ~$20-50/month to start

### Option B: Scalable (Future)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Your Apps   │────▶│   Kafka/     │────▶│  Analytics   │────▶│  Dashboard   │
│  (webhooks)  │     │   Redis      │     │  Processor   │     │  (Next.js)   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                │
                                                ▼
                                         ┌──────────────┐
                                         │ TimescaleDB  │
                                         │ (time-series)│
                                         └──────────────┘
```

---

## How Data Flows (Technical)

### Step 1: Developer Integrates ASH

```php
// Their Laravel app - AshMiddleware.php
public function handle($request, $next)
{
    $result = Ash::verify($request);

    // OPTIONAL: Send to ASH Cloud (if they opted in)
    if (config('ash.cloud_enabled')) {
        AshCloud::report([
            'project_id' => config('ash.project_id'),
            'endpoint' => $request->path(),
            'result' => $result->status, // 'valid' or 'rejected'
            'reason' => $result->reason, // 'expired', 'tampered', etc.
            'timestamp' => now()->timestamp,
            'country' => geoip($request->ip())->country,
        ]);
    }

    if (!$result->valid) {
        return response()->json(['error' => 'Invalid request'], 403);
    }

    return $next($request);
}
```

### Step 2: ASH Cloud Receives Webhook

```javascript
// ASH Cloud API - /api/v1/events
app.post('/api/v1/events', authenticate, async (req, res) => {
    const { project_id, endpoint, result, reason, timestamp, country } = req.body;

    // Store in database
    await db.query(`
        INSERT INTO ash_events (project_id, endpoint, result, reason, timestamp, country)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, [project_id, endpoint, result, reason, timestamp, country]);

    // Update real-time counters (Redis)
    await redis.incr(`project:${project_id}:${result}`);

    res.json({ received: true });
});
```

### Step 3: Dashboard Displays Data

```javascript
// Dashboard - fetches aggregated data
const stats = await fetch('/api/dashboard/stats?project_id=xxx');
// Returns: { total: 10000, valid: 9850, rejected: 150, rejection_rate: 1.5% }
```

---

## Dashboard Wireframes

### Page 1: Overview Dashboard

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ASH Cloud                                    [Project ▼]  [Settings]   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   Total     │  │   Valid     │  │  Rejected   │  │  Rejection  │   │
│  │  Requests   │  │  Requests   │  │  Requests   │  │    Rate     │   │
│  │             │  │             │  │             │  │             │   │
│  │  1,234,567  │  │  1,230,000  │  │    4,567    │  │    0.37%    │   │
│  │   ▲ 12%     │  │   ▲ 12%     │  │   ▼ 5%      │  │   ▼ 0.05%   │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Requests Over Time                              [24h] [7d] [30d]│   │
│  │                                                                   │   │
│  │      ▂▃▅▇█▇▅▃▂▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▂▃▄▅▆▇█▇▆▅▄▃▂                      │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  12am    4am    8am    12pm    4pm    8pm    12am                │   │
│  │                                                                   │   │
│  │  ── Valid Requests   ── Rejected Requests                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌────────────────────────────┐  ┌────────────────────────────────┐   │
│  │  Top Endpoints             │  │  Rejection Reasons              │   │
│  │                            │  │                                  │   │
│  │  POST /api/checkout  45%   │  │  ██████████ Expired      67%   │   │
│  │  POST /api/login     30%   │  │  ████       Tampered     20%   │   │
│  │  POST /api/profile   15%   │  │  ██         Replay        8%   │   │
│  │  POST /api/transfer  10%   │  │  █          Invalid       5%   │   │
│  └────────────────────────────┘  └────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Page 2: Security Alerts

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ASH Cloud  >  Alerts                         [Project ▼]  [Settings]   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ ⚠️  ACTIVE ALERT                                      [Dismiss] │   │
│  │                                                                   │   │
│  │  Unusual rejection spike detected on POST /api/checkout          │   │
│  │  Normal: 0.5%  →  Current: 8.2%  (16x increase)                  │   │
│  │  Started: 14 minutes ago                                          │   │
│  │                                                                   │   │
│  │  [View Details]  [Mark as False Positive]                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Recent Alerts                                          [Filter ▼]     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  🔴  High rejection rate on /api/login       Today 2:34 PM       │   │
│  │  🟡  New country detected: Russia            Today 11:20 AM      │   │
│  │  🟢  Resolved: Spike on /api/transfer        Yesterday           │   │
│  │  🟢  Resolved: High traffic from single IP   Yesterday           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Page 3: Integration Setup

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ASH Cloud  >  Setup                          [Project ▼]  [Settings]   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Your Project: my-ecommerce-app                                         │
│  Project ID: ash_proj_a1b2c3d4e5f6                                     │
│  API Key: ash_key_••••••••••••••••              [Regenerate]           │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────     │
│                                                                         │
│  Integration Guide                                                      │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  [PHP/Laravel]  [Node.js]  [Python]  [Go]  [.NET]               │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │                                                                   │   │
│  │  1. Install the ASH Cloud reporter:                              │   │
│  │                                                                   │   │
│  │  ┌─────────────────────────────────────────────────────────┐    │   │
│  │  │  composer require 3maem/ash-cloud                        │    │   │
│  │  └─────────────────────────────────────────────────────────┘    │   │
│  │                                                                   │   │
│  │  2. Add to your .env:                                            │   │
│  │                                                                   │   │
│  │  ┌─────────────────────────────────────────────────────────┐    │   │
│  │  │  ASH_CLOUD_ENABLED=true                                  │    │   │
│  │  │  ASH_CLOUD_PROJECT_ID=ash_proj_a1b2c3d4e5f6             │    │   │
│  │  │  ASH_CLOUD_API_KEY=ash_key_xxxxxxxxxxxxx                │    │   │
│  │  └─────────────────────────────────────────────────────────┘    │   │
│  │                                                                   │   │
│  │  3. The middleware will automatically report to ASH Cloud.       │   │
│  │                                                                   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Status: ✅ Receiving data (last event: 3 seconds ago)                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## When to Introduce ASH Cloud

### The Simple Rule

```
ASH Core Users    →    Action
─────────────────────────────────
0-100             →    Don't build it yet (focus on Core)
100-500           →    Build MVP quietly
500-1000          →    Beta launch (free tier only)
1000+             →    Introduce paid tiers
5000+             →    Add enterprise features
```

### The Right Timing

| Milestone | Action | Focus |
|-----------|--------|-------|
| 0 users | Focus 100% on ASH Core | Documentation, SDKs, integrations |
| 100 users | Start building ASH Cloud MVP | Basic dashboard, event collection |
| 500 users | Beta launch ASH Cloud (free) | Gather feedback, iterate |
| 1,000 users | Introduce paid tiers | Pro tier ($49/mo) |
| 5,000 users | Add enterprise features | SSO, SLA, compliance reports |
| 10,000+ users | Launch ASH AI Agent | AI-powered threat detection |

### Trigger Metrics (Start Building When You See These)

1. **GitHub stars > 500** - Indicates real community interest
2. **Production deployments > 100** - People are actually using it
3. **Repeated questions about monitoring** - Market demand signal
4. **"How do I see blocked requests?"** - Direct feature request
5. **Companies emailing for support contracts** - Enterprise interest
6. **Framework maintainers reaching out** - Ecosystem validation

### Why Not Launch Immediately?

| Too Early | Just Right |
|-----------|------------|
| Empty dashboard = bad first impression | Real data = impressive demo |
| No feedback on what users actually need | Users telling you what they want |
| Wasted dev time if Core fails to get adopted | Proven demand before investment |
| Splitting focus hurts both products | Core is stable, ready for expansion |

### The Risk of Launching Too Early

```
❌ WRONG APPROACH:
   Build ASH Core + ASH Cloud simultaneously
   Result: Both products are half-baked, neither gets traction

✅ RIGHT APPROACH:
   Phase 1: ASH Core only (make it excellent)
   Phase 2: ASH Cloud (when demand is proven)
   Result: Strong foundation, clear market signal
```

### Signs You're Ready to Launch ASH Cloud

**Green Lights (GO):**
- [ ] 500+ GitHub stars
- [ ] 100+ production deployments confirmed
- [ ] 5+ companies asking about monitoring/support
- [ ] ASH Core is stable (no major bugs in 30 days)
- [ ] You have at least 3 beta testers lined up

**Red Flags (WAIT):**
- [ ] Less than 100 GitHub stars
- [ ] No production usage confirmed
- [ ] Still finding bugs in ASH Core weekly
- [ ] No one has asked about monitoring features
- [ ] You're the only one using it

### Recommended Launch Timeline

```
Month 1-3:   ASH Core v2.1 launch
             Focus: Documentation, blog posts, Hacker News
             Goal: 500 stars, 50 production users

Month 4-6:   ASH Core integrations
             Focus: Laravel, Django, Express, Spring packages
             Goal: 1000 stars, 200 production users

Month 7-9:   ASH Cloud MVP (stealth)
             Focus: Build dashboard, invite 10 beta testers
             Goal: Validate features, gather feedback

Month 10-12: ASH Cloud public launch
             Focus: Free tier + Pro tier ($49/mo)
             Goal: 50 paying customers, $2,500 MRR

Year 2:      ASH Enterprise + AI Agent
             Focus: Large customers, AI features
             Goal: 500 paying customers, $25,000 MRR
```

---

## How to Start Building

### Phase 1: MVP (2-4 weeks)

**Step 1: Set up the project**
```bash
# Dashboard (Next.js)
npx create-next-app@latest ash-cloud-dashboard --typescript --tailwind
cd ash-cloud-dashboard
npm install @shadcn/ui recharts date-fns
```

**Step 2: Database schema**
```sql
-- PostgreSQL
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE ash_events (
    id BIGSERIAL PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    endpoint VARCHAR(255) NOT NULL,
    result VARCHAR(20) NOT NULL, -- 'valid', 'rejected'
    reason VARCHAR(50), -- 'expired', 'tampered', 'replay', etc.
    ip_country VARCHAR(2),
    timestamp BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Index for fast queries
CREATE INDEX idx_events_project_time ON ash_events(project_id, timestamp DESC);
```

**Step 3: API endpoints**
```
POST /api/v1/events          - Receive events from ASH middleware
GET  /api/v1/stats           - Get aggregated statistics
GET  /api/v1/events          - List recent events (paginated)
GET  /api/v1/alerts          - Get active alerts
```

**Step 4: ASH middleware integration**

Add optional reporting to the existing ASH PHP library:

```php
// In Ash.php - add this method
public static function reportToCloud(VerifyResult $result, Request $request): void
{
    if (!config('ash.cloud_enabled')) {
        return;
    }

    // Non-blocking HTTP call
    Http::async()->post('https://api.ashcloud.dev/v1/events', [
        'project_id' => config('ash.cloud_project_id'),
        'api_key' => config('ash.cloud_api_key'),
        'endpoint' => $request->method() . ' ' . $request->path(),
        'result' => $result->valid ? 'valid' : 'rejected',
        'reason' => $result->reason,
        'timestamp' => time() * 1000,
    ]);
}
```

### Phase 2: Polish (2-4 weeks)

- Add authentication (NextAuth.js or Clerk)
- Add real-time updates (WebSockets or polling)
- Add email alerts
- Add team/organization support
- Add billing (Stripe)

### Phase 3: Scale (ongoing)

- Move to time-series database (TimescaleDB)
- Add message queue (Redis/Kafka)
- Add AI anomaly detection
- Add geographic map visualization
- Add compliance report generation

---

## Cost Estimation

### MVP Infrastructure

| Service | Provider | Cost/Month |
|---------|----------|------------|
| Dashboard hosting | Vercel | $0 (free tier) |
| API server | Railway | $5-20 |
| Database | Railway PostgreSQL | $5-20 |
| Domain | Cloudflare | $10/year |
| **Total** | | **$10-40/month** |

### At Scale (1000+ customers)

| Service | Provider | Cost/Month |
|---------|----------|------------|
| Dashboard | Vercel Pro | $20 |
| API servers (3x) | DigitalOcean | $60 |
| TimescaleDB | Timescale Cloud | $100 |
| Redis | Upstash | $20 |
| **Total** | | **$200/month** |

---

## Summary: The Relationship

```
ASH Core (FREE)                    ASH Cloud (PAID)
─────────────────                  ─────────────────
✓ Protects requests                ✓ Shows you what's happening
✓ Works offline                    ✓ Analytics & charts
✓ No data collection               ✓ Alerts & anomaly detection
✓ Proprietary                     ✓ Compliance reports
                                   ✓ Team collaboration

        │                                   │
        │         OPTIONAL WEBHOOK          │
        └──────────────────────────────────▶│
          (only if developer enables it)
```

**Key Point:** ASH Cloud is a **companion service**, not a requirement. Developers can use ASH Core forever without ASH Cloud. But if they WANT visibility into their security, they pay for ASH Cloud.

---

*Document created for 3maem Co. - ASH Project*
