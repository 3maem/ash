# ASH Business Plan
## Anti-tamper Security Hash | 3maem Co.

**Version:** 1.0
**Date:** January 2026
**Confidential**

---

## Executive Summary

ASH (Anti-tamper Security Hash) is an source-available security protocol that provides cryptographic request integrity verification for web applications. Unlike traditional CSRF tokens, ASH cryptographically binds the request context to the payload, preventing tampering, replay attacks, and parameter manipulation.

**Business Model:** Open Core with Platform Services

- **ASH Core:** Free to use, source-available (Proprietary License)
- **ASH Cloud:** SaaS platform for monitoring and analytics
- **ASH Enterprise:** Premium features, support, and SLA
- **ASH AI:** AI-powered threat detection and response (future)

---

## Problem Statement

### Current Security Landscape

1. **CSRF tokens are insufficient** - They verify session, not payload integrity
2. **Request tampering is easy** - Attackers modify parameters in transit
3. **Replay attacks succeed** - No cryptographic binding to context
4. **Bot attacks scale** - No computational cost to attackers

### Market Pain Points

| Problem | Impact | Current Solutions |
|---------|--------|-------------------|
| Form tampering | Data corruption, fraud | Basic validation (weak) |
| Price manipulation | Revenue loss | Server-side checks (reactive) |
| Replay attacks | Duplicate transactions | Rate limiting (incomplete) |
| Bot automation | Resource abuse | CAPTCHAs (poor UX) |

### Why Now?

- API-first architectures expose more attack surface
- Mobile/SPA apps can't rely on traditional session security
- Zero-trust security models require proof of request integrity
- Regulatory pressure (PCI-DSS, GDPR) demands stronger controls

---

## Solution: ASH Protocol

### Core Innovation

ASH provides **cryptographic proof of request integrity** through:

```
clientSecret = HMAC-SHA256(serverNonce, contextId | binding)
proof = HMAC-SHA256(clientSecret, timestamp | binding | bodyHash)
```

### Key Differentiators

| Feature | CSRF Token | JWT | ASH |
|---------|------------|-----|-----|
| Payload binding | No | No | Yes |
| Replay protection | No | Partial | Yes |
| Context binding | No | Partial | Yes |
| Timing attack safe | Varies | Varies | Yes |
| Zero server state option | No | Yes | Yes |

### Security Properties

1. **One-way derivation** - Server nonce never exposed to client
2. **Context binding** - Proof valid only for specific endpoint
3. **Payload integrity** - Any modification invalidates proof
4. **Replay resistance** - Timestamp and single-use context
5. **Timing-safe** - Constant-time comparison prevents leakage

---

## Product Strategy

### Phase 1: Foundation (Months 1-6)

**Goal:** Establish ASH as the standard for request integrity

**Products:**
- ASH Core (all languages) - FREE
- Documentation site
- Framework integrations (Laravel, Django, Express, Spring, Rails)
- GitHub community

**Metrics:**
- 1,000 GitHub stars
- 500 production deployments
- 5 framework integrations
- Active Discord community (500+ members)

**Investment:** $0 (organic growth)

### Phase 2: Platform (Months 7-12)

**Goal:** Launch ASH Cloud for visibility and analytics

**Products:**
- ASH Cloud Free - Basic dashboard, 10K requests/month
- ASH Cloud Pro - Advanced analytics, 100K requests/month
- Self-hosted option

**Features:**
- Real-time request monitoring
- Rejection rate analytics
- Geographic distribution
- Anomaly alerts
- Integration guides

**Metrics:**
- 2,000 total deployments
- 100 paying customers
- $5,000 MRR

**Investment:** $10,000 (infrastructure, design)

### Phase 3: Monetization (Months 13-24)

**Goal:** Scale revenue through enterprise and AI products

**Products:**
- ASH Enterprise - SSO, compliance reports, SLA, dedicated support
- ASH AI Agent - Automated threat response, pattern learning
- ASH Certification - Developer certification program
- ASH Consulting - Implementation services

**Metrics:**
- 10,000 total deployments
- 500 paying customers
- 10 enterprise accounts
- $50,000 MRR

**Investment:** $50,000 (team, AI development)

---

## Revenue Model

### Pricing Structure

| Tier | Price | Target | Features |
|------|-------|--------|----------|
| **Core** | Free | All developers | Full protocol, all SDKs |
| **Cloud Free** | $0/mo | Hobbyists | 10K requests, basic dashboard |
| **Cloud Pro** | $49/mo | Startups | 100K requests, analytics, alerts |
| **Cloud Business** | $199/mo | Growing companies | 1M requests, team access, API |
| **Enterprise** | $999+/mo | Large orgs | Unlimited, SSO, SLA, support |
| **AI Agent** | $299/mo add-on | Security teams | AI threat detection |

### Revenue Projections

| Year | Customers | MRR | ARR |
|------|-----------|-----|-----|
| Year 1 | 100 | $5,000 | $60,000 |
| Year 2 | 500 | $25,000 | $300,000 |
| Year 3 | 2,000 | $100,000 | $1,200,000 |

### Unit Economics

- **CAC:** $50 (content marketing, community)
- **LTV:** $1,200 (24-month average retention)
- **LTV:CAC Ratio:** 24:1

---

## Go-to-Market Strategy

### Target Segments

**Primary:** Mid-market SaaS companies (50-500 employees)
- Pain: Increasing API attacks, compliance requirements
- Budget: $200-2,000/month for security tools
- Decision: Engineering lead or CISO

**Secondary:** Enterprise (500+ employees)
- Pain: Compliance, audit requirements, zero-trust initiatives
- Budget: $10,000+/year
- Decision: Security team, procurement

**Tertiary:** Startups and indie developers
- Pain: Security with limited resources
- Budget: $0-50/month
- Decision: Founder or lead developer

### Marketing Channels

| Channel | Strategy | Budget |
|---------|----------|--------|
| **Content** | Technical blog, security research | $0 |
| **Community** | Discord, GitHub Discussions, Stack Overflow | $0 |
| **Developer Relations** | Conference talks, podcasts, tutorials | $2,000 |
| **SEO** | "request integrity", "CSRF alternative", "API security" | $0 |
| **Partnerships** | Framework maintainers, security tools | $0 |

### Launch Strategy

1. **Soft Launch:** GitHub release, Hacker News post
2. **Community Building:** Discord, early adopter program
3. **Content Marketing:** Technical blog posts, comparisons
4. **Framework Integrations:** Official packages for major frameworks
5. **Case Studies:** Document early adopter success stories
6. **Product Hunt:** Timed launch for ASH Cloud

---

## Competitive Analysis

### Direct Competitors

| Competitor | Approach | Weakness |
|------------|----------|----------|
| Traditional CSRF | Session token | No payload binding |
| JWT | Stateless auth | Not designed for request integrity |
| HMAC signing | API authentication | Complex, not standardized |
| Cloudflare Bot Management | Edge protection | Expensive, not protocol-level |

### Competitive Advantages

1. **Open Source Core** - No vendor lock-in, community trust
2. **Multi-language SDKs** - Works with any stack
3. **Protocol-level** - Deeper security than edge solutions
4. **Simple Integration** - Drop-in middleware
5. **No Telemetry** - Privacy-first approach builds trust

### Moat Strategy

1. **Standard Adoption** - Become the RFC for request integrity
2. **Community** - Build largest community around request security
3. **Integrations** - Native support in major frameworks
4. **Data Network Effect** - ASH Cloud threat intelligence (opt-in)
5. **Brand** - "Protected by ASH" becomes trust signal

---

## Team Requirements

### Current (Founder Phase)

- **Founder/CEO** - Product, strategy, development
- **Advisors** - Security experts, open source leaders

### Year 1 Hires

| Role | When | Salary Range |
|------|------|--------------|
| Developer Advocate | Month 6 | $80-120K |
| Full-stack Developer | Month 9 | $100-150K |

### Year 2 Hires

| Role | When | Salary Range |
|------|------|--------------|
| Sales (Enterprise) | Month 15 | $80K + commission |
| Security Engineer | Month 18 | $120-180K |
| Customer Success | Month 20 | $60-90K |

---

## Financial Projections

### Year 1

| Category | Q1 | Q2 | Q3 | Q4 |
|----------|-----|-----|-----|-----|
| Revenue | $0 | $0 | $2,000 | $5,000 |
| Expenses | $1,000 | $2,000 | $5,000 | $8,000 |
| Net | -$1,000 | -$2,000 | -$3,000 | -$3,000 |

### Year 2

| Category | Q1 | Q2 | Q3 | Q4 |
|----------|-----|-----|-----|-----|
| Revenue | $8,000 | $15,000 | $25,000 | $40,000 |
| Expenses | $20,000 | $30,000 | $40,000 | $50,000 |
| Net | -$12,000 | -$15,000 | -$15,000 | -$10,000 |

### Year 3

| Category | Q1 | Q2 | Q3 | Q4 |
|----------|-----|-----|-----|-----|
| Revenue | $60,000 | $90,000 | $130,000 | $180,000 |
| Expenses | $80,000 | $100,000 | $120,000 | $140,000 |
| Net | -$20,000 | -$10,000 | $10,000 | $40,000 |

**Break-even:** Month 30

---

## Funding Strategy

### Bootstrap Phase (Current)

- Self-funded development
- Focus on product-market fit
- Build community and early traction

### Seed Round (Optional, Month 12-18)

- **Amount:** $500K - $1M
- **Use:** Team, infrastructure, enterprise sales
- **Valuation:** $5-10M (based on ARR multiple)

### Metrics for Fundraising

- 5,000+ GitHub stars
- 1,000+ production deployments
- $100K+ ARR
- 3+ enterprise customers
- Clear path to $1M ARR

---

## Risk Analysis

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Low adoption | Medium | High | Strong community, integrations |
| Security vulnerability | Low | Critical | Audit, bug bounty, versioning |
| Competitor copies | Medium | Medium | Move fast, build community moat |
| Enterprise sales cycle | High | Medium | Focus on self-serve first |
| Burnout (solo founder) | Medium | High | Automate, hire early |

---

## Success Metrics

### North Star Metric

**Protected Requests per Month**
- Year 1: 10M requests/month
- Year 2: 100M requests/month
- Year 3: 1B requests/month

### Key Performance Indicators

| Metric | Year 1 | Year 2 | Year 3 |
|--------|--------|--------|--------|
| GitHub Stars | 1,000 | 5,000 | 15,000 |
| Production Deployments | 500 | 2,000 | 10,000 |
| Paying Customers | 50 | 500 | 2,000 |
| MRR | $5,000 | $25,000 | $100,000 |
| Enterprise Accounts | 0 | 5 | 25 |
| Community Members | 500 | 2,000 | 10,000 |

---

## Appendix

### A. Technical Architecture (ASH Cloud)

```
[Client SDK] --> [ASH Middleware] --> [Your API]
                       |
                       v (opt-in telemetry)
                [ASH Cloud API]
                       |
                       v
              [Analytics Dashboard]
```

### B. Integration Example

```php
// Laravel middleware (2 lines to integrate)
$ashContext = Ash::createContext('POST /checkout');
return response()->json($ashContext->toClientArray());
```

### C. Security Audit Plan

- [ ] Internal code review (ongoing)
- [ ] External audit by Trail of Bits (Year 1)
- [ ] Bug bounty program (Year 1)
- [ ] SOC 2 Type II (Year 2)

### D. Intellectual Property

- ASH Protocol: Open specification (CC-BY)
- ASH SDKs: Proprietary License
- ASH Cloud: Proprietary
- ASH AI: Proprietary

---

## Contact

**3maem Co.**
Research & Development

---

*This document is confidential and intended for internal planning purposes.*
