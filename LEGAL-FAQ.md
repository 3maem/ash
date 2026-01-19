# Legal FAQ – ASH SDK

This document answers common legal and usage-related questions
regarding ASH (Application Security Hash).

---

## Is ASH an attack prevention or detection system?

No.

ASH does not provide attack prevention, attack detection, or threat
mitigation capabilities.

ASH is a request integrity validation mechanism only.

---

## Can ASH be considered a security control?

ASH is a **technical integrity mechanism**, not a security control
for preventing attacks.

It must not be relied upon as a substitute for authentication,
authorization, firewalls, or secure coding practices.

---

## Does ASH guarantee security?

No.

ASH does not guarantee protection against any class of attack or
security incident.

It validates request integrity and enforces single-use constraints only.

---

## Can ASH stop SQL injection, XSS, or logic attacks?

No.

ASH does not analyze input semantics, validate business logic,
or prevent injection-style vulnerabilities.

These must be handled by the application itself.

---

## Can ASH protect against compromised clients or malware?

No.

If a client or execution environment is compromised, ASH cannot
distinguish malicious requests from legitimate ones.

---

## Is ASH a replacement for TLS, JWT, or OAuth?

No.

ASH does not replace:
- TLS / HTTPS
- JWT, OAuth, sessions, or API keys
- API gateways or firewalls

ASH is designed to complement these mechanisms.

---

## Is ASH free to use?

Yes, subject to the license terms.

ASH may be used in personal and commercial projects, but modification,
redistribution, or forking is prohibited unless explicitly permitted
by 3maem Co.

---

## Who is responsible for secure deployment?

The implementing party is solely responsible for:

- Correct integration
- Secure configuration
- Operational monitoring
- Overall application security

ASH is provided "as is".

---

## Why is the source code available if it is proprietary?

The source code is made available for transparency and auditability.

Availability of source code does not imply permission to modify,
redistribute, or create derivative works.

---

## Who maintains and develops ASH?

All official development, maintenance, and enhancements are
exclusively performed by 3maem Co.

---

© 3maem Co. | شركة عمائم
All Rights Reserved.
