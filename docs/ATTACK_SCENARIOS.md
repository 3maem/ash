# ASH Attack Scenarios & Defense Diagrams

This document visualizes common attack attempts and how ASH prevents them.

---

## 1. Request Tampering

### Attack

```
Attacker intercepts request
         ↓
   Modifies body/params
         ↓
   Forwards to server
```

### Result

❌ Proof mismatch → verification fails

### Defense

- HMAC proof
- Body hashing

---

## 2. Replay Attack

### Attack

```
Attacker captures valid request
         ↓
    Resends later
```

### Result

❌ Context already consumed → rejected

### Defense

- Single-use contexts
- TTL expiration

---

## 3. Endpoint Substitution

### Attack

```
Valid proof for /profile
         ↓
  Reused on /transfer
```

### Result

❌ Binding mismatch → rejected

### Defense

- Method/path/query binding

---

## 4. Timing Attacks

### Attack

```
Attacker measures comparison timing
```

### Result

❌ No signal leakage

### Defense

- Constant-time comparisons

---

## 5. Memory Forensics

### Attack

```
Extract secrets from process memory
```

### Result

❌ Secrets cleared after use

### Defense

- Secure memory utilities

---

## Summary Table

| Attack | Prevented By |
|--------|--------------|
| Tampering | HMAC proof |
| Replay | Single-use contexts |
| Endpoint swap | Binding validation |
| Timing | Constant-time compare |
| Memory leaks | Secure clearing |
