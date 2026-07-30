     1|# ADR-003: Me-Guard Execution Enforcement Mode
     2|
     3|**Status:** Accepted (2026-05-22) · Updated: 2026-07-29  
**Architect:** Stefan Rohringer  
**Context:** Me-Guard v2.0 – Preload hook before gateway startup
     6|
     7|---
     8|
     9|## Decision
    10|
    11|Me-Guard implements a **configurable hybrid mode** for preload enforcement:
    12|
    13|```
    14|Default Mode:    FAIL_CLOSED (Hard Gate)
    15|Config Switch:   FAIL_SAFE   (Quarantine)
Severity Logic:  CRITICAL → always Fail-Closed (not configurable)
                 WARNING  → configurable (quarantine or abort)
    18|```
    19|
    20|## Rationale
    21|
### Primary Target Market: OT / Manufacturing (Physical-First)

The architect's portfolio consists of:
- **ME-System** – deterministic knowledge layer for the autonomous factory
- **ki-kunststoff** – OPC-UA control for Arburg injection molding machines
- **musterung-kunststoff** – digital sampling at the production line
- **Siemens vision** – Industry 4.0, Safety, Certification

In OT environments, **safety is primary to availability**. A compromised skill in the shared memory of a gateway process sending OPC-UA signals to an injection molding machine is an unacceptable risk. **Fail-Closed is the only justifiable default.**
    31|
### Secondary Target Market: Enterprise / SaaS / Multi-Tenant

The hybrid mode enables expansion without architecture refactoring. A config flag switches between:
- **FAIL_CLOSED** – Every CRITICAL skill stops the gateway
- **FAIL_SAFE** – CRITICAL skills are moved to quarantine, gateway starts with N-1
    37|
### Why not Fail-Safe as Default?

The reverse direction (Fail-Safe first, Fail-Closed later) would be architecturally unsound:
- Fail-Closed for OT is stricter than Fail-Safe for Cloud
- Fail-Closed is a secure foundation, Fail-Safe is an extension
- The opposite would be a security risk
    44|
    45|## Architecture
    46|
    47|```
    48|[Gateway-Start]
    49|    ↓
    50|Me-Guard-Preload v2.1
    ↓
AST Scan + Signature Verification of ALL Skills
    ↓
┌─────────────────────────────────────────────────────┐
│ Severity Matrix (not configurable):                  │
│                                                     │
│ blocked  → CRITICAL → enforce Fail-Closed           │
│ review   → WARNING  → configurable                  │
│ trusted  → OK       → no intervention               │
└─────────────────────────────────────────────────────┘
    ↓
┌── Decision ──────────────────────────────────────┐
│                                                  │
│ FAIL_CLOSED:                                     │
│   CRITICAL exists → Gateway ABORT                │
│                                                  │
│ FAIL_SAFE:                                       │
│   CRITICAL → Skill → ~/.me-guard/quarantine        │
│   Gateway starts with N-1 skills                 │
│                                                  │
└──────────────────────────────────────────────────┘
    72|```
    73|
    74|## Configuration
    75|
    76|```bash
# Fail-Closed (Default – Factory/OT)
python3 me-guard-preload.py || exit 1

# Fail-Safe (Enterprise/Cloud)
ME_GUARD_MODE=FAIL_SAFE python3 me-guard-preload.py || exit 1

# Persistent via Config
    84|echo '{"mode": "FAIL_SAFE"}' > ~/.me-guard/governance/preload_config.json
    85|```
    86|
## Consequences

### Positive
- **Unified codebase** for OT and Enterprise – no fork, no refactoring
- **Safety-by-Default** as a selling point for industrial customers
- **Zero-Trust at gateway level** – no skill touches memory before verification
- **Extensible** without architecture changes

### Negative
- Higher complexity in the preload bootloader (two modes + quarantine logic)
- Documentation effort for mode transitions
- Quarantine directory needs storage and cleanup logic

## Comparison: Market Positioning

| Criterion | NVIDIA Verified Skills | STSS | skillsign | Me-Guard |
|---|---|---|---|---|
| Signature | Ed25519 | Ed25519+Merkle | Ed25519 | Ed25519+AES-256 |
| Code Scan | Card-based | Semgrep | ❌ | **AST-Level** |
| Preload Hook | ❌ | ❌ | ❌ | **✅** |
| Fail-Closed | ❌ | ❌ | ❌ | **✅ Default** |
| Fail-Safe | ❌ | ❌ | ❌ | **✅ Config** |
| OT-Ready | ❌ | ❌ | ❌ | **✅** |

## References

- NVIDIA Verified Agent Skills (May 2026)
- STSS – Skill Trust & Signing Service (March 2026)
- skillsign – 360 Security Skills Center (May 2026)
- Arxiv: "A Trust Schema for Modular Agent Skills" (May 2026)
- ADR-001: Me-Guard v2.0 Architecture
- ADR-002: Ed25519 + AES-256 Key Management
   119|