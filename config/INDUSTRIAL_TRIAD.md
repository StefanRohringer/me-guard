     1|# 🏭 Industrial Triad Architecture
     2|
**The deterministic platform for the autonomous factory.**  
*As of: July 2026 · Stefan Rohringer*
     5|
     6|---
     7|
     8|## 🧩 Die Drei
     9|
    10|```
    11|┌────────────────────────────────────────────────────────────┐
    12|│                INDUSTRIAL TRIAD ARCHITECTURE                │
    13|├────────────────────────────────────────────────────────────┤
    14|│                                                            │
    15|│  1. ME-System          ──> Das Gehirn                      │
    16|│                            (Deterministisches Wissen,      │
    17|│                             94 MEs, kein LLM, kein Cloud)  │
    18|│                                                            │
    19|│  2. Me-Guard  ──> Der Schutzschild                │
    20|│                            (AST-Preload-Hook, Ed25519,     │
    21|│                             Fail-Closed Hard Gate)         │
    22|│                                                            │
    23|│  3. ki-kunststoff      ──> Der Arm                         │
    24|│                            (256 OPC-UA-Punkte, SPC, TTS,   │
    25|│                             Arburg ALLROUNDER 370H)        │
    26|│                                                            │
    27|└────────────────────────────────────────────────────────────┘
    28|```
    29|
## 🎯 The Thesis

While the tech industry blindly bets on LLMs and the cloud, this portfolio occupies a market that the cloud giants don't understand: **the manufacturing floor (OT).**

| Criterion | Industrial Triad | Cloud AI |
|-----------|-----------------|----------|
| Knowledge Base | Deterministic (94 MEs) | Probabilistic (LLM) |
| Error Behavior | Fail-Closed (machine stops) | Hallucination (machine runs) |
| Infrastructure | Raspberry Pi, 200 MB RAM | GPU cluster, 100 kW power |
| Network | No internet required | Always online |
| Certifiable | IEC 61508-compatible | Not auditable |
| Operating Cost | €5 power/month | €10,000+/month cloud |
    42|
## 🛡️ The Pitch

> *"Me-Guard is not just another skill-signing tool. Me-Guard is the only security layer that can stand between an AI agent and an injection molding machine. While others say 'We scan skills,' we say: 'If a skill isn't verified, the gateway doesn't boot.' That's the difference between IT security and OT safety."*
    46|
    47|## 🔗 The Triad in Action
    48|
    49|```
    50|Sensor (OPC-UA) → ME-System (evaluates) → Me-Guard (checks skill) → Actor (machine)
    51|     ↑                    ↓                       ↓                     ↓
  256 Values        94 MEs              AST Scan + Sig      Fail-Closed
  Real-time         Deterministic       Ed25519 + Preload   Hard Gate

No step is executed until all three layers have verified it.

## 📌 Strategy

1. **OT first** – Fail-Closed for the factory is stricter than Fail-Safe for the cloud. Whoever achieves that has the hybrid as a config flag.
2. **ME-System as Trojan horse** – When a Siemens architect evaluates the ME-System and discovers Me-Guard, an ecosystem argument emerges.
3. **Capture the market before the cloud giants understand OT** – NVIDIA and STSS compete for cloud agents. The OT market is free.
    63|
## ⚖️ ADR-003: Execution Enforcement Mode

**Decision:** Fail-Closed as default, Hybrid as architecture.  
**Rationale:** CRITICAL severity overrides the operator – not negotiable.  
**Consequence:** Safety-by-Default as selling point, no architecture refactoring needed for enterprise expansion.

---

*"The best defense against cloud competition is a market they don't understand."*
    73|