# ARGUS Launch Playbook (48-Hour Distribution Sprint)

This playbook gives channel-ready technical posts to drive early velocity after a launch/update.

## Proof Assets to Prepare First

- Terminal recording: blocked prompt injection + PII redaction + incident metadata (`docs/assets/argus-terminal-demo.gif`)
- Architecture visual: `docs/assets/argus-demo.svg`
- Quickstart snippet from README
- Current release tag and changelog link

---

## 1) Reddit Post (technical framing)

**Target subreddits:** r/cybersecurity, r/netsec, r/Python, r/selfhosted, r/LocalLLaMA

**Title option:**
`Built an open-source LLM security gateway that blocks prompt injection and redacts PII in real time`

**Post body template:**

```text
I built ARGUS, an open-source FastAPI gateway that sits between clients and LLM providers.

What it does in-path:
- detects prompt injection/jailbreak patterns,
- redacts PII and credential-like content,
- enforces YAML policy decisions (ALLOW/FLAG/REDACT/BLOCK),
- stores incident telemetry for SOC workflows.

Interesting engineering constraints:
- low-latency request/response inspection,
- deterministic rule actions under mixed attack payloads,
- auditable forensic traces without breaking API compatibility.

Repo + quickstart: https://github.com/Vrishinram/ARGUS

I’d value feedback on edge cases you see in real LLM traffic (nested prompt-injection chains, multilingual jailbreaks, false-positive tuning, etc.).
```

---

## 2) Hacker News (Show HN)

**Submission title:**
`Show HN: ARGUS – Open-source LLM security gateway for prompt-injection defense`

**Top-level comment template:**

```text
I built ARGUS after seeing how hard it is to enforce consistent LLM input/output policy in production apps.

Stack:
- FastAPI + async proxy pattern
- YAML policy engine for ALLOW/FLAG/REDACT/BLOCK decisions
- request/response inspection for jailbreaks, PII, and secret leakage
- SQLite WAL audit trail + SOC dashboard

The goal is to preserve API compatibility while adding a security decision layer in front of upstream models.

Repo: https://github.com/Vrishinram/ARGUS
Quickstart is in README (5 minutes to run locally).

Happy to discuss architecture tradeoffs and false-positive mitigation.
```

---

## 3) Dev.to / Medium / Hashnode Article Outline

**Working title:**
`How I built an LLM security gateway that enforces policy in real time`

**Recommended structure:**
1. Problem statement (why app-level checks were insufficient)
2. Traffic interception model and compatibility constraints
3. Detection layers (prompt injection, PII, secrets)
4. Risk scoring + policy action engine
5. Edge cases and false-positive control
6. Auditability and SOC visibility
7. Local quickstart and demo scenarios
8. Lessons learned + open issues

**CTA:** Link to repo + release notes + issue tracker.

---

## 4) Awesome List Submission Targets

When submitting, include concise maintenance signals:
- latest release tag,
- active CI status badge,
- short one-line value proposition.

Suggested targets:
- awesome-cybersecurity
- awesome-threat-intelligence
- awesome-llm
- awesome-generative-ai
- awesome-selfhosted (if deployment posture fits)

PR blurb template:

```text
ARGUS — Open-source LLM security gateway that blocks prompt injection, redacts PII/secrets, and enforces YAML policy actions in real time. Includes SOC dashboard and incident audit trail.
```
