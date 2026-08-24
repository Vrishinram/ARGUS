# 🛡️ ARGUS

> Enterprise-grade LLM Security Gateway that blocks prompt attacks, redacts sensitive data, and enforces policy before model responses reach your users.

![License](https://img.shields.io/badge/license-MIT-yellow)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![GitHub Stars](https://img.shields.io/github/stars/Vrishinram/ARGUS?style=social)

ARGUS is a FastAPI-based defense proxy for LLM applications. It inspects inbound and outbound model traffic in real time to detect prompt injection, prevent secret leakage, and enforce configurable security policy decisions.

## 🎬 Demo / Visual

![ARGUS Demo Preview](docs/assets/argus-demo.svg)

> Optional: replace with an asciinema/GIF recording at `docs/assets/argus-terminal-demo.gif` for live attack/defense walkthroughs.

## ✨ Key Features

- **Prompt Injection & Jailbreak Defense** with rule-driven threat detection.
- **PII and Secret Redaction** for inbound prompts and outbound model responses.
- **Policy Engine Decisions** (`ALLOW`, `FLAG`, `REDACT`, `BLOCK`) with configurable YAML rules.
- **Async, Non-Blocking Gateway Flow** built on FastAPI + HTTPX for low-latency proxying.
- **Forensic Audit Trail** with SQLite/WAL-backed incident logging and dashboard visibility.

## ⚡ Quickstart

### 1) Prerequisites

- Python **3.10+**
- `pip`

### 2) Clone + Install

```bash
git clone https://github.com/Vrishinram/ARGUS.git
cd ARGUS
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
```

### 3) Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- API Docs: http://localhost:8000/docs
- Dashboard: http://localhost:8000/dashboard
- Health: http://localhost:8000/health

### Minimal Docker Run

```bash
docker run --rm -p 8000:8000 ghcr.io/vrishinram/argus:latest
```

## 🧭 Architecture / Flow

```mermaid
flowchart LR
    A[Client App] --> B[ARGUS Gateway]
    B --> C[Inbound Inspectors\nPII / Prompt Injection / Secrets]
    C --> D[Policy Engine\nALLOW | FLAG | REDACT | BLOCK]
    D -->|ALLOW/REDACT| E[Upstream LLM Provider]
    D -->|BLOCK| F[Rejected Response + Incident ID]
    E --> G[Outbound Inspectors\nPII / Secret Leak Checks]
    G --> H[Sanitized Response]
    F --> I[(Audit Log)]
    G --> I
    I --> J[Admin Dashboard / Metrics API]
```

## 🛣️ Roadmap

- [ ] Add provider-specific hardening profiles (OpenAI, Anthropic, Gemini).
- [ ] Introduce tenant-isolated policy packs and scoped API keys.
- [ ] Add SIEM integrations (Splunk, Sentinel, Datadog).
- [ ] Expand adversarial test corpus and benchmark suite.
- [ ] Publish production Helm chart and deployment guides.

## 🤝 Contributing

- [ ] Fork the repository and create a feature branch.
- [ ] Add/modify tests for behavior changes.
- [ ] Run local checks:
  - [ ] `python -m pytest -v`
- [ ] Open a pull request with a clear summary and validation notes.

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE).
