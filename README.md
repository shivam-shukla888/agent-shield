# AgentShield 🛡️

**AI Agent Security Testing & Risk Analysis Platform**

AgentShield is an enterprise-grade security testing framework designed to audit, evaluate, and quantify security risks in LLM-powered autonomous AI agents and agentic workflows operating in a **local, CI/CD, or controlled security testing environment**.

> ⚠️ **Production note:** The Streamlit UI ships with a placeholder API key default (`changeme-generate-a-real-key`) purely for local development convenience. Before deploying anywhere reachable outside your own machine, set the `AGENTSHIELD_API_KEY` environment variable to a real, secret value — the backend will refuse to start with a weak/missing key in production mode, but the UI's local default should never be relied upon.

---

## 1. The Problem AgentShield Solves

Traditional AI evaluation tools ask:
> *"Did the LLM produce an offensive or toxic text response?"*

Security engineers and developers building production AI agents need to ask:
> **"Did the AI agent violate its intended security policy and access controls?"**

AI agents combine LLMs with tool execution capabilities (`refund_order`, `send_email`, `query_database`). Relying on system prompts or LLM alignment as a primary security boundary is inherently flawed. 

AgentShield treats AI agents as complex, non-deterministic software systems, systematically mapping their attack surfaces, testing for vulnerability exploitation, evaluating traces, and providing quantitative risk analysis.

---

## 2. Fundamental Security & Architectural Principles

> 💡 **"LLM alignment is not authorization."**
> 
> The LLM or system prompt must NEVER be treated as the primary authorization boundary for privileged actions. Authorization MUST be enforced by a deterministic policy/authorization layer outside the LLM context.

```
+-------------------------------------------------------------------------------+
|                             UNSECURE PATTERN                                  |
|                                                                               |
|  [ User Prompt ] ---> [ LLM Agent ] ---> [ Direct Tool Execution ]            |
|                                        (e.g., refund_order())                 |
|  * High Risk: Relying on system prompt / LLM alignment as authorization boundary|
+-------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------+
|                             SECURE ARCHITECTURE                               |
|                                                                               |
|  [ User Prompt ] ---> [ LLM Agent ] ---> [ Policy / Auth Layer ] ---> [ Tool ]|
|                                        (Deterministic Check)                  |
|  * Secure: Authorization & permissions enforced independently of LLM reasoning|
+-------------------------------------------------------------------------------+
```

### Attack vs. Vulnerability Pipeline

```
Attack (Test Probe) ──► Agent Behavior ──► Evaluation (Rules + Judge) ──► Policy Violation? ──► Finding
```

Executing a security probe (attack) does NOT automatically mean a vulnerability exists. A **Finding** is created only when evaluation confirms that the agent's behavior breached defined policy boundaries.

---

## 3. High-Level System Architecture

```
User / Security Engineer / CI/CD Pipeline
             │
             ▼
     [ AgentShield UI ]
             │
             ▼
      [ API Layer ]
             │
             ▼
   [ Scan Orchestrator ]
             │
     ┌───────┴──────────────┐
     ▼                      ▼
[ Discovery ] ───► [ Threat Model ]
                            │
                            ▼
                    [ Attack Engine ]
                            │
                            ▼
   [ Target Adapter ] ◄── (Normalized TargetResult) ──► [ Target AI Agent ]
   (SSRF Protected)
                            │
                            ▼
              [ Observation & Traces ]
               (Black-Box / OTel Ready)
                            │
     ┌──────────────────────┴──────────────────────┐
     ▼                                             ▼
[ Detection Engine ]                      [ LLM Judge ]
(Version-Controlled Rules)                (Semantic Rubric)
     │                                             │
     └──────────────────────┬──────────────────────┘
                            │
                            ▼
                    [ Finding Engine ]
                            │
                            ▼
                 [ Attack Path Engine ]
                            │
                            ▼
                     [ Risk Engine ]
                            │
                            ▼
                 [ Report & Remediation ]
                            │
                            ▼
                 [ Regression Suite ]
```

---

## 4. Architectural Component Isolation & Target Adapters

* **Target Adapter Abstraction**: The core scanner engine never depends on a specific HTTP request/response JSON schema. The `TargetAdapter` converts framework-specific request/response formats into a normalized internal `TargetResult` representation.
  * **Week 1 MVP**: `GenericHTTPAdapter` with target connector **SSRF Protection** (blocking metadata IPs like `169.254.169.254` and private subnets).
  * **Future Extension Adapters**: Local Python, LangGraph, LangChain, CrewAI, OpenAI Agents, n8n, and MCP.
* **Role of n8n**: **n8n** is an external workflow orchestration and automation layer (scheduling scans, triggering webhooks, sending alerts). n8n does **NOT** contain the core AgentShield scanning engine. Future async queues/workers are part of AgentShield's backend architecture and are separate from n8n.
* **Security Rule Storage**: Week 1 security test probes and detection rules are **version-controlled files** (YAML/JSON/Python) in git for auditability, reproducibility, and simple CI deployment.

---

## 5. Week 1 MVP Scope

The initial release focuses on establishing a clean **Modular Monolith** architecture:

* **Target Support**: Generic HTTP REST AI Agent adapter with SSRF protection.
* **Trace Mode**: Black-box response and header observation.
* **Static Analysis**: Basic system prompt anti-pattern and tool schema checks.
* **Dynamic Security Suite**: 20 targeted security test probes covering:
  1. Direct Prompt Injection
  2. System Prompt Leakage
  3. Sensitive Information Disclosure (PII / Credentials)
  4. Excessive Agency & Unauthorized Tool Misuse
* **Evaluation**: Hybrid engine combining high-speed deterministic version-controlled rules with an optional LLM Judge.
* **Output**: Machine-readable JSON findings, single-page HTML report, quantitative risk scoring, and evidence packaging.

---

## 6. Current Project Status & Roadmap

| Phase | Milestone | Status | Key Deliverables |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Architecture & Threat Modeling | 🟢 **Complete** | Specifications (`docs/architecture.md`, `docs/threat-model.md`, `docs/mvp-scope.md`) |
| **Phase 2** | Core Modular Monolith Implementation | 🟢 **Complete** | FastAPI core, Target Adapter, probes, evaluation, findings, risk, reporting |
| **Phase 3** | Production Hardening & Infrastructure | 🟢 **Complete** | Security hardening, observability, Docker, CI/CD, PostgreSQL persistence |
| **Phase 4** | Platform Integration & Production Release | 🟢 **Complete** | End-to-end integration, performance hardening, SRE runbooks, release readiness (`docs/release.md`, `docs/production-readiness.md`) |

---

## 7. Local Development

### Prerequisites
* **Python 3.11+** installed on your system.

### Step-by-Step Setup

1. **Create Virtual Environment**:
   ```bash
   # Windows / macOS / Linux
   python -m venv .venv
   ```

2. **Activate Virtual Environment**:
   * **Windows (PowerShell)**:
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
   * **Windows (Command Prompt)**:
     ```cmd
     .\.venv\Scripts\activate.bat
     ```
   * **macOS / Linux**:
     ```bash
     source .venv/bin/activate
     ```

3. **Install Dependencies**:
   ```bash
   pip install -e .[dev]
   ```
   *Or install directly:*
   ```bash
   pip install fastapi uvicorn pydantic httpx pytest
   ```

 4. **Run FastAPI Backend**:
   ```bash
   # Windows PowerShell / CMD (using project virtual environment)
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
   ```
   The API will be available at `http://127.0.0.1:8000`. You can check the health status at `http://127.0.0.1:8000/health` and the Web Dashboard at `http://127.0.0.1:8000/dashboard`.

 5. **Run Tests**:
   ```bash
   .\.venv\Scripts\python.exe -m pytest tests/ -q
   ```

 6. **Run Streamlit Security Workstation**:
   ```bash
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```
   The Streamlit client workstation will launch at `http://localhost:8501`.

---

### 🎨 Cybernetic Precision Design System Integration

AgentShield implements the **Cybernetic Precision Light Theme** design system across both the Streamlit UI and the standalone FastAPI Web Audit Dashboard (`/dashboard`).

* **Design Source of Truth**: [`design/stitch_mockups/stitch_agentshield_security_platform/cybernetic_precision/DESIGN.md`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/design/stitch_mockups/stitch_agentshield_security_platform/cybernetic_precision/DESIGN.md)
* **Tokens**: Primary Electric Blue (`#004AC6`), Success Emerald (`#006C4A`), Error Crimson (`#D52022`), Slate Canvas (`#FAF8FF`), Surface (`#FFFFFF`), Text (`#131B2E`).
* **Typography**: **Plus Jakarta Sans** (Headlines) + **Inter** (Body/Labels) + **JetBrains Mono** (Telemetry/IDs/Hashes/Logs).
* **Workstation Screens**:
  1. **Executive Security Overview**: [`executive_security_overview_polished`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/design/stitch_mockups/stitch_agentshield_security_platform/executive_security_overview_polished/)
  2. **Scan Studio & Pipeline Orchestrator**: [`pipeline_orchestrator_scan_studio_polished`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/design/stitch_mockups/stitch_agentshield_security_platform/pipeline_orchestrator_scan_studio_polished/)
  3. **Audit Log & Forensic Inspector**: [`audit_log_forensic_inspector_polished`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/design/stitch_mockups/stitch_agentshield_security_platform/audit_log_forensic_inspector_polished/)
  4. **Adversarial Sandbox & Diagnostics**: [`adversarial_sandbox_diagnostics_polished`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/design/stitch_mockups/stitch_agentshield_security_platform/adversarial_sandbox_diagnostics_polished/)

---

## 8. Streamlit Community Cloud Deployment

AgentShield includes a production Streamlit client app (`streamlit_app.py`).

### Deployment Steps:
1. **Fork / Push Repo to GitHub**:
   Ensure `streamlit_app.py`, `.streamlit/config.toml`, and `requirements.txt` are pushed to your repository.
2. **Deploy on Streamlit Community Cloud**:
   * Go to [share.streamlit.io](https://share.streamlit.io/)
   * Click **New App** -> Select repository `shivam-shukla888/agent-shield`
   * Set Main file path: `streamlit_app.py`
3. **Configure Secrets (Optional)**:
   In Streamlit Cloud App Settings -> **Secrets**, add:
   ```toml
   BACKEND_URL = "https://your-agent-shield-backend.onrender.com"
   API_KEY = "your-secure-api-key"
   ```
4. **Offline / Demo Mode**:
   If the FastAPI server is not reachable, toggle **Demo / Offline Mock Mode** in the Streamlit sidebar to present interactive demo scans without backend dependency.

---

## 8. Documentation Index

Detailed architectural blueprints are available in the [`docs/`](./docs) directory:

* 📄 [Architecture Specification](./docs/architecture.md) — System design, component responsibilities, lifecycle state machines, Target Adapter abstraction, SSRF protection, and scaling roadmap.
* 📄 [Target Adapter Contract](./docs/target-contract.md) — TargetAdapter interface, TargetResult normalization, timeout lifecycle, SSRF security boundary, and error model.
* 📄 [SSRF Security Boundary Spec](./docs/ssrf-security.md) — Outbound SSRF security boundary, policy rules, DNS resolution, redirect protection, and error mapping.
* 📄 [REST API Endpoint Spec](./docs/api-routes.md) — POST /api/v1/scans REST endpoint, DTO request/response schemas, status codes, and error handling rules.
* 📄 [API Contract Specification](./docs/api-contract.md) — DTO schemas, request validation, URL validation, and public response security.
* 📄 [Attack Engine Specification](./docs/attack-engine.md) — AttackEngine design, probe execution lifecycle, ExecutionStatus, retry safety, and dataflow contract.
* 📄 [Evaluation Domain Specification](./docs/evaluation-model.md) — EvaluationResult model, EvaluationVerdict taxonomy, evidence structure, confidence validation, and evaluator abstraction.
* 📄 [Deterministic Evaluator Engine Spec](./docs/deterministic-evaluator.md) — DeterministicEvaluator design, rule taxonomy, verdict criteria, evidence extraction, and detection rules.
* 📄 [Hybrid Evaluation Strategy Spec](./docs/hybrid-evaluation.md) — HybridEvaluationStrategy policy layer, deterministic vs LLM combination matrix, transport error defense, and evidence merging rules.
* 📄 [Production LLM Provider Spec](./docs/production-llm-provider.md) — ProductionLLMProvider REST adapter, LLMProviderConfig, provider factory, secret non-disclosure, and credential isolation.
* 📄 [Finding Domain Specification](./docs/finding-model.md) — Finding model, severity taxonomy, status taxonomy, evidence structure, and remediation metadata.
* 📄 [Finding Engine Specification](./docs/finding-engine.md) — FindingEngine design, evaluation result conversion, finding aggregation, and deterministic ID derivation.
* 📄 [Risk Domain Specification](./docs/risk-model.md) — Risk assessment domain models, factor enums, risk level taxonomy, and weighted scoring model.
* 📄 [Risk Engine Specification](./docs/risk-engine.md) — RiskEngine design, mathematical scoring algorithm, and risk level derivation rules.
* 📄 [Scan Model Specification](./docs/scan-model.md) — ScanResult container, ScanSummary counters, ScanStatus taxonomy, and lineage validation rules.
* 📄 [Scan Engine Specification](./docs/scan-engine.md) — ScanEngine orchestrator, execution pipeline dataflow, error status semantics, and dependency injection.
* 📄 [Security Probe Domain Specification](./docs/probe-model.md) — SecurityProbe model, category taxonomy, pipeline separation, stable IDs, and initial probe suite.
* 📄 [Local Security Test Target Spec](./docs/test-agent.md) — Purpose, synthetic tools, controlled vulnerability triggers, and local testing boundaries for the test agent fixture.
* 📄 [Production Observability & Structured Logging Spec](./docs/observability.md) — Production-grade structured JSON logging, X-Request-ID correlation middleware, event taxonomy, secret redaction, and monotonic timing.
* 📄 [Production Security Hardening & Audit Spec](./docs/security-hardening.md) — Production SSRF defense, DNS rebinding mitigation, redirect policies, payload size limits, header sanitization, endpoint validation, and security headers.
* 📄 [Security Report Domain Specification](./docs/report-model.md) — ReportFinding, ReportRisk, SecurityReport DTO contracts, immutability, and boundary rules.
* 📄 [Reporting Engine Specification](./docs/report-engine.md) — ReportEngine architecture, template executive summary, deterministic risk sorting, Markdown & JSON rendering.
* 📄 [Customer Support Agent Threat Model](./docs/threat-model.md) — Threat taxonomy, attack surface analysis, and vulnerability breakdown.
* 📄 [MVP Scope & Boundary](./docs/mvp-scope.md) — Detailed Week 1 feature set, test suite specification, version-controlled rules rationale, and technology baseline.






---

## 9. Current Known Limitations

* **Scan Progress Polling**: The Streamlit Scan Studio workspace uses HTTP status polling (`GET /api/v1/scans/{id}`) to visualize probe execution progress, rather than persistent WebSocket/SSE streaming.
* **Target Domain Allowlisting**: Server-side domain allowlisting is optional and environment-gated (`AGENTSHIELD_ALLOWED_TARGET_DOMAINS`). When unconfigured (empty), all target hostnames are permitted.
* **Sandbox Evaluation Scope**: The Adversarial Sandbox tab routes prompt payloads directly to the backend `POST /api/v1/evaluate/payload` endpoint using `DeterministicEvaluator` rules. Complex multi-step LLM reasoning evaluations require running a full scan via Scan Studio.

---

## 10. Architectural Decisions & Resolutions


> [!NOTE]
> **Decision 1: Target Adapter Response Parsing Fallback — Resolved**  
> `GenericHTTPAdapter` supports automatic key fallback (`"response"`, `"answer"`, `"output"`, `"text"`, `"message"`, `"content"`) when no explicit `response_path` is configured, while honoring explicit JSONPath mapping when supplied.

> [!NOTE]
> **Decision 2: LLM Judge Provider Selection — Resolved**  
> `ProductionLLMProvider` uses a vendor-agnostic OpenAI-compatible REST interface (`/v1/chat/completions`), allowing seamless deployment with both cloud LLM APIs (OpenAI, Groq) and local open-weights model servers (Ollama, vLLM) for zero-data-leakage enterprise environments.

