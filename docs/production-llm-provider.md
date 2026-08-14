# Production LLM Provider & Configuration Boundary Specification

## Overview & Architecture

AgentShield decouples security evaluation reasoning from vendor-specific LLM SDKs (`openai`, `anthropic`). The **Production LLM Provider Integration** (`ProductionLLMProvider`) implements a vendor-agnostic HTTP adapter using `httpx` to communicate with OpenAI-compatible REST endpoints (`/v1/chat/completions`).

```
    LLMEvaluator
         │
         ▼
    LLMProvider (Abstract Base Class)
         │
  ┌──────┴───────────────────────────┐
  ▼                                  ▼
FakeLLMProvider            ProductionLLMProvider
(Mock / Offline)           (httpx REST Adapter)
                                     │
                                     ▼
                          External OpenAI-compatible API
```

---

## Key Components

### 1. Provider Abstraction (`LLMProvider`)
Defined in `app/evaluation/provider.py`. Provides abstract method `generate(prompt: str, system_prompt: Optional[str] = None) -> str`.

### 2. Mock Provider (`FakeLLMProvider`)
Defined in `app/evaluation/provider.py`. Configurable in-memory mock provider supporting canned responses, keyword maps, and exception simulation for unit/integration testing without network calls.

### 3. Production Adapter (`ProductionLLMProvider`)
Defined in `app/evaluation/production_provider.py`. Vendor-agnostic REST client subclassing `LLMProvider`.
- Communicates over standard HTTP JSON payload schemas.
- Configured with bounded timeouts, endpoint URLs, and secret-wrapped API keys.
- Converts transport, authentication, rate limit, and server failures into safe `LLMProviderError` exceptions.

### 4. Configuration Model (`LLMProviderConfig`)
Defined in `app/evaluation/config.py`. Immutable Pydantic model (`ConfigDict(frozen=True)`) supporting environment-driven configuration.

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `provider_type` | `str` | `"fake"` | Provider implementation (`fake`, `production`, `openai`) |
| `api_key` | `Optional[SecretStr]` | `None` | Vendor API key (wrapped in `SecretStr`) |
| `model` | `str` | `"gpt-4o"` | Model version string |
| `timeout_seconds` | `float` | `30.0` | Bounded request timeout ceiling ($0.1\text{s} - 300\text{s}$) |
| `endpoint` | `str` | `https://api.openai.com/v1/chat/completions` | Vendor REST API endpoint URL |

---

## Environment Variables

Configuration can be driven automatically via environment variables:

| Environment Variable | Alias | Default | Description |
| :--- | :--- | :--- | :--- |
| `AGENTSHIELD_LLM_PROVIDER` | `LLM_PROVIDER` | `"fake"` | Provider type selector |
| `AGENTSHIELD_LLM_API_KEY` | `LLM_API_KEY` | `None` | Production vendor API authorization key |
| `AGENTSHIELD_LLM_MODEL` | `LLM_MODEL` | `"gpt-4o"` | Target LLM model name |
| `AGENTSHIELD_LLM_TIMEOUT` | `LLM_TIMEOUT` | `30.0` | HTTP request timeout in seconds |
| `AGENTSHIELD_LLM_ENDPOINT` | `LLM_ENDPOINT` | OpenAI default | Custom REST API endpoint URL |

---

## Provider Selection Factory (`build_llm_provider`)

Defined in `app/evaluation/factory.py`.

```python
from app.evaluation import build_llm_provider, LLMProviderConfig

# Construct based on environment variables
provider = build_llm_provider()

# Construct with explicit configuration
config = LLMProviderConfig(
    provider_type="production",
    api_key=SecretStr("sk-prod-..."),
    model="claude-3-5-sonnet",
)
provider = build_llm_provider(config)
```

- Returns `FakeLLMProvider` when `provider_type == "fake"`.
- Returns `ProductionLLMProvider` when `provider_type in ("production", "openai")`.
- Raises `LLMProviderError` if production credentials are missing or invalid, preventing unhandled crashes or secret leakage.

---

## Security Boundaries & Secret Redaction

1. **Secret Non-Disclosure**:
   - `LLMProviderConfig` and `ProductionLLMProvider` implement custom `__repr__` and `__str__` methods to prevent API key exposure in logs or tracebacks.
   - `LLMProviderError` automatically redacts `Bearer` tokens and authorization strings from exception text.
2. **Credential Isolation**:
   - **Target API Key $\neq$ LLM API Key**: Target agent authorization headers (`TargetAuthConfig`) are strictly isolated from LLM provider API keys (`LLMProviderConfig`).
   - The scanner never forwards target bearer tokens to LLM providers or LLM keys to target endpoints.
3. **Transport Error Defense-in-Depth**:
   - Operational target failures (`ExecutionStatus.ERROR`) bypass LLM provider calls entirely, preserving `EvaluationVerdict.ERROR`.
   - LLM provider failures yield safe `EvaluationResult(verdict=ERROR)` without exposing credentials or turning transport errors into vulnerabilities.

---

## Testing Strategy

- **Mocked HTTP Transports**: Unit tests use `httpx.MockTransport` to simulate provider HTTP status codes (200 OK, 401 Auth Error, 429 Rate Limit, 5xx Server Error, Timeout, Malformed JSON).
- **Zero Real Network Calls**: Pytest runs entirely offline without external API keys or live network requests.
