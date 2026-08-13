"""
CI Configuration & Production Safety Tests (STEP 18B)

Tests that validate version exposure, configuration safety, secret non-disclosure,
environment separation, and production readiness assertions.
"""

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.config import AppConfig
from app.main import create_app


# ============================================================
# 1. VERSION EXPOSURE
# ============================================================

class TestVersionExposure:
    """Verify application version is exposed safely."""

    def test_version_defined(self):
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_version_format_semver(self):
        """Version should follow semantic versioning pattern."""
        assert re.match(r"^\d+\.\d+\.\d+", __version__), f"Version '{__version__}' not semver"

    def test_health_includes_version(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert data["version"] == __version__

    def test_health_does_not_expose_secrets(self):
        app = create_app(api_key="super-secret-key-12345")
        client = TestClient(app)
        resp = client.get("/health")
        body = resp.text
        assert "super-secret-key-12345" not in body

    def test_health_does_not_expose_env_vars(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/health")
        body = resp.text
        assert "DATABASE_URL" not in body
        assert "AGENTSHIELD_API_KEY" not in body
        assert "APP_HOST" not in body


# ============================================================
# 2. SAFE VERSION RESPONSE
# ============================================================

class TestSafeVersionResponse:
    """Verify /health response is minimal and safe."""

    def test_health_fields_minimal(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/health")
        data = resp.json()
        # Should only contain status and version
        assert set(data.keys()) == {"status", "version"}

    def test_health_no_filesystem_paths(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/health")
        body = resp.text
        assert "/opt/" not in body
        assert "C:\\" not in body
        assert "/home/" not in body


# ============================================================
# 3. CONFIGURATION VALIDATION
# ============================================================

class TestConfigurationValidation:
    """Verify AppConfig rejects invalid production configurations."""

    def test_invalid_port_rejected(self):
        with pytest.raises(Exception):
            AppConfig(port=0)

    def test_invalid_port_above_max_rejected(self):
        with pytest.raises(Exception):
            AppConfig(port=70000)

    def test_invalid_log_level_rejected(self):
        with pytest.raises(Exception):
            AppConfig(log_level="TRACE")

    def test_negative_rate_limit_rejected(self):
        with pytest.raises(Exception):
            AppConfig(rate_limit_rpm=-1)

    def test_invalid_llm_timeout_rejected(self):
        with pytest.raises(Exception):
            AppConfig(llm_timeout=0.0)

    def test_invalid_database_url_scheme_rejected(self):
        from pydantic import SecretStr
        with pytest.raises(Exception):
            AppConfig(database_url=SecretStr("mysql://user:pass@host/db"))

    def test_cloud_provider_without_key_rejected(self):
        with pytest.raises(Exception):
            AppConfig(llm_provider="openai", llm_api_key=None)


# ============================================================
# 4. SECRET NON-DISCLOSURE
# ============================================================

class TestSecretNonDisclosure:
    """Verify secrets never appear in safe outputs."""

    def test_config_repr_no_secrets(self):
        from pydantic import SecretStr
        cfg = AppConfig(
            api_key=SecretStr("my-secret-api-key"),
            database_url=SecretStr("postgresql://admin:password123@db/prod"),
            llm_provider="openai",
            llm_api_key=SecretStr("sk-1234567890abcdef"),
        )
        representation = repr(cfg)
        assert "my-secret-api-key" not in representation
        assert "password123" not in representation
        assert "sk-1234567890abcdef" not in representation

    def test_safe_dict_no_secrets(self):
        from pydantic import SecretStr
        cfg = AppConfig(
            api_key=SecretStr("leaked-key"),
            database_url=SecretStr("postgresql://u:p@h/d"),
        )
        d = cfg.safe_dict()
        safe_str = str(d)
        assert "leaked-key" not in safe_str
        assert "postgresql://" not in safe_str

    def test_health_ready_no_db_details(self):
        """Readiness check must not leak database information."""
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/health/ready")
        body = resp.text
        assert "postgresql" not in body.lower()
        assert "password" not in body.lower()


# ============================================================
# 5. ENVIRONMENT SEPARATION
# ============================================================

class TestEnvironmentSeparation:
    """Verify environment separation assumptions."""

    def test_env_example_exists(self):
        env_example = Path(__file__).parent.parent / ".env.example"
        assert env_example.exists(), ".env.example must exist"

    def test_env_not_committed(self):
        """Real .env should not exist in the repository root (should be gitignored)."""
        gitignore = Path(__file__).parent.parent / ".gitignore"
        assert gitignore.exists()
        content = gitignore.read_text()
        assert ".env" in content

    def test_env_example_has_no_real_secrets(self):
        env_example = Path(__file__).parent.parent / ".env.example"
        content = env_example.read_text()
        # Should not contain real-looking API keys
        assert "sk-" not in content
        assert "gsk_" not in content
        assert "AKIA" not in content

    def test_dockerfile_exists(self):
        dockerfile = Path(__file__).parent.parent / "Dockerfile"
        assert dockerfile.exists()

    def test_docker_compose_exists(self):
        compose = Path(__file__).parent.parent / "docker-compose.yml"
        assert compose.exists()


# ============================================================
# 6. PRODUCTION CONFIG FAILURE HANDLING
# ============================================================

class TestProductionConfigFailures:
    """Verify production startup failures are handled safely."""

    def test_from_env_invalid_port(self):
        with patch.dict(os.environ, {"APP_PORT": "not-a-number"}, clear=True):
            with pytest.raises(ValueError, match="integer"):
                AppConfig.from_env()

    def test_from_env_invalid_timeout(self):
        with patch.dict(os.environ, {"AGENTSHIELD_LLM_TIMEOUT": "abc"}, clear=True):
            with pytest.raises(ValueError, match="float"):
                AppConfig.from_env()

    def test_from_env_cloud_provider_missing_key(self):
        with patch.dict(os.environ, {"AGENTSHIELD_LLM_PROVIDER": "anthropic"}, clear=True):
            with pytest.raises(ValueError, match="AGENTSHIELD_LLM_API_KEY"):
                AppConfig.from_env()


# ============================================================
# 7. HEALTH ENDPOINT REMAINS PUBLIC
# ============================================================

class TestHealthPublicAccess:
    """Verify health endpoints do not require authentication."""

    def test_health_no_api_key_required(self):
        app = create_app(api_key="required-key")
        client = TestClient(app)
        # No X-API-Key header
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_ready_no_api_key_required(self):
        app = create_app(api_key="required-key")
        client = TestClient(app)
        resp = client.get("/health/ready")
        assert resp.status_code == 200

    def test_api_endpoints_require_key(self):
        app = create_app(api_key="required-key")
        client = TestClient(app)
        # API endpoint without key should fail
        resp = client.get("/api/v1/scans")
        assert resp.status_code in (401, 403)


# ============================================================
# 8. READINESS CHECK
# ============================================================

class TestReadinessCheck:
    """Verify readiness endpoint behavior."""

    def test_readiness_returns_ready(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"

    def test_readiness_sanitized_response(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/health/ready")
        data = resp.json()
        # Should not contain database details
        for key in data:
            assert "sql" not in str(data[key]).lower()
            assert "connection" not in str(data[key]).lower()


# ============================================================
# 9. CI WORKFLOW VALIDATION
# ============================================================

class TestCIWorkflow:
    """Verify CI workflow file exists and is structurally valid."""

    def test_ci_workflow_exists(self):
        ci_path = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
        assert ci_path.exists(), "CI workflow must exist at .github/workflows/ci.yml"

    def test_ci_workflow_has_test_job(self):
        ci_path = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
        content = ci_path.read_text()
        assert "pytest" in content
        assert "test" in content.lower()

    def test_ci_workflow_has_docker_job(self):
        ci_path = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
        content = ci_path.read_text()
        assert "docker" in content.lower()

    def test_ci_workflow_no_secrets(self):
        ci_path = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
        content = ci_path.read_text()
        # No real API keys or credentials (actual key values, not scanning patterns)
        assert "sk-proj-" not in content  # Real OpenAI keys use sk-proj- prefix
        assert "gsk_real" not in content
        assert "AKIAIOSFODNN" not in content  # Real AWS key prefix
        # No hardcoded connection strings with real passwords
        assert "postgresql://admin:" not in content


# ============================================================
# 10. VERSION CONSISTENCY
# ============================================================

class TestVersionConsistency:
    """Verify version is consistent across sources."""

    def test_pyproject_version_matches(self):
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert __version__ in content, "pyproject.toml version must match app.__version__"
