"""
Production Configuration Validation Tests (STEP 18A)

Tests that AppConfig correctly validates, rejects, and parses environment
configuration parameters for production deployment safety.
"""

import os
import pytest
from unittest.mock import patch
from pydantic import SecretStr

from app.config import AppConfig, VALID_LOG_LEVELS, CLOUD_LLM_PROVIDERS


# ============================================================
# 1. DEFAULT VALUES
# ============================================================

class TestAppConfigDefaults:
    """Verify sane defaults when no overrides are provided."""

    def test_default_host(self):
        cfg = AppConfig()
        assert cfg.host == "0.0.0.0"

    def test_default_port(self):
        cfg = AppConfig()
        assert cfg.port == 8000

    def test_default_log_level(self):
        cfg = AppConfig()
        assert cfg.log_level == "INFO"

    def test_default_rate_limit_rpm(self):
        cfg = AppConfig()
        assert cfg.rate_limit_rpm == 60

    def test_default_api_key_none(self):
        cfg = AppConfig()
        assert cfg.api_key is None

    def test_default_database_url_none(self):
        cfg = AppConfig()
        assert cfg.database_url is None

    def test_default_llm_provider_groq(self):
        cfg = AppConfig()
        assert cfg.llm_provider == "groq"

    def test_default_llm_timeout(self):
        cfg = AppConfig()
        assert cfg.llm_timeout == 30.0

    def test_default_llm_api_key_none(self):
        cfg = AppConfig()
        assert cfg.llm_api_key is None

    def test_default_llm_model_none(self):
        cfg = AppConfig()
        assert cfg.llm_model is None

    def test_default_llm_endpoint_none(self):
        cfg = AppConfig()
        assert cfg.llm_endpoint is None


# ============================================================
# 2. PORT VALIDATION
# ============================================================

class TestPortValidation:
    """Validate port range enforcement (1..65535)."""

    def test_port_minimum_valid(self):
        cfg = AppConfig(port=1)
        assert cfg.port == 1

    def test_port_maximum_valid(self):
        cfg = AppConfig(port=65535)
        assert cfg.port == 65535

    def test_port_zero_rejected(self):
        with pytest.raises(Exception, match="1 and 65535"):
            AppConfig(port=0)

    def test_port_negative_rejected(self):
        with pytest.raises(Exception, match="1 and 65535"):
            AppConfig(port=-1)

    def test_port_above_max_rejected(self):
        with pytest.raises(Exception, match="1 and 65535"):
            AppConfig(port=65536)

    def test_port_typical_production(self):
        cfg = AppConfig(port=443)
        assert cfg.port == 443


# ============================================================
# 3. LOG LEVEL VALIDATION
# ============================================================

class TestLogLevelValidation:
    """Validate log level normalization and rejection."""

    @pytest.mark.parametrize("level", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    def test_valid_log_levels(self, level):
        cfg = AppConfig(log_level=level)
        assert cfg.log_level == level

    @pytest.mark.parametrize("level", ["debug", "info", "warning", "error", "critical"])
    def test_lowercase_normalized_to_upper(self, level):
        cfg = AppConfig(log_level=level)
        assert cfg.log_level == level.upper()

    def test_invalid_log_level_rejected(self):
        with pytest.raises(Exception, match="LOG_LEVEL"):
            AppConfig(log_level="VERBOSE")

    def test_empty_log_level_rejected(self):
        with pytest.raises(Exception, match="LOG_LEVEL"):
            AppConfig(log_level="")

    def test_whitespace_log_level_rejected(self):
        with pytest.raises(Exception, match="LOG_LEVEL"):
            AppConfig(log_level="   ")


# ============================================================
# 4. RATE LIMIT VALIDATION
# ============================================================

class TestRateLimitValidation:
    """Validate rate limit enforcement."""

    def test_positive_rate_limit(self):
        cfg = AppConfig(rate_limit_rpm=100)
        assert cfg.rate_limit_rpm == 100

    def test_zero_rate_limit_rejected(self):
        with pytest.raises(Exception, match="positive integer"):
            AppConfig(rate_limit_rpm=0)

    def test_negative_rate_limit_rejected(self):
        with pytest.raises(Exception, match="positive integer"):
            AppConfig(rate_limit_rpm=-10)

    def test_one_rpm_valid(self):
        cfg = AppConfig(rate_limit_rpm=1)
        assert cfg.rate_limit_rpm == 1


# ============================================================
# 5. LLM PROVIDER VALIDATION
# ============================================================

class TestLLMProviderValidation:
    """Validate LLM provider selection and cloud credential requirements."""

    @pytest.mark.parametrize("provider", ["fake", "openai", "anthropic", "groq", "ollama", "custom", "none"])
    def test_valid_providers_accepted(self, provider):
        kwargs = {"llm_provider": provider}
        if provider in CLOUD_LLM_PROVIDERS:
            kwargs["llm_api_key"] = SecretStr("test-key-12345")
        cfg = AppConfig(**kwargs)
        assert cfg.llm_provider == provider

    def test_invalid_provider_rejected(self):
        with pytest.raises(Exception, match="AGENTSHIELD_LLM_PROVIDER"):
            AppConfig(llm_provider="gpt-magic")

    def test_cloud_provider_without_key_rejected(self):
        with pytest.raises(Exception, match="AGENTSHIELD_LLM_API_KEY"):
            AppConfig(llm_provider="openai", llm_api_key=None)

    def test_cloud_provider_with_empty_key_rejected(self):
        with pytest.raises(Exception, match="AGENTSHIELD_LLM_API_KEY"):
            AppConfig(llm_provider="anthropic", llm_api_key=SecretStr("   "))

    def test_cloud_provider_with_valid_key_accepted(self):
        cfg = AppConfig(llm_provider="groq", llm_api_key=SecretStr("gsk_test_key"))
        assert cfg.llm_provider == "groq"

    def test_fake_provider_no_key_required(self):
        cfg = AppConfig(llm_provider="fake")
        assert cfg.llm_api_key is None

    def test_none_provider_no_key_required(self):
        cfg = AppConfig(llm_provider="none")
        assert cfg.llm_api_key is None


# ============================================================
# 6. LLM TIMEOUT VALIDATION
# ============================================================

class TestLLMTimeoutValidation:
    """Validate LLM timeout boundaries."""

    def test_valid_timeout(self):
        cfg = AppConfig(llm_timeout=60.0)
        assert cfg.llm_timeout == 60.0

    def test_max_timeout_boundary(self):
        cfg = AppConfig(llm_timeout=300.0)
        assert cfg.llm_timeout == 300.0

    def test_zero_timeout_rejected(self):
        with pytest.raises(Exception, match="AGENTSHIELD_LLM_TIMEOUT"):
            AppConfig(llm_timeout=0.0)

    def test_negative_timeout_rejected(self):
        with pytest.raises(Exception, match="AGENTSHIELD_LLM_TIMEOUT"):
            AppConfig(llm_timeout=-5.0)

    def test_above_max_timeout_rejected(self):
        with pytest.raises(Exception, match="AGENTSHIELD_LLM_TIMEOUT"):
            AppConfig(llm_timeout=301.0)

    def test_small_valid_timeout(self):
        cfg = AppConfig(llm_timeout=0.5)
        assert cfg.llm_timeout == 0.5


# ============================================================
# 7. DATABASE URL VALIDATION
# ============================================================

class TestDatabaseURLValidation:
    """Validate database URL scheme enforcement."""

    def test_postgresql_scheme_accepted(self):
        cfg = AppConfig(database_url=SecretStr("postgresql://user:pass@host/db"))
        assert cfg.database_url is not None

    def test_postgres_scheme_accepted(self):
        cfg = AppConfig(database_url=SecretStr("postgres://user:pass@host/db"))
        assert cfg.database_url is not None

    def test_sqlite_scheme_accepted(self):
        cfg = AppConfig(database_url=SecretStr("sqlite:///path/to/db.sqlite"))
        assert cfg.database_url is not None

    def test_mysql_scheme_rejected(self):
        with pytest.raises(Exception, match="DATABASE_URL"):
            AppConfig(database_url=SecretStr("mysql://user:pass@host/db"))

    def test_empty_database_url_becomes_none(self):
        cfg = AppConfig(database_url=SecretStr(""))
        assert cfg.database_url is None

    def test_whitespace_database_url_becomes_none(self):
        cfg = AppConfig(database_url=SecretStr("   "))
        assert cfg.database_url is None

    def test_none_database_url_accepted(self):
        cfg = AppConfig(database_url=None)
        assert cfg.database_url is None


# ============================================================
# 8. HOST VALIDATION
# ============================================================

class TestHostValidation:
    """Validate host address sanitization."""

    def test_valid_host(self):
        cfg = AppConfig(host="0.0.0.0")
        assert cfg.host == "0.0.0.0"

    def test_localhost_valid(self):
        cfg = AppConfig(host="localhost")
        assert cfg.host == "localhost"

    def test_host_with_newline_rejected(self):
        with pytest.raises(Exception, match="control characters"):
            AppConfig(host="host\ninjection")

    def test_host_with_carriage_return_rejected(self):
        with pytest.raises(Exception, match="control characters"):
            AppConfig(host="host\rinjection")

    def test_host_with_null_rejected(self):
        with pytest.raises(Exception, match="control characters"):
            AppConfig(host="host\0injection")

    def test_empty_host_rejected(self):
        with pytest.raises(Exception, match="non-empty"):
            AppConfig(host="")

    def test_whitespace_only_host_rejected(self):
        with pytest.raises(Exception, match="non-empty"):
            AppConfig(host="   ")


# ============================================================
# 9. SAFE DICT (SECRET REDACTION)
# ============================================================

class TestSafeDict:
    """Verify safe_dict never leaks secrets."""

    def test_safe_dict_redacts_api_key(self):
        cfg = AppConfig(api_key=SecretStr("super-secret-key"))
        d = cfg.safe_dict()
        assert d["api_key_configured"] is True
        assert "super-secret-key" not in str(d)

    def test_safe_dict_redacts_database_url(self):
        cfg = AppConfig(database_url=SecretStr("postgresql://user:pass@host/db"))
        d = cfg.safe_dict()
        assert d["database_configured"] is True
        assert "pass" not in str(d)

    def test_safe_dict_redacts_llm_key(self):
        cfg = AppConfig(llm_provider="openai", llm_api_key=SecretStr("sk-12345"))
        d = cfg.safe_dict()
        assert d["llm_key_configured"] is True
        assert "sk-12345" not in str(d)

    def test_safe_dict_shows_non_sensitive_fields(self):
        cfg = AppConfig(port=9000, log_level="DEBUG", rate_limit_rpm=120)
        d = cfg.safe_dict()
        assert d["port"] == 9000
        assert d["log_level"] == "DEBUG"
        assert d["rate_limit_rpm"] == 120

    def test_safe_dict_no_key_configured_false(self):
        cfg = AppConfig()
        d = cfg.safe_dict()
        assert d["api_key_configured"] is False
        assert d["database_configured"] is False
        assert d["llm_key_configured"] is False


# ============================================================
# 10. FROM_ENV PARSING
# ============================================================

class TestFromEnv:
    """Validate AppConfig.from_env() reads and validates environment correctly."""

    def test_from_env_defaults(self):
        env = {}
        with patch.dict(os.environ, env, clear=True):
            cfg = AppConfig.from_env()
        assert cfg.host == "0.0.0.0"
        assert cfg.port == 8000
        assert cfg.log_level == "INFO"
        assert cfg.llm_provider == "fake"

    def test_from_env_custom_port(self):
        with patch.dict(os.environ, {"APP_PORT": "9090"}, clear=True):
            cfg = AppConfig.from_env()
        assert cfg.port == 9090

    def test_from_env_invalid_port_string(self):
        with patch.dict(os.environ, {"APP_PORT": "not-a-number"}, clear=True):
            with pytest.raises(ValueError, match="valid integer"):
                AppConfig.from_env()

    def test_from_env_database_url(self):
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql://u:p@h/d"}, clear=True):
            cfg = AppConfig.from_env()
        assert cfg.database_url is not None
        assert cfg.database_url.get_secret_value() == "postgresql://u:p@h/d"

    def test_from_env_api_key(self):
        with patch.dict(os.environ, {"AGENTSHIELD_API_KEY": "my-test-key"}, clear=True):
            cfg = AppConfig.from_env()
        assert cfg.api_key is not None
        assert cfg.api_key.get_secret_value() == "my-test-key"

    def test_from_env_llm_cloud_provider_with_key(self):
        with patch.dict(os.environ, {
            "AGENTSHIELD_LLM_PROVIDER": "openai",
            "AGENTSHIELD_LLM_API_KEY": "sk-test",
        }, clear=True):
            cfg = AppConfig.from_env()
        assert cfg.llm_provider == "openai"
        assert cfg.llm_api_key.get_secret_value() == "sk-test"

    def test_from_env_llm_cloud_provider_without_key_raises(self):
        with patch.dict(os.environ, {
            "AGENTSHIELD_LLM_PROVIDER": "openai",
        }, clear=True):
            with pytest.raises(ValueError, match="AGENTSHIELD_LLM_API_KEY"):
                AppConfig.from_env()

    def test_from_env_invalid_rpm(self):
        with patch.dict(os.environ, {"AGENTSHIELD_RATE_LIMIT_RPM": "abc"}, clear=True):
            with pytest.raises(ValueError, match="integer"):
                AppConfig.from_env()

    def test_from_env_invalid_timeout(self):
        with patch.dict(os.environ, {"AGENTSHIELD_LLM_TIMEOUT": "abc"}, clear=True):
            with pytest.raises(ValueError, match="float"):
                AppConfig.from_env()

    def test_from_env_fallback_api_key(self):
        """API_KEY env var is the fallback when AGENTSHIELD_API_KEY is not set."""
        with patch.dict(os.environ, {"API_KEY": "fallback-key"}, clear=True):
            cfg = AppConfig.from_env()
        assert cfg.api_key is not None
        assert cfg.api_key.get_secret_value() == "fallback-key"


# ============================================================
# 11. SECRET REPR SAFETY
# ============================================================

class TestSecretSafety:
    """Ensure repr() / str() never leaks secret values."""

    def test_repr_does_not_leak_api_key(self):
        cfg = AppConfig(api_key=SecretStr("leaked-api-key-danger"))
        representation = repr(cfg)
        assert "leaked-api-key-danger" not in representation

    def test_str_does_not_leak_database_url(self):
        cfg = AppConfig(database_url=SecretStr("postgresql://admin:s3cret@db/prod"))
        representation = str(cfg)
        assert "s3cret" not in representation

    def test_repr_does_not_leak_llm_key(self):
        cfg = AppConfig(llm_provider="openai", llm_api_key=SecretStr("sk-very-secret"))
        representation = repr(cfg)
        assert "sk-very-secret" not in representation
