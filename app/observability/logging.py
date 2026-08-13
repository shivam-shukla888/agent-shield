"""
Structured Logging & Secret Redaction Facility (STEP 15A)

This module provides a centralized structured JSON logging facility using Python standard library logging.

SECURITY & ARCHITECTURAL DIRECTIVES:
1. Every log entry is formatted as a machine-readable single-line JSON object.
2. Every entry contains: timestamp (UTC ISO-8601), level, and event name.
3. Secret redaction regex automatically strips Bearer tokens, API keys, and authorization secrets.
4. Request correlation ID (request_id) is managed using ContextVar for thread/async safety.
5. NEVER logs prompts, target responses, authorization headers, or request/response bodies.
"""

from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import re
import sys
from typing import Any, Dict, Optional

# Context variable for request correlation ID
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

# Secret redaction pattern regexes
REDACT_PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.=]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(X-API-Key:\s*)[A-Za-z0-9_\-\.=]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(api_key=)[A-Za-z0-9_\-\.=]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(password=)[A-Za-z0-9_\-\.=]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token=)[A-Za-z0-9_\-\.=]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"sk-[A-Za-z0-9_\-]{15,}", re.IGNORECASE), "[REDACTED_API_KEY]"),
    (re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s]+", re.IGNORECASE), "postgresql://[REDACTED]@..."),
]


def redact_secrets(val: Any) -> Any:
    """
    Recursively redact sensitive patterns from text strings, dicts, or lists.
    Redacts sensitive key names in dictionaries as well as regex secret matches in strings.
    """
    if isinstance(val, str):
        res = val
        for pattern, replacement in REDACT_PATTERNS:
            res = pattern.sub(replacement, res)
        return res
    elif isinstance(val, dict):
        redacted_dict = {}
        for k, v in val.items():
            k_lower = str(k).lower()
            if any(term in k_lower for term in ("authorization", "api_key", "bearer", "password", "secret", "db_url", "postgres_url")):
                redacted_dict[k] = "[REDACTED]"
            else:
                redacted_dict[k] = redact_secrets(v)
        return redacted_dict
    elif isinstance(val, list):
        return [redact_secrets(v) for v in val]
    return val


class JSONFormatter(logging.Formatter):
    """
    Custom Logging Formatter converting LogRecords into single-line JSON objects.
    """

    # Reserved standard LogRecord attributes to ignore when extracting extra context
    RESERVED_ATTRS = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "msg", "name", "pathname", "process", "processName", "relativeCreated",
        "stack_info", "thread", "threadName", "event", "taskName"
    }

    def format(self, record: logging.LogRecord) -> str:
        now_utc = datetime.now(timezone.utc).isoformat()
        
        event_name = getattr(record, "event", record.getMessage())
        
        log_obj: Dict[str, Any] = {
            "timestamp": now_utc,
            "level": record.levelname,
            "event": event_name,
        }

        # Include request_id from ContextVar if available, or record extra
        req_id = request_id_var.get() or getattr(record, "request_id", None)
        if req_id:
            log_obj["request_id"] = req_id

        # Extract custom extra attributes attached to record
        for key, value in record.__dict__.items():
            if key not in self.RESERVED_ATTRS and not key.startswith("_"):
                log_obj[key] = value

        # Redact secrets across all log fields
        redacted_obj = redact_secrets(log_obj)
        return json.dumps(redacted_obj, default=str)


def get_logger(name: str = "agentshield") -> logging.Logger:
    """
    Get or configure a structured JSON logger instance.

    Args:
        name (str): Logger name / component name.

    Returns:
        logging.Logger: Configured logger instance emitting structured JSON.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers if logger is already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger


def emit_event(
    logger: logging.Logger,
    event: str,
    level: int = logging.INFO,
    **kwargs: Any,
) -> None:
    """
    Emit a structured operational event.

    Args:
        logger (logging.Logger): Logger instance.
        event (str): Machine-readable event name (e.g. 'scan.started').
        level (int): Logging level (default logging.INFO).
        **kwargs: Contextual metadata key-value pairs (e.g. scan_id=..., duration_ms=...).
    """
    extra = {"event": event}
    req_id = request_id_var.get()
    if req_id:
        extra["request_id"] = req_id

    for k, v in kwargs.items():
        if v is not None:
            extra[k] = v

    logger.log(level, event, extra=extra)
