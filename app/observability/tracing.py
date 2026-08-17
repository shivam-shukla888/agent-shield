"""
OpenTelemetry GenAI & Security Scan Trace Collector (STEP 23C)

Provides lightweight OpenTelemetry span instrumentation around AgentShield scan execution stages
(scan creation, probe attack dispatch, deterministic evaluation, finding derivation, risk assessment).

ARCHITECTURAL DIRECTIVES:
1. Emits standard OTel GenAI security convention spans when `opentelemetry` package is present.
2. Graceful fallback: if OpenTelemetry API is omitted, logs structured trace events without crashing.
3. Zero network requirement: exports to ConsoleSpanExporter or in-memory tracer provider.
"""

from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional


from app.observability.logging import get_logger, emit_event

logger = get_logger("agentshield.tracing")

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False


class AgentShieldTracer:
    """
    OpenTelemetry trace instrumentation manager for AgentShield scan execution lifecycle.
    """

    def __init__(self, tracer_name: str = "agentshield.tracer") -> None:
        self.tracer_name = tracer_name
        self._tracer: Any = None
        if _HAS_OTEL:
            try:
                self._tracer = trace.get_tracer(self.tracer_name)
            except Exception:
                self._tracer = None

    @contextmanager
    def span(
        self,
        name: str,
        scan_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Generator[Any, None, None]:
        """
        Context manager starting an OpenTelemetry span for a scan lifecycle operation.

        Args:
            name (str): Span operation name (e.g. `scan.execute`, `attack.dispatch`).
            scan_id (Optional[str]): Scan ID associated with span.
            attributes (Optional[Dict[str, Any]]): Key-value attribute dictionary.

        Yields:
            Span or Dummy object.
        """
        attrs = dict(attributes) if attributes else {}
        if scan_id:
            attrs["agentshield.scan_id"] = scan_id

        if _HAS_OTEL and self._tracer is not None:
            with self._tracer.start_as_current_span(name, attributes=attrs) as span:
                try:
                    yield span
                except Exception as exc:
                    span.set_status(Status(StatusCode.ERROR, str(exc)))
                    span.record_exception(exc)
                    raise
        else:
            emit_event(logger, "otel.span.started", span_name=name, **attrs)
            try:
                yield None
                emit_event(logger, "otel.span.completed", span_name=name, status="ok", **attrs)
            except Exception as exc:
                emit_event(logger, "otel.span.failed", span_name=name, error=str(exc), **attrs)
                raise
