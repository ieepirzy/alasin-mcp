# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry tracing.

An SDK tracer provider is always installed, so trace IDs are real even when
nothing is exported: they still go into commit trailers and audit events.
Spans are exported over OTLP/HTTP only when an endpoint is configured.

Trace shape: the MCP SDK opens a span per request, continuing the client's
``_meta.traceparent`` when one is sent (SEP-414). ``begin_change`` records the
trace it ran in on the work session. Later tool spans are parented to that
trace, so one work session is one trace. When a later call arrives with a
different incoming trace (some clients send a fresh traceparent per request),
the tool span links to it instead.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Link, NonRecordingSpan, Span, SpanContext, TraceFlags

_TRACER_NAME = "alasin_mcp"


def configure(
    service_name: str, otlp_endpoint: str = "", extra: SpanProcessor | None = None
) -> TracerProvider:
    """Install (once) an SDK tracer provider; add an OTLP exporter if configured."""
    current = trace.get_tracer_provider()
    if isinstance(current, TracerProvider):
        provider = current
    else:
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        trace.set_tracer_provider(provider)
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
    if extra is not None:
        provider.add_span_processor(extra)
    return provider


def tracer() -> trace.Tracer:
    return trace.get_tracer(_TRACER_NAME)


def ids(span: Span) -> tuple[str, str]:
    ctx = span.get_span_context()
    return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")


@contextmanager
def tool_span(
    name: str, session_trace: tuple[str, str] | None, attributes: dict[str, Any]
) -> Iterator[Span]:
    """A span for one tool call, in the work session's trace when there is one."""
    current = trace.get_current_span().get_span_context()
    context = None
    links: list[Link] = []
    if session_trace is not None:
        trace_id, span_id = int(session_trace[0], 16), int(session_trace[1], 16)
        if not (current.is_valid and current.trace_id == trace_id):
            parent = SpanContext(
                trace_id=trace_id,
                span_id=span_id,
                is_remote=True,
                trace_flags=TraceFlags(TraceFlags.SAMPLED),
            )
            context = trace.set_span_in_context(NonRecordingSpan(parent))
            if current.is_valid:
                links.append(Link(current))
    with tracer().start_as_current_span(
        f"alasin.{name}", context=context, links=links, attributes=attributes
    ) as span:
        yield span
