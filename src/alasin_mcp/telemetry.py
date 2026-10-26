# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry tracing.

An SDK tracer provider is always installed, so trace IDs are real even when
nothing is exported: they still go into commit trailers and audit events.
Spans are exported over OTLP/HTTP only when an endpoint is configured.

Trace shape: ``begin_change`` always starts a new trace and records it on the
work session; a client's ``_meta.traceparent`` (SEP-414) is kept as a span
link, so a client can't choose the Trace-Id stamped into commits. Later tool
spans are parented into the session's trace, so one work session is one
trace; an incoming trace on those calls is linked too.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from opentelemetry import propagate, trace
from opentelemetry.context import Context
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


def incoming_context(meta: Mapping[str, Any] | None) -> SpanContext | None:
    """The client's span context from ``_meta.traceparent`` (SEP-414), if valid."""
    if not meta or not isinstance(meta.get("traceparent"), str):
        return None
    try:
        ctx = propagate.extract({k: v for k, v in meta.items() if isinstance(v, str)})
    except (ValueError, TypeError):
        return None
    span_ctx = trace.get_current_span(ctx).get_span_context()
    return span_ctx if span_ctx.is_valid else None


def _remote(trace_id: int, span_id: int) -> Context:
    parent = SpanContext(
        trace_id=trace_id,
        span_id=span_id,
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    return trace.set_span_in_context(NonRecordingSpan(parent))


@contextmanager
def tool_span(
    name: str,
    session_trace: tuple[str, str] | None,
    attributes: dict[str, Any],
    meta: Mapping[str, Any] | None = None,
    new_root: bool = False,
) -> Iterator[Span]:
    """A span for one tool call.

    Parent, in order: the work session's trace; for ``new_root`` (begin_change)
    no parent at all; else the client's incoming traceparent; else whatever span
    is current. An incoming trace that isn't the parent is kept as a link.
    """
    incoming = incoming_context(meta)
    current = trace.get_current_span().get_span_context()
    upstream = incoming or (current if current.is_valid else None)
    context: Context | None = None
    links: list[Link] = []
    if session_trace is not None:
        trace_id, span_id = int(session_trace[0], 16), int(session_trace[1], 16)
        if upstream is not None and upstream.trace_id == trace_id:
            context = trace.set_span_in_context(NonRecordingSpan(upstream))
        else:
            context = _remote(trace_id, span_id)
            if upstream is not None:
                links.append(Link(upstream))
    elif new_root:
        # A work session's trace is always minted here, so a client can't choose
        # the Trace-Id that goes into commits. Its own trace is kept as a link.
        context = Context()
        if upstream is not None:
            links.append(Link(upstream))
    elif upstream is not None:
        context = trace.set_span_in_context(NonRecordingSpan(upstream))
    # Exceptions are not recorded here: the caller sets a sanitised status, and
    # an exception's text (for example an authorization link) must not leak.
    with tracer().start_as_current_span(
        f"alasin.{name}",
        context=context,
        links=links,
        attributes=attributes,
        record_exception=False,
        set_status_on_exception=False,
    ) as span:
        yield span
