# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Iterator

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from alasin_mcp import telemetry

EXPORTER = InMemorySpanExporter()
telemetry.configure("alasin-mcp-tests", extra=SimpleSpanProcessor(EXPORTER))


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    EXPORTER.clear()
    yield EXPORTER


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
