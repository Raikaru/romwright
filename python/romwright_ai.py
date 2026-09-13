"""Read-mostly tool adapter for AI clients.

The adapter exposes OpenAI-compatible tool metadata but delegates every
invocation to the versioned Romwright API. It never hands an AI client a direct
SQLite or filesystem capability.
"""
from __future__ import annotations

from typing import Any, Mapping

from romwright_sdk import Client, ApiError

_READ_TOOLS = {
    "romwright_search": ("search", {"program": "string", "term": "string", "limit": "integer"}),
    "romwright_functions": ("functions", {"program": "string"}),
    "romwright_symbols": ("symbols", {"program": "string"}),
    "romwright_xrefs": ("xrefs", {"program": "string", "address": "object", "incoming": "boolean"}),
    "romwright_strings": ("strings", {"program": "string"}),
    "romwright_decompile": (
        "decompile_doc",
        {"binary": "string", "program": "string", "address": "object", "base": "integer"},
    ),
    "romwright_types": ("type_defs", {"program": "string"}),
    "romwright_type_graph": ("type_graph", {"program": "string"}),
    "romwright_debug_backtrace": (
        "debug_backtrace",
        {"program": "string", "backend": "string", "timeout_ms": "integer"},
    ),
    "romwright_debug_registers": (
        "debug_registers",
        {"program": "string", "backend": "string", "timeout_ms": "integer"},
    ),
    "romwright_debug_memory": (
        "debug_memory",
        {
            "program": "string",
            "backend": "string",
            "address": "integer",
            "count": "integer",
            "timeout_ms": "integer",
        },
    ),
}
_WRITE_TOOLS = {
    "romwright_rename": ("rename", {"program": "string", "address": "object", "name": "string"}),
    "romwright_comment": (
        "comment",
        {"program": "string", "address": "object", "text": "string", "kind": "string"},
    ),
}


class AiToolError(RuntimeError):
    pass


class CoreToolAdapter:
    """Maps model tool calls to Core requests with an explicit write gate."""

    def __init__(self, client: Client, allow_mutations: bool = False):
        self._client = client
        self._allow_mutations = allow_mutations

    def tool_definitions(self) -> list[dict[str, Any]]:
        definitions = []
        for name, (_, fields) in {**_READ_TOOLS, **(_WRITE_TOOLS if self._allow_mutations else {})}.items():
            properties = {key: {"type": value} for key, value in fields.items()}
            definitions.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": f"Romwright Core API operation: {name}",
                        "parameters": {"type": "object", "properties": properties},
                    },
                }
            )
        return definitions

    def invoke(self, name: str, arguments: Mapping[str, Any]) -> Any:
        operation = _READ_TOOLS.get(name)
        if operation is None:
            operation = _WRITE_TOOLS.get(name)
            if operation is None:
                raise AiToolError(f"unknown AI tool {name!r}")
            if not self._allow_mutations:
                raise AiToolError(f"AI mutation denied for {name!r}")
        method, _ = operation
        try:
            return self._client.request(method, **dict(arguments))
        except ApiError as error:
            raise AiToolError(str(error)) from error
