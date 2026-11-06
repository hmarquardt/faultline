"""Closed synthetic tool environment with explicit, recorded authorization.

Every tool operates on an in-memory `SyntheticEnvironment`. There is no shell, no
filesystem write, no network call, no credential access and no real delivery: the
`send_message` tool queues into a synthetic outbox that is labelled as such in
every receipt and report. A model's claim that it ran a tool is never evidence;
only a `ToolExecutionReceipt` is.
"""

from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as SchemaValidationError

from faultline.domain import (
    ToolDefinition,
    ToolExecutionReceipt,
    ToolPolicyDecision,
    ToolRequest,
    ToolStateChange,
    canonical_digest,
    now,
)

TOOL_POLICY = "faultline.synthetic-tools/1"
SANDBOX_PROVENANCE = "synthetic-sandbox"


class ToolPolicy:
    """Authorize tool calls against a closed, declared allow-list."""

    def __init__(
        self,
        allowed_tools: list[str],
        *,
        allowed_records: dict[str, str] | None = None,
        allowed_recipients: list[str] | None = None,
    ) -> None:
        self.allowed_tools = set(allowed_tools)
        self.allowed_records = dict(allowed_records or {})
        self.allowed_recipients = set(allowed_recipients or ["synthetic-review-queue"])

    def _decision(self, request: ToolRequest, decision: str, reason: str) -> ToolPolicyDecision:
        return ToolPolicyDecision(
            request_id=request.id,
            tool=request.name,
            decision=decision,
            reason=reason,
            decided_at=now(),
        )

    def decide(self, request: ToolRequest, definition: ToolDefinition | None) -> ToolPolicyDecision:
        if definition is None:
            return self._decision(
                request, "denied", "Tool is not registered in the synthetic registry"
            )
        if request.name not in self.allowed_tools:
            return self._decision(
                request, "denied", "Tool is outside the scenario's authorized tool set"
            )
        if request.name == "update_record" and (
            request.arguments.get("record_id") not in self.allowed_records
        ):
            return self._decision(
                request,
                "denied",
                "Record is not in the scenario's writable synthetic records",
            )
        if request.name == "send_message" and (
            request.arguments.get("recipient") not in self.allowed_recipients
        ):
            return self._decision(
                request, "denied", "Recipient is outside the synthetic outbox allow-list"
            )
        return self._decision(
            request,
            "allowed",
            "Tool, argument scope and side-effect class are authorized",
        )


class SyntheticEnvironment:
    """In-memory documents, notes, outbox and toy records."""

    def __init__(
        self,
        documents: dict[str, dict[str, str]] | None = None,
        records: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.documents = dict(documents or {})
        self.records = dict(records or {})
        self.notes: list[dict[str, Any]] = []
        self.outbox: list[dict[str, Any]] = []

    def record_digest(self, record_id: str) -> str | None:
        record = self.records.get(record_id)
        return None if record is None else canonical_digest(record)

    def snapshot(self) -> dict[str, Any]:
        return {
            "records": self.records,
            "notes": len(self.notes),
            "outbox": len(self.outbox),
        }


def _definition(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    side_effect: str,
    authorization: str,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        version="1.0.0",
        description=description,
        input_schema=input_schema,
        side_effect=side_effect,
        authorization=authorization,
        receipt_required=True,
    )


def registry() -> dict[str, ToolDefinition]:
    """The closed registry of synthetic tools."""
    definitions = [
        _definition(
            "search_documents",
            "Search the synthetic document corpus for a keyword.",
            {
                "type": "object",
                "required": ["query"],
                "properties": {"query": {"type": "string", "minLength": 1}},
                "additionalProperties": False,
            },
            "synthetic-read",
            "read-only",
        ),
        _definition(
            "read_document",
            "Read one synthetic document by id.",
            {
                "type": "object",
                "required": ["document_id"],
                "properties": {"document_id": {"type": "string", "minLength": 1}},
                "additionalProperties": False,
            },
            "synthetic-read",
            "read-only",
        ),
        _definition(
            "write_note",
            "Write a note into the synthetic environment only.",
            {
                "type": "object",
                "required": ["title", "body"],
                "properties": {
                    "title": {"type": "string", "minLength": 1},
                    "body": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "synthetic-write",
            "synthetic-write",
        ),
        _definition(
            "send_message",
            "Queue a message in the synthetic outbox; nothing is delivered.",
            {
                "type": "object",
                "required": ["recipient", "body"],
                "properties": {
                    "recipient": {"type": "string", "minLength": 1},
                    "body": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "synthetic-message",
            "synthetic-write",
        ),
        _definition(
            "update_record",
            "Update one field of a toy record in the synthetic environment.",
            {
                "type": "object",
                "required": ["record_id", "field", "value"],
                "properties": {
                    "record_id": {"type": "string", "minLength": 1},
                    "field": {"type": "string", "minLength": 1},
                    "value": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "synthetic-write",
            "synthetic-write",
        ),
    ]
    return {definition.name: definition for definition in definitions}


def tool_specifications(definitions: dict[str, ToolDefinition]) -> list[dict[str, Any]]:
    """OpenAI-compatible tool declarations for providers that support them."""
    return [
        {
            "type": "function",
            "function": {
                "name": definition.name,
                "description": definition.description,
                "parameters": definition.input_schema,
            },
        }
        for definition in definitions.values()
    ]


def _invalid(
    request: ToolRequest, definition: ToolDefinition, message: str
) -> ToolExecutionReceipt:
    return ToolExecutionReceipt(
        request_id=request.id,
        tool=request.name,
        tool_version=definition.version,
        executed=False,
        error=message,
        provenance=SANDBOX_PROVENANCE,
    )


def execute(
    request: ToolRequest,
    definition: ToolDefinition,
    environment: SyntheticEnvironment,
) -> ToolExecutionReceipt:
    """Execute one authorized call inside the synthetic sandbox."""
    started = now()
    validator = Draft202012Validator(definition.input_schema)
    try:
        validator.validate(request.arguments)
    except SchemaValidationError:
        return _invalid(request, definition, "Arguments do not match the tool input schema")
    arguments = request.arguments
    output: dict[str, Any] = {}
    text = ""
    changes: list[ToolStateChange] = []
    if request.name == "search_documents":
        query = str(arguments["query"]).lower()
        matches = [
            {
                "document_id": document_id,
                "title": document["title"],
                "excerpt": document["content"][:160],
            }
            for document_id, document in environment.documents.items()
            if query in document["title"].lower() or query in document["content"].lower()
        ]
        output = {"matches": matches, "synthetic": True}
        text = f"Synthetic search returned {len(matches)} document(s)."
    elif request.name == "read_document":
        document_id = str(arguments["document_id"])
        document = environment.documents.get(document_id)
        if document is None:
            return _invalid(request, definition, "Unknown synthetic document id")
        output = {
            "document_id": document_id,
            "title": document["title"],
            "content": document["content"],
            "source_note": document.get("source_note", "synthetic-corpus"),
            "synthetic": True,
        }
        text = document["content"]
    elif request.name == "write_note":
        environment.notes.append({"title": str(arguments["title"]), "body": str(arguments["body"])})
        changes.append(
            ToolStateChange(
                kind="note-written",
                target=str(arguments["title"]),
                after_sha256=canonical_digest(environment.notes[-1]),
            )
        )
        output = {"note_index": len(environment.notes) - 1, "synthetic": True}
        text = "Synthetic note stored in the sandbox environment."
    elif request.name == "send_message":
        environment.outbox.append(
            {"recipient": str(arguments["recipient"]), "body": str(arguments["body"])}
        )
        changes.append(
            ToolStateChange(
                kind="message-queued",
                target=str(arguments["recipient"]),
                after_sha256=canonical_digest(environment.outbox[-1]),
            )
        )
        output = {"queued": len(environment.outbox), "delivered": False, "synthetic": True}
        text = "Message queued in the synthetic outbox; nothing was delivered."
    elif request.name == "update_record":
        record_id = str(arguments["record_id"])
        record = environment.records.get(record_id)
        if record is None:
            return _invalid(request, definition, "Unknown synthetic record id")
        before = canonical_digest(record)
        record[str(arguments["field"])] = str(arguments["value"])
        changes.append(
            ToolStateChange(
                kind="record-updated",
                target=record_id,
                before_sha256=before,
                after_sha256=canonical_digest(record),
            )
        )
        output = {"record_id": record_id, "record": record, "synthetic": True}
        text = "Synthetic record updated inside the sandbox environment."
    else:  # pragma: no cover - registry and executor are validated together
        return _invalid(request, definition, "Tool has no synthetic implementation")
    return ToolExecutionReceipt(
        request_id=request.id,
        tool=request.name,
        tool_version=definition.version,
        executed=True,
        output=output,
        output_text=text,
        state_changes=changes,
        started_at=started,
        finished_at=now(),
        provenance=SANDBOX_PROVENANCE,
    )
