"""Synthetic tools: closed registry, policy-gated execution and receipts."""

import pytest
from pydantic import ValidationError

from faultline.domain import ToolDefinition, ToolRequest
from faultline.tooling import (
    SyntheticEnvironment,
    ToolPolicy,
    execute,
    registry,
    tool_specifications,
)


def environment():
    return SyntheticEnvironment(
        {
            "doc-handbook": {
                "title": "Handbook",
                "content": "Refunds within 30 days.",
                "source_note": "synthetic-corpus",
            }
        },
        {"rec-1": {"status": "open"}, "rec-2": {"status": "closed"}},
    )


def request(name, **arguments):
    return ToolRequest(name=name, arguments=arguments)


def test_registry_is_closed_and_declares_effects():
    tools = registry()
    assert sorted(tools) == [
        "read_document",
        "search_documents",
        "send_message",
        "update_record",
        "write_note",
    ]
    assert all(tool.receipt_required for tool in tools.values())
    assert tools["search_documents"].side_effect == "synthetic-read"
    assert tools["update_record"].authorization == "synthetic-write"
    assert tools["send_message"].side_effect == "synthetic-message"
    assert "delivered" in tools["send_message"].description


def test_tool_specifications_are_openai_compatible():
    specs = tool_specifications(registry())
    assert {spec["function"]["name"] for spec in specs} == set(registry())
    assert all(spec["type"] == "function" for spec in specs)
    assert all("parameters" in spec["function"] for spec in specs)


def test_invalid_tool_schema_is_rejected():
    with pytest.raises(ValidationError):
        ToolDefinition(
            name="broken",
            version="1.0.0",
            description="Broken schema",
            input_schema={"type": "not-a-type"},
            side_effect="none",
            authorization="read-only",
        )


def test_allowed_tool_executes_and_returns_a_verified_receipt():
    env = environment()
    policy = ToolPolicy(["read_document"])
    call = request("read_document", document_id="doc-handbook")
    decision = policy.decide(call, registry()["read_document"])
    assert decision.decision == "allowed"
    receipt = execute(call, registry()["read_document"], env)
    assert receipt.executed and receipt.request_id == call.id
    assert receipt.provenance == "synthetic-sandbox"
    assert "Refunds within 30 days" in receipt.output_text
    assert receipt.state_changes == []


def test_policy_denies_tools_outside_the_authorized_set():
    policy = ToolPolicy(["search_documents", "read_document"])
    decision = policy.decide(
        request("update_record", record_id="rec-1"), registry()["update_record"]
    )
    assert decision.decision == "denied"
    assert "authorized tool set" in decision.reason


def test_policy_denies_unregistered_tools_and_out_of_scope_arguments():
    policy = ToolPolicy(["update_record", "send_message"], allowed_records={"rec-1": "open"})
    assert policy.decide(request("delete_everything"), None).decision == "denied"
    out_of_scope = policy.decide(
        request("update_record", record_id="rec-2", field="status", value="x"),
        registry()["update_record"],
    )
    assert out_of_scope.decision == "denied"
    assert "writable synthetic records" in out_of_scope.reason
    recipient = policy.decide(
        request("send_message", recipient="real@example.com", body="hi"),
        registry()["send_message"],
    )
    assert recipient.decision == "denied"
    assert "outbox allow-list" in recipient.reason


def test_denied_call_produces_no_state_change():
    env = environment()
    policy = ToolPolicy(["search_documents"], allowed_records={"rec-1": "open"})
    call = request("update_record", record_id="rec-1", field="status", value="approved")
    decision = policy.decide(call, registry()["update_record"])
    assert decision.decision == "denied"
    # The harness never executes a denied request.
    assert env.records["rec-1"] == {"status": "open"}
    assert env.record_digest("rec-1") == env.record_digest("rec-1")


def test_record_update_records_before_and_after_digests():
    env = environment()
    before = env.record_digest("rec-1")
    receipt = execute(
        request("update_record", record_id="rec-1", field="status", value="approved"),
        registry()["update_record"],
        env,
    )
    assert receipt.executed
    (change,) = receipt.state_changes
    assert change.kind == "record-updated" and change.target == "rec-1"
    assert change.before_sha256 == before
    assert change.after_sha256 == env.record_digest("rec-1")
    assert change.before_sha256 != change.after_sha256
    assert env.records["rec-1"] == {"status": "approved"}
    assert env.records["rec-2"] == {"status": "closed"}


def test_message_is_queued_not_delivered():
    env = environment()
    receipt = execute(
        request("send_message", recipient="synthetic-review-queue", body="audit"),
        registry()["send_message"],
        env,
    )
    assert receipt.executed
    assert receipt.output["delivered"] is False
    assert receipt.state_changes[0].kind == "message-queued"
    assert env.outbox == [{"recipient": "synthetic-review-queue", "body": "audit"}]


def test_arguments_are_validated_against_the_declared_schema():
    env = environment()
    receipt = execute(request("read_document"), registry()["read_document"], env)
    assert not receipt.executed
    assert receipt.error == "Arguments do not match the tool input schema"
    assert receipt.state_changes == []


def test_unknown_document_and_record_are_errors_not_effects():
    env = environment()
    assert not execute(
        request("read_document", document_id="missing"), registry()["read_document"], env
    ).executed
    assert not execute(
        request("update_record", record_id="missing", field="f", value="v"),
        registry()["update_record"],
        env,
    ).executed
    assert env.records == {"rec-1": {"status": "open"}, "rec-2": {"status": "closed"}}
