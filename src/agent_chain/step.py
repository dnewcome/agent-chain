"""A Step is one node in the agent-chain.

Identity: `step_id = sha256(canonical_json(content))` where `content` is
(index, parent_step_id, kind, timestamp, payload). Signature commits to
that hash. Chain linkage is `parent_step_id`.

Payloads are hashes only. Raw bytes live in a blob store (v1). For v0 we
record the hashes and leave persistence of bytes to the caller.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_json, content_hash

VALID_KINDS = {"user", "llm", "tool", "harness"}


@dataclass
class Step:
    index: int
    parent_step_id: str | None
    kind: str
    timestamp: float
    payload: dict[str, Any]
    # Derived:
    step_id: str = ""
    backend: str = ""
    signer_key_id: str = ""
    signature: str = ""

    def content(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "parent_step_id": self.parent_step_id,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }

    def compute_id(self) -> str:
        return content_hash(canonical_json(self.content()))

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.content(),
            "step_id": self.step_id,
            "backend": self.backend,
            "signer_key_id": self.signer_key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Step":
        return cls(
            index=d["index"],
            parent_step_id=d["parent_step_id"],
            kind=d["kind"],
            timestamp=d["timestamp"],
            payload=d["payload"],
            step_id=d.get("step_id", ""),
            backend=d.get("backend", ""),
            signer_key_id=d.get("signer_key_id", ""),
            signature=d.get("signature", ""),
        )


def validate_payload(kind: str, payload: dict[str, Any]) -> None:
    if kind not in VALID_KINDS:
        raise ValueError(f"invalid step kind: {kind}")
    required = {
        "user": {"input_hash"},
        "llm": {"provider", "model", "input_hash", "output_hash", "usage"},
        "tool": {"tool_name", "input_hash", "output_hash", "deterministic"},
        "harness": {"event", "harness_id", "harness_version_hash"},
    }[kind]
    missing = required - payload.keys()
    if missing:
        raise ValueError(f"{kind} step missing payload keys: {sorted(missing)}")
