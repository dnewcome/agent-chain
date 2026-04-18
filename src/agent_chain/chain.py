"""AgentChain = harness identity + sealed sequence of signed Steps.

Invariants enforced at build and verify time:
  - steps[0].parent_step_id is None
  - steps[i].parent_step_id == steps[i-1].step_id for i > 0
  - steps[i].index == i
  - Every step_id matches the content hash of its fields
  - Every signature verifies against signer_key_id
  - chain_id == steps[-1].step_id
  - chain_signature verifies over (chain_id, harness_id, harness_version_hash, len(steps))
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .signing import Signer
from .step import Step, validate_payload


@dataclass
class AgentChain:
    harness_id: str
    harness_version_hash: str
    steps: list[Step] = field(default_factory=list)
    chain_id: str = ""
    ca_key_id: str = ""
    chain_signature: str = ""

    def head_id(self) -> str | None:
        return self.steps[-1].step_id if self.steps else None

    def seal_payload(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "harness_id": self.harness_id,
            "harness_version_hash": self.harness_version_hash,
            "step_count": len(self.steps),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "harness_id": self.harness_id,
            "harness_version_hash": self.harness_version_hash,
            "chain_id": self.chain_id,
            "ca_key_id": self.ca_key_id,
            "chain_signature": self.chain_signature,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentChain":
        return cls(
            harness_id=d["harness_id"],
            harness_version_hash=d["harness_version_hash"],
            steps=[Step.from_dict(s) for s in d["steps"]],
            chain_id=d.get("chain_id", ""),
            ca_key_id=d.get("ca_key_id", ""),
            chain_signature=d.get("chain_signature", ""),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> "AgentChain":
        return cls.from_dict(json.loads(Path(path).read_text()))


def _append(chain: AgentChain, kind: str, payload: dict[str, Any], signer: Signer, *, timestamp: float | None = None) -> Step:
    validate_payload(kind, payload)
    step = Step(
        index=len(chain.steps),
        parent_step_id=chain.head_id(),
        kind=kind,
        timestamp=timestamp if timestamp is not None else time.time(),
        payload=payload,
    )
    step.step_id = step.compute_id()
    step.backend = signer.backend
    step.signer_key_id = signer.key_id
    step.signature = signer.sign(step.step_id.encode("utf-8"))
    chain.steps.append(step)
    return step


def seal(chain: AgentChain, signer: Signer) -> None:
    if not chain.steps:
        raise ValueError("cannot seal empty chain")
    chain.chain_id = chain.steps[-1].step_id
    chain.ca_key_id = signer.key_id
    chain.chain_signature = signer.sign(canonical_json(chain.seal_payload()))


def build(
    *,
    harness_id: str,
    harness_version_hash: str,
    events: list[dict[str, Any]],
    signer: Signer,
) -> AgentChain:
    """Build a sealed chain from a transcript of events.

    Each event is `{kind: str, payload: dict, timestamp?: float}`.
    """
    chain = AgentChain(harness_id=harness_id, harness_version_hash=harness_version_hash)
    for ev in events:
        _append(chain, ev["kind"], ev["payload"], signer, timestamp=ev.get("timestamp"))
    seal(chain, signer)
    return chain


@dataclass
class VerifyResult:
    ok: bool
    errors: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> None:
        self.ok = False
        self.errors.append(msg)


def verify(chain: AgentChain, signer: Signer) -> VerifyResult:
    result = VerifyResult(ok=True)
    prev_id: str | None = None
    for i, step in enumerate(chain.steps):
        if step.index != i:
            result.fail(f"step {i}: index mismatch ({step.index})")
        if step.parent_step_id != prev_id:
            result.fail(f"step {i}: parent_step_id mismatch (got {step.parent_step_id!r}, want {prev_id!r})")
        recomputed = step.compute_id()
        if step.step_id != recomputed:
            result.fail(f"step {i}: step_id hash mismatch")
        if not signer.verify(step.step_id.encode("utf-8"), step.signature, step.signer_key_id):
            result.fail(f"step {i}: signature invalid")
        prev_id = step.step_id

    if chain.steps and chain.chain_id != chain.steps[-1].step_id:
        result.fail("chain_id does not match head step_id")
    if not signer.verify(canonical_json(chain.seal_payload()), chain.chain_signature, chain.ca_key_id):
        result.fail("chain seal signature invalid")

    return result
