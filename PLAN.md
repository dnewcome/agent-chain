# work-chain — v0 Plan

## Positioning

A **provenance chain for code creation**. Every change to an artifact is the
output of some *process*: a user prompt, an LLM call, a tool call, a
human edit. A work-chain is a signed, hash-linked log of those steps, such
that a third party can verify the artifact was born through an approved
harness — not hand-rolled, not tampered with mid-stream, not produced by a
model or prompt the policy forbids.

**Analogy.** A competitive game's anti-cheat replay file records every
input frame and RNG seed. A verifier re-simulates against the canonical
engine and checks the final state matches. We want the same shape for code
creation: record the inputs (prompts, tool results, seeds), name the
canonical engine (the harness version), and let a verifier replay.

**Relation to `../energy-secops`.** That project audits *finished*
artifacts: "artifact X received T tokens of adversarial analysis against
threat model M, findings F." work-chain is the dual: "artifact X was born
from harness H v2.3, transcript T, signed by provider P." An artifact's
full provenance package is work-chain (birth) + energy-secops (health).
Both use ed25519, content addressing, and a hash chain anchored to a
trusted CA; the data models are siblings.

## Core claim

> "This artifact is the canonical output of harness H at version V, fed
> this sequence of steps S, attested by provider P (for LLM calls) and
> CA K (for the chain itself)."

## The verifiability gap and how we close it

LLM inference is the only non-deterministic step. Two honest ways to close
the gap:

### (A) Attested-step chain (v0 target)
Each LLM call produces a terse signed tuple — `(input_hash, output_hash,
model_id, usage, timestamp)` — from the provider. The chain stitches these
together; everything between LLM calls is a deterministic harness
transition the verifier can replay.

Analogy: an optimistic rollup. LLM calls are "transactions" signed by the
provider. The harness is the state machine. The chain head is the
post-state hash.

**v0 gap**: Anthropic (etc.) does not currently sign per-request receipts.
We stand in with a **trusted-oracle** recorder: the recorder's own CA key
signs each observed (input, output) pair, same trust story as
`energy-secops`'s SOC-2-style backstop (reconcile claimed tokens against
provider billing; log full request/response to append-only storage).

**Migration path**: when providers publish per-call signed receipts, drop
them into `provider_receipt` without changing the chain format.

### (B) Full-replay (v2 target)
A canonical harness re-executes every step from recorded inputs. LLM calls
are replayed against (a) a TEE-hosted model running deterministic sampling
at a pinned weight hash, or (b) a quorum of observers who saw the original
call. Expensive; an optional high-assurance tier.

v0 ships (A). (B) is a backend swap at the provider-receipt boundary, not
a rewrite.

## Data model

### Step
```
Step {
  index: int                    # 0-based position in the chain
  parent_step_id: sha256 | null # previous step's step_id; null for index 0
  kind: "user" | "llm" | "tool" | "harness"
  timestamp: float
  payload: dict                 # kind-specific, hashes only (never raw bytes)
  # Identity + signature (derived):
  step_id: sha256               # hash of canonical_json of the above fields
  backend: str                  # "trusted-oracle" | "tee" | "consensus"
  signer_key_id: str
  signature: hex                # ed25519(step_id bytes)
}
```

`step_id` is a content hash over the step fields; `signature` commits to
that hash. Chain linkage is the `parent_step_id` field, i.e., a hash
chain. A Merkle tree over step_ids (for selective disclosure) is a v1
add-on — unnecessary for verifying the full chain.

### Payloads by kind

- **user**: `{ input_hash }`. Raw prompt bytes go to the blob store.
- **llm**: `{ provider, model, input_hash, output_hash, usage: {input_tokens, output_tokens}, provider_receipt: null | {...} }`.
  `provider_receipt` is null in v0; see trust-model ladder.
- **tool**: `{ tool_name, input_hash, output_hash, deterministic: bool }`.
  For `Read` of a tracked file, `input_hash` covers (path, repo-pin);
  `output_hash` covers the bytes at read time. `deterministic=true` means
  a verifier can rerun this tool against the blob store and expect the
  same `output_hash`. Tool results that depend on wall-clock, RNG,
  network, or mutating side effects are `deterministic=false`.
- **harness**: `{ event, harness_id, harness_version_hash }`. Anchors the
  chain to a specific harness binary. `event` ∈ { `init`, `checkpoint`,
  `terminate` }.

### Chain
```
WorkChain {
  chain_id: sha256              # = last step's step_id (head)
  harness_id: str
  harness_version_hash: sha256
  steps: [Step, ...]
  ca_key_id: str                # key that signed the chain seal
  chain_signature: hex          # ed25519 over (chain_id, harness_*, step count)
}
```

### Blob store (v1)
Content-addressed dir at `~/.work-chain/blobs/`. Raw bytes for every
`input_hash` / `output_hash` in the chain. Lets verifiers reconstruct
inputs and replay deterministic steps without re-fetching. v0: hashes
only, blobs live wherever the recorder left them.

## v0 scaffold

```
work-chain/
  pyproject.toml
  README.md
  PLAN.md
  examples/
    transcript.json                 # canonical sample input
  src/work_chain/
    canonical.py                    # canonical JSON + sha256
    signing.py                      # ed25519 CA keypair mgmt (mirrors energy-secops)
    step.py                         # Step dataclass + hashing
    chain.py                        # WorkChain build/append/verify
    recorder.py                     # transcript → chain (v0 sole recorder)
    cli.py                          # work-chain record | verify | show | ca
```

## Milestones

1. **M1 — transcript → signed chain** (this PR). Record a transcript JSON
   into a chain; verify linkage + signatures. No blob store, no LLM
   integration, no replay.
2. **M2 — blob store**. `~/.work-chain/blobs/`; recorder persists raw
   bytes for every hash; verifier can dump them back out.
3. **M3 — deterministic tool replay**. Given blobs, rerun every
   `deterministic=true` tool step and confirm output hashes.
4. **M4 — live recorder hook**. Wire into Claude Code (or an Anthropic
   SDK wrapper) so chains are produced during actual coding sessions,
   not post-hoc from transcripts.
5. **M5 — provider receipts**. Accept a `provider_receipt` shape and
   verify it against a known provider public key. First real external
   trust anchor.
6. **M6 — transparency log**. Publish chain heads to an append-only log
   (Rekor, Trillian, or self-hosted), so a chain can't be silently
   rewritten.
7. **M7 — artifact linkage with `energy-secops`**. A work-chain's terminal
   artifact becomes an `energy-secops` `Source.kind = "work-chain"`, so
   audit attestations reference the provenance chain explicitly.

## Trust-model ladder

v0 → v2, increasing trust:

| tier | what signs an LLM step             | why you'd want it                |
|------|------------------------------------|----------------------------------|
| 0    | Recorder CA (trusted oracle)       | ship something today             |
| 1    | Provider signature                 | remove recorder from trust base  |
| 2a   | TEE attestation quote              | remove provider from trust base  |
| 2b   | Quorum of independent observers    | decentralize                     |

Data model supports all four via `provider_receipt`. v0 implements tier 0.

## Open questions deferred past v0

- **Partial chains / selective disclosure.** Today every verifier sees
  every step. Switching `step_id` linkage to a Merkle tree enables proving
  "this step is in this chain" without revealing siblings. Add once a
  consumer actually wants it.
- **Sampler determinism.** Full-replay (tier 2a) needs deterministic
  sampling at a pinned weight hash. Open research problem at the model
  layer; we can't force it.
- **Chain-of-chains.** An LLM step whose output is itself a work-chain
  (agent spawns sub-agent). Nest by storing the inner chain's `chain_id`
  as the step's `output_hash`; verifier recurses.
- **Cost model.** Recording doubles storage (blobs + chain). Pricing a
  verifier-as-a-service is future work.
- **Policy language.** "This artifact was produced by an allowed harness
  + prompt + tools" is a predicate over the chain. Define it once a
  second consumer exists.

## Non-goals for v0

- Decentralization.
- LLM replay.
- Smart-contract deployment. The "VM analogy" is about data model, not
  operational chain deployment.
- UI beyond CLI.
- Federation with `energy-secops` beyond shared primitives.
