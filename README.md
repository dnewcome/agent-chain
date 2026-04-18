# agent-chain

Cryptographic provenance for **how code was created**, not what it looks like
after. An `agent-chain` is a signed, replay-verifiable log of the steps an AI
harness took to produce an artifact — prompts in, model calls, tool calls,
tool results, user edits — each step hash-linked to its predecessor.

> Anti-cheat replay files prove a game run came from an approved engine. An
> agent-chain proves a code change came from an approved agent loop.

Complement to [../energy-secops](../energy-secops) — that project issues
signed receipts that a **finished artifact** was audited. agent-chain issues
signed receipts that an artifact was **born through an attested process**.
Same crypto primitives (ed25519, content-addressed everything, hash chain);
opposite side of the lifecycle.

## Status

v0 prototype. Records a transcript JSON into a signed hash chain;
verifies linkage + signatures. No provider-signed LLM receipts yet — the
recorder's own CA key stands in (trusted-oracle backend, identical trust
model to `energy-secops`).

## Install

```
pip install -e .
```

First run auto-generates `~/.agent-chain/ca.key` (+ `.pub`).

## Quick start

```
agent-chain record examples/transcript.json --out /tmp/chain.json
agent-chain verify /tmp/chain.json
agent-chain show   /tmp/chain.json
```

## Step kinds (v0)

| kind       | payload                                                              |
|------------|----------------------------------------------------------------------|
| `user`     | `input_hash`                                                         |
| `llm`      | `provider, model, input_hash, output_hash, usage, provider_receipt`  |
| `tool`     | `tool_name, input_hash, output_hash, deterministic`                  |
| `harness`  | `event, harness_id, harness_version_hash`                            |

Each step stores only hashes; raw bytes go to a content-addressed blob
store (v1 — `~/.agent-chain/blobs/`). A verifier armed with the blobs and a
deterministic harness replay can re-derive every deterministic step.

## Trust model

`provider_receipt` is the load-bearing gap. v0 leaves it `null` and the
recorder's CA key signs every step, so the claim is "the recorder observed
this (input, output) pair from the stated model." Paths to tighten:

- **Provider-signed receipts** — Anthropic (etc.) signs a terse
  `(request_hash, response_hash, model, usage, timestamp)` tuple. Drop in
  as `provider_receipt`; no chain-format changes.
- **TEE-wrapped call** — HTTPS call is made from inside an enclave; remote
  attestation quote goes in `provider_receipt`.
- **Consensus observers** — N independent recorders sign the same pair;
  verifier requires quorum.

See `PLAN.md` for the full trust-model ladder and milestones.

## Verifier modes

- **Linkage-only** (v0): hash chain intact, signatures valid.
- **Replay-deterministic** (v1): re-execute every `tool` step marked
  `deterministic=true`, confirm output hash matches.
- **Full-replay** (v2): re-run LLM steps against a canonical harness and a
  provider-receipt signature; confirm transcript bit-identical modulo
  sampler nondeterminism. Expensive; optional tier.

## Non-goals (v0)

- Decentralization / federated observers.
- Replay of LLM steps.
- Blob store beyond local filesystem.
- Real-time recording hook into Claude Code. (v1 — see PLAN.)
