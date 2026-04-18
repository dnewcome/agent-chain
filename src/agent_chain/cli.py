"""agent-chain CLI: record | verify | show | ca."""
from __future__ import annotations

import json
from pathlib import Path

import click

from . import chain as chain_mod
from .signing import DEFAULT_KEY_PATH, Signer


@click.group()
def main() -> None:
    """Cryptographic provenance chain for AI-authored code."""


@main.command()
@click.argument("transcript", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.option("--key", type=click.Path(dir_okay=False, path_type=Path), default=DEFAULT_KEY_PATH, show_default=True)
def record(transcript: Path, out: Path, key: Path) -> None:
    """Record a transcript JSON into a signed agent-chain.

    Transcript shape:
        { "harness_id": str,
          "harness_version_hash": str,
          "events": [ {"kind": str, "payload": {...}, "timestamp": float?}, ... ] }
    """
    t = json.loads(transcript.read_text())
    signer = Signer(key)
    wc = chain_mod.build(
        harness_id=t["harness_id"],
        harness_version_hash=t["harness_version_hash"],
        events=t["events"],
        signer=signer,
    )
    wc.save(out)
    click.echo(f"wrote {out}  ({len(wc.steps)} steps, chain_id={wc.chain_id})")


@main.command()
@click.argument("chain_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--key", type=click.Path(dir_okay=False, path_type=Path), default=DEFAULT_KEY_PATH, show_default=True)
def verify(chain_file: Path, key: Path) -> None:
    """Verify an agent-chain's linkage, step signatures, and seal."""
    wc = chain_mod.AgentChain.load(chain_file)
    signer = Signer(key)
    result = chain_mod.verify(wc, signer)
    if result.ok:
        click.echo(f"OK  {chain_file}  ({len(wc.steps)} steps)")
    else:
        click.echo(f"FAIL {chain_file}", err=True)
        for e in result.errors:
            click.echo(f"  - {e}", err=True)
        raise SystemExit(1)


@main.command()
@click.argument("chain_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def show(chain_file: Path) -> None:
    """Pretty-print an agent-chain."""
    wc = chain_mod.AgentChain.load(chain_file)
    click.echo(f"harness         : {wc.harness_id} @ {wc.harness_version_hash}")
    click.echo(f"chain_id (head) : {wc.chain_id}")
    click.echo(f"sealed by       : {wc.ca_key_id}")
    click.echo(f"steps           : {len(wc.steps)}")
    for s in wc.steps:
        summary = _summarize_payload(s.kind, s.payload)
        click.echo(f"  [{s.index:>3}] {s.kind:<7} {s.step_id[:23]}…  {summary}")


def _summarize_payload(kind: str, p: dict) -> str:
    if kind == "user":
        return f"input={p['input_hash'][:19]}…"
    if kind == "llm":
        u = p.get("usage", {})
        return f"{p['provider']}/{p['model']}  in={p['input_hash'][:19]}…  out={p['output_hash'][:19]}…  tokens={u.get('input_tokens')}→{u.get('output_tokens')}"
    if kind == "tool":
        det = "det" if p.get("deterministic") else "nondet"
        return f"{p['tool_name']} [{det}]  in={p['input_hash'][:19]}…  out={p['output_hash'][:19]}…"
    if kind == "harness":
        return f"{p['event']}  {p['harness_id']} @ {p['harness_version_hash'][:19]}…"
    return json.dumps(p, sort_keys=True)


@main.group()
def ca() -> None:
    """CA key management."""


@ca.command("show")
@click.option("--key", type=click.Path(dir_okay=False, path_type=Path), default=DEFAULT_KEY_PATH, show_default=True)
def ca_show(key: Path) -> None:
    signer = Signer(key)
    click.echo(f"key_id   : {signer.key_id}")
    click.echo(f"key_path : {key}")
    click.echo(signer.public_key_pem().decode())


if __name__ == "__main__":
    main()
