# OmegaClaw

PRIMUS's native **OmegaClaw** — the Hyperon-whitepaper §6 operational-control / agent / governance layer,
built on the unified MORK substrate (Core · MORK · WorldModel · FactorVSA · HMH · FabricPC) rather than
ported from asi-alliance/OmegaClaw-Core's PeTTa + Prolog + Python + chromadb runtime. See
[`ADR-061`](../docs/architecture/ADR-061_agent_shell_governed_driver_over_worldmodel.md).

The design in one line: **PRIMUS's own cognition decides, a capability gate is the only path to the world,
and every decision lands in a tamper-resistant evidence ledger.**

```
 perceive(raw) ─▶ WorldModel.mid_step!  ─▶ PLN action id ─▶ governed() ─▶ capability ─▶ result
                  (PLN decides + MetaMo)      │                 │            (exact argv)     │
                                              │                 └─▶ hash-chained evidence ledger
                                              └─────────── reinforcement / Sdyn learning ◀────┘
```

## Run it

```bash
julia --project=OmegaClaw OmegaClaw/demo/agent_demo.jl
```

A narrated end-to-end run on the **real 14-Space WorldModel**: PLN picks an action and the gate allows a
permitted capability / denies an unlisted one; the agent **learns** which action works (reinforcement flips
its preference); the keyed ledger **catches a live on-disk tamper**; and the FabricPC/Sdyn organ learns a
forward model. Nothing is mocked.

## The pieces

| Layer | What | Where |
|-------|------|-------|
| **Cognition** | WorldModel PLN action-selection + MetaMo motive — *PRIMUS decides, not the LLM* | `WorldModel` |
| **Gate** | typed hash-pinned `Proposal` → 5-way `Decision` from a signed-manifest `Policy` → TOCTOU re-check → commit-before-exec | `Gate.jl`, `GroundedOps.jl` |
| **Capabilities** | exact-argv `Cmd`, **default-deny** — there is no "run anything" primitive; dangerous ops simply aren't capabilities | `GroundedOps.jl` |
| **Ledger** | append-only, **keyed HMAC chain** + authenticated head anchor, persisted + reload-verified | `Ledger.jl` |
| **Driver** | the governed agent loop over WorldModel; reinforcement teaches action-selection from outcomes | `Driver.jl` |
| **Channels** | native CLI / buffer IO (`run_agent!`) | `Channels.jl` |
| **Sdyn organ** | trains the FabricPC forward model; retrain cadence is a **MeTTa rule**, not a Julia constant | `SdynTrain.jl` |

Outbound ops are **dual-registered** (`MORK.register_grounded!` for the compiled MM2/ZAM lane + the
interpreter's `TOKEN_REGISTRY` fallback), so `!(echo "…")` runs identically whether Core compiles or
interprets it, and always behind the gate.

## Security posture (B7/B10)

Tamper-**resistant**, adversarially verified over three red-team rounds:

- **Re-forge** — chain links are `HMAC-SHA256(trust_key, payload+prev)` when a key is in force; a full
  re-forge needs the key. The `.head` anchor (`HMAC(key, "count:tip")`) authenticates length + tip and is the
  keyed-mode marker.
- **Reload + verify (B7)** — `load_ledger` reparses and re-verifies on startup; `__init__` **fails closed**
  (locks the gate to Deny-all) on any verification failure, and catches a deleted-ledger-with-surviving-anchor.
- **Downgrade paths fail closed** — a `:locked` (configured-but-unresolvable) key never drops to sha256; a
  keyless verify of a keyed ledger is rejected; truncate-to-empty is rejected.
- **Crash tolerance** — a `.head` lagging by exactly one over a chain-valid tail (a crash between the entry
  fsync and the head rewrite) is tolerated; anything else is rejected.

**Honest limitation (by design, not a bug):** rollback/replay of a captured earlier `(ledger + .head)` and
full deletion of *both* files are **not** defendable with self-contained on-disk state — they need a
genuinely *external* monotonic witness the agent cannot rewrite (an operator-written read-only high-water, a
TPM/sealed counter, or a remote transparency witness). A self-written anchor was prototyped and **removed**
(the agent wrote it, so it wasn't actually external); the extension point is an operator-run `seal_ledger!`.

**Trust key** (enables the keyed mode) is resolved from *outside* the agent's revision loop —
`OMEGACLAW_TRUST_KEYFILE` / `OMEGACLAW_TRUST_KEY` (≥32 bytes). Without it, the ledger runs in an
unauthenticated shadow (dev) mode.

## Test

```bash
julia --project=OmegaClaw -e 'using Pkg; Pkg.test()'
```
