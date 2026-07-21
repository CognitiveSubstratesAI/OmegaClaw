"""
    OmegaClaw

PRIMUS's native **OmegaClaw** — the whitepaper §6 operational control fabric (the agent / act-in-the-
world / governance layer), built on the unified MORK substrate rather than ported from
asi-alliance/OmegaClaw-Core's PeTTa+Prolog+Python+chromadb runtime (see `docs/architecture/ADR-061`).

This first stone is the **governed outbound-action seam** (WP §7.7): outbound grounded ops
(`shell`, `read-file`, …) that execute ONLY behind the governance gate — a typed, hash-pinned
`Proposal` → a 5-way `Decision` from a `Policy` rooted in an external manifest → an append-only,
hash-chained evidence `Ledger`. The agent's cognition (perceive → decide → act) is WorldModel's
(PLN/MetaMo); the LLM/FabricPC is the language organ; nothing reaches the world except through this gate.

Ops are DUAL-REGISTERED — `MORK.register_grounded!` for the primary compiled MM2/ZAM lane and a
`Grounded(Operation)` in the interpreter's `TOKEN_REGISTRY` for the fallback — so `!(shell "…")` runs
identically whether Core compiles or interprets it.
"""
module OmegaClaw

using MeTTaCore
using Dates
using SHA
import MORK
import TOML
import JSON3

include("Gate.jl")
include("Ledger.jl")
include("GroundedOps.jl")
include("Driver.jl")
include("SdynTrain.jl")
include("Channels.jl")

# The live policy + ledger the registered ops run under. Set at load (__init__), from the external
# manifest so the authority is not the agent's own code.
const DEFAULT_POLICY = Ref{Policy}()
const DEFAULT_LEDGER = Ref{Ledger}()

function __init__()
    manifest = get(ENV, "OMEGACLAW_POLICY", joinpath(@__DIR__, "..", "config", "policy.toml"))
    DEFAULT_POLICY[] = load_policy(manifest)          # signed + fail-closed when a trust key is set
    lpath = get(ENV, "OMEGACLAW_LEDGER", nothing)
    if lpath !== nothing                              # B7: reload prior evidence AND verify it on startup.
        # NOTE: run load_ledger even when the file is ABSENT — a DELETED ledger whose `.head` survives must be
        # caught (verify_head: 0 entries + present anchor ⇒ fail), not silently started fresh (a `rm` bypass).
        # A failed (or errored) integrity check FAILS CLOSED: lock the gate to Deny-all until an operator
        # re-anchors — never bring the world-facing ops up over tampered/truncated evidence.
        r = try
            load_ledger(lpath)
        catch err
            @warn "OmegaClaw ledger load errored — LOCKING gate (Deny-all)" path = lpath err = err
            nothing
        end
        if r === nothing
            DEFAULT_POLICY[] = _locked_policy("ledger-load-error:" * lpath)
            DEFAULT_LEDGER[] = Ledger(; path = lpath)
        elseif !(r.chain_ok && r.head_ok)
            @warn("OmegaClaw ledger failed integrity verification — LOCKING gate (Deny-all) until re-anchored",
                path = lpath, chain_ok = r.chain_ok, head_ok = r.head_ok, authenticated = r.authenticated)
            DEFAULT_POLICY[] = _locked_policy("ledger-unverified:" * lpath)
            DEFAULT_LEDGER[] = r.ledger
        else
            DEFAULT_LEDGER[] = r.ledger
        end
    else
        DEFAULT_LEDGER[] = Ledger(; path = lpath)
    end
    register_ops!()                                   # ops read the LIVE DEFAULT_POLICY[]/DEFAULT_LEDGER[]
    return nothing
end

export Proposal, Policy, Decision, Allow, Deny, RequireProbe, RequireReview, Defer,
    decide, default_policy, load_policy, verify_manifest, sign_manifest!,
    Ledger, LedgerEntry, record!, verify_chain, verify_head, verify_ledger, load_ledger,
    governed, register_ops!, register_capability!, register_probe!, PROBE_REGISTRY,
    DeferQueue, DEFER_QUEUE, defer!, drain_deferred!,
    DEFAULT_POLICY, DEFAULT_LEDGER,
    Driver, seed!, step!, reinforce!,
    gather_transitions, train_sdyn!,
    OmegaChannel, BufferChannel, CLIChannel, poll, emit, run_agent!

end # module OmegaClaw
