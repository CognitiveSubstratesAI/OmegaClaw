# GroundedOps.jl — outbound grounded operations, reachable ONLY through the gate.
#
# `governed` is the single choke point: snapshot evidence → build a bound, hash-pinned Proposal → 5-way
# decide → for Allow, COMMIT the decision before running (§7.6), TOCTOU-re-check immediately pre-exec
# (expiry, policy-version, live signature, evidence unchanged, decision still Allow), run, append a receipt.
# Any drift/expiry/exception is NEVER permission — it fails closed (§11.5). Ops read the LIVE policy/ledger
# (module Refs), so a policy reload takes effect immediately; names are registered once (no silent
# re-registration to a wider policy).

using SHA: sha256
import MORK
const _SM = MeTTaCore.Interpreter

# ── RequireProbe: a read-only precheck that is itself a typed proposal (§7.7) ──
const PROBE_REGISTRY = Dict{String,Function}()   # action => (args)->(ok::Bool, evidence::String)
register_probe!(action::AbstractString, f::Function) = (PROBE_REGISTRY[String(action)] = f; nothing)

# ── Defer: hold while prerequisites incomplete (§7.7) ──
mutable struct DeferQueue
    items::Vector{Tuple{Policy,Ledger,String,Vector{String},Function,Function}}
    lock::ReentrantLock
end
DeferQueue() = DeferQueue(Tuple{Policy,Ledger,String,Vector{String},Function,Function}[], ReentrantLock())
const DEFER_QUEUE = DeferQueue()

defer!(q::DeferQueue, policy::Policy, ledger::Ledger, action::AbstractString, args::Vector{String},
    run::Function; evidence::Function = () -> "") =
    (lock(q.lock) do; push!(q.items, (policy, ledger, String(action), args, run, evidence)); end; nothing)

"Re-dispatch every deferred proposal through the gate (fresh proposal/expiry/snapshot); keep those still deferring."
function drain_deferred!(q::DeferQueue = DEFER_QUEUE)
    lock(q.lock) do
        still = eltype(q.items)[]
        done = Tuple{String,String}[]
        for (policy, ledger, action, args, run, evidence) in q.items
            out = governed(policy, ledger, action, args, run; evidence = evidence)
            startswith(out, "GATE[Defer") ? push!(still, (policy, ledger, action, args, run, evidence)) :
                push!(done, (action, out))
        end
        q.items = still
        return done
    end
end

_snap(evidence::Function)::String = bytes2hex(sha256(codeunits(String(evidence()))))

# TOCTOU pre-exec re-check: ALL must hold or it is not permission (fail closed).
function _recheck(policy::Policy, p::Proposal, evidence::Function)::Bool
    try
        (p.expiry == 0.0 || unixnow() <= p.expiry) || return false                 # not expired
        policy.version == p.policy_version || return false                          # policy unchanged
        (!policy.enforce_signature ||
            verify_manifest(policy.manifest_path, _trust_key())) || return false    # signature still valid
        _snap(evidence) == p.evidence_snapshot || return false                      # world unchanged
        decide(policy, p) === Allow || return false                                 # decision still Allow
        return true
    catch
        return false
    end
end

"""
    governed(policy, ledger, action, args, run; evidence, ttl_seconds, capabilities, predicted_effect, rollback) -> String

The single path to the world. Returns the op result on Allow, else a `GATE[...]` marker (op never ran).
"""
function governed(policy::Policy, ledger::Ledger, action::AbstractString, args,
    run::Function; evidence::Function = () -> "", ttl_seconds::Real = _MAX_TTL,
    capabilities = String[], predicted_effect::AbstractString = "", rollback::AbstractString = "")::String
    a = collect(String, args)
    expiry = ttl_seconds == 0 ? 0.0 : unixnow() + Float64(ttl_seconds)
    p = Proposal(action, a; policy_version = policy.version, evidence_snapshot = _snap(evidence),
        expiry = expiry, capabilities = collect(String, capabilities),
        predicted_effect = predicted_effect, rollback = rollback)
    d = decide(policy, p)

    if d === Deny
        record!(ledger, p, Deny); return "GATE[Deny]"
    elseif d === RequireReview
        record!(ledger, p, RequireReview; receipt = "review-pending"); return "GATE[RequireReview]"
    elseif d === Defer
        record!(ledger, p, Defer); defer!(DEFER_QUEUE, policy, ledger, action, a, run; evidence = evidence)
        return "GATE[Defer]"
    elseif d === RequireProbe
        f = get(PROBE_REGISTRY, String(action), nothing)
        f === nothing && (record!(ledger, p, RequireProbe; receipt = "no-probe-registered"); return "GATE[RequireProbe]")
        ok, ev = try
            f(a)
        catch e
            (false, "probe-error:" * first(split(sprint(showerror, e), '\n')))
        end
        record!(ledger, Proposal("probe:" * String(action), a; policy_version = policy.version),
            ok ? Allow : Deny; receipt = "probe:" * String(ev))
        ok || (record!(ledger, p, RequireProbe; receipt = "probe-failed"); return "GATE[RequireProbe]")
        # probe passed → fall through to the Allow execution path
    end

    # Allow (or probe-passed): commit-before-exec → TOCTOU re-check → run → receipt
    record!(ledger, p, Allow)
    _recheck(policy, p, evidence) ||
        (record!(ledger, p, Deny; receipt = "toctou-recheck-failed"); return "GATE[Deny]")
    out = try
        run(a)
    catch e
        "ERROR: " * first(split(sprint(showerror, e), '\n'))
    end
    record!(ledger, p, Allow; receipt = "executed")
    return String(out)
end

# ── the outbound op implementations (bare effect; only ever invoked via `governed`) ──
function _shell(args::Vector{String})::String
    isempty(args) && return "ERROR: shell needs a command"
    try
        return String(strip(read(`sh -c $(args[1])`, String)))
    catch e
        return "ERROR: " * first(split(sprint(showerror, e), '\n'))
    end
end

_readfile(args::Vector{String})::String =
    isempty(args) ? "ERROR: read-file needs a path" :
    (isfile(args[1]) ? read(args[1], String) : "ERROR: no such file: $(args[1])")

const _OUTBOUND = Dict{String,Function}("shell" => _shell, "read-file" => _readfile)

# reachability lock: a name is registered ONCE — never silently re-registered to a wider/ungoverned handler
const _REGISTERED = Set{String}()

"""
    register_ops!()

Register every outbound op on BOTH grounding lanes, each wrapped by `governed` reading the LIVE
DEFAULT_POLICY[]/DEFAULT_LEDGER[]. Idempotent (won't re-register a name).
"""
function register_ops!()
    for (name, run) in _OUTBOUND
        name in _REGISTERED && continue
        MORK.register_grounded!(name, function (a::Vector{String})
            out = governed(DEFAULT_POLICY[], DEFAULT_LEDGER[], name, a, run)
            return string("\"", replace(out, "\\" => "\\\\", "\"" => "\\\""), "\"")
        end)
        _SM.TOKEN_REGISTRY[name] = _SM.Grounded(_SM.Operation(name, function (xs::Vector{_SM.Atom})
            length(xs) == 1 || return _SM.ExecNoReduce()
            (xs[1] isa _SM.Grounded && xs[1].value isa AbstractString) || return _SM.ExecNoReduce()
            out = governed(DEFAULT_POLICY[], DEFAULT_LEDGER[], name, String[String(xs[1].value)], run)
            _SM.ExecOk(_SM.Atom[_SM.Grounded(out)])
        end))
        push!(_REGISTERED, name)
    end
    return sort!(collect(_REGISTERED))
end
