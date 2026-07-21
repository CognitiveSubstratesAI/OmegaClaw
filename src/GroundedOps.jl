# GroundedOps.jl — outbound grounded operations, reachable ONLY through the gate.
#
# Each op is DUAL-REGISTERED (verified from Core code bodies): `register_grounded!`/`GROUNDED_REGISTRY`
# for the PRIMARY compiled MM2/ZAM lane, and a `Grounded(Operation)` in the interpreter's `TOKEN_REGISTRY`
# for the fallback — mirroring how `println!` is registered in both (`Primitives.jl` + `Interpreter.jl`).
# The op body NEVER runs unless `decide` returns `Allow`; every call is recorded in the evidence ledger.

import MORK
const _SM = MeTTaCore.Interpreter

"""
    governed(policy, ledger, action, args, run) -> String

The single choke point: build a hash-pinned Proposal, get the 5-way Decision, record it in the ledger,
and run `run(args)` ONLY on `Allow`. Any other disposition returns a `GATE[...]` marker and does NOT
touch the world.
"""
function governed(policy::Policy, ledger::Ledger, action::AbstractString,
    args::Vector{String}, run::Function)::String
    p = Proposal(action, args)
    d = decide(policy, p)
    record!(ledger, p, d)
    d === Allow || return string("GATE[", d, "]")
    return run(args)
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

"""
    register_ops!(policy, ledger)

Register every outbound op on BOTH grounding lanes, each wrapped by `governed(policy, ledger, …)`.
"""
function register_ops!(policy::Policy, ledger::Ledger)
    for (name, run) in _OUTBOUND
        # Primary compiled lane (MM2/ZAM): string-in → sexpr-string-out.
        MORK.register_grounded!(name, function (a::Vector{String})
            out = governed(policy, ledger, name, a, run)
            return string("\"", replace(out, "\\" => "\\\\", "\"" => "\\\""), "\"")
        end)
        # Interpreter fallback lane: Grounded(Operation) in TOKEN_REGISTRY.
        _SM.TOKEN_REGISTRY[name] = _SM.Grounded(_SM.Operation(name, function (xs::Vector{_SM.Atom})
            length(xs) == 1 || return _SM.ExecNoReduce()
            (xs[1] isa _SM.Grounded && xs[1].value isa AbstractString) || return _SM.ExecNoReduce()
            out = governed(policy, ledger, name, String[String(xs[1].value)], run)
            _SM.ExecOk(_SM.Atom[_SM.Grounded(out)])
        end))
    end
    return sort!(collect(keys(_OUTBOUND)))
end
