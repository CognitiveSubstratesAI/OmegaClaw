# MettaLoop.jl — the agent TICK LOOP as a PURE-MeTTa tail-recursion (upstream-faithful, like mettaclaw's
# `(mettaclaw (+ 1 $k))`), driving grounded Julia "organ" ops BY HANDLE.
#
# Verified (feasibility study w73mhdc8s): Core does NOT compile a recursive, effectful, grounded-op
# orchestration — the ZAM/MM2 compiled lane provably bails on recursion (head-graph cycle) and on any
# grounded/control head. So this runs on the Core INTERPRETER. That is fine: the "5-30x materialize" caveat
# is the opt-in SUPERCOMPILER (off), not this path; the real cost is a few grounded dispatches + let*/if per
# tick, additive over the fixed ~0.44ms mid_step!. The heavy state (1024-vec context, mid_step! NamedTuple,
# sense, governor) NEVER crosses the ABI — it stays in the WorldModel reg + the Julia Driver, reached BY
# HANDLE; the MeTTa loop passes only small tokens (handle, goal, action-id, result, scalars).
#
# Grounded ABI used: the Core INTERPRETER lane (Interpreter.jl:306-339) — Atom-in/Atom-out, `Operation(name,
# (xs::Vector{Atom})->ExecResult)` in TOKEN_REGISTRY, return `ExecOk(Atom[Grounded(token)])`. NOT the MORK
# string lane. Every world-facing effect still routes through `governed` (the gate is never bypassed).

const _DRIVERS = Dict{String,Driver}()          # handle → Driver: heavy state lives here, never in MeTTa
const _TICK_MID = Dict{String,Any}()            # handle → last mid_step! result (transient, within a tick)
const _HANDLE_CTR = Ref(0)

"Register a Driver behind a small handle token the MeTTa loop can pass around."
oc_handle!(d::Driver) = (h = "oc$(_HANDLE_CTR[] += 1)"; _DRIVERS[h] = d; h)

_astr(a) = (a isa _SM.Grounded && a.value isa AbstractString) ? String(a.value) : string(a)
_gok(s::AbstractString) = _SM.ExecOk(_SM.Atom[_SM.Grounded(String(s))])
_decision(res::AbstractString) = startswith(res, "GATE[") ? :blocked : (res == "none" ? nothing : :allowed)

const _LOOP_OPS_REGISTERED = Ref(false)

# Register the by-handle organ ops on the interpreter lane. Each looks up the Driver, runs the REAL Julia
# organ (perceive/mid_step!/governed/reinforce!/…), mutates driver+reg state in place, returns a small token.
function _register_loop_ops!()
    _LOOP_OPS_REGISTERED[] && return nothing
    reg = _SM.TOKEN_REGISTRY

    reg["oc-pick-goal"] = _SM.Grounded(_SM.Operation("oc-pick-goal", function (xs::Vector{_SM.Atom})
        length(xs) == 2 || return _SM.ExecNoReduce()
        d = get(_DRIVERS, _astr(xs[1]), nothing); d === nothing && return _gok("none")
        goal = _astr(xs[2])
        if isempty(d.plan)                                   # harness bookkeeping: pick a plan / target
            chose = _pick_goal(d, goal, false)
            chose !== nothing && haskey(d.plans, chose) && (d.plan = copy(d.plans[chose]); d.frontier = 1)
        end
        _gok(!isempty(d.plan) ? d.plan[d.frontier] : goal)
    end))

    reg["oc-mid-step"] = _SM.Grounded(_SM.Operation("oc-mid-step", function (xs::Vector{_SM.Atom})
        length(xs) == 3 || return _SM.ExecNoReduce()
        h = _astr(xs[1]); d = get(_DRIVERS, h, nothing); d === nothing && return _gok("none")
        obs = _perceive(_astr(xs[2]), d.loop.tick)           # WorldModel decides — 1024-vec written to Sctx, NOT returned
        r = WorldModel.mid_step!(d.loop, obs; goal = _astr(xs[3]), governor = nothing)
        _TICK_MID[h] = r
        _gok(r.action === nothing ? "none" : r.action[1])    # only the action-id token crosses the ABI
    end))

    reg["oc-act"] = _SM.Grounded(_SM.Operation("oc-act", function (xs::Vector{_SM.Atom})
        length(xs) == 2 || return _SM.ExecNoReduce()
        h = _astr(xs[1]); d = get(_DRIVERS, h, nothing); d === nothing && return _gok("none")
        aid = _astr(xs[2])
        (aid == "none" || !haskey(d.actions, aid)) && return _gok("none")
        op, args = d.actions[aid]
        result = governed(_live_policy(d), d.ledger, op, args, _OUTBOUND[op]; evidence = () -> _op_evidence(op, args))
        if !isempty(d.plan) && _action_success(d, _decision(result), result)   # advance the plan on a clean step
            d.frontier += 1
            d.frontier > length(d.plan) && (d.plan = String[]; d.frontier = 0)
        end
        _gok(result)
    end))

    reg["oc-reinforce"] = _SM.Grounded(_SM.Operation("oc-reinforce", function (xs::Vector{_SM.Atom})
        length(xs) == 4 || return _SM.ExecNoReduce()
        h = _astr(xs[1]); d = get(_DRIVERS, h, nothing); d === nothing && return _gok("none")
        aid, tgt, res = _astr(xs[2]), _astr(xs[3]), _astr(xs[4])
        (aid != "none" && haskey(d.actions, aid)) &&
            reinforce!(d, aid, tgt, _action_success(d, _decision(res), res))
        _gok("ok")
    end))

    reg["oc-learn-step"] = _SM.Grounded(_SM.Operation("oc-learn-step", function (xs::Vector{_SM.Atom})
        length(xs) == 1 || return _SM.ExecNoReduce()
        h = _astr(xs[1]); d = get(_DRIVERS, h, nothing); d === nothing && return _gok("none")
        r = get(_TICK_MID, h, nothing); r === nothing && return _gok("none")
        s = _learn_step!(d, r; hidden = 32, epochs = 80)
        _gok(s === nothing ? "none" : string(s))
    end))

    reg["oc-sense!"] = _SM.Grounded(_SM.Operation("oc-sense!", function (xs::Vector{_SM.Atom})
        length(xs) == 3 || return _SM.ExecNoReduce()
        h = _astr(xs[1]); d = get(_DRIVERS, h, nothing); d === nothing && return _gok("none")
        srp, res = _astr(xs[2]), _astr(xs[3])
        surprise = srp == "none" ? nothing : tryparse(Float64, srp)
        dec = _decision(res)
        isempty(d.sense) && (d.sense = _initial_sense(d))
        d.sense = _next_sense(d, surprise, _action_success(d, dec, res), dec === :blocked)
        _gok("ok")
    end))

    _LOOP_OPS_REGISTERED[] = true
    return nothing
end

# The tick program — PURE MeTTa tail-recursion (upstream `(mettaclaw (+ 1 $k))` shape). Only small tokens
# cross the ABI. `$n` is a bounded countdown (mirrors run_agent! max_turns); `$res` feeds the next `$raw`.
const DEFAULT_OC_TICK_RULE = raw"""
(= (oc-tick $h $goal $raw $n)
   (if (== $n 0) Done
      (let* (($tgt (oc-pick-goal $h $goal))
             ($aid (oc-mid-step $h $raw $tgt))
             ($res (oc-act $h $aid))
             ($ok  (oc-reinforce $h $aid $tgt $res)))
         (oc-tick $h $goal $res (- $n 1)))))
"""

# A FLAT (non-recursive) single tick — the same organ chain WITHOUT the MeTTa self-recursion. Driven N times
# from the Julia host (run_metta_loop_flat!), this is O(N) constant-per-tick, sidestepping the Core
# interpreter's lack of tail-call optimization that makes the recursive form O(N^2). (Experiment from the
# compiled-paths study w5udypv7g: isolates whether the 120x was pure recursion-depth vs per-tick baseline.)
const DEFAULT_OC_TICK1_RULE = raw"""
(= (oc-tick1 $h $goal $raw)
   (let* (($tgt (oc-pick-goal $h $goal))
          ($aid (oc-mid-step $h $raw $tgt))
          ($res (oc-act $h $aid))
          ($ok  (oc-reinforce $h $aid $tgt $res)))
      $res))
"""

"""
    run_metta_loop_flat!(d; goal, max_turns=100, init="start") -> d

Same organ chain as `run_metta_loop!` but the tick is FLAT (non-recursive) and the loop is driven from the
Julia host over ONE persistent interpreter Space — O(N) instead of the recursive form's no-TCO O(N^2). The
tick body is still MeTTa (the orchestration is a MeTTa rule); only the countdown/iteration lives in the host.
"""
function run_metta_loop_flat!(d::Driver; goal::AbstractString, max_turns::Int = 100, init::AbstractString = "start")
    _register_loop_ops!()
    h = oc_handle!(d)
    try
        sp = _SM.Space()
        _SM.load_core_stdlib!(sp)
        _SM.load_metta!(sp, DEFAULT_OC_TICK1_RULE)
        raw = init
        for _ in 1:max_turns
            res = _SM.metta_run(_SM.parse_program("(oc-tick1 \"$h\" \"$goal\" \"$raw\")")[1][2], sp)
            raw = isempty(res) ? init : replace(_astr(res[1]), r"[\"\\\n]" => "_")   # sanitize for re-embedding
        end
    finally
        delete!(_DRIVERS, h); delete!(_TICK_MID, h)
    end
    return d
end

"""
    run_metta_loop!(d; goal, max_turns=100, init="start", rule=DEFAULT_OC_TICK_RULE) -> d

Drive the OmegaClaw agent for `max_turns` ticks with the tick LOOP itself running as a MeTTa tail-recursion
(the upstream-faithful topology), NOT a Julia harness. The whole `(oc-tick …)` runs inside ONE persistent
interpreter Space (stdlib + the tick rule; the organ ops are global in TOKEN_REGISTRY) — critically NOT via
`mc_run` per tick, which would rebuild the Space + reload stdlib every call. WorldModel decides each action,
the gate authorizes it, the ledger records it — identical organs to `step!`, driven from MeTTa.
"""
function run_metta_loop!(d::Driver; goal::AbstractString, max_turns::Int = 100,
    init::AbstractString = "start", rule::AbstractString = DEFAULT_OC_TICK_RULE)
    _register_loop_ops!()
    h = oc_handle!(d)
    try
        sp = _SM.Space()
        _SM.load_core_stdlib!(sp)                            # if / let* / == / - live here
        _SM.load_metta!(sp, rule)                            # the tick rule (organ ops are global)
        _SM.metta_run(_SM.parse_program("(oc-tick \"$h\" \"$goal\" \"$init\" $max_turns)")[1][2], sp)
    finally
        delete!(_DRIVERS, h); delete!(_TICK_MID, h)          # release the handle
    end
    return d
end
