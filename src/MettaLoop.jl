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
const _SLOW_FIRES = Ref(0)                       # observability: cumulative oc-slow-step (ambient) firings

"Register a Driver behind a small handle token the MeTTa loop can pass around."
oc_handle!(d::Driver) = (h = "oc$(_HANDLE_CTR[] += 1)"; _DRIVERS[h] = d; h)

_astr(a) = (a isa _SM.Grounded && a.value isa AbstractString) ? String(a.value) : string(a)
_gok(s::AbstractString) = _SM.ExecOk(_SM.Atom[_SM.Grounded(String(s))])
_decision(res::AbstractString) = startswith(res, "GATE[") ? :blocked : (res == "none" ? nothing : :allowed)

# Atom → Real (a grounded number, or a numeric literal that stayed symbolic); `nothing` if it isn't a number.
_num(a) = (a isa _SM.Grounded && a.value isa Real) ? Float64(a.value) : tryparse(Float64, string(a))

# Marshal the tick loop's final `(cadence $sn $t0)` back onto the driver (see run_metta_loop!). Fail-SAFE by
# construction: any shape we don't recognise — a custom `rule` whose base case is a bare `Done`, an unreduced
# arithmetic atom, an empty result — leaves the driver UNTOUCHED rather than writing a garbage cadence.
function _writeback_cadence!(d::Driver, res)
    (res isa AbstractVector && !isempty(res)) || return nothing
    a = res[1]
    (a isa _SM.Expression && length(a.children) == 3 && string(a.children[1]) == "cadence") || return nothing
    sn = _num(a.children[2]); t0 = _num(a.children[3])
    (sn === nothing || t0 === nothing) && return nothing
    (isfinite(sn) && isfinite(t0) && sn >= 0) || return nothing
    d.slow_pending = round(Int, sn)
    d.last_slow = t0
    return nothing
end

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

    # oc-slow-step — the SLOW-rate ORGAN only (§7 ambient background loop): fire WorldModel.slow_step! once
    # (belief-decay + HMH consolidation + WILLIAM mining + SubRep admit + MOSES/GEO-EVO synthesis). The CADENCE
    # (counter, threshold, reset) is NOT here — it lives in the MeTTa tick rule (the `$sn` loop param + the
    # `should-consolidate` rule), mirroring Core/lib ECAN's fully-MeTTa `scan-due?`. So this grounded atom is a
    # pure numeric organ — nothing but the FabricPC/HMH/PLN work. Best-effort: never fails the tick.
    reg["oc-slow-step"] = _SM.Grounded(_SM.Operation("oc-slow-step", function (xs::Vector{_SM.Atom})
        length(xs) == 1 || return _SM.ExecNoReduce()
        h = _astr(xs[1]); d = get(_DRIVERS, h, nothing); d === nothing && return _gok("none")
        _SLOW_FIRES[] += 1
        _ambient_step!(d)
        _gok("ok")
    end))

    # oc-now — the WALL CLOCK as a pure numeric organ (upstream's `(get_time)`). Returns seconds as a grounded
    # Float64 so the tick rule can do `(- $now $t0)` in MeTTa. No policy here: the IDLE THRESHOLD and the
    # or-combination live in the `should-consolidate` rule, and the last-fire timestamp is threaded as a loop
    # PARAM (`$t0`) — deliberately NOT a mutable state cell (upstream's `&nextWakeAt`), which PeTTa flags as a
    # data-race hazard and which its own stdlib avoids in favour of parameter threading (`iterate`).
    reg["oc-now"] = _SM.Grounded(_SM.Operation("oc-now", function (xs::Vector{_SM.Atom})
        isempty(xs) || return _SM.ExecNoReduce()
        _SM.ExecOk(_SM.Atom[_SM.Grounded(time())])
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
(= (oc-tick $h $goal $raw $n $sn $t0)
   (if (== $n 0) (cadence $sn $t0)
      (let* (($tgt (oc-pick-goal $h $goal))
             ($aid (oc-mid-step $h $raw $tgt))
             ($res (oc-act $h $aid))
             ($ok  (oc-reinforce $h $aid $tgt $res))
             ($sn1 (+ $sn 1))
             ($now (oc-now))
             ($dt  (- $now $t0))
             ($due (should-consolidate $sn1 $dt))
             ($amb (if $due (oc-slow-step $h) skip))
             ($sn2 (if $due 0 $sn1))
             ($t1  (if $due $now $t0)))
         (oc-tick $h $goal $res (- $n 1) $sn2 $t1))))
"""

# A FLAT (non-recursive) single tick — the same organ chain WITHOUT the MeTTa self-recursion. Driven N times
# from the Julia host (run_metta_loop_flat!), this is O(N) constant-per-tick, sidestepping the Core
# interpreter's lack of tail-call optimization that makes the recursive form O(N^2). (Experiment from the
# compiled-paths study w5udypv7g: isolates whether the 120x was pure recursion-depth vs per-tick baseline —
# now historical: Core's TCO frame-collapse (MeTTaCore a8be1af) made the RECURSIVE form O(N) too.)
# ⚠️ NO AMBIENT CADENCE: this rule carries no `$sn`/`$t0` params, so run_metta_loop_flat! NEVER runs the §7
# ambient/slow rate. That is deliberate — it exists to isolate per-tick cost, not to be a production driver.
# Use run_metta_loop! (MeTTa cadence) or step!(…; ambient=true) (host cadence) for a real agent.
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
        _SM.load_core_stdlib!(sp)                            # if / let* / == / - / + / >= live here
        _SM.load_metta!(sp, d.consolidate_rule)              # the ambient-cadence rule (should-consolidate) — editable
        _SM.load_metta!(sp, rule)                            # the tick rule (organ ops are global)
        # 5th/6th args = the ambient cadence STATE, threaded PURELY in MeTTa (incremented/gated/reset in the
        # rule, never in a mutable cell): `$sn` = mid-ticks since the last ambient step, `$t0` = the wall-clock
        # second it last fired (seeded from the driver's own idle clock, so time spent idle BEFORE this loop
        # started still counts toward the idle trigger).
        res = _SM.metta_run(_SM.parse_program(
            "(oc-tick \"$h\" \"$goal\" \"$init\" $max_turns $(d.slow_pending) $(d.last_slow))")[1][2], sp)
        # …and MARSHAL the loop's FINAL state back onto the driver. Without this the seed above is a
        # half-contract: read on entry, dropped on exit — so a caller that CHUNKS the loop (4×max_turns=4
        # instead of 1×16), or mixes this lane with step!/run_agent!, restarts the tick counter every call and
        # the ACTIVITY trigger never fires (measured: 16 ticks chunked = 0 ambient steps vs 2 in one call).
        # The idle arm is unaffected either way (_ambient_step! re-stamps last_slow on every fire). This is
        # pure boundary MARSHALLING, not policy — the counter/clock stay threaded as MeTTa loop params
        # throughout; the base case just hands them back. A custom `rule` that keeps a bare `Done` base case
        # simply won't match and degrades to the old restart-per-call behaviour.
        _writeback_cadence!(d, res)
    finally
        delete!(_DRIVERS, h); delete!(_TICK_MID, h)          # release the handle
    end
    return d
end
