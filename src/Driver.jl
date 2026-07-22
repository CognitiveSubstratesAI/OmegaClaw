# Driver.jl — the governed agent loop (ADR-061 D2/S5).
#
# WorldModel DECIDES (PLN action-selection + MetaMo motive); OmegaClaw's gate is the ONLY seam to the
# world; the LLM/FabricPC is (later) the language/perception organ. One tick:
#   perceive(raw) → mid_step!(WM decides) → PLN action id → (op,args) → governed() → result → feed back.
# Included INTO `module OmegaClaw`, so `governed`/`_OUTBOUND`/`DEFAULT_POLICY`/`DEFAULT_LEDGER`/`Policy`/
# `Ledger` are in scope unqualified. `import WorldModel` (not `using`) — WM exports (add!/select_action/…)
# would collide, so every WM reference is qualified.

import WorldModel

# The canonical PLN library's ENTRY POINT, loaded into every driver's policy space (see `_policy_space`)
# so the agent's cognitive-control rules can DELEGATE to `Truth_w2c`/`EvidenceConfidence` instead of
# re-deriving them. Resolved from the installed MeTTaCore rather than a relative path, exactly as
# `WorldModel/src/PLNCore.jl` does — one library, one location, no vendored copy in this repo.
const _LIBPLN_ENTRY = abspath(joinpath(dirname(pathof(MeTTaCore)), "..", "lib", "pln", "pln.metta"))

"""
    Driver(; store, policy, ledger, goal=nothing, governor=nothing)

A live OmegaClaw agent over a WorldModel braid. `actions` maps a PLN action-id (the antecedent token of a
seeded `id ⇒ goal` implication) to a registered outbound op + its args. An explicit `goal` ⇒ deterministic
selection; a `governor` ⇒ MetaMo picks the goal (leave `goal=nothing`).
"""
# The retrain cadence is a MeTTa RULE, not a Julia constant. `should-retrain` receives (pending, surprise)
# and returns True/False — so *when the agent learns* is an atom it can inspect and rewrite, the MeTTa-First
# line: the numeric organ (FabricPC train / surprise-norm) is grounded Julia, but the control policy is MeTTa.
const DEFAULT_LEARN_RULE = "(= (should-retrain \$n \$s) (>= \$n 8))"   # surprise-aware form: (or (>= \$n 8) (> \$s θ))

# The AMBIENT/SLOW-rate cadence (whitepaper §7 ambient background loop): when WorldModel.slow_step! runs —
# the SAME editable-atom idiom as `should-retrain` above and Core/lib ECAN's `scan-due?` (counter ≥ interval),
# so *when the agent consolidates in the background* is a rewritable policy atom, not a Julia constant.
#
# TWO triggers, OR'd — the union of an ACTIVITY clock and a WALL clock:
#   · `$n`  = mid-ticks since the last ambient step  ⇒ consolidate every K ticks while the agent is BUSY.
#   · `$dt` = wall-clock SECONDS since the last ambient step ⇒ consolidate after T seconds even when the agent
#             is IDLE (few/no ticks). This is the upstream self-wake semantic (mettaclaw/OmegaClaw-Core re-arm
#             `&nextWakeAt` on a `get_time` deadline) — but WITHOUT their host-side mutable state cell: we read
#             the clock via the `oc-now` numeric organ and thread the last-fire timestamp as a LOOP PARAM, the
#             idiom PeTTa's own stdlib uses (`iterate`) and the one PeTTa flags mutable cells as hazardous against.
# Both thresholds are separate named atoms so either can be retuned (or the whole predicate rewritten) at runtime.
const DEFAULT_CONSOLIDATE_RULE = raw"""
(= (consolidate-every) 8)
(= (consolidate-idle-secs) 600)
(= (should-consolidate $n $dt) (or (>= $n (consolidate-every)) (>= $dt (consolidate-idle-secs))))
"""

# The agent's cognitive-control POLICY, as MeTTa rules (inspectable + rewritable atoms), NOT Julia constants —
# the same MeTTa-First line as the cadence rule above (verified: the ecosystem — mettaclaw/CeTTa/PeTTa —
# keeps appraisal/estimator formulas + their coefficients in .metta, host holds only the numeric organ + FFI).
# `appraise`  : experience → the 4-channel MetaMo stimulus (novelty,conduciveness,risk,effort). The novelty
#               NUMBER (surprise/max, self-normalized) is computed native and passed in; the channel weights
#               and the no-signal decay are policy here.
# `action-success?` : what COUNTS as a successful action (drives the stimulus, plan-advance, and reward).
# `evidence->stv`   : the reward-outcome → PLN truth-value estimator (frequency + count→confidence, k = PLN
#               look-ahead). `initial-sense` : the agent's prior affect disposition.
#
# The confidence half DELEGATES to `Core/lib/pln`'s `EvidenceConfidence` (= the canonical `Truth_w2c`,
# k = 1) instead of writing `(/ $n (+ $n $k))` out again. That inline form was a SECOND MeTTa COPY of
# pln_core_logic.metta:214-216 — and, because `_policy_space` used to load only the Core stdlib (which
# contains no `Truth_w2c`), it was a copy that structurally COULD NOT delegate. Being MeTTa is not the
# property that matters; being the SAME definition is. `EvidenceConfidence (/safe $n $k)` is exactly
# equal to `n/(n+k)` for every k > 0 — w2c(n/k) = (n/k)/((n/k)+1) = n/(n+k) — so the k look-ahead
# parameter survives intact while the confidence MAP has one definition. At the shipped k = 1 it is the
# canonical map applied directly, which is what puts these confidences on the same evidence scale as
# every other truth value in the system (and is why PeTTaChainer's k = 800 must not be imported).
# `/safe` also replaces bare `/`: n = 0 now prunes rather than emitting NaN.
const DEFAULT_POLICY_RULES = raw"""
(= (novelty-decay) 0.9)
(= (effort-baseline) 0.3)
(= (initial-sense) (stimulus 0.1 0.5 0.1 0.3))
(= (action-success? $d $e) (and (== $d allowed) (not $e)))
(= (novelty $s $maxs $hassig $prev)
   (if $hassig (if (<= $maxs 0) 0.0 (min 1.0 (max 0.0 (/ $s $maxs)))) (* $prev (novelty-decay))))
(= (appraise $s $maxs $hassig $prev $success $blocked)
   (stimulus (novelty $s $maxs $hassig $prev)
             (if $success 0.8 0.2)
             (if $blocked 0.8 0.1)
             (effort-baseline)))
(= (evidence->stv $s $n $k) (STV (/safe $s $n) (EvidenceConfidence (/safe $n $k))))
"""

mutable struct Driver
    reg::WorldModel.SpaceRegistry
    loop::WorldModel.CognitiveLoop
    policy::Union{Policy,Nothing}                         # nothing ⇒ read the LIVE DEFAULT_POLICY[] each tick (B6)
    ledger::Ledger
    actions::Dict{String,Tuple{String,Vector{String}}}   # action_id => (op_name, args)
    outcomes::Dict{String,Tuple{Int,Int}}                # action_id => (successes, attempts) — reinforcement stats
    transitions::Vector{Tuple{Vector{Float64},Vector{Float64}}}   # online (context_t → context_{t+1}) buffer
    prev_context::Union{Vector{Float64},Nothing}         # last tick's context vector (to form a transition)
    pending::Int                                          # transitions since the last retrain (fed to the rule)
    slow_pending::Int                                     # mid-ticks since the last ambient/slow step (fed to should-consolidate)
    last_slow::Float64                                    # wall-clock (s) of the last ambient step — drives the IDLE trigger ($dt)
    learn_rule::String                                   # MeTTa `should-retrain` cadence rule (editable = re-schedule)
    consolidate_rule::String                             # MeTTa `should-consolidate` cadence rule (ambient/slow rate — editable)
    policy_rules::String                                 # MeTTa cognitive-control policy (appraise/action-success?/evidence->stv/…) — rewritable
    learn_space::Any                                     # lazily-built Core space (stdlib + learn_rule + policy_rules); nothing until used
    goal::Union{String,Nothing}
    governor::Any                                         # MetaMo (; goals,mods,stimulus,candidates) | nothing
    plans::Dict{String,Vector{String}}                   # goal => ordered subgoal ladder (last element == goal)
    plan::Vector{String}                                 # the active plan's subgoal sequence (empty = none active)
    frontier::Int                                        # 1-based cursor into `plan` (which subgoal this tick pursues)
    sense::Vector{Float64}                               # adaptive stimulus (novelty,conduciveness,risk,effort) from last tick
    max_surprise::Float64                                # running max surprise — normalizes surprise → novelty ∈ [0,1]
end

function Driver(; store::AbstractString = mktempdir(),
    policy::Union{Policy,Nothing} = nothing, ledger::Ledger = DEFAULT_LEDGER[],
    learn_rule::AbstractString = DEFAULT_LEARN_RULE, consolidate_rule::AbstractString = DEFAULT_CONSOLIDATE_RULE,
    policy_rules::AbstractString = DEFAULT_POLICY_RULES,
    goal::Union{AbstractString,Nothing} = nothing, governor = nothing)
    reg = WorldModel.SpaceRegistry(WorldModel.manifest(; store = store))
    WorldModel.seed_world_model!(reg)
    loop = WorldModel.CognitiveLoop(reg)
    return Driver(reg, loop, policy, ledger,
        Dict{String,Tuple{String,Vector{String}}}(), Dict{String,Tuple{Int,Int}}(),
        Tuple{Vector{Float64},Vector{Float64}}[], nothing, 0, 0, time(),   # last_slow: idle clock starts at construction
        String(learn_rule), String(consolidate_rule), String(policy_rules), nothing,
        goal === nothing ? nothing : String(goal), governor,
        Dict{String,Vector{String}}(), String[], 0,
        Float64[], 0.0)   # sense: empty ⇒ lazily initialized from the `(initial-sense)` MeTTa rule on first adaptive tick
end

"""
    reinforce!(d, action_id, goal, success; k=1) -> NamedTuple

Update the `action_id ⇒ goal` PLN truth-value from an execution outcome (the reward channel): accumulate
(successes, attempts) and re-assert the implication with strength = successes/attempts and confidence
growing with evidence. So `select_action(goal)` prefers actions that have actually succeeded, and demotes
actions that were blocked or errored. Re-uses WorldModel's own `assert_implication!` (no bespoke store).
"""
function reinforce!(d::Driver, action_id::AbstractString, goal::AbstractString, success::Bool; k::Int = 1)
    s0, n0 = get(d.outcomes, String(action_id), (0, 0))
    s1, n1 = s0 + (success ? 1 : 0), n0 + 1
    d.outcomes[String(action_id)] = (s1, n1)              # counter accumulation = native bookkeeping
    # count→STV estimator = MeTTa policy. REQUIRED: there is deliberately no Julia fallback here. The
    # previous `stv === nothing ? (s1/n1, n1/(n1+k)) : …` was a third copy of the canonical count→
    # confidence map (at k=1, `n/(n+k)` IS `Truth_w2c`) that took over invisibly whenever the rule failed.
    stv = _policy_vec_req(d, "(evidence->stv $s1 $n1 $k)", "STV", "evidence->stv")
    strength, confidence = stv[1], stv[2]
    WorldModel.assert_implication!(d.reg, action_id, goal, strength, confidence, float(d.loop.tick))
    return (; action = String(action_id), goal = String(goal), success = success,
        strength = strength, confidence = confidence, attempts = n1)
end

"The policy this driver runs under this tick: an explicit pinned policy, else the LIVE default (B6)."
_live_policy(d::Driver)::Policy = d.policy === nothing ? DEFAULT_POLICY[] : d.policy

"""
    seed!(d, action_id, goal, op, args; s=0.9, c=0.9, t=0.0) -> d

Install ONE PLN action rule: `assert_implication!(reg, action_id, goal, s,c,t)` writes `(implies action_id
goal)` + a belief so `select_action(reg, goal)` returns `action_id` (1-hop), and bind that id to an
outbound op. `action_id` must be whitespace-free and contain no `=>` (belief-key parse). `op` must be a
registered outbound op (`shell`, `read-file`).
"""
# `t = -1.0` (NOT 0.0): a seed is a PRIOR and must precede every observation. Beliefs resolve
# latest-wins by `t` (see Beliefs.beliefs), and reinforce! stamps `t = d.loop.tick` — which is still
# 0.0 until the loop actually ticks. Sharing t=0.0 let the seed's optimistic c=0.9 outrank real
# evidence (5/6 = 0.833), freezing selection on the prior for a FAILING action just as much as a
# succeeding one. A prior is superseded by the first real observation, by construction.
function seed!(d::Driver, action_id::AbstractString, goal::AbstractString,
    op::AbstractString, args::Vector{String}; s::Real = 0.9, c::Real = 0.9, t::Real = -1.0)
    (occursin(r"\s", action_id) || occursin("=>", action_id)) &&
        error("action_id must be whitespace-free and contain no '=>': $action_id")
    haskey(_OUTBOUND, String(op)) ||
        error("no outbound op registered: $op (have $(collect(keys(_OUTBOUND))))")
    WorldModel.assert_implication!(d.reg, action_id, goal, s, c, t)
    d.actions[String(action_id)] = (String(op), args)
    return d
end

# Deterministic perception: raw string → Observation (NO LLM). Always ≥1 slot; the entity filler is a
# single [()\s]-free token so nothing structural is spliced into the MORK s-expr.
function _perceive(raw::AbstractString, tick::Int; modality::String = "text")
    tok = replace(strip(raw), r"[()\s]+" => "_")
    isempty(tok) && (tok = "empty")
    ek = "e$tick"
    return WorldModel.Observation(
        String(strip(raw)),                       # payload (content-addressed by hash downstream)
        modality,
        ek,                                       # entity_key
        "(entity $ek $tok)",                      # entity_atom (well-formed s-expr)
        Symbol("ep_", tick),                      # fresh episode_key per tick
        Dict(:item => (:thing, Symbol(tok))),     # slots: role => (type, filler_symbol)
    )
end

"""
    seed_plan!(d, goal, steps) -> d

Install a MULTI-STEP plan for `goal`: `steps` is an ordered list of `(action_id, op, args)`, executed in
sequence. Each step becomes a 1-hop reflex toward a fresh progress subgoal (`goal__step1`, `goal__step2`, …,
and the LAST step's subgoal IS `goal`) via `seed!`. At run time the Driver walks the ladder one gated action
per tick (`frontier`), advancing only on a clean gated action — so the agent executes the whole SEQUENCE to
reach a goal no single reflex covers (the demo's `shelter` = `gather` → `build`). This composes `seed!` (a
robust 1-hop reflex per subgoal) — deliberately NOT PLN's 2-hop deduction, which is inert without node STVs.

For AUTONOMY, give the Driver a MetaMo `governor` whose candidate `id`s include `goal`; then `step!(d, raw)`
(goal defaulting to `nothing`) lets MetaMo choose WHICH plan to pursue. INVARIANT: a governor `candidate.id`
must match a `seed_plan!` (or `seed!`) goal, else that pick has nothing to run and the agent idles.
"""
function seed_plan!(d::Driver, goal::AbstractString, steps::AbstractVector)
    isempty(steps) && error("seed_plan!: empty plan for goal $goal")
    n = length(steps); ladder = String[]
    for (i, step) in enumerate(steps)
        aid, op, args = step
        sg = i == n ? String(goal) : string(goal, "__step", i)   # progress token (whitespace/'=>'-free)
        seed!(d, String(aid), sg, String(op), collect(String, args))
        push!(ladder, sg)
    end
    d.plans[String(goal)] = ladder
    return d
end

# The governor (autonomy) picks WHICH plan/goal to pursue; else the pinned `goal`. In ADAPTIVE mode the
# stimulus is the agent's own `sense` (surprise→novelty, gate outcomes→conduciveness/risk) and the evolved
# modulators are carried forward — so the motive state is DYNAMIC, shaped by experience, not a fixed governor.
function _pick_goal(d::Driver, goal, adaptive::Bool)
    d.governor === nothing && return goal
    gv = d.governor
    stim = adaptive ? d.sense : collect(Float64, gv.stimulus)
    g = WorldModel.MetaMoCore.govern(gv.goals, gv.mods, stim, gv.candidates)
    g === nothing && return goal
    adaptive && (d.governor = merge(gv, (mods = g.mods, stimulus = stim)))   # carry the evolved affect state forward
    return g.chosen
end

# Next tick's 4-channel stimulus from THIS tick's experience, via the `appraise` MeTTa POLICY rule (the
# perception→motive channel; MetaMo's (novelty,conduciveness,risk,effort) — MetaMoCore.jl:64). Julia computes
# ONLY the numeric novelty MAGNITUDE (self-normalized surprise) — a numeric organ; the channel WEIGHTS and the
# no-signal decay are the MeTTa rule. Fail-safe: keep the prior sense (or the prior) on eval error.
function _next_sense(d::Driver, surprise, success::Bool, blocked::Bool)
    hassig = surprise !== nothing && isfinite(surprise)
    s = hassig ? Float64(surprise) : 0.0                   # L2 surprise-norm = numeric organ (like upstream embeddings)
    hassig && (d.max_surprise = max(d.max_surprise, s))    # running-max STATE only (the sqlite-kv analog); NORMALIZATION is MeTTa
    prev = isempty(d.sense) ? 0.1 : d.sense[1]
    expr = "(appraise $s $(d.max_surprise) $(hassig ? "True" : "False") $prev $(success ? "True" : "False") $(blocked ? "True" : "False"))"
    st = _policy_vec(d, expr, "stimulus")
    st === nothing ? (isempty(d.sense) ? _initial_sense(d) : d.sense) : st
end

"""
    step!(d, raw; goal=d.goal) -> NamedTuple

One agent tick. Returns `(; action, op, args, decision, result, goal, chose, surprise, mid)`; `decision ∈
(:allowed, :blocked, nothing)`. If a plan is active the tick pursues the current subgoal (the `frontier`) and
advances on a clean gated action; `chose` is the goal MetaMo (or the pinned goal) picked when a fresh plan
started (else `nothing`), `goal` is the subgoal actually pursued this tick. `action === nothing` (no goal / no
matching rule / unbound id) is a NORMAL "no action this tick". Feed `result` back as the next `raw`.
"""
function step!(d::Driver, raw::AbstractString; goal = d.goal, reinforce::Bool = false,
    learn::Bool = false, adaptive::Bool = false, ambient::Bool = false, hidden::Int = 32, epochs::Int = 80)
    obs = _perceive(raw, d.loop.tick)
    adaptive && isempty(d.sense) && (d.sense = _initial_sense(d))   # prior affect from the (initial-sense) rule
    # plan pick (autonomy): with no active plan, the governor (or pinned goal) chooses which plan to run.
    chose = nothing
    if isempty(d.plan)
        chose = _pick_goal(d, goal, adaptive)
        chose !== nothing && haskey(d.plans, chose) && (d.plan = copy(d.plans[chose]); d.frontier = 1)
    end
    # this tick's target = the current subgoal (frontier drives PLN selection), else the chosen/pinned goal.
    target = !isempty(d.plan) ? d.plan[d.frontier] : (chose !== nothing ? chose : goal)
    planned = !isempty(d.plan)
    # governor=nothing here ON PURPOSE: we already resolved the goal (a plan pins the SUBGOAL); passing the
    # governor to mid_step! with goal=nothing would make it act on the FINAL goal, firing the last step first.
    r = WorldModel.mid_step!(d.loop, obs; goal = target, governor = nothing)
    surprise = learn ? _learn_step!(d, r; hidden = hidden, epochs = epochs) : nothing

    name = r.action === nothing ? nothing : r.action[1]  # (id::String, score::Float64) → id
    op = args = result = decision = nothing
    success = false
    if name !== nothing && haskey(d.actions, name)
        op, args = d.actions[name]
        # live policy (honours a runtime reload, B6) + real op evidence for the TOCTOU snapshot (B5)
        result = governed(_live_policy(d), d.ledger, op, args, _OUTBOUND[op]; evidence = () -> _op_evidence(op, args))
        decision = startswith(result, "GATE[") ? :blocked : :allowed
        success = _action_success(d, decision, result)   # the `action-success?` MeTTa rule (once, reused below)
        if planned && success                            # advance the plan on a clean gated step
            d.frontier += 1
            d.frontier > length(d.plan) && (d.plan = String[]; d.frontier = 0)   # plan complete
        end
        if reinforce && target isa AbstractString        # reward channel (opt-in): learn from the outcome
            reinforce!(d, name, target, success)
        end
    end
    adaptive && (d.sense = _next_sense(d, surprise, success, decision === :blocked))   # perception → motive, next pick
    # ambient/slow rate (§7): after the goal-directed mid tick, run background consolidation on its own cadence.
    slow = nothing
    if ambient
        d.slow_pending += 1
        # BOTH triggers OR'd in MeTTa: ticks-since ($n) and wall-clock seconds-since ($dt, the idle trigger).
        if _should_consolidate(d, d.slow_pending, time() - d.last_slow)   # ← the MeTTa rule decides, not a constant
            slow = _ambient_step!(d)
        end
    end
    return (; action = name, op = op, args = args, decision = decision, result = result,
        goal = target, chose = chose, surprise = surprise, mid = r, slow = slow)
end

# Online forward-model step: surprise = how well the CURRENT Sdyn predicted this context from the last one;
# buffer the (prev → cur) transition; retrain Sdyn when the MeTTa cadence rule fires. Returns the surprise.
function _learn_step!(d::Driver, r; hidden::Int, epochs::Int)
    cur = copy(r.context_vector)                         # copy: lift! hands back the raw stored HMH .data ref
    surprise = nothing
    if d.prev_context !== nothing
        surprise = _forward_surprise(d, d.prev_context, cur)
        push!(d.transitions, (d.prev_context, cur))
        d.pending += 1
        if _should_retrain(d, d.pending, surprise)       # ← the MeTTa rule decides, not a Julia constant
            try
                WorldModel.train_dynamics!(d.reg, d.transitions;
                    hidden = hidden, epochs = epochs, adam = true, into = :Sdyn)   # AdamW: plain SGD diverges
                d.pending = 0
            catch
            end
        end
    end
    d.prev_context = cur
    return surprise
end

# ‖predict_dynamics(prev) − cur‖ under the CURRENT Sdyn model (nothing until a predictor is trained).
function _forward_surprise(d::Driver, prev::Vector{Float64}, cur::Vector{Float64})
    try
        pred = WorldModel.predict_dynamics(d.reg, prev)
        pred === nothing && return nothing
        return sqrt(sum(abs2, Float64.(pred) .- cur))
    catch
        return nothing
    end
end

# Evaluate the MeTTa cadence rule `(should-retrain <pending> <surprise>)` in the driver's learn-space.
# Returns True/False; any parse/eval failure ⇒ false (fail safe: don't retrain on garbage). `_SM =
# MeTTaCore.Interpreter` (from GroundedOps.jl, same module). A non-finite surprise is normalized to 0.0 so
# only the pending branch can fire.
function _should_retrain(d::Driver, pending::Int, surprise)::Bool
    s = (surprise === nothing || !isfinite(surprise)) ? 0.0 : Float64(surprise)
    try
        res = _SM.metta_run(_SM.parse_program("(should-retrain $pending $s)")[1][2], _policy_space(d))
        return !isempty(res) && string(res[1]) == "True"
    catch
        return false
    end
end

# ── ambient / slow rate — whitepaper §7 ambient background loop ───────────────
# The SLOW rate of the two-loop×3-rate architecture, driven for the first time here. `WorldModel.slow_step!`
# runs the ambient loop in one call: stale-belief revalidation (factor-graph PLN tightening), HMH schema
# `consolidate!` + WILLIAM `mine!` (recurring-structure detection → Smine), SubRep `admit_proposed!` → Sopt,
# MOSES/GEO-EVO `geo_synthesize!` → Sprog. Rate-limited by the `should-consolidate` MeTTa cadence atom (same
# idiom as `should-retrain`). `t = loop.tick` is the monotonic belief-decay time (mid_step! advances it). Fail-
# safe: the ambient step is best-effort background work — a failure never breaks the agent's goal-directed tick.
# `n` = mid-ticks since the last ambient step; `dt` = wall-clock SECONDS since it (the idle trigger). A
# non-finite/negative dt is clamped to 0.0 so only the tick branch can fire on a bad clock reading.
function _should_consolidate(d::Driver, n::Int, dt::Real = 0.0)::Bool
    s = (dt === nothing || !isfinite(dt) || dt < 0) ? 0.0 : Float64(dt)
    try
        res = _SM.metta_run(_SM.parse_program("(should-consolidate $n $s)")[1][2], _policy_space(d))
        return !isempty(res) && string(res[1]) == "True"
    catch
        return false
    end
end

# Fire one ambient/slow step and RESET BOTH cadence clocks (tick counter + wall clock). Every path that
# consolidates goes through here — the tick cadence, and the idle self-wake in run_agent! — so the two
# triggers can never drift apart. Best-effort: a failure never breaks the agent's goal-directed tick, but
# the clocks still reset so a persistently-failing organ can't spin every tick.
function _ambient_step!(d::Driver)
    d.slow_pending = 0
    d.last_slow = time()
    try
        return WorldModel.slow_step!(d.loop; t = Float64(d.loop.tick))
    catch
        return nothing
    end
end

# Lazily build the driver's POLICY space: Core stdlib (>=, and, not, if, arithmetic …) + the cadence rule +
# the cognitive-control policy rules (appraise / action-success? / evidence->stv / initial-sense). Cached on
# the driver so the stdlib load is paid ONCE, and only by drivers that actually evaluate policy.
function _policy_space(d::Driver)
    if d.learn_space === nothing
        sp = _SM.Space()
        _SM.load_core_stdlib!(sp)
        # …and the canonical PLN library, so policy rules can DELEGATE to `Truth_w2c`/`EvidenceConfidence`
        # rather than re-deriving them. Without this the space held only stdlib.metta + CoreExtensions.metta
        # (neither of which defines `Truth_w2c`), so `evidence->stv` had no canonical formula in scope and
        # was forced to spell the confidence map out again — a second copy that could not be collapsed.
        # Loaded through `pln.metta`, the library's own ENTRY POINT, so this space gets whatever the library
        # exports rather than a hand-picked subset that can drift from it.
        _SM.load_metta!(sp, "!(import! &self \"$(_LIBPLN_ENTRY)\")")
        _SM.load_metta!(sp, d.learn_rule)
        _SM.load_metta!(sp, d.consolidate_rule)
        _SM.load_metta!(sp, d.policy_rules)
        d.learn_space = sp
    end
    return d.learn_space
end

# Evaluate `expr` in the driver's policy space and marshal a `(head v1 v2 …)` result to a Float64 vector
# (e.g. `(stimulus …)`, `(STV …)`); nothing on any parse/eval failure (callers fail safe to a native value).
function _policy_vec(d::Driver, expr::AbstractString, head::AbstractString)
    try
        res = _SM.metta_run(_SM.parse_program(expr)[1][2], _policy_space(d))
        isempty(res) && return nothing
        m = match(Regex("\\(" * head * "\\s+([-0-9.eE ]+)\\)"), string(res[1]))
        m === nothing ? nothing : [parse(Float64, t) for t in split(strip(m.captures[1]))]
    catch
        return nothing
    end
end

# Same, for a policy rule the agent CANNOT run without. Fails LOUD instead of failing SAME.
#
# `_policy_vec` collapses "the rule is missing", "it threw", and "it returned a shape I don't recognise"
# all into `nothing`, and each caller then substituted a hand-written Julia twin of the very formula that
# just failed. That makes a rewritable atom UNREWRITABLE-OUT: a MOSES/GEO-EVO edit that renames the
# constructor or leaves a term unreduced silently reverts the agent to the original numbers with zero
# signal — and, because the twin was numerically identical on the default inputs, the test that claimed to
# prove "policy is a MeTTa atom, not hardcoded Julia" passed with the MeTTa rule DELETED.
# A truth value written into the metagraph from a hardcoded Julia constant, while the policy that was
# supposed to produce it is broken, is worse than stopping. So: stop, and say which rule.
function _policy_vec_req(d::Driver, expr::AbstractString, head::AbstractString, rule::AbstractString)
    v = _policy_vec(d, expr, head)
    v === nothing && throw(ArgumentError(
        "OmegaClaw policy rule `$rule` did not yield a `($head …)` for `$expr`. The cognitive-control " *
        "policy is a required MeTTa atom — it has no Julia substitute. Check the `policy_rules` this " *
        "driver was built with (a rewrite that renames the constructor or leaves a term unreduced lands " *
        "here), or that `Core/lib/pln` loaded (`$(_LIBPLN_ENTRY)`)."))
    return v
end

# What COUNTS as a successful action — the `action-success?` MeTTa rule (fail-safe to the native predicate).
function _action_success(d::Driver, decision, result)::Bool
    dsym = decision === :allowed ? "allowed" : decision === :blocked ? "blocked" : "none"
    err = result isa AbstractString && startswith(result, "ERROR")
    try
        res = _SM.metta_run(_SM.parse_program("(action-success? $dsym $(err ? "True" : "False"))")[1][2], _policy_space(d))
        return !isempty(res) && string(res[1]) == "True"
    catch
        return decision === :allowed && !err
    end
end

# The agent's prior affect disposition — the `initial-sense` rule (fail-safe to the neutral baseline).
_initial_sense(d::Driver) = (v = _policy_vec(d, "(initial-sense)", "stimulus"); v === nothing ? [0.1, 0.5, 0.1, 0.3] : v)
