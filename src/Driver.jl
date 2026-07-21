# Driver.jl — the governed agent loop (ADR-061 D2/S5).
#
# WorldModel DECIDES (PLN action-selection + MetaMo motive); OmegaClaw's gate is the ONLY seam to the
# world; the LLM/FabricPC is (later) the language/perception organ. One tick:
#   perceive(raw) → mid_step!(WM decides) → PLN action id → (op,args) → governed() → result → feed back.
# Included INTO `module OmegaClaw`, so `governed`/`_OUTBOUND`/`DEFAULT_POLICY`/`DEFAULT_LEDGER`/`Policy`/
# `Ledger` are in scope unqualified. `import WorldModel` (not `using`) — WM exports (add!/select_action/…)
# would collide, so every WM reference is qualified.

import WorldModel

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
    learn_rule::String                                   # MeTTa `should-retrain` cadence rule (editable = re-schedule)
    learn_space::Any                                     # lazily-built Core space (stdlib + learn_rule); nothing until used
    goal::Union{String,Nothing}
    governor::Any                                         # MetaMo (; goals,mods,stimulus,candidates) | nothing
end

function Driver(; store::AbstractString = mktempdir(),
    policy::Union{Policy,Nothing} = nothing, ledger::Ledger = DEFAULT_LEDGER[],
    learn_rule::AbstractString = DEFAULT_LEARN_RULE,
    goal::Union{AbstractString,Nothing} = nothing, governor = nothing)
    reg = WorldModel.SpaceRegistry(WorldModel.manifest(; store = store))
    WorldModel.seed_world_model!(reg)
    loop = WorldModel.CognitiveLoop(reg)
    return Driver(reg, loop, policy, ledger,
        Dict{String,Tuple{String,Vector{String}}}(), Dict{String,Tuple{Int,Int}}(),
        Tuple{Vector{Float64},Vector{Float64}}[], nothing, 0, String(learn_rule), nothing,
        goal === nothing ? nothing : String(goal), governor)
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
    d.outcomes[String(action_id)] = (s1, n1)
    strength = s1 / n1
    confidence = n1 / (n1 + k)                            # 0.5 at 1 attempt → 0.9 at 9
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
function seed!(d::Driver, action_id::AbstractString, goal::AbstractString,
    op::AbstractString, args::Vector{String}; s::Real = 0.9, c::Real = 0.9, t::Real = 0.0)
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
    step!(d, raw; goal=d.goal) -> NamedTuple

One agent tick. Returns `(; action, op, args, decision, result, mid)`; `decision ∈ (:allowed, :blocked,
nothing)`. `action === nothing` (no goal / no matching rule / unbound id) is a NORMAL "no action this tick".
Feed `result` back as the next `raw` to close the loop.
"""
function step!(d::Driver, raw::AbstractString; goal = d.goal, reinforce::Bool = false,
    learn::Bool = false, hidden::Int = 32, epochs::Int = 80)
    obs = _perceive(raw, d.loop.tick)
    r = WorldModel.mid_step!(d.loop, obs; goal = goal, governor = d.governor)
    # online forward-model (Sdyn) learning: measure surprise, buffer the transition, retrain when the MeTTa
    # cadence rule fires (no Julia `retrain_every` constant — the schedule is `d.learn_rule`)
    surprise = learn ? _learn_step!(d, r; hidden = hidden, epochs = epochs) : nothing
    r.action === nothing &&
        return (; action = nothing, op = nothing, args = nothing, decision = nothing, result = nothing, surprise = surprise, mid = r)
    name = r.action[1]                                   # (id::String, score::Float64) → id
    haskey(d.actions, name) ||
        return (; action = name, op = nothing, args = nothing, decision = nothing, result = nothing, surprise = surprise, mid = r)
    op, args = d.actions[name]
    # live policy (honours a runtime reload, B6) + real op evidence for the TOCTOU snapshot (B5)
    result = governed(_live_policy(d), d.ledger, op, args, _OUTBOUND[op]; evidence = () -> _op_evidence(op, args))
    decision = startswith(result, "GATE[") ? :blocked : :allowed
    if reinforce && r.goal isa AbstractString            # reward channel (opt-in): learn from the outcome
        success = decision === :allowed && !startswith(result, "ERROR")
        reinforce!(d, name, r.goal, success)
    end
    return (; action = name, op = op, args = args, decision = decision, result = result, surprise = surprise, mid = r)
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
        res = _SM.metta_run(_SM.parse_program("(should-retrain $pending $s)")[1][2], _learn_space(d))
        return !isempty(res) && string(res[1]) == "True"
    catch
        return false
    end
end

# Lazily build the driver's learn-space: Core stdlib (for >=, or, > …) + the `should-retrain` rule. Cached
# on the driver so the stdlib load is paid once, and only by drivers that actually learn.
function _learn_space(d::Driver)
    if d.learn_space === nothing
        sp = _SM.Space()
        _SM.load_core_stdlib!(sp)
        _SM.load_metta!(sp, d.learn_rule)
        d.learn_space = sp
    end
    return d.learn_space
end
