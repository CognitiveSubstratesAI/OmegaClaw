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
mutable struct Driver
    reg::WorldModel.SpaceRegistry
    loop::WorldModel.CognitiveLoop
    policy::Union{Policy,Nothing}                         # nothing ⇒ read the LIVE DEFAULT_POLICY[] each tick (B6)
    ledger::Ledger
    actions::Dict{String,Tuple{String,Vector{String}}}   # action_id => (op_name, args)
    outcomes::Dict{String,Tuple{Int,Int}}                # action_id => (successes, attempts) — reinforcement stats
    goal::Union{String,Nothing}
    governor::Any                                         # MetaMo (; goals,mods,stimulus,candidates) | nothing
end

function Driver(; store::AbstractString = mktempdir(),
    policy::Union{Policy,Nothing} = nothing, ledger::Ledger = DEFAULT_LEDGER[],
    goal::Union{AbstractString,Nothing} = nothing, governor = nothing)
    reg = WorldModel.SpaceRegistry(WorldModel.manifest(; store = store))
    WorldModel.seed_world_model!(reg)
    loop = WorldModel.CognitiveLoop(reg)
    return Driver(reg, loop, policy, ledger,
        Dict{String,Tuple{String,Vector{String}}}(), Dict{String,Tuple{Int,Int}}(),
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
function step!(d::Driver, raw::AbstractString; goal = d.goal, reinforce::Bool = false)
    obs = _perceive(raw, d.loop.tick)
    r = WorldModel.mid_step!(d.loop, obs; goal = goal, governor = d.governor)
    r.action === nothing &&
        return (; action = nothing, op = nothing, args = nothing, decision = nothing, result = nothing, mid = r)
    name = r.action[1]                                   # (id::String, score::Float64) → id
    haskey(d.actions, name) ||
        return (; action = name, op = nothing, args = nothing, decision = nothing, result = nothing, mid = r)
    op, args = d.actions[name]
    # live policy (honours a runtime reload, B6) + real op evidence for the TOCTOU snapshot (B5)
    result = governed(_live_policy(d), d.ledger, op, args, _OUTBOUND[op]; evidence = () -> _op_evidence(op, args))
    decision = startswith(result, "GATE[") ? :blocked : :allowed
    if reinforce && r.goal isa AbstractString            # reward channel (opt-in): learn from the outcome
        success = decision === :allowed && !startswith(result, "ERROR")
        reinforce!(d, name, r.goal, success)
    end
    return (; action = name, op = op, args = args, decision = decision, result = result, mid = r)
end
