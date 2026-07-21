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
    policy::Policy
    ledger::Ledger
    actions::Dict{String,Tuple{String,Vector{String}}}   # action_id => (op_name, args)
    goal::Union{String,Nothing}
    governor::Any                                         # MetaMo (; goals,mods,stimulus,candidates) | nothing
end

function Driver(; store::AbstractString = mktempdir(),
    policy::Policy = DEFAULT_POLICY[], ledger::Ledger = DEFAULT_LEDGER[],
    goal::Union{AbstractString,Nothing} = nothing, governor = nothing)
    reg = WorldModel.SpaceRegistry(WorldModel.manifest(; store = store))
    WorldModel.seed_world_model!(reg)
    loop = WorldModel.CognitiveLoop(reg)
    return Driver(reg, loop, policy, ledger,
        Dict{String,Tuple{String,Vector{String}}}(),
        goal === nothing ? nothing : String(goal), governor)
end

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
function step!(d::Driver, raw::AbstractString; goal = d.goal)
    obs = _perceive(raw, d.loop.tick)
    r = WorldModel.mid_step!(d.loop, obs; goal = goal, governor = d.governor)
    r.action === nothing &&
        return (; action = nothing, op = nothing, args = nothing, decision = nothing, result = nothing, mid = r)
    name = r.action[1]                                   # (id::String, score::Float64) → id
    haskey(d.actions, name) ||
        return (; action = name, op = nothing, args = nothing, decision = nothing, result = nothing, mid = r)
    op, args = d.actions[name]
    result = governed(d.policy, d.ledger, op, args, _OUTBOUND[op])
    decision = startswith(result, "GATE[") ? :blocked : :allowed
    return (; action = name, op = op, args = args, decision = decision, result = result, mid = r)
end
