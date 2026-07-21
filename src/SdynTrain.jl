# SdynTrain.jl — train Sdyn (the FabricPC dynamics Space) as the driver's forward-prediction organ.
#
# ADR-061 "Sdyn in-loop training" gap. The WorldModel braid DECIDES (PLN/MetaMo in mid_step!); Sdyn is the
# FAST reflex forward model that predict_dynamics/fast_step! run each tick (Loops.jl:59-66). But
# seed_world_model! attaches NO Sdyn predictor and NOTHING in the WM/OmegaClaw tree ever called train_pcn —
# so fast_step! short-circuits to `nothing` (Loops.jl:62) and the graph, once attached, stays at its
# `initialize_params` weights (Dense.jl:51). This module closes that gap:
#   1. gather_transitions — drive the agent and snapshot the per-tick Sctx context vector, zip consecutive
#      ticks into (x_t → x_{t+1}) pairs.
#   2. train_sdyn! — fit the Sdyn FabricPC x→h→y forward model on those pairs and write the trained params
#      back into the Sdyn dense store, so predict_dynamics/fast_step! become a LEARNED forward model.
#
# It stays a clean OmegaClaw module: the FabricPC coupling lives entirely behind WorldModel.train_dynamics!
# (WorldModel already owns the DenseStore.model handle and is the only layer that touches FabricPC), so
# OmegaClaw gains NO new dependency. Included INTO `module OmegaClaw`; `Driver`/`step!` are unqualified,
# `WorldModel` is `import`ed by Driver.jl.

"""
    gather_transitions(d::Driver, inputs; goal=d.goal)
        -> Vector{Tuple{Vector{Float64},Vector{Float64}}}

Drive the OmegaClaw agent over `inputs` (one raw perception string per tick) and collect the per-tick Sctx
context vector `step!(d, raw).mid.context_vector` (a 1024-dim `Vector{Float64}`; `Loops.jl:96`), then zip
consecutive ticks into `(x_t → x_{t+1})` transitions. `mid_step!` runs before any early return in `step!`
(`Driver.jl:107`), so the context vector exists every tick even when no action fires.

`copy()` is load-bearing: `lift!` returns the raw stored HMH `.data` reference (`Braid.jl:121`,
`HMHStore.jl:88`), so two ticks that retrieve the same top-1 episode would otherwise alias the same buffer.
"""
function gather_transitions(d::Driver, inputs::AbstractVector{<:AbstractString}; goal = d.goal)
    ctxs = Vector{Vector{Float64}}()
    for raw in inputs
        r = step!(d, raw; goal = goal)                 # runs mid_step! → context_vector (Driver.jl:107)
        push!(ctxs, copy(r.mid.context_vector))        # copy() beats the top-1 HMH aliasing gotcha
    end
    return [(ctxs[i], ctxs[i + 1]) for i in 1:(length(ctxs) - 1)]
end

"""
    train_sdyn!(d::Driver, transitions; hidden=64, epochs=100, lr=0.01, adam=false, rng=nothing)
        -> (; store, energies, first_energy, last_energy, n)

Build/train the Sdyn FabricPC `x → h → y` forward model on the gathered `(x_t → x_{t+1})` `transitions` and
write the trained params back into the Sdyn dense store, so `predict_dynamics`/`fast_step!` become a LEARNED
forward model. Delegates to `WorldModel.train_dynamics!` (which attaches a fresh predictor sized to the data
if none is bound, calls FabricPC `train_pcn` — local PC learning, no backprop — and writes back
`dense_store(reg,:Sdyn).model`). `adam=true` uses AdamW instead of plain SGD; pass an `rng` for determinism.
Returns the store plus the first/last per-batch energy of the run as a quick learning signal.
"""
function train_sdyn!(d::Driver, transitions::AbstractVector;
    hidden::Int = 64, epochs::Real = 100, lr::Real = 0.01, adam::Bool = false, rng = nothing)
    isempty(transitions) && error("train_sdyn!: no transitions — call gather_transitions first")
    rngkw = rng === nothing ? (;) : (; rng = rng)      # let WorldModel.train_dynamics! own the default rng
    store, energies = WorldModel.train_dynamics!(d.reg, transitions;
        hidden = hidden, lr = lr, epochs = epochs, adam = adam, into = :Sdyn, rngkw...)
    e_first = (isempty(energies) || isempty(first(energies))) ? NaN : Float64(first(first(energies)))
    e_last  = (isempty(energies) || isempty(last(energies)))  ? NaN : Float64(first(last(energies)))
    return (; store = store, energies = energies, first_energy = e_first, last_energy = e_last,
        n = length(transitions))
end
