# Channels.jl — the agent's IO layer (perception in / action out).
#
# A pluggable channel abstraction: the native CLI (stdin→stdout, no Python) and an in-memory buffer
# channel (for tests / embedding). `run_agent!` is the interactive loop that ties a channel to the driver:
# poll input → drive WorldModel (perceive → PLN decide → gate → capability → optional learn) → emit result.

abstract type OmegaChannel end

# poll for the next input (nothing ⇒ exhausted); emit a result. (Internal generics — not Base.receive/send.)
poll(::OmegaChannel)::Union{String,Nothing} = error("poll not implemented for this channel")
emit(::OmegaChannel, ::AbstractString) = error("emit not implemented for this channel")

"An in-memory channel: a fixed input queue + captured outputs. For tests and embedding."
mutable struct BufferChannel <: OmegaChannel
    inputs::Vector{String}
    outputs::Vector{String}
    idx::Int
end
BufferChannel(inputs = String[]) = BufferChannel(collect(String, inputs), String[], 0)

function poll(ch::BufferChannel)::Union{String,Nothing}
    ch.idx += 1
    return ch.idx <= length(ch.inputs) ? ch.inputs[ch.idx] : nothing
end
emit(ch::BufferChannel, msg::AbstractString) = (push!(ch.outputs, String(msg)); nothing)

"The native CLI channel (stdin → stdout)."
struct CLIChannel <: OmegaChannel
    prompt::String
end
CLIChannel(; prompt::AbstractString = "you> ") = CLIChannel(String(prompt))

function poll(ch::CLIChannel)::Union{String,Nothing}
    print(ch.prompt); flush(stdout)
    eof(stdin) && (println(); return nothing)
    line = readline(stdin; keep = false)
    return (eof(stdin) && isempty(line)) ? nothing : line
end
emit(::CLIChannel, msg::AbstractString) = (println("agent> ", msg); nothing)

"""
    run_agent!(d, ch; goal=d.goal, reinforce=false, max_turns=100) -> Int

The interactive agent loop: poll the channel → `step!` the driver (perceive → decide → gate → act →
optional reinforce) → emit the result. Runs until the channel is exhausted or `max_turns`. Returns the
number of turns taken.
"""
function run_agent!(d::Driver, ch::OmegaChannel; goal = d.goal, reinforce::Bool = false,
    ambient::Bool = false, max_turns::Int = 100)
    turns = 0
    while turns < max_turns
        input = poll(ch)
        if input === nothing
            # IDLE SELF-WAKE (§7 ambient loop): there is no input to react to, so spend the idle moment on
            # background maintenance instead of exiting with consolidation still pending. Upstream
            # (mettaclaw/OmegaClaw-Core) does the same on a `get_time` deadline once its per-message budget
            # empties; here the decision is the SAME editable MeTTa `should-consolidate` rule the tick cadence
            # uses — so "consolidate when idle" is policy ($dt ≥ idle-secs), not a hardcoded flush-on-exit.
            ambient && _should_consolidate(d, d.slow_pending, time() - d.last_slow) && _ambient_step!(d)
            break
        end
        r = step!(d, input; goal = goal, reinforce = reinforce, ambient = ambient)
        emit(ch, r.result === nothing ? "(no action for goal)" : r.result)
        turns += 1
    end
    return turns
end
