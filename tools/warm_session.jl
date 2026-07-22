# tools/warm_session.jl — PERSISTENT warm OmegaClaw session with Revise hot-reload + a file-command loop.
#
# Mirrors Core/tools/warm_session.jl exactly (same protocol, same Revise discipline), but loads the AGENT
# stack: OmegaClaw → WorldModel → MeTTaCore, all of which are path-deps, so Revise tracks every `src/` in
# the chain. Editing OmegaClaw/src, WorldModel/src OR Core/src hot-reloads here with NO cold restart —
# which is the point: `test/runtests.jl` for these two packages was the last thing in the tree that still
# needed a ~60-90s cold start per iteration, and the project's own rule is warm-only.
#
# ONE session serves BOTH suites — OmegaClaw's Project.toml has WorldModel as a path-dep, so
# `include("../WorldModel/test/runtests.jl")` runs in the same warm process.
#
# Start (persistent):  systemd-run --user --unit=omegaclaw-warm --working-directory=$PWD \
#                          $(which julia) --project=. tools/warm_session.jl
# Drive it:            tools/warm_send.sh <snippet.jl>
# Revise MUST load before the packages so it tracks all three src/ trees for hot-reload.
try
    using Revise
catch
    @warn "Revise unavailable — src edits will NOT hot-reload"
end
using OmegaClaw
import WorldModel      # ensure Revise tracks the path-dep's src/ (Loops.jl, PLNCore.jl, Beliefs.jl …)
import MeTTaCore       # …and the interpreter + lib/pln underneath it

const DIR  = abspath(joinpath(@__DIR__, "..", ".warm"))
mkpath(DIR)
const INF  = joinpath(DIR, "in.jl")
const OUTF = joinpath(DIR, "out.txt")
const SEQF = joinpath(DIR, "seq")
const DONE = joinpath(DIR, "done")
function _serve()
    rm(INF; force = true); rm(DONE; force = true)
    write(joinpath(DIR, "ready"), "1")
    println("WARM SESSION READY (OmegaClaw + WorldModel + MeTTaCore loaded)")
    seen = ""
    while true
        if isfile(SEQF) && isfile(INF)
            n = strip(read(SEQF, String))
            if n != seen && !isempty(n)
                seen = n
                code = read(INF, String)
                # Revise FIRST, and surface failures LOUDLY. A bare `catch; end` here was the
                # swallow-revise-errors bug (feedback_warm_harness_swallows_revise_errors): a failed
                # revision drains the queue, throws, gets swallowed, and the session silently runs
                # STALE code — a silent-wrong-answer machine. `throw=true` + REFUSE to run the snippet
                # on failure, so a stale result can never masquerade as a fresh one.
                revise_fail = nothing
                if isdefined(Main, :Revise)
                    try
                        Base.invokelatest(Main.Revise.revise; throw = true)
                    catch e
                        revise_fail = (e, catch_backtrace())
                    end
                end
                open(OUTF, "w") do io
                    redirect_stdout(io) do
                        redirect_stderr(io) do
                            if revise_fail !== nothing
                                println(io, "REVISE FAILED — refusing to run this snippet (session would be STALE):")
                                showerror(io, revise_fail[1], revise_fail[2])
                                println(io)
                            else
                                try
                                    Base.include_string(Main, code)
                                catch e
                                    showerror(io, e, catch_backtrace())
                                    println(io)
                                end
                            end
                        end
                    end
                end
                write(DONE, n)
            end
        end
        sleep(0.15)
    end
end

_serve()
