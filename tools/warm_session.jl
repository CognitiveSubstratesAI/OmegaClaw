# tools/warm_session.jl — PERSISTENT warm MeTTaCore session with Revise hot-reload + a file-command
# loop (mirrors FabricPC's). Loads MeTTaCore ONCE; evaluates snippets on demand by watching
# `.warm/seq`, running `.warm/in.jl`, writing stdout/stderr to `.warm/out.txt`, echoing the seq into
# `.warm/done`. Round-trips are warm (<1s). Revise hot-reloads src/ edits between snippets — AND,
# because MorkSupercompiler is a PATH-dep of Core, edits to its src/ (e.g. SCPipeline.jl) hot-reload
# too. So iterating on Core OR the supercompiler needs NO cold restart.
#
# Start (persistent):  systemd-run --user --unit=omegaclaw-warm --working-directory=$PWD \
#                          $(which julia) --project=. tools/warm_session.jl
# Drive it:            tools/warm_send.sh <snippet.jl>
# Revise MUST load before MeTTaCore so it tracks both packages' src/ files for hot-reload.
try
    using Revise
catch
    @warn "Revise unavailable — src edits will NOT hot-reload"
end
using OmegaClaw
import WorldModel

const ROOT = abspath(joinpath(@__DIR__, ".."))
# Pin the working directory to the PROJECT ROOT. Snippets arrive as strings via `include_string`, so
# any relative `include("test/runtests.jl")` in them resolves against `pwd()` — which was whatever
# directory the session happened to be LAUNCHED from. Launch from tools/ and it silently looks for
# tools/test/runtests.jl. Same class as everything else fixed here: the caller's result depended on
# invocation trivia rather than on the code under test.
cd(ROOT)
# …and REBIND `Main.include` to resolve against the root too. `cd` alone does NOT fix it and neither
# does anchoring `include_string`'s filename: when julia runs a script, it binds `Main.include` to
# THAT SCRIPT'S directory, so a snippet's `include("test/runtests.jl")` looked for
# tools/test/runtests.jl no matter what pwd() or the source-path anchor said. Both were tried and
# measured before landing this. Snippets are sent from the project root by every caller, so the root
# is the only defensible base.
# `const` is REQUIRED: `Main.include` is a bound closure, not a generic function, so a method
# definition dies with "cannot define function include; it already has a value" and a plain
# assignment with "invalid assignment to constant Main.include". Both were tried.
#
# The DEPTH FLAG is required too. Anchoring every relative include at the root also rewrote the
# NESTED ones — `test/runtests.jl` doing `include("test_corespace.jl")` went looking for it at the
# root and died. Only the snippet's own top-level include should be anchored; everything deeper must
# resolve against the file that included it. `Base.source_path(nothing)` alone can't distinguish
# them: at snippet top level it reports the SESSION SCRIPT, not the snippet, even when
# `include_string` is handed an anchored filename (measured).
Core.eval(Main, :(const _WARM_TOP = Ref(true)))
Core.eval(Main, :(const include = function (p::AbstractString)
    isabspath(p) && return Base.include(Main, p)
    if _WARM_TOP[]                                   # snippet's own include → project root
        _WARM_TOP[] = false
        try
            return Base.include(Main, joinpath($ROOT, p))
        finally
            _WARM_TOP[] = true
        end
    end
    sp = Base.source_path(nothing)                   # nested → relative to the including file
    Base.include(Main, joinpath(sp === nothing ? $ROOT : dirname(sp), p))
end))
const DIR  = joinpath(ROOT, ".warm")
mkpath(DIR)
const INF  = joinpath(DIR, "in.jl")
const OUTF = joinpath(DIR, "out.txt")
const SEQF = joinpath(DIR, "seq")
const DONE = joinpath(DIR, "done")
const STATUSF = joinpath(DIR, "status")   # "0"/"1" — see the STATUS note in _serve
function _serve()
    rm(INF; force = true); rm(DONE; force = true); rm(STATUSF; force = true)
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
                # STATUS: 0 = snippet completed, 1 = it threw (or revise refused it).
                # WHY THIS EXISTS (2026-07-23): this harness was EXIT-CODE BLIND. The snippet's
                # exception was caught, written to out.txt, and then `warm_send.sh` exited 0 — so a
                # FAILING TEST SUITE reported success to any caller. Verified end-to-end: a testset
                # containing `@test 1 == 2` exits 0 through this path and 1 under plain `julia file.jl`.
                # (`julia -i` with piped stdin is the same trap — interactive mode swallows, so
                # MORK's mandated `printf '…' | julia -i tools/repl.jl` also always exits 0.)
                # Consequence: every "green" warm-session result was read off PRINTED TEXT, never an
                # exit code, and automation would see success unconditionally. A Julia testset throws
                # `Some tests did not pass: …` at the end, so catching that throw IS the right signal —
                # failures AND errors both land here.
                status = 0
                open(OUTF, "w") do io
                    redirect_stdout(io) do
                        redirect_stderr(io) do
                            if revise_fail !== nothing
                                println(io, "REVISE FAILED — refusing to run this snippet (session would be STALE):")
                                showerror(io, revise_fail[1], revise_fail[2])
                                println(io)
                                status = 1
                            else
                                try
                                    # The 3rd arg ANCHORS relative `include`s in the snippet at the
                                    # PROJECT ROOT. Without it Julia resolves them against the
                                    # directory of the file that called `include_string` — i.e.
                                    # tools/ — so `include("test/runtests.jl")` went looking for
                                    # tools/test/runtests.jl and died. `cd(ROOT)` above is NOT
                                    # sufficient: `include` uses the source-file context, not pwd().
                                    Base.include_string(Main, code, joinpath(ROOT, "warm_snippet.jl"))
                                catch e
                                    showerror(io, e, catch_backtrace())
                                    println(io)
                                    status = 1
                                end
                            end
                        end
                    end
                end
                write(STATUSF, string(status))   # BEFORE `done`, so a waiter polling `done` can read it
                write(DONE, n)
            end
        end
        sleep(0.15)
    end
end

_serve()
