# adaptive_demo.jl — ADAPTIVE autonomy: the agent's motive state EVOLVES from its own experience.
#
#   julia --project=OmegaClaw OmegaClaw/demo/adaptive_demo.jl
#
# Closes the loop into a self-modifying one. Each tick the agent's stimulus is derived from what it just
# experienced — surprise → novelty (the Sdyn prediction error), gate-ALLOW → conduciveness, gate-BLOCK → risk
# (MetaMo's own (novelty,conduciveness,risk,effort) channels). That stimulus drives the OpenPsi appraisal Ψ,
# which updates the 6 modulators (the affect state), which are carried forward and shape the NEXT goal choice.
# So the governor is no longer fixed: perception → motive → goal → action → learning → perception … evolves.

haskey(ENV, "OMEGACLAW_TRUST_KEY") || (ENV["OMEGACLAW_TRUST_KEY"] = "omegaclaw-demo-trust-key-0123456789abcdef")
using OmegaClaw

r3(x) = round(x; digits = 2)

function run_adaptive_demo(io::IO = stdout)
    println(io, "═"^66)
    println(io, " OmegaClaw — ADAPTIVE autonomy (the motive state evolves from experience)")
    println(io, "═"^66)

    policy = Policy(Set(["echo"]), Regex[], Regex[], Regex[], Regex[], "demo", "demo", true, false, nothing)
    # two candidate goals; a MAGUS governor. mods start neutral (0.5) and will EVOLVE tick-to-tick.
    governor = (goals = [0.25, 0.75, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5], mods = fill(0.5, 6),
                stimulus = [0.2, 0.5, 0.1, 0.3],
                candidates = [
                    (id = "explore", corrs = [0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0], risk = 0.0, dg = fill(0.05, 8)),
                    (id = "settle",  corrs = [0.0, 0.0, 0.2, 0.2, 0.2, 0.2, 0.2, 0.2], risk = 0.3, dg = zeros(8)) ])

    print(io, "\n▸ building an adaptive agent over the real WorldModel … ")
    d = Driver(; store = mktempdir(), policy = policy, ledger = Ledger(),
        governor = governor, learn_rule = "(= (should-retrain \$n \$s) (>= \$n 3))")   # retrain early so surprise moves
    seed!(d, "look", "explore", "echo", ["exploring"])
    seed!(d, "rest", "settle", "echo", ["settling"])
    println(io, "ready — goals: explore / settle; modulators start neutral (0.5)")

    println(io, "\n── the agent runs (adaptive=true, learn=true) — stimulus comes from experience ──")
    println(io, "    tick  novelty  chose     action  │ valence arousal  (the evolving affect state)")
    inputs = ["alpha", "beta", "gamma", "delta", "delta", "delta", "delta"]
    for (t, raw) in enumerate(inputs)
        r = step!(d, raw; adaptive = true, learn = true, hidden = 16, epochs = 30)
        m = d.governor.mods
        println(io, "    $(rpad(t, 5)) $(rpad(r3(d.sense[1]), 8)) $(rpad(r.chose, 9)) $(rpad(string(r.action), 7)) │ " *
                    "$(rpad(r3(m[1]), 7)) $(r3(m[2]))")
    end

    println(io, "\n── what happened ──")
    println(io, "    the stimulus was NOT a fixed input — each tick it was (novelty,conduciveness,risk,effort)")
    println(io, "    derived from the agent's surprise + gate outcomes; the OpenPsi appraisal turned that into")
    println(io, "    a shifting modulator (affect) state that fed the next goal choice.")
    println(io, "    modulators now: $(r3.(d.governor.mods))   (started $([0.5,0.5,0.5,0.5,0.5,0.5]))")
    println(io, "    ledger: $(length(d.ledger.entries)) gated decisions, verify → $(verify_ledger(d.ledger))")
    println(io, "\n" * "═"^66)
    println(io, " the agent's motive is now DYNAMIC — a perception→motive→goal→action→")
    println(io, " learning loop that modifies itself, not a fixed governor.")
    println(io, "═"^66)
    return d
end

run_adaptive_demo()
