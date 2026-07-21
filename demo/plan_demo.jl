# plan_demo.jl — AUTONOMOUS multi-step OmegaClaw: MetaMo chooses the goal, the agent executes a gated PLAN.
#
#   julia --project=OmegaClaw OmegaClaw/demo/plan_demo.jl
#
# The agent must reach `shelter`, which NO single reflex covers — it requires `gather` (echo) THEN `build`
# (write-file). MetaMo picks `shelter` over `idle` from its OpenPsi motive state (positive goal-correlations,
# zero risk); the Driver then walks the subgoal ladder, one GATED capability per tick, until shelter is built.
# Nothing is scripted-per-tick: the goal is chosen by cognition and the sequence is derived from the plan.

haskey(ENV, "OMEGACLAW_TRUST_KEY") || (ENV["OMEGACLAW_TRUST_KEY"] = "omegaclaw-demo-trust-key-0123456789abcdef")
using OmegaClaw

function run_plan_demo(io::IO = stdout)
    println(io, "═"^66)
    println(io, " OmegaClaw — AUTONOMOUS multi-step plan (MetaMo chooses, agent executes)")
    println(io, "═"^66)

    policy = Policy(Set(["echo", "write-file"]), Regex[], Regex[], Regex[], Regex[], "demo", "demo", true, false, nothing)
    hut = joinpath(mktempdir(), "hut")

    # A MetaMo governor over two candidate goals: `shelter` = positive goal-correlations + zero risk;
    # `idle` = negative correlations + high risk. metamoGovern (Ψ→𝔻→MAGUS) will prefer `shelter`.
    governor = (goals = [0.25, 0.75, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5], mods = fill(0.5, 6),
                stimulus = [0.2, 0.8, 0.1, 0.2],
                candidates = [
                    (id = "shelter", corrs = [0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0], risk = 0.0, dg = fill(0.05, 8)),
                    (id = "idle",    corrs = [0.0, 0.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0], risk = 1.0, dg = zeros(8)) ])

    print(io, "\n▸ building an autonomous agent over the real WorldModel … ")
    d = Driver(; store = mktempdir(), policy = policy,
        ledger = Ledger(; path = joinpath(mktempdir(), "plan.ledger.jsonl")), governor = governor)
    println(io, "ready")

    # A 2-step plan for a goal no single reflex reaches: gather → build ≡ shelter.
    seed_plan!(d, "shelter", [("gather", "echo", ["gathered-wood"]),
                              ("build", "write-file", [hut, "shelter-built"])])
    println(io, "    goals MetaMo may pursue:  shelter (needs gather→build)   vs   idle")
    println(io, "    no single reflex reaches `shelter` — it MUST be planned + sequenced")

    println(io, "\n── the agent runs (no explicit goal — MetaMo decides) ──")
    for t in 1:2
        r = step!(d, "survey the area")                     # NO goal passed — the governor picks it
        t == 1 && println(io, "    MetaMo chose goal → $(r.chose)   (over `idle`)")
        v = r.decision === :allowed ? "ALLOW → $(r.result)" : "DENY ($(r.result))"
        println(io, "    tick $t: subgoal=$(rpad(r.goal, 15)) action=$(rpad(string(r.action), 7)) gate: $v")
    end

    println(io, "\n── result ──")
    built = isfile(hut)
    println(io, "    shelter built:  $built" * (built ? "  (\"$(read(hut, String))\")" : ""))
    println(io, "    ledger:         $(length(d.ledger.entries)) gated decisions, verify → $(verify_ledger(d.ledger))")
    println(io, "\n" * "═"^66)
    println(io, " the agent CHOSE its goal and executed a multi-step gated plan to reach")
    println(io, " it — cognition all the way down, every step through the gate + ledger.")
    println(io, "═"^66)
    return d
end

run_plan_demo()
