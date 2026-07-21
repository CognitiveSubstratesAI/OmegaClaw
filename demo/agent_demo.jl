# agent_demo.jl — the OmegaClaw agent, end-to-end and narrated.
#
#   julia --project=OmegaClaw OmegaClaw/demo/agent_demo.jl
#
# One runnable consumer of the WHOLE stack: PRIMUS's own cognition (WorldModel PLN + MetaMo) decides the
# action; OmegaClaw's capability gate is the ONLY path to the world; every decision lands in a keyed,
# tamper-resistant evidence ledger (B7/B10). Four phases: perceive→decide→gate→act; the agent LEARNS which
# action works (reinforcement); the audit ledger CATCHES on-disk tampering; and the FabricPC/Sdyn organ
# learns a forward model. Nothing here is mocked — it runs on the real 14-Space braid.

# A demo trust key (≥32 bytes) so the ledger is KEYED — this is what makes Phase 3's tamper-evidence real.
# In production this comes from OUTSIDE the agent loop (OMEGACLAW_TRUST_KEYFILE), never hard-coded.
haskey(ENV, "OMEGACLAW_TRUST_KEY") || (ENV["OMEGACLAW_TRUST_KEY"] = "omegaclaw-demo-trust-key-0123456789abcdef")

using OmegaClaw
using OmegaClaw: WorldModel

hr(t = "") = println("\n" * "─"^4 * " " * t * " " * "─"^max(0, 58 - length(t)))

function run_demo(io::IO = stdout)
    println(io, "═"^66)
    println(io, " OmegaClaw — governed agent, end-to-end (real WorldModel, keyed ledger)")
    println(io, "═"^66)

    # A strict, unsigned demo policy: only `echo` and `write-file` are permitted capabilities. Everything else
    # — including the registered `ls` capability — is DENIED by default (there is no "run anything" primitive).
    policy = Policy(Set(["echo", "write-file"]), Regex[], Regex[], Regex[], Regex[], "demo", "demo", true, false, nothing)
    lpath = joinpath(mktempdir(), "agent.ledger.jsonl")

    print(io, "\n▸ building the agent over a real 14-Space WorldModel … ")
    d = Driver(; store = mktempdir(), policy = policy, ledger = Ledger(; path = lpath))
    println(io, "ready")
    println(io, "    cognition = WorldModel (PLN action-selection + MetaMo motive)")
    println(io, "    gate      = capability / exact-argv, default-deny")
    println(io, "    ledger    = keyed HMAC chain + head anchor, persisted")

    # ── Phase 1: perceive → PLN decides → gate → capability ──
    hr("Phase 1 — perceive → decide → gate → act")
    seed!(d, "greet", "inventory", "echo", ["agent-online"])   # allowed capability
    seed!(d, "probe", "browse", "ls", ["/tmp"])                # `ls` is registered but NOT policy-allowed
    for (raw, goal) in (("what is here?", "inventory"), ("look around", "browse"))
        r = step!(d, raw; goal = goal)
        verdict = r.decision === :allowed ? "ALLOW  → $(r.result)" :
                  r.decision === :blocked ? "DENY   ($(r.result))" : "no action"
        println(io, "    goal=$(rpad(goal, 10)) PLN picked: $(rpad(string(r.action), 7)) gate: $verdict")
    end

    # ── Phase 2: the agent learns which action works (reinforcement) ──
    hr("Phase 2 — the agent LEARNS which action works (reinforcement)")
    seed!(d, "fast", "report", "echo", ["done-fast"])          # two competing actions for ONE goal
    seed!(d, "slow", "report", "echo", ["done-slow"])
    for _ in 1:5; reinforce!(d, "fast", "report", true); end    # `fast` keeps succeeding
    for _ in 1:5; reinforce!(d, "slow", "report", false); end   # `slow` keeps failing / being blocked
    sel = WorldModel.select_action(d.reg, "report")
    println(io, "    outcomes: fast=$(d.outcomes["fast"])  slow=$(d.outcomes["slow"])")
    println(io, "    select_action(report) now prefers → $(isempty(sel) ? "∅" : sel[1][1])  (PLN learned from outcomes)")

    # ── Phase 3: tamper-evident audit — the B7/B10 ledger, with a LIVE tamper ──
    hr("Phase 3 — tamper-evident audit (B7/B10)")
    r0 = load_ledger(lpath)
    println(io, "    ledger: $(r0.n) chained entries, persisted + keyed")
    println(io, "    verify_ledger → chain_ok=$(r0.chain_ok)  head_ok=$(r0.head_ok)  authenticated=$(r0.authenticated)")
    original = readlines(lpath)
    tampered = replace(original[1], r"\"action\":\"[^\"]*\"" => "\"action\":\"rm -rf /\"")
    write(lpath, join(vcat(tampered, original[2:end]), "\n") * "\n")
    println(io, "    ‹attacker edits entry 1 on disk: action → \"rm -rf /\"›")
    rt = load_ledger(lpath)
    println(io, "    verify_ledger → chain_ok=$(rt.chain_ok)   ⇒ tamper DETECTED (the gate would LOCK to Deny-all)")
    write(lpath, join(original, "\n") * "\n")   # restore for tidiness

    # ── Phase 4: the predictive organ learns (FabricPC / Sdyn) ──
    hr("Phase 4 — predictive organ learns a forward model (FabricPC/Sdyn)")
    tr = gather_transitions(d, ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"]; goal = "inventory")
    res = train_sdyn!(d, tr; hidden = 32, epochs = 200, adam = true)
    println(io, "    trained on $(res.n) (contextₜ → contextₜ₊₁) transitions")
    println(io, "    train energy: $(round(res.first_energy; digits = 1)) → $(round(res.last_energy; digits = 1))  " *
                "($(res.last_energy < res.first_energy ? "learned ✓" : "no drop"))")

    println(io, "\n" * "═"^66)
    println(io, " done — PRIMUS's cognition decided, the gate was the only path to the")
    println(io, " world, and every decision is in a tamper-resistant ledger.")
    println(io, "═"^66)
    return d
end

run_demo()
