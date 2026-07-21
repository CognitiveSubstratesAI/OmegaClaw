using Test
using OmegaClaw

@testset "OmegaClaw governed-action gate" begin

    @testset "Proposal is content-pinned" begin
        p1 = Proposal("shell", ["echo hi"]; actor = "a", timestamp = "t")
        p2 = Proposal("shell", ["echo hi"]; actor = "a", timestamp = "t")
        p3 = Proposal("shell", ["echo HO"]; actor = "a", timestamp = "t")
        @test p1.hash == p2.hash          # deterministic
        @test p1.hash != p3.hash          # different body ⇒ different pin
        @test length(p1.hash) == 64       # sha256 hex
    end

    @testset "5-way decision" begin
        pol = default_policy()
        @test decide(pol, Proposal("echo", ["hi"])) === Allow
        @test decide(pol, Proposal("echo", ["rm -rf /tmp/x"])) === Deny         # deny-pattern on args
        @test decide(pol, Proposal("launch-missile", ["now"])) === Deny         # unlisted capability (default-deny)
        @test decide(pol, Proposal("echo", ["sudo apt update"])) === RequireReview
    end

    @testset "hash-chained evidence ledger" begin
        led = Ledger()
        e1 = record!(led, Proposal("shell", ["echo a"]), Allow)
        e2 = record!(led, Proposal("shell", ["rm -rf /"]), Deny)
        @test e1.prev_hash === nothing
        @test e2.prev_hash == e1.entry_hash          # chained
        @test verify_chain(led)
        # tamper: mutate a recorded decision ⇒ chain must fail
        led.entries[1] = OmegaClaw.LedgerEntry(e1.seq, e1.proposal_hash, e1.action, e1.args,
            e1.actor, "Allow-TAMPERED", e1.timestamp, e1.prev_hash, e1.entry_hash)
        @test !verify_chain(led)
    end

    @testset "governed() gates execution" begin
        pol = default_policy(); led = Ledger()
        ran = Ref(false)
        run = _ -> (ran[] = true; "did-run")
        @test governed(pol, led, "echo", ["hi"], run) == "did-run"              # Allow → runs (stub)
        @test ran[]
        ran[] = false
        out = governed(pol, led, "echo", ["rm -rf /tmp/x"], run)
        @test startswith(out, "GATE[Deny")                                       # deny-pattern on args → blocked
        @test !ran[]                                                             # body never ran
        # Allow commits the decision BEFORE run + a receipt AFTER (§7.6) = 2 entries; Deny = 1 ⇒ 3 total
        @test length(led.entries) == 3
    end

    @testset "signed-manifest fail-closed (C1)" begin
        dir = mktempdir(); man = joinpath(dir, "policy.toml"); key = rand(UInt8, 32)
        write(man, "allow_actions = [\"shell\"]\npolicy_version = \"v1\"\n")
        sign_manifest!(man, key)
        pol = load_policy(man; key = key)
        @test pol.signature_valid && pol.version == "v1"
        @test decide(pol, Proposal("shell", ["echo hi"])) === Allow
        open(man, "a") do io; write(io, "\n# agent tampers with its own policy\n") end   # bytes change
        @test !verify_manifest(man, key)                                          # signature no longer valid
        @test decide(load_policy(man; key = key), Proposal("shell", ["echo hi"])) === Deny   # LOCKED (fail-closed)
        @test decide(load_policy(man; key = nothing), Proposal("shell", ["echo hi"])) === Allow # shadow mode
    end

    @testset "ledger authenticates ALL fields (H1)" begin
        led = Ledger(); e = record!(led, Proposal("shell", ["echo a"]), Allow)
        led.entries[1] = LedgerEntry(e.seq, e.proposal_hash, "rm -rf /", e.args, e.actor,
            e.decision, e.timestamp, e.prev_hash, e.entry_hash)                    # edit ACTION only
        @test !verify_chain(led)                                                   # detected (was undetectable before)
    end

    @testset "TOCTOU + expiry recheck (H2)" begin
        pol = default_policy(); led = Ledger()
        c = Ref(0); drift = () -> (c[] += 1; string(c[]))                          # evidence changes between decide + exec
        @test startswith(governed(pol, led, "echo", ["hi"], _ -> "ran"; evidence = drift), "GATE[Deny")
        @test startswith(governed(pol, led, "echo", ["hi"], _ -> "ran"; ttl_seconds = -1.0), "GATE[Deny")
        @test governed(pol, led, "echo", ["hi"], _ -> "ran") == "ran"              # stable evidence ⇒ runs
    end

    @testset "RequireProbe + Defer (R6)" begin
        pp = Policy(Set(["http-get"]), Regex[], Regex[], Regex[r"\bhttp-get\b"], Regex[], "v1", "t", true, false, nothing)
        register_probe!("http-get", _ -> (false, "no-net"))
        @test startswith(governed(pp, Ledger(), "http-get", ["x"], _ -> "got"), "GATE[RequireProbe")
        dp = Policy(Set(["deploy"]), Regex[], Regex[], Regex[], Regex[r"\bdeploy\b"], "v1", "t", true, false, nothing)
        @test startswith(governed(dp, Ledger(), "deploy", ["x"], _ -> "done"), "GATE[Defer")
    end

    @testset "trust-key fail-closed on unresolvable key (B1/B8)" begin
        dir = mktempdir(); man = joinpath(dir, "p.toml")
        write(man, "allow_actions = [\"shell\"]\npolicy_version = \"v1\"\n")
        withenv("OMEGACLAW_TRUST_KEYFILE" => joinpath(dir, "missing.key"), "OMEGACLAW_TRUST_KEY" => nothing) do
            pol = load_policy(man)                                     # key set but file absent ⇒ :locked
            @test pol.version == "LOCKED"
            @test decide(pol, Proposal("shell", ["echo hi"])) === Deny
        end
        withenv("OMEGACLAW_TRUST_KEY" => "too-short", "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            @test load_policy(man).version == "LOCKED"                 # <32-byte key ⇒ LOCKED
        end
    end

    @testset "ledger timestamp is authenticated (B2)" begin
        led = Ledger(); e = record!(led, Proposal("shell", ["echo a"]), Allow)
        led.entries[1] = LedgerEntry(e.seq, e.proposal_hash, e.action, e.args, e.actor,
            e.decision, "1970-01-01T00:00:00", e.prev_hash, e.entry_hash)   # backdate ts, keep hash
        @test !verify_chain(led)                                      # detected (was undetectable before B2)
    end

    @testset "drain_deferred! does not wedge or double-track (B4)" begin
        q = DeferQueue()
        dp = Policy(Set(["deploy"]), Regex[], Regex[], Regex[], Regex[r"\bdeploy\b"], "v1", "t", true, false, nothing)
        @test startswith(governed(dp, Ledger(), "deploy", ["x"], _ -> "done"; defer_queue = q), "GATE[Defer")
        @test length(q.items) == 1
        gbefore = length(DEFER_QUEUE.items)
        done = drain_deferred!(q)                                     # must terminate (no self-append DoS)
        @test isempty(done)                                          # still defers
        @test length(q.items) == 1                                   # re-queued to q…
        @test length(DEFER_QUEUE.items) == gbefore                    # …NOT the global queue
    end

    @testset "passing probe authorizes execution (B9)" begin
        pp = Policy(Set(["http-get"]), Regex[], Regex[], Regex[r"\bhttp-get\b"], Regex[], "v1", "t", true, false, nothing)
        register_probe!("http-get", _ -> (true, "net-ok"))            # a PASSING probe
        @test governed(pp, Ledger(), "http-get", ["x"], _ -> "fetched") == "fetched"   # now runs (was Deny)
    end

    @testset "reinforcement teaches action selection (B)" begin
        strict = Policy(Set(["echo"]), Regex[], Regex[], Regex[], Regex[], "t", "t", true, false, nothing)
        d = Driver(; store = mktempdir(), ledger = Ledger(), policy = strict)
        seed!(d, "act-good", "task", "echo", ["good"])
        seed!(d, "act-alt", "task", "echo", ["alt"])          # competing action for the SAME goal
        for _ in 1:5; reinforce!(d, "act-good", "task", true); end   # succeeds
        for _ in 1:5; reinforce!(d, "act-alt", "task", false); end   # fails/blocked
        @test d.outcomes["act-good"] == (5, 5)
        @test d.outcomes["act-alt"] == (0, 5)
        sel = OmegaClaw.WorldModel.select_action(d.reg, "task")
        @test !isempty(sel) && sel[1][1] == "act-good"        # PLN now prefers the reinforced-success action
    end

    @testset "channels: run_agent! over a buffer channel (C)" begin
        strict = Policy(Set(["echo"]), Regex[], Regex[], Regex[], Regex[], "t", "t", true, false, nothing)
        d = Driver(; store = mktempdir(), ledger = Ledger(), policy = strict)
        seed!(d, "greet", "inventory", "echo", ["hello-from-channel"])
        ch = BufferChannel(["hi there", "again"])
        turns = run_agent!(d, ch; goal = "inventory")
        @test turns == 2                                  # both inputs processed
        @test length(ch.outputs) == 2
        @test all(o -> o == "hello-from-channel", ch.outputs)   # each input → echo capability output
    end

    @testset "Sdyn training learns a forward model (D)" begin
        # Gather (context_t → context_{t+1}) transitions from a driver run, train the FabricPC Sdyn forward
        # model, assert a real learning signal (train energy drops). AdamW — plain SGD diverges at this dim.
        d = Driver(; store = mktempdir(), ledger = Ledger())
        inputs = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"]
        tr = gather_transitions(d, inputs)
        @test length(tr) == length(inputs) - 1
        @test length(tr[1][1]) == length(tr[1][2]) > 0        # consistent, non-empty context dim
        res = train_sdyn!(d, tr; hidden = 32, epochs = 200, adam = true)
        @test res.n == length(tr)
        @test isfinite(res.first_energy) && isfinite(res.last_energy)
        @test res.last_energy < res.first_energy              # train energy dropped ⇒ Sdyn learned
    end

    @testset "online learning, MeTTa-controlled cadence (D-online)" begin
        # The retrain CADENCE is a MeTTa rule, not a Julia constant. Install a rule that fires at 3 pending
        # transitions, drive the agent with learn=true, and verify Sdyn trained ONLINE: pending resets when
        # the rule fires, surprise (forward-model prediction error) is measured, and predict_dynamics becomes
        # a live finite forward model. Re-scheduling the agent's learning = editing this atom, no recompile.
        d = Driver(; store = mktempdir(), ledger = Ledger(),
            learn_rule = "(= (should-retrain \$n \$s) (>= \$n 3))")
        inputs = ["a1", "b2", "c3", "d4", "e5", "f6", "g7", "h8"]
        surprises = Float64[]
        for raw in inputs
            r = step!(d, raw; learn = true, hidden = 16, epochs = 40)
            r.surprise !== nothing && push!(surprises, r.surprise)
        end
        @test length(d.transitions) == length(inputs) - 1     # every transition buffered (organ memory)
        @test d.pending < 3                                   # rule fired ⇒ pending was reset below threshold
        @test !isempty(surprises) && all(isfinite, surprises) # forward model produced predictions once trained
        pred = OmegaClaw.WorldModel.predict_dynamics(d.reg, d.transitions[end][1])
        @test pred !== nothing && all(isfinite, pred)         # Sdyn is a live, finite forward model post-train
    end

    @testset "driver loop over WorldModel (capabilities)" begin
        # The full agent tick on the REAL 14-Space braid: perceive → mid_step! (PLN decides) → translate
        # action → governed capability (exact argv, no shell) → recorded. Heavy (constructs a WorldModel).
        strict = Policy(Set(["echo"]), Regex[], Regex[], Regex[], Regex[], "test", "test", true, false, nothing)
        d = Driver(; store = mktempdir(), ledger = Ledger(), policy = strict)
        seed!(d, "greet", "inventory", "echo", ["hello-from-omegaclaw"])
        seed!(d, "list", "browse", "ls", ["/tmp"])
        r1 = step!(d, "what is here"; goal = "inventory")
        @test r1.action == "greet"                       # PLN selected the seeded action
        @test r1.decision === :allowed
        @test r1.result == "hello-from-omegaclaw"         # echo capability ran (Cmd, no shell)
        r2 = step!(d, "browse files"; goal = "browse")
        @test r2.action == "list"
        @test r2.decision === :blocked                    # ls not in the strict allow-list ⇒ default-deny
        @test startswith(r2.result, "GATE[Deny")
        @test verify_chain(d.ledger)                      # both decisions recorded + chained
    end
end
