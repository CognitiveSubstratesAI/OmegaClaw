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

    @testset "keyed chain defeats re-forge (B10)" begin
        # With a trust key the chain links are HMAC, so an attacker who rewrites entries and recomputes a
        # valid *unkeyed* sha256 chain (the B10 re-forge) is rejected — they cannot produce the HMAC.
        withenv("OMEGACLAW_TRUST_KEY" => "k"^40, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            led = Ledger()
            e = record!(led, Proposal("shell", ["echo a"]), Allow)
            @test verify_chain(led)                       # keyed verify passes
            @test verify_ledger(led)                      # in-memory ⇒ head_ok true (no path)
            # forge: swap in the sha256 hash a keyless attacker WOULD compute over the same fields
            sha = OmegaClaw._entry_hash(nothing, e.seq, e.proposal_hash, e.action, e.args, e.actor,
                e.decision, e.policy_version, e.evidence_snapshot, e.expiry, e.receipt, e.timestamp, nothing)
            @test sha != e.entry_hash                     # keyed ≠ unkeyed hash of the same content
            led.entries[1] = LedgerEntry(e.seq, e.proposal_hash, e.action, e.args, e.actor, e.decision,
                e.policy_version, e.evidence_snapshot, e.expiry, e.receipt, e.timestamp, e.prev_hash, sha)
            @test !verify_chain(led)                      # the unkeyed (forgeable) hash is rejected — B10 closed
        end
    end

    @testset "persisted reload + verify + anchored head (B7/B10)" begin
        withenv("OMEGACLAW_TRUST_KEY" => "s"^40, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            dir = mktempdir(); path = joinpath(dir, "ledger.jsonl")
            led = Ledger(; path = path)
            for i in 1:4; record!(led, Proposal("shell", ["echo $i"]), Allow); end
            @test isfile(path) && isfile(path * ".head")  # entries + co-located head anchor persisted
            r = load_ledger(path)                         # B7: reload from disk + verify
            @test r.n == 4 && r.chain_ok && r.head_ok && r.authenticated
            # tail-truncation: drop the last entry line (the chain alone can't notice — each remaining link is valid)
            lines = readlines(path); write(path, join(lines[1:end - 1], "\n") * "\n")
            r2 = load_ledger(path)
            @test r2.n == 3 && r2.chain_ok                # remaining 3 are internally consistent…
            @test !r2.head_ok                             # …but the keyed head anchor pins count:tip=4 ⇒ truncation caught
            # on-disk field tamper (action shell→rm) leaves the stored HMAC unchanged ⇒ keyed reload rejects
            forged = replace(readlines(path)[1], "\"action\":\"shell\"" => "\"action\":\"rm\"")
            write(path, forged * "\n")
            @test !load_ledger(path).chain_ok
        end
    end

    @testset "shadow mode: unkeyed sha256 chain unchanged (no trust key)" begin
        withenv("OMEGACLAW_TRUST_KEY" => nothing, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            led = Ledger()
            record!(led, Proposal("shell", ["echo a"]), Allow)
            record!(led, Proposal("shell", ["echo b"]), Deny)
            @test verify_chain(led) && verify_ledger(led) # plain sha256 tamper-evidence still holds
            r = load_ledger(joinpath(mktempdir(), "absent.jsonl"))
            @test r.n == 0 && r.chain_ok && r.head_ok && !r.authenticated
        end
    end

    @testset "fix-review fixes: truncate-to-empty / deletion / :locked / downgrade / crash-window" begin
        K = "z"^40
        # (1) CRITICAL: truncate-to-empty must NOT pass — the surviving .head pins count>0
        withenv("OMEGACLAW_TRUST_KEY" => K, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            dir = mktempdir(); path = joinpath(dir, "l.jsonl")
            led = Ledger(; path = path)
            for i in 1:4; record!(led, Proposal("shell", ["e$i"]), Allow); end
            write(path, "")                                    # attacker wipes the log, leaves .head
            @test load_ledger(path).n == 0
            @test !load_ledger(path).head_ok                   # truncation-to-empty caught (was the critical false-accept)
        end
        # (2) HIGH: DELETING the ledger file (leaving .head) is caught — not silently started fresh+unlocked (F1)
        withenv("OMEGACLAW_TRUST_KEY" => K, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            dir = mktempdir(); path = joinpath(dir, "l.jsonl")
            led = Ledger(; path = path)
            for i in 1:3; record!(led, Proposal("shell", ["e$i"]), Allow); end
            rm(path)                                           # `rm ledger.jsonl`, .head survives
            @test !load_ledger(path).head_ok                   # deletion caught by the keyed marker
            @test load_ledger(joinpath(mktempdir(), "fresh.jsonl")).head_ok   # genuine first run still passes
        end
        # (3) HIGH: a configured-but-unresolvable (:locked) key fails CLOSED, never silently sha256
        withenv("OMEGACLAW_TRUST_KEY" => K, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            dir = mktempdir(); path = joinpath(dir, "l.jsonl")
            led = Ledger(; path = path)
            for i in 1:3; record!(led, Proposal("shell", ["e$i"]), Allow); end
            withenv("OMEGACLAW_TRUST_KEYFILE" => joinpath(dir, "gone.key"), "OMEGACLAW_TRUST_KEY" => nothing) do
                r = load_ledger(path)                          # _trust_key() == :locked
                @test !r.chain_ok && !r.head_ok && !r.authenticated
            end
        end
        # (4) HIGH: keyed→shadow downgrade — a present .head is the keyed marker; verifying keyless must fail
        withenv("OMEGACLAW_TRUST_KEY" => K, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            dir = mktempdir(); path = joinpath(dir, "l.jsonl")
            led = Ledger(; path = path)
            for i in 1:3; record!(led, Proposal("shell", ["e$i"]), Allow); end
            withenv("OMEGACLAW_TRUST_KEY" => nothing, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
                @test !load_ledger(path).head_ok               # shadow verify of a keyed ledger ⇒ rejected
            end
        end
        # (5) crash-window (F3): a head lagging by EXACTLY one over a chain-valid tail is a torn write ⇒
        #     tolerated (no brick); lagging by two ⇒ not a single crash ⇒ rejected
        withenv("OMEGACLAW_TRUST_KEY" => K, "OMEGACLAW_TRUST_KEYFILE" => nothing) do
            dir = mktempdir(); path = joinpath(dir, "l.jsonl")
            led = Ledger(; path = path)
            for i in 1:3; record!(led, Proposal("shell", ["e$i"]), Allow); end
            es = load_ledger(path).ledger.entries; key = Vector{UInt8}(codeunits(K))
            write(path * ".head", bytes2hex(OmegaClaw._head_mac(key, 2, es[2].entry_hash)))  # crash: e3 written, head at 2
            @test load_ledger(path).head_ok                    # torn-tail (lag by one) tolerated
            write(path * ".head", bytes2hex(OmegaClaw._head_mac(key, 1, es[1].entry_hash)))  # head lags by two
            @test !load_ledger(path).head_ok                   # not a single torn write ⇒ rejected
        end
    end

    @testset "autonomous multi-step plan (MetaMo chooses + gated sequence)" begin
        # The agent must reach `shelter` — no single reflex covers it (gather → build). A MetaMo governor
        # picks `shelter` over `idle`; the driver walks the subgoal ladder, one gated action per tick.
        policy = Policy(Set(["echo", "write-file"]), Regex[], Regex[], Regex[], Regex[], "t", "t", true, false, nothing)
        hut = joinpath(mktempdir(), "hut")
        governor = (goals = [0.25, 0.75, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5], mods = fill(0.5, 6),
            stimulus = [0.2, 0.8, 0.1, 0.2],
            candidates = [
                (id = "shelter", corrs = [0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0], risk = 0.0, dg = fill(0.05, 8)),
                (id = "idle", corrs = [0.0, 0.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0], risk = 1.0, dg = zeros(8))])
        d = Driver(; store = mktempdir(), ledger = Ledger(), policy = policy, governor = governor)
        seed_plan!(d, "shelter", [("gather", "echo", ["got-wood"]), ("build", "write-file", [hut, "built"])])
        r1 = step!(d, "survey")                          # goal=nothing ⇒ MetaMo picks the goal autonomously
        @test r1.chose == "shelter"                      # chose `shelter` over `idle`
        @test r1.action == "gather" && r1.decision === :allowed && r1.goal == "shelter__step1"   # plan step 1
        r2 = step!(d, "survey")
        @test r2.action == "build" && r2.decision === :allowed && r2.goal == "shelter"            # plan step 2
        @test isfile(hut)                                # the sequence actually reached the goal
        @test d.frontier == 0 && isempty(d.plan)         # plan complete
        @test verify_chain(d.ledger)                     # every gated step recorded + chained
    end

    @testset "adaptive autonomy — motive state evolves from experience" begin
        # The stimulus is derived from the agent's own experience each tick (surprise→novelty, gate→con/risk);
        # the OpenPsi appraisal evolves the modulators, which carry forward and shape the next goal choice.
        policy = Policy(Set(["echo"]), Regex[], Regex[], Regex[], Regex[], "t", "t", true, false, nothing)
        init_mods = fill(0.5, 6)
        governor = (goals = [0.25, 0.75, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5], mods = copy(init_mods),
            stimulus = [0.2, 0.5, 0.1, 0.3],
            candidates = [
                (id = "explore", corrs = [0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0], risk = 0.0, dg = fill(0.05, 8)),
                (id = "settle", corrs = [0.0, 0.0, 0.2, 0.2, 0.2, 0.2, 0.2, 0.2], risk = 0.3, dg = zeros(8))])
        d = Driver(; store = mktempdir(), ledger = Ledger(), policy = policy, governor = governor,
            learn_rule = "(= (should-retrain \$n \$s) (>= \$n 3))")
        seed!(d, "look", "explore", "echo", ["exploring"])
        seed!(d, "rest", "settle", "echo", ["settling"])
        chosen = String[]
        for raw in ["a", "b", "c", "d", "e", "f"]
            r = step!(d, raw; adaptive = true, learn = true, hidden = 16, epochs = 30)
            push!(chosen, string(r.chose))
        end
        @test all(c -> c in ("explore", "settle"), chosen)   # a goal chosen autonomously every tick
        @test d.governor.mods != init_mods                   # the affect (modulator) state EVOLVED from experience
        @test d.sense != [0.1, 0.5, 0.1, 0.3]                # perception updated the stimulus (not the baseline)
        @test verify_chain(d.ledger)                         # every gated action recorded + chained
    end

    @testset "cognitive-control policy is a rewritable MeTTa atom (not hardcoded Julia)" begin
        # The reward estimator (count→STV) is a MeTTa rule; override it per-driver ⇒ different behavior,
        # proving it's an inspectable/rewritable atom, not a Julia constant.
        d0 = Driver(; store = mktempdir(), ledger = Ledger())
        r0 = reinforce!(d0, "a", "g", true)                  # default evidence->stv: strength=s/n, conf=n/(n+k)
        @test r0.strength ≈ 1.0 && r0.confidence ≈ 0.5       # 1/1, 1/(1+1)
        # a custom policy that Laplace-smooths strength (s+1)/(n+2) — same rules, one line changed
        custom = raw"""
        (= (novelty-decay) 0.9)
        (= (effort-baseline) 0.3)
        (= (initial-sense) (stimulus 0.1 0.5 0.1 0.3))
        (= (action-success? $d $e) (and (== $d allowed) (not $e)))
        (= (novelty $s $maxs $hassig $prev) (if $hassig (if (<= $maxs 0) 0.0 (min 1.0 (max 0.0 (/ $s $maxs)))) (* $prev (novelty-decay))))
        (= (appraise $s $maxs $hassig $prev $success $blocked) (stimulus (novelty $s $maxs $hassig $prev) (if $success 0.8 0.2) (if $blocked 0.8 0.1) (effort-baseline)))
        (= (evidence->stv $s $n $k) (STV (/ (+ $s 1) (+ $n 2)) (/ $n (+ $n $k))))
        """
        d1 = Driver(; store = mktempdir(), ledger = Ledger(), policy_rules = custom)
        r1 = reinforce!(d1, "a", "g", true)
        @test r1.strength ≈ 2 / 3                            # Laplace (1+1)/(1+2) — the rewritten rule took effect
        @test r1.strength != r0.strength                     # same inputs, different policy ⇒ different STV
    end

    @testset "pure-MeTTa tick loop drives grounded organs (run_metta_loop!)" begin
        # The tick LOOP itself is a MeTTa tail-recursion (upstream-faithful), driving by-handle grounded Julia
        # organs — WorldModel decides, the gate authorizes, the ledger records — none of the 1024-vec crosses
        # the ABI. Proves the loop-in-MeTTa topology works end-to-end on Core's interpreter.
        policy = Policy(Set(["echo", "write-file"]), Regex[], Regex[], Regex[], Regex[], "t", "t", true, false, nothing)
        hut = joinpath(mktempdir(), "hut")
        d = Driver(; store = mktempdir(), ledger = Ledger(), policy = policy)
        seed_plan!(d, "shelter", [("gather", "echo", ["got-wood"]), ("build", "write-file", [hut, "built"])])
        run_metta_loop!(d; goal = "shelter", max_turns = 2)      # the LOOP is MeTTa, not a Julia harness
        @test isfile(hut)                                        # the gated 2-step plan executed via the MeTTa loop
        @test verify_chain(d.ledger) && !isempty(d.ledger.entries)   # every decision recorded + chained
    end

    @testset "ambient/slow rate (§7) on a MeTTa cadence (should-consolidate)" begin
        # The SLOW rate of the two-loop×3-rate architecture: WorldModel.slow_step! (belief-decay + HMH
        # consolidation + WILLIAM mining + SubRep admit + MOSES/GEO-EVO synthesis), rate-limited by the
        # `should-consolidate` MeTTa cadence rule. In run_metta_loop! the WHOLE cadence (the `$sn` counter,
        # threshold, reset) is MeTTa; the Julia grounded op `oc-slow-step` is a pure organ (mirrors Core/lib
        # ECAN's fully-MeTTa `scan-due?`). Default K=8.
        pol = Policy(Set(["echo"]), Regex[], Regex[], Regex[], Regex[], "t", "t", true, false, nothing)
        mk() = (dd = Driver(; store = mktempdir(), ledger = Ledger(), policy = pol);
                seed!(dd, "greet", "task", "echo", ["hi"]); dd)
        # (a) MeTTa-loop path: fires 0× below K, ⌊N/K⌋× at/after K
        OmegaClaw._SLOW_FIRES[] = 0; run_metta_loop!(mk(); goal = "task", max_turns = 2)
        @test OmegaClaw._SLOW_FIRES[] == 0                    # cadence not due
        OmegaClaw._SLOW_FIRES[] = 0; run_metta_loop!(mk(); goal = "task", max_turns = 16)
        @test OmegaClaw._SLOW_FIRES[] == 2                    # fired at ticks 8 and 16
        # (a2) CHUNKED + CROSS-LANE continuity: the loop marshals its final cadence state back onto the driver,
        # so N ticks split across calls behave like N ticks in one call, and MeTTa-lane ticks are visible to the
        # step!/run_agent! lane. (Regression: the seed was read on entry and dropped on exit, so chunked driving
        # silently restarted the counter and the ACTIVITY trigger never fired — 16 chunked ticks gave 0 fires.)
        OmegaClaw._SLOW_FIRES[] = 0; dchunk = mk()
        for _ in 1:4; run_metta_loop!(dchunk; goal = "task", max_turns = 4); end
        @test OmegaClaw._SLOW_FIRES[] == 2                   # 4×4 ticks ≡ 1×16 ticks
        dmix = mk(); run_metta_loop!(dmix; goal = "task", max_turns = 7)
        @test dmix.slow_pending == 7                         # MeTTa-lane ticks visible to the step! lane
        @test step!(dmix, "start"; goal = "task", ambient = true).slow !== nothing   # ⇒ the 8th real tick fires
        # (b) step! (Julia-harness path) returns the slow_step! summary on the tick it fires
        d2 = mk(); slow_ticks = Int[]
        for i in 1:8
            r = step!(d2, "start"; goal = "task", ambient = true)
            r.slow !== nothing && push!(slow_ticks, i)
        end
        @test slow_ticks == [8]                              # the K=8 cadence, in step!
        # (c) the cadence is an EDITABLE MeTTa rule, not a Julia constant — re-schedule to K=3
        d3 = Driver(; store = mktempdir(), ledger = Ledger(), policy = pol,
                    consolidate_rule = "(= (should-consolidate \$n \$dt) (>= \$n 3))")
        seed!(d3, "greet", "task", "echo", ["hi"])
        OmegaClaw._SLOW_FIRES[] = 0; run_metta_loop!(d3; goal = "task", max_turns = 6)
        @test OmegaClaw._SLOW_FIRES[] == 2                    # K=3 ⇒ fired at ticks 3 and 6
    end

    @testset "ambient IDLE trigger — wall-clock self-wake (§7)" begin
        # The second ambient trigger, OR'd with the tick counter: consolidate after T seconds even when the
        # agent is IDLE (few/no ticks). Upstream (mettaclaw/OmegaClaw-Core) re-arms a `&nextWakeAt` mutable
        # cell on a get_time deadline; ours reads the clock via the `oc-now` organ and threads the last-fire
        # timestamp as a LOOP PARAM (`$t0`) — no mutable state cell (the idiom PeTTa's stdlib uses).
        pol = Policy(Set(["echo"]), Regex[], Regex[], Regex[], Regex[], "t", "t", true, false, nothing)
        # idle-secs = 0 ⇒ the wall-clock branch is ALWAYS due ⇒ fires every tick even though K=999 never is.
        mkd(rule) = (dd = Driver(; store = mktempdir(), ledger = Ledger(), policy = pol, consolidate_rule = rule);
                     seed!(dd, "greet", "task", "echo", ["hi"]); dd)
        idle_now = "(= (should-consolidate \$n \$dt) (or (>= \$n 999) (>= \$dt 0)))"
        OmegaClaw._SLOW_FIRES[] = 0; run_metta_loop!(mkd(idle_now); goal = "task", max_turns = 3)
        @test OmegaClaw._SLOW_FIRES[] == 3                    # idle branch fired every tick (tick branch never)
        # the tick branch alone must NOT fire it — proves the 3 above came from $dt, not $n
        idle_never = "(= (should-consolidate \$n \$dt) (or (>= \$n 999) (>= \$dt 99999)))"
        OmegaClaw._SLOW_FIRES[] = 0; run_metta_loop!(mkd(idle_never); goal = "task", max_turns = 3)
        @test OmegaClaw._SLOW_FIRES[] == 0
        # $dt is real elapsed WALL time, not a tick count: after sleeping past a 0.3s threshold, one tick fires.
        d = mkd("(= (should-consolidate \$n \$dt) (or (>= \$n 999) (>= \$dt 0.3)))")
        step!(d, "start"; goal = "task", ambient = true)       # warm-up tick: JIT for mid_step!/perceive costs
        d.last_slow = time()                                  # …>0.3s, so start the measured interval cleanly
        r1 = step!(d, "start"; goal = "task", ambient = true)
        @test r1.slow === nothing                             # ~0s elapsed ⇒ not due
        sleep(0.35)
        r2 = step!(d, "start"; goal = "task", ambient = true)
        @test r2.slow !== nothing                             # elapsed > 0.3s ⇒ idle trigger fired
        # firing RESETS the wall clock, so the very next tick is not due again
        @test step!(d, "start"; goal = "task", ambient = true).slow === nothing
        # (d) idle SELF-WAKE in run_agent!: an exhausted channel consolidates instead of dying with work
        # pending. `last_slow` is the observable — _ambient_step! stamps it BEFORE doing the (best-effort)
        # work, so it proves the wake PATH ran regardless of what the organ returns.
        d4 = mkd(idle_now); before4 = d4.last_slow
        n4 = run_agent!(d4, BufferChannel(String[]); goal = "task", ambient = true)   # no input at all ⇒ idle
        @test n4 == 0                                         # zero turns…
        @test d4.last_slow > before4                          # …but the idle wake DID consolidate
        # and it is strictly OPT-IN: same empty channel, ambient=false ⇒ no ambient work at all
        d5 = mkd(idle_now); before5 = d5.last_slow
        run_agent!(d5, BufferChannel(String[]); goal = "task", ambient = false)
        @test d5.last_slow == before5
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
