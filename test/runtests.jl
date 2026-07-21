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
        @test decide(pol, Proposal("shell", ["echo hi"])) === Allow
        @test decide(pol, Proposal("shell", ["rm -rf /tmp/x"])) === Deny        # deny-pattern
        @test decide(pol, Proposal("launch-missile", ["now"])) === Deny         # unlisted action
        @test decide(pol, Proposal("shell", ["sudo apt update"])) === RequireReview
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
        @test governed(pol, led, "shell", ["echo hi"], run) == "did-run"        # Allow → runs
        @test ran[]
        ran[] = false
        out = governed(pol, led, "shell", ["rm -rf /tmp/x"], run)
        @test startswith(out, "GATE[Deny")                                       # Deny → blocked
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
        @test startswith(governed(pol, led, "shell", ["echo hi"], _ -> "ran"; evidence = drift), "GATE[Deny")
        @test startswith(governed(pol, led, "shell", ["echo hi"], _ -> "ran"; ttl_seconds = -1.0), "GATE[Deny")
        @test governed(pol, led, "shell", ["echo hi"], _ -> "ran") == "ran"        # stable evidence ⇒ runs
    end

    @testset "RequireProbe + Defer (R6)" begin
        pp = Policy(Set(["http-get"]), Regex[], Regex[], Regex[r"\bhttp-get\b"], Regex[], "v1", "t", true, false, nothing)
        register_probe!("http-get", _ -> (false, "no-net"))
        @test startswith(governed(pp, Ledger(), "http-get", ["x"], _ -> "got"), "GATE[RequireProbe")
        dp = Policy(Set(["deploy"]), Regex[], Regex[], Regex[], Regex[r"\bdeploy\b"], "v1", "t", true, false, nothing)
        @test startswith(governed(dp, Ledger(), "deploy", ["x"], _ -> "done"), "GATE[Defer")
    end

    @testset "driver loop over WorldModel" begin
        # The full agent tick on the REAL 14-Space braid: perceive → mid_step! (PLN decides) →
        # translate action → governed() → recorded. Heavy (constructs a WorldModel).
        d = Driver(; store = mktempdir(), ledger = Ledger())
        seed!(d, "greet", "inventory", "shell", ["echo hello-from-omegaclaw"])
        seed!(d, "wipe", "cleanup", "shell", ["rm -rf /tmp/omegaclaw-demo"])
        r1 = step!(d, "what is here"; goal = "inventory")
        @test r1.action == "greet"                       # PLN selected the seeded action
        @test r1.decision === :allowed
        @test r1.result == "hello-from-omegaclaw"         # governed shell op ran
        r2 = step!(d, "clean it up"; goal = "cleanup")
        @test r2.action == "wipe"
        @test r2.decision === :blocked                    # deny-pattern → gate blocked
        @test startswith(r2.result, "GATE[Deny")
        @test verify_chain(d.ledger)                      # both decisions recorded + chained
    end
end
