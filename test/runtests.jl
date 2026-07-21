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
        @test length(led.entries) == 2                                           # both recorded
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
