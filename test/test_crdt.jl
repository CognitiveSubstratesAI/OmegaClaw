# test_crdt.jl — the four invariants WP §2.6 names, each as its own test.
#
# §2.6 lists them explicitly: "replica convergence, idempotent replay, preserved transaction
# identity, and (where required) a nonnegative-domain balance." A CRDT whose merge is not
# commutative/associative/idempotent is not a CRDT, so those are asserted directly rather than
# inferred from a scenario passing.
using Test, OmegaClaw

@testset "PN-counter CRDT (WP §2.6 Eq. 1)" begin
    @testset "value = ΣP − ΣN" begin
        c = PNCounter()
        @test pn_value(c) == 0                       # empty maps ⇒ 0, not an error
        pn_increment!(c, "r1", 5)
        pn_decrement!(c, "r1", 2)
        @test pn_value(c) == 3
        pn_increment!(c, "r2", 4)
        @test pn_value(c) == 7                       # Σ across replicas
        pn_decrement!(c, "r2", 10)
        @test pn_value(c) == -3                      # negative is legal for a general quantity
    end

    @testset "a decrement must NOT be representable as a negative increment (§3.8)" begin
        # "a grow-only counter is used only for quantities that are genuinely monotone" — the whole
        # reason P and N are separate. Routing a negative through the P map is how a decrease
        # silently becomes an increase on merge, so it is refused at the door.
        c = PNCounter()
        @test_throws ArgumentError pn_increment!(c, "r1", -3)
        @test_throws ArgumentError pn_decrement!(c, "r1", -3)
        @test pn_value(c) == 0                       # neither rejected call mutated anything
    end

    @testset "merge is a JOIN — commutative, associative, idempotent" begin
        a = PNCounter(); pn_increment!(a, "r1", 3); pn_decrement!(a, "r1", 1)
        b = PNCounter(); pn_increment!(b, "r2", 7)
        c = PNCounter(); pn_decrement!(c, "r3", 2)

        @test pn_value(pn_merge(a, b)) == pn_value(pn_merge(b, a))                 # commutative
        @test pn_value(pn_merge(pn_merge(a, b), c)) ==
              pn_value(pn_merge(a, pn_merge(b, c)))                                # associative
        @test pn_value(pn_merge(a, a)) == pn_value(a)                              # idempotent
        # idempotence is the one that matters operationally: redelivering the same state must not
        # double-count. Componentwise max gives it; `+` would not.
        m = pn_merge(a, b)
        @test pn_value(pn_merge(m, b)) == pn_value(m)
        @test pn_value(pn_merge(pn_merge(m, b), b)) == pn_value(m)

        @test pn_merge(a, b) !== a                                                 # pure, no aliasing
        pn_increment!(a, "r1", 100)
        @test pn_value(pn_merge(b, c)) == 5                                        # unaffected
    end

    @testset "CONCURRENT increment and decrement converge (the G-counter failure case)" begin
        # Two replicas act on the same logical quantity without seeing each other: r1 adds 10,
        # r2 subtracts 4. A grow-only counter cannot tell these apart; a PN-counter can.
        r1 = PNCounter(); r2 = PNCounter()
        pn_increment!(r1, "r1", 10)
        pn_decrement!(r2, "r2", 4)
        @test pn_value(pn_merge(r1, r2)) == 6
        @test pn_value(pn_merge(r2, r1)) == 6        # order of delivery is irrelevant
    end

    @testset "replica convergence under out-of-order, duplicated delivery" begin
        r1 = PNCounter(); r2 = PNCounter(); r3 = PNCounter()
        pn_increment!(r1, "r1", 5)
        pn_decrement!(r2, "r2", 3)
        pn_increment!(r3, "r3", 8)
        # three replicas gossip in three different orders, some messages arriving twice
        v1 = pn_merge(pn_merge(r1, r2), pn_merge(r3, r2))
        v2 = pn_merge(r3, pn_merge(r2, pn_merge(r1, r1)))
        v3 = pn_merge(pn_merge(pn_merge(r2, r3), r1), r3)
        @test pn_value(v1) == pn_value(v2) == pn_value(v3) == 10
    end
end

@testset "Transfers — idempotent, transaction-identified debit/credit pairs (§2.6)" begin
    @testset "applied once; replay is a no-op" begin
        t = TransferLog()
        pn_increment!(get!(() -> PNCounter(), t.accounts, "alice"), "r1", 100)
        tr = Transfer("tx-1", "alice", "bob", 30)

        @test tl_apply!(t, tr; replica = "r1") === :applied
        @test tl_balance(t, "alice") == 70
        @test tl_balance(t, "bob") == 30

        @test tl_apply!(t, tr; replica = "r1") === :duplicate     # idempotent replay
        @test tl_balance(t, "alice") == 70                         # ...with no second effect
        @test tl_balance(t, "bob") == 30
        @test "tx-1" in t.applied                                  # transaction identity RETAINED
    end

    @testset "value is conserved — a transfer is a PAIR, never one mutation" begin
        t = TransferLog()
        pn_increment!(get!(() -> PNCounter(), t.accounts, "alice"), "r1", 50)
        before = tl_balance(t, "alice") + tl_balance(t, "bob")
        @test tl_apply!(t, Transfer("tx-2", "alice", "bob", 20); replica = "r1") === :applied
        @test tl_balance(t, "alice") + tl_balance(t, "bob") == before
    end

    @testset "nonnegative domain — escrow refuses the debit, leaving NO partial effect" begin
        t = TransferLog(; nonnegative = true)
        pn_increment!(get!(() -> PNCounter(), t.accounts, "alice"), "r1", 10)
        @test tl_apply!(t, Transfer("tx-3", "alice", "bob", 40); replica = "r1") === :quarantined
        @test tl_balance(t, "alice") == 10        # debit leg did NOT land
        @test tl_balance(t, "bob") == 0           # ...and neither did the credit leg
        @test !("tx-3" in t.applied)              # a quarantined tx is not "applied"
        @test length(t.quarantined) == 1
        @test occursin("insufficient", t.quarantined[1][2])

        # the SAME transfer succeeds once the rights exist — quarantine is not a permanent verdict
        pn_increment!(t.accounts["alice"], "r1", 100)
        @test tl_apply!(t, Transfer("tx-3", "alice", "bob", 40); replica = "r1") === :applied
        @test tl_balance(t, "bob") == 40
    end

    @testset "unbounded domain permits the same debit" begin
        t = TransferLog(; nonnegative = false)
        @test tl_apply!(t, Transfer("tx-4", "alice", "bob", 40); replica = "r1") === :applied
        @test tl_balance(t, "alice") == -40
    end

    @testset "policy-invalid records are quarantined, not applied" begin
        t = TransferLog(; nonnegative = false)
        @test tl_apply!(t, Transfer("tx-5", "a", "b", 0); replica = "r1") === :quarantined
        @test tl_apply!(t, Transfer("tx-6", "a", "b", -5); replica = "r1") === :quarantined
        @test tl_apply!(t, Transfer("tx-7", "a", "a", 5); replica = "r1") === :quarantined
        @test isempty(t.applied)
        @test length(t.quarantined) == 3
    end

    @testset "TWO WRITERS — the case last-writer-wins gets wrong" begin
        # SPACES_2026-07-22:162 — latest-wins by wall-clock over an append-only log is "correct
        # single-node, and *not* a merge function". Two replicas each apply a DIFFERENT transfer
        # against the same accounts without seeing each other; LWW would keep one and discard the
        # other. Merging must keep BOTH.
        seed() = (t = TransferLog(); pn_increment!(get!(() -> PNCounter(), t.accounts, "alice"), "seed", 100); t)
        a = seed(); b = seed()
        @test tl_apply!(a, Transfer("tx-a", "alice", "bob", 10); replica = "ra") === :applied
        @test tl_apply!(b, Transfer("tx-b", "alice", "carol", 25); replica = "rb") === :applied

        tl_merge!(a, b)
        @test tl_balance(a, "bob") == 10           # both survived...
        @test tl_balance(a, "carol") == 25
        @test tl_balance(a, "alice") == 100 - 10 - 25   # ...and the debits composed, not overwrote
        @test "tx-a" in a.applied && "tx-b" in a.applied

        # merging again must not move anything (idempotent across replicas)
        tl_merge!(a, b)
        @test tl_balance(a, "alice") == 65
        @test tl_balance(a, "carol") == 25
    end

    @testset "merged txid set blocks re-application across replicas" begin
        seed() = (t = TransferLog(); pn_increment!(get!(() -> PNCounter(), t.accounts, "alice"), "seed", 100); t)
        a = seed(); b = seed()
        tr = Transfer("tx-shared", "alice", "bob", 15)
        @test tl_apply!(b, tr; replica = "rb") === :applied
        tl_merge!(a, b)
        @test tl_balance(a, "bob") == 15
        @test tl_apply!(a, tr; replica = "ra") === :duplicate   # already applied on b, seen via merge
        @test tl_balance(a, "bob") == 15
    end
end
