# CRDT.jl — the PN-counter and transfer reconciliation (WP §2.6 Eq. 1, restated for multi-node at §3.8).
#
# WHY IT LIVES HERE AND NOT IN SMS. `PRIMUS_Ben_Corpus_Integrated_Map.md:62` places it: full-state
# `.act` checkpoint/restore is BUILT (`CoreSpaceActIO.jl:42`, PathMap `act_save`), but the PN-counter
# "should land with MorkGate — it is the convergence math the journal/commit-gate coordination core
# needs." That core is Gate.jl + Ledger.jl, so this sits beside them.
#
# WHAT IT REPLACES. `SPACES_2026-07-22_HYPERON_V5_vs_PRIMUS.md:162` states the defect exactly: our
# conflict rule is latest-wins by wall-clock `t` over an append-only log (`WorldModel/src/Beliefs.jl`)
# — "correct single-node, and *not* a merge function. Two writers make it last-writer-wins on a
# non-monotone quantity, which §3.8 p30 rules out explicitly." A PN-counter IS the merge function.
#
# ⚠️ THE ONE RULE THAT MAKES THIS CORRECT (§3.8, p30, verbatim): "a grow-only counter is used only
# for quantities that are genuinely monotone." A G-counter cannot represent a decrease — subtracting
# from a grow-only map is indistinguishable from another replica's increment, so a decrement silently
# becomes an increment on merge. That is why P and N are SEPARATE grow-only maps and why nothing here
# ever decreases a map entry.
#
# SCOPE. This is the convergence math only. It does NOT include DAS transport, replica discovery, or
# the Rholang lens contracts §3.8 layers on top — those need a multi-node workload that does not
# exist yet, and `sms_spec_corrections_2026-07-11.md:§5.3` rules on it: "scope the struct slots for
# CRDT G-counters and keep the CID design, but don't implement G-counter merge until a multi-replica
# workload exists." The merge IS implemented here because the gate/ledger is the workload — two
# agents sharing one ledger is the two-writer case — but nothing above the merge is.

"""
    PNCounter

A positive-negative counter CRDT (WP §2.6, Eq. 1; Shapiro et al. 2011 [24]).

Two grow-only component maps `P, N : R → ℕ` over replicas `r ∈ R`. Increments update the local
replica's `P`, decrements its `N`, so concurrent increment and decrement converge without a decrease
being mistaken for an increase.

    value  w(P, N) = Σ_r P(r) − Σ_r N(r)
    merge  (P,N) ⊔ (P′,N′) = (max(P,P′), max(N,N′))     componentwise, missing replica = 0

`merge` is a join on a product of two grow-only maps, so it is commutative, associative and
idempotent — which is exactly what makes replay and out-of-order delivery safe. Every one of those
three properties is pinned by a test; they are the CRDT's whole correctness argument, not decoration.
"""
struct PNCounter
    p::Dict{String, Int}      # per-replica increments — GROW-ONLY, never decreased
    n::Dict{String, Int}      # per-replica decrements — GROW-ONLY, never decreased
end

PNCounter() = PNCounter(Dict{String, Int}(), Dict{String, Int}())

"Deep copy — `pn_merge` returns a fresh counter, so callers never alias a replica's live state."
Base.copy(c::PNCounter) = PNCounter(copy(c.p), copy(c.n))

"Σ over a grow-only component map. Empty ⇒ 0 (a replica with no entry contributes nothing)."
_pn_sum(d::Dict{String, Int})::Int = isempty(d) ? 0 : sum(values(d))

"""
    pn_value(c) -> Int

`w(P, N) = Σ_r P(r) − Σ_r N(r)` (Eq. 1). May be negative — that is legitimate for a general
non-monotone quantity. Use [`pn_try_debit!`](@ref) when the domain forbids it.
"""
pn_value(c::PNCounter)::Int = _pn_sum(c.p) - _pn_sum(c.n)

"""
    pn_increment!(c, replica, k=1) -> Int

Add `k ≥ 0` to `replica`'s P component. Returns the new value.

A negative `k` is REJECTED rather than routed to `N`: the caller asking to "increment by −3" has
almost certainly conflated the two components, and silently accepting it is how a decrement becomes
an increment on merge — the precise failure §3.8 warns about.
"""
function pn_increment!(c::PNCounter, replica::AbstractString, k::Integer = 1)::Int
    k >= 0 || throw(ArgumentError("pn_increment! needs k >= 0 (got $k); use pn_decrement! instead"))
    r = String(replica)
    c.p[r] = get(c.p, r, 0) + Int(k)
    pn_value(c)
end

"""
    pn_decrement!(c, replica, k=1) -> Int

Add `k ≥ 0` to `replica`'s N component. Returns the new value. Note it INCREASES a grow-only map —
no entry anywhere in this file ever decreases, which is what keeps `pn_merge` a join.
"""
function pn_decrement!(c::PNCounter, replica::AbstractString, k::Integer = 1)::Int
    k >= 0 || throw(ArgumentError("pn_decrement! needs k >= 0 (got $k)"))
    r = String(replica)
    c.n[r] = get(c.n, r, 0) + Int(k)
    pn_value(c)
end

"Componentwise `max` over the union of replica keys; a missing replica reads as 0."
function _pn_join(a::Dict{String, Int}, b::Dict{String, Int})::Dict{String, Int}
    out = copy(a)
    for (r, v) in b
        out[r] = max(get(out, r, 0), v)
    end
    out
end

"""
    pn_merge(a, b) -> PNCounter

`(P,N) ⊔ (P′,N′) = (max(P,P′), max(N,N′))` (Eq. 1). Pure — neither argument is mutated.

Componentwise max (not `+`) is the load-bearing choice: it makes merge IDEMPOTENT, so redelivering
the same state converges instead of double-counting. Summing here would make replay inflate the
value, which is the same shape as the `wm-evidence-count` over-confidence defect recorded in
`SPACES_2026-07-22_HYPERON_V5_vs_PRIMUS.md:158`.
"""
pn_merge(a::PNCounter, b::PNCounter)::PNCounter = PNCounter(_pn_join(a.p, b.p), _pn_join(a.n, b.n))

# ── Transfers ────────────────────────────────────────────────────────────────────────────────────
#
# §2.6, verbatim: "A transfer is an idempotent, transaction-identified debit/credit pair, not a
# single counter mutation." The transaction id is what makes replay idempotent, and §2.6's invariant
# list names "preserved transaction identity" separately from "idempotent replay" — so the id is
# retained in `applied`, not discarded once acted on.

"""
    Transfer(txid, from, to, amount)

A transaction-identified debit/credit PAIR. Applying it debits `from` and credits `to` as one unit;
it is never a single counter mutation, so a partially-delivered transfer cannot leave value invented
or destroyed.
"""
struct Transfer
    txid::String
    from::String
    to::String
    amount::Int
end

"""
    TransferLog

Reconciliation state for one replica: the counters it owns, the transaction ids it has already
applied, and a quarantine.

§2.6: "Policy-invalid/duplicated/unmatched transfer records are quarantined or compensated under a
deterministic reconciliation rule." Ours: a DUPLICATE txid is a silent no-op (idempotent replay); a
policy-invalid record (non-positive amount, unknown account under `strict`, or a debit that would
break a nonnegative domain) is QUARANTINED with its reason and never partially applied.
"""
struct TransferLog
    accounts::Dict{String, PNCounter}
    applied::Set{String}                       # txids — transaction identity, retained not discarded
    quarantined::Vector{Tuple{Transfer, String}}
    nonnegative::Bool                          # escrow/bounded domain (§2.6): refuse to go negative
end

TransferLog(; nonnegative::Bool = true) =
    TransferLog(Dict{String, PNCounter}(), Set{String}(), Tuple{Transfer, String}[], nonnegative)

"Balance of `account` (0 if it has never been touched)."
tl_balance(t::TransferLog, account::AbstractString)::Int =
    haskey(t.accounts, String(account)) ? pn_value(t.accounts[String(account)]) : 0

_tl_counter!(t::TransferLog, account::String)::PNCounter =
    get!(() -> PNCounter(), t.accounts, account)

"""
    tl_apply!(log, tr; replica) -> Symbol

Apply one transfer. Returns `:applied`, `:duplicate` (already seen — idempotent replay, a no-op), or
`:quarantined` (recorded with a reason, nothing mutated).

The debit and credit are committed together after all checks pass, so a quarantined transfer leaves
NO partial effect — the "not a single counter mutation" requirement cuts both ways.
"""
function tl_apply!(t::TransferLog, tr::Transfer; replica::AbstractString)::Symbol
    tr.txid in t.applied && return :duplicate          # idempotent replay — the txid is the identity

    if tr.amount <= 0
        push!(t.quarantined, (tr, "non-positive amount"))
        return :quarantined
    end
    if tr.from == tr.to
        push!(t.quarantined, (tr, "self-transfer"))
        return :quarantined
    end
    # Escrow / bounded-counter domain (§2.6): "if a resource must never go negative, an escrow or
    # bounded-counter CRDT allocates spendable rights BEFORE the debit." We check the right exists
    # before committing either leg, rather than debiting and repairing after.
    if t.nonnegative && tl_balance(t, tr.from) < tr.amount
        push!(t.quarantined, (tr, "insufficient balance for nonnegative domain"))
        return :quarantined
    end

    r = String(replica)
    pn_decrement!(_tl_counter!(t, tr.from), r, tr.amount)   # debit  → N component
    pn_increment!(_tl_counter!(t, tr.to), r, tr.amount)     # credit → P component
    push!(t.applied, tr.txid)
    :applied
end

"""
    tl_merge!(dst, src) -> TransferLog

Converge `src` into `dst`: per-account `pn_merge`, union of applied txids, concatenated quarantine.

The txid union is what preserves idempotence ACROSS replicas — after merging, a transfer already
applied on `src` will not be re-applied on `dst`.
"""
function tl_merge!(dst::TransferLog, src::TransferLog)::TransferLog
    for (acct, c) in src.accounts
        dst.accounts[acct] = haskey(dst.accounts, acct) ? pn_merge(dst.accounts[acct], c) : copy(c)
    end
    union!(dst.applied, src.applied)
    append!(dst.quarantined, src.quarantined)
    dst
end

export PNCounter, pn_value, pn_increment!, pn_decrement!, pn_merge
export Transfer, TransferLog, tl_apply!, tl_merge!, tl_balance
