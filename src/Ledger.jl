# Ledger.jl — the append-only, hash-chained evidence ledger (WP §7.3), authenticated over ALL fields.
#
# Every gate decision is a tamper-evident chained entry whose hash covers EVERY evidentiary field (action,
# args, actor, timestamp, proposal_hash, decision, policy_version, evidence_snapshot, expiry, receipt,
# prev_hash) — so editing the human-readable `action` on disk is detected, not just the decision. The
# decision is committed BEFORE the op runs (§7.6 "prediction committed before execution, never edited
# after"); a receipt entry is appended after. Optionally fsync-persisted so a torn write replays cleanly.

using SHA: sha256, hmac_sha256
using Dates: now, UTC

struct LedgerEntry
    seq::Int
    proposal_hash::String
    action::String
    args::Vector{String}
    actor::String
    decision::String
    policy_version::String
    evidence_snapshot::String
    expiry::Float64
    receipt::String
    timestamp::String
    prev_hash::Union{String,Nothing}
    entry_hash::String
end

# 9-arg back-compat constructor (seq, proposal_hash, action, args, actor, decision, timestamp, prev, entry_hash)
LedgerEntry(seq::Integer, phash::AbstractString, action::AbstractString, args::AbstractVector,
    actor::AbstractString, decision::AbstractString, timestamp::AbstractString,
    prev::Union{AbstractString,Nothing}, entry_hash::AbstractString) =
    LedgerEntry(Int(seq), String(phash), String(action), collect(String, args), String(actor),
        String(decision), "", "", 0.0, "", String(timestamp),
        prev === nothing ? nothing : String(prev), String(entry_hash))

mutable struct Ledger
    path::Union{String,Nothing}
    entries::Vector{LedgerEntry}
    lock::ReentrantLock
end
Ledger(; path::Union{AbstractString,Nothing} = nothing) =
    Ledger(path === nothing ? nothing : String(path), LedgerEntry[], ReentrantLock())

# The ledger's authentication key: the trust key when it resolves to real material, else `nothing`
# (shadow/dev ⇒ unauthenticated sha256 chain). `:locked` (configured-but-unresolvable) also ⇒ nothing here —
# a locked gate Denies every action, so the ledger only accrues Deny entries and we never emit a FORGEABLE
# keyed head. Same live-key resolution the gate uses (`_trust_key`, Gate.jl), so a key set out-of-loop
# authenticates the ledger with no code change.
_ledger_mac_key()::Union{Vector{UInt8},Nothing} = (k = _trust_key(); k isa Vector{UInt8} ? k : nothing)

# Per-entry authenticator over ALL evidentiary fields + prev (the chain link). KEYED (HMAC-SHA256) when a
# trust key is present — so a full re-forge (rewrite every entry AND recompute every hash) is impossible
# without the key (B10); falls back to plain sha256 in shadow/dev mode (no key), preserving tamper-evidence.
function _entry_hash(key::Union{Vector{UInt8},Nothing}, seq, phash, action, args, actor, decision, pv, es, expiry, receipt, timestamp, prev)::String
    payload = _canon(String[
        string(seq), String(phash), String(action), _canon(String.(args)), String(actor),
        String(decision), String(pv), String(es), string(expiry), String(receipt),
        String(timestamp),                                    # B2: timestamp is authenticated
        prev === nothing ? "" : String(prev),
    ])
    msg = Vector{UInt8}(codeunits(payload))
    return bytes2hex(key === nothing ? sha256(msg) : hmac_sha256(key, msg))
end

"""
    record!(ledger, proposal, decision; receipt="") -> LedgerEntry

Append a hash-chained entry for `(proposal, decision)`, carrying the proposal's policy_version /
evidence_snapshot / expiry (so an Allow can't be replayed under a changed policy/world). Thread-safe.
"""
function record!(ledger::Ledger, p::Proposal, decision::Decision; receipt::AbstractString = "")::LedgerEntry
    lock(ledger.lock) do
        key = _ledger_mac_key()
        prev = isempty(ledger.entries) ? nothing : ledger.entries[end].entry_hash
        seq = length(ledger.entries) + 1
        d = string(decision)
        ts = string(now(UTC))
        eh = _entry_hash(key, seq, p.hash, p.action, p.args, p.actor, d, p.policy_version,
            p.evidence_snapshot, p.expiry, receipt, ts, prev)
        e = LedgerEntry(seq, p.hash, p.action, p.args, p.actor, d, p.policy_version,
            p.evidence_snapshot, p.expiry, String(receipt), ts, prev, eh)
        push!(ledger.entries, e)
        if ledger.path !== nothing
            _persist!(ledger.path, e)
            key === nothing || _persist_head!(ledger.path, seq, eh, key)   # co-located head anchor over (count:tip)
        end
        return e
    end
end

# JSON string escape (so an arg with quotes/backslashes/newlines can't corrupt the persisted line)
function _jstr(io::IO, s::AbstractString)
    print(io, '"')
    for c in s
        c == '"' ? print(io, "\\\"") : c == '\\' ? print(io, "\\\\") :
        c == '\n' ? print(io, "\\n") : c == '\r' ? print(io, "\\r") :
        c == '\t' ? print(io, "\\t") : c < '\x20' ? print(io, "\\u", lpad(string(UInt16(c); base = 16), 4, '0')) :
        print(io, c)
    end
    print(io, '"')
end

function _persist!(path::AbstractString, e::LedgerEntry)
    mkpath(dirname(path))
    io = IOBuffer()
    print(io, "{\"seq\":", e.seq, ",\"proposal_hash\":"); _jstr(io, e.proposal_hash)
    print(io, ",\"action\":"); _jstr(io, e.action)
    print(io, ",\"args\":["); for (i, a) in enumerate(e.args); i > 1 && print(io, ','); _jstr(io, a); end; print(io, "]")
    print(io, ",\"actor\":"); _jstr(io, e.actor)
    print(io, ",\"decision\":"); _jstr(io, e.decision)
    print(io, ",\"policy_version\":"); _jstr(io, e.policy_version)
    print(io, ",\"evidence_snapshot\":"); _jstr(io, e.evidence_snapshot)
    print(io, ",\"expiry\":", e.expiry, ",\"receipt\":"); _jstr(io, e.receipt)
    print(io, ",\"timestamp\":"); _jstr(io, e.timestamp)
    print(io, ",\"prev_hash\":"); e.prev_hash === nothing ? print(io, "null") : _jstr(io, e.prev_hash)
    print(io, ",\"entry_hash\":"); _jstr(io, e.entry_hash); print(io, "}")
    line = String(take!(io))
    open(path, "a") do fh
        write(fh, line, "\n"); flush(fh)
        try; ccall(:fsync, Cint, (Cint,), fd(fh)); catch; end
    end
    return nothing
end

_head_path(path::AbstractString) = string(path, ".head")

# The authenticated chain HEAD: HMAC(key, "count:tip_entry_hash"). Each entry_hash commits to its prev, so
# the tip commits to the WHOLE chain; MAC-ing (count:tip) also pins the LENGTH, so FORWARD tail-truncation
# (N→k<N) is detected and neither a re-forge nor a truncation can recompute the MAC without the key. This
# `.head` is a CO-LOCATED sibling (overwritten in place each record!); its PRESENCE is also the on-disk
# "this ledger is keyed" marker — verify refuses a keyed ledger under a downgraded/absent key when it exists.
#
# ⚠️ RESIDUAL LIMITATION (by design, documented — NOT closed here): the `.head` is co-located and overwritten,
# so it does NOT defend ROLLBACK/REPLAY (restoring a captured earlier ledger+`.head` prefix) nor FULL DELETION
# of both the log and its anchor. Those are indistinguishable from an authentic shorter/fresh ledger using
# only self-contained on-disk state. Closing them requires a genuinely EXTERNAL monotonic witness the agent
# cannot rewrite (an operator-written/read-only high-water, TPM/sealed counter, or a remote transparency
# witness) — a deployment-layer property, not something agent-written application code can honestly provide.
# The intended extension point is an operator-run `seal_ledger!`-style tool that writes a read-only witness
# outside the agent's uid; verify would then require `entries ≥ witnessed_count`. Left as a deployment hook.
_head_mac(key::Vector{UInt8}, count::Integer, tip::AbstractString) =
    hmac_sha256(key, Vector{UInt8}(codeunits(string(count, ':', tip))))

function _persist_head!(path::AbstractString, count::Integer, tip::AbstractString, key::Vector{UInt8})
    mkpath(dirname(path))
    open(_head_path(path), "w") do fh
        write(fh, bytes2hex(_head_mac(key, count, tip))); flush(fh)
        try; ccall(:fsync, Cint, (Cint,), fd(fh)); catch; end
    end
    return nothing
end

# Rebuild a LedgerEntry from a parsed JSON object (the persisted line). Full 13-field ctor.
function _entry_from_json(o)::LedgerEntry
    LedgerEntry(Int(o.seq), String(o.proposal_hash), String(o.action),
        String[String(a) for a in o.args], String(o.actor), String(o.decision),
        String(o.policy_version), String(o.evidence_snapshot), Float64(o.expiry),
        String(o.receipt), String(o.timestamp),
        o.prev_hash === nothing ? nothing : String(o.prev_hash), String(o.entry_hash))
end

# The VERIFICATION-time key: the FULL trust-key resolution (Vector | nothing | :locked). Unlike the write
# path (`_ledger_mac_key`, which may drop to sha256), verification must SEE `:locked` so it can fail closed —
# never verify a configured-but-unresolvable ledger as a plain sha256 chain (the B10 downgrade). Non-Vector
# results are handled explicitly by each verifier.
_verify_key() = _trust_key()
_MAX_LINE = 1 << 20   # 1 MiB: an oversized line is treated as torn (fail closed), not a large allocation (DoS)

"""
    verify_chain(ledger; key=_verify_key()) -> Bool

Re-derive every entry's hash from ITS stored fields and confirm the chain (tamper-evidence over ALL fields).
With a trust key the links are HMAC, so recomputing them — the full re-forge (B10) — is impossible without
the key; without a key it is the plain sha256 chain. A `:locked` key (configured-but-unresolvable) fails
CLOSED — it is NEVER silently downgraded to sha256.
"""
function verify_chain(ledger::Ledger; key = _verify_key())::Bool
    key === :locked && return false                        # B10: configured-but-unresolvable ⇒ fail closed
    kk = key isa Vector{UInt8} ? key : nothing
    prev = nothing
    for (i, e) in enumerate(ledger.entries)
        e.seq == i || return false
        e.prev_hash == prev || return false
        want = _entry_hash(kk, e.seq, e.proposal_hash, e.action, e.args, e.actor, e.decision,
            e.policy_version, e.evidence_snapshot, e.expiry, e.receipt, e.timestamp, prev)
        e.entry_hash == want || return false
        prev = e.entry_hash
    end
    return true
end

"""
    verify_head(ledger; key=_verify_key()) -> Bool

Check the persisted `.head` anchor. It authenticates (count:tip): a full re-forge OR forward tail-truncation
(N→k<N) changes it and can't be re-MAC'd without the key. `.head`'s PRESENCE is also the keyed-mode marker.
Fails CLOSED on: `:locked`; a downgraded/absent key while a `.head` exists (keyed→shadow); a keyed ledger
truncated-to-empty with a stale `.head`; entries with no anchor. TOLERATES exactly one case that is a torn
write, never an attack: the head lagging by ONE over a chain-valid tail (a crash after the entry fsync but
before the head rewrite) — in keyed mode a keyless attacker cannot forge that extra HMAC-valid entry, and a
truncation leaves the head AHEAD (rejected), so a one-behind head is provably a crash. Rollback/full-deletion
are NOT defended (see the head-anchor limitation note). In-memory (no path) ⇒ persistence-scoped, true.

PRESUPPOSES `verify_chain`: this authenticates the `.head` anchor plus (in the torn case) the single tail
link — it does NOT re-derive the whole chain. ALWAYS pair it with `verify_chain` (load_ledger / verify_ledger
/ __init__ all do); never trust `verify_head` alone as a full-integrity gate.
"""
function verify_head(ledger::Ledger; key = _verify_key())::Bool
    key === :locked && return false                        # fail closed, never sha256
    ledger.path === nothing && return true                # in-memory: anchor is persistence-scoped
    hp = _head_path(ledger.path)
    if !(key isa Vector{UInt8})                           # shadow (no key): legit ONLY if there is no keyed anchor
        return !isfile(hp)                                # a present `.head` ⇒ keyed ledger under no key ⇒ downgrade ⇒ fail
    end
    n = length(ledger.entries)
    n == 0 && return !isfile(hp)                          # empty: legit iff no stale anchor (present ⇒ truncated-to-empty)
    # entries but no anchor ⇒ fail closed. This also (correctly) locks a crash during the very FIRST record!
    # (1 entry, `.head` not yet written): an "entries, no anchor" state MUST reject to defend truncation, and
    # there is no anchor to prove a one-behind torn tail. Recover by operator re-anchor — do NOT weaken this.
    isfile(hp) || return false
    got = try; hex2bytes(strip(read(hp, String))); catch; return false; end
    _ct_eq(_head_mac(key, n, ledger.entries[end].entry_hash), got) && return true   # normal: head pins (n:tip_n)
    # torn-tail tolerance: head lagging by exactly one over a chain-valid tail = crash, not attack (truncation
    # leaves the head AHEAD, not behind; a keyless attacker can't forge the HMAC-valid entry n).
    n >= 2 && _ct_eq(_head_mac(key, n - 1, ledger.entries[n - 1].entry_hash), got) &&
        _valid_link(key, ledger.entries, n) && return true
    return false
end

# entry `i` is a valid keyed chain link over entry i-1 (recompute its HMAC entry_hash + prev_hash link).
function _valid_link(key::Vector{UInt8}, entries::Vector{LedgerEntry}, i::Int)::Bool
    e, p = entries[i], entries[i - 1]
    e.seq == i && e.prev_hash == p.entry_hash &&
        e.entry_hash == _entry_hash(key, e.seq, e.proposal_hash, e.action, e.args, e.actor, e.decision,
            e.policy_version, e.evidence_snapshot, e.expiry, e.receipt, e.timestamp, p.entry_hash)
end

"chain + authenticated head both hold (the full on-load / on-demand integrity check)."
verify_ledger(ledger::Ledger; key = _verify_key())::Bool =
    verify_chain(ledger; key = key) && verify_head(ledger; key = key)

"""
    load_ledger(path; key=_verify_key()) -> (; ledger, chain_ok, head_ok, authenticated, n)

B7: reload a persisted ledger from disk and VERIFY it (chain + authenticated `.head`). Each JSONL entry is
parsed with JSON3 (robust to embedded quotes/newlines/unicode in args); a malformed, torn, or oversized
(`>_MAX_LINE`) line fails closed (`chain_ok=false`), never a silent accept or a large allocation.
`authenticated` = a real key was in force (`:locked`/shadow ⇒ false). A returned ledger with
`chain_ok && head_ok == false` MUST NOT be trusted — the on-disk evidence was tampered or forward-truncated
(rollback/full-deletion are NOT detectable here — see the head-anchor limitation note).
"""
function load_ledger(path::AbstractString; key = _verify_key())
    entries = LedgerEntry[]
    parse_ok = true
    if isfile(path)
        for line in eachline(path)
            isempty(strip(line)) && continue
            (ncodeunits(line) > _MAX_LINE) && (parse_ok = false; break)   # oversized ⇒ torn (no DoS alloc)
            e = try
                _entry_from_json(JSON3.read(line))
            catch
                parse_ok = false; break                     # torn/corrupt line ⇒ fail closed
            end
            push!(entries, e)
        end
    end
    led = Ledger(String(path), entries, ReentrantLock())
    return (; ledger = led,
        chain_ok = parse_ok && verify_chain(led; key = key),
        head_ok = verify_head(led; key = key),
        authenticated = key isa Vector{UInt8}, n = length(entries))
end
