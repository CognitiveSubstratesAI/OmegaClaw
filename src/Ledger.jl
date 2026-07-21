# Ledger.jl — the append-only, hash-chained evidence ledger (WP §7.3), authenticated over ALL fields.
#
# Every gate decision is a tamper-evident chained entry whose hash covers EVERY evidentiary field (action,
# args, actor, timestamp, proposal_hash, decision, policy_version, evidence_snapshot, expiry, receipt,
# prev_hash) — so editing the human-readable `action` on disk is detected, not just the decision. The
# decision is committed BEFORE the op runs (§7.6 "prediction committed before execution, never edited
# after"); a receipt entry is appended after. Optionally fsync-persisted so a torn write replays cleanly.

using SHA: sha256
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

function _entry_hash(seq, phash, action, args, actor, decision, pv, es, expiry, receipt, timestamp, prev)::String
    payload = _canon(String[
        string(seq), String(phash), String(action), _canon(String.(args)), String(actor),
        String(decision), String(pv), String(es), string(expiry), String(receipt),
        String(timestamp),                                    # B2: timestamp is now authenticated
        prev === nothing ? "" : String(prev),
    ])
    return bytes2hex(sha256(codeunits(payload)))
end

"""
    record!(ledger, proposal, decision; receipt="") -> LedgerEntry

Append a hash-chained entry for `(proposal, decision)`, carrying the proposal's policy_version /
evidence_snapshot / expiry (so an Allow can't be replayed under a changed policy/world). Thread-safe.
"""
function record!(ledger::Ledger, p::Proposal, decision::Decision; receipt::AbstractString = "")::LedgerEntry
    lock(ledger.lock) do
        prev = isempty(ledger.entries) ? nothing : ledger.entries[end].entry_hash
        seq = length(ledger.entries) + 1
        d = string(decision)
        ts = string(now(UTC))
        eh = _entry_hash(seq, p.hash, p.action, p.args, p.actor, d, p.policy_version,
            p.evidence_snapshot, p.expiry, receipt, ts, prev)
        e = LedgerEntry(seq, p.hash, p.action, p.args, p.actor, d, p.policy_version,
            p.evidence_snapshot, p.expiry, String(receipt), ts, prev, eh)
        push!(ledger.entries, e)
        ledger.path === nothing || _persist!(ledger.path, e)
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

"""
    verify_chain(ledger) -> Bool

Re-derive every entry's hash from ITS stored fields and confirm the chain (tamper-evidence over ALL
fields — editing action/args/decision/policy_version/… all break it).
"""
function verify_chain(ledger::Ledger)::Bool
    prev = nothing
    for (i, e) in enumerate(ledger.entries)
        e.seq == i || return false
        e.prev_hash == prev || return false
        want = _entry_hash(e.seq, e.proposal_hash, e.action, e.args, e.actor, e.decision,
            e.policy_version, e.evidence_snapshot, e.expiry, e.receipt, e.timestamp, prev)
        e.entry_hash == want || return false
        prev = e.entry_hash
    end
    return true
end
