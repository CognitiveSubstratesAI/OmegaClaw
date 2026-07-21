# Ledger.jl — the append-only, hash-chained evidence ledger (WP §7.3).
#
# Every gate decision is recorded as a tamper-evident chained entry: entry_hash = sha256(seq ∥
# proposal_hash ∥ decision ∥ prev_hash). This is the shared governance foundation the outbound-action
# gate and the metagraph write-gate both consume (ADR-061 D4) — the durable record that a proposal was
# seen and how it was disposed, independent of whether it executed. Optionally persisted (fsync) so a
# torn write replays cleanly.

using SHA: sha256
using Dates: now, UTC

struct LedgerEntry
    seq::Int
    proposal_hash::String
    action::String
    args::Vector{String}
    actor::String
    decision::String
    timestamp::String
    prev_hash::Union{String,Nothing}
    entry_hash::String
end

mutable struct Ledger
    path::Union{String,Nothing}
    entries::Vector{LedgerEntry}
    lock::ReentrantLock
end
Ledger(; path::Union{AbstractString,Nothing} = nothing) =
    Ledger(path === nothing ? nothing : String(path), LedgerEntry[], ReentrantLock())

_entry_hash(seq, phash, decision, prev) =
    bytes2hex(sha256(codeunits(string(seq, _US, phash, _US, decision, _US,
        prev === nothing ? "" : prev))))

"""
    record!(ledger, proposal, decision) -> LedgerEntry

Append a hash-chained entry for `(proposal, decision)`. Thread-safe. Returns the entry.
"""
function record!(ledger::Ledger, p::Proposal, decision::Decision)::LedgerEntry
    lock(ledger.lock) do
        prev = isempty(ledger.entries) ? nothing : ledger.entries[end].entry_hash
        seq = length(ledger.entries) + 1
        dstr = string(decision)
        e = LedgerEntry(seq, p.hash, p.action, p.args, p.actor, dstr,
            string(now(UTC)), prev, _entry_hash(seq, p.hash, dstr, prev))
        push!(ledger.entries, e)
        ledger.path === nothing || _persist!(ledger.path, e)
        return e
    end
end

# One JSON-ish line per entry (canonical field order), fsync-before-return (journal-first durability).
function _persist!(path::AbstractString, e::LedgerEntry)
    mkpath(dirname(path))
    line = string("{\"seq\":", e.seq,
        ",\"proposal_hash\":\"", e.proposal_hash, "\"",
        ",\"action\":\"", e.action, "\"",
        ",\"decision\":\"", e.decision, "\"",
        ",\"actor\":\"", e.actor, "\"",
        ",\"timestamp\":\"", e.timestamp, "\"",
        ",\"prev_hash\":", e.prev_hash === nothing ? "null" : string("\"", e.prev_hash, "\""),
        ",\"entry_hash\":\"", e.entry_hash, "\"}")
    open(path, "a") do io
        write(io, line, "\n")
        flush(io)
        try
            ccall(:fsync, Cint, (Cint,), fd(io))
        catch
        end
    end
    return nothing
end

"""
    verify_chain(ledger) -> Bool

Re-derive the hash chain and confirm every link (tamper-evidence check).
"""
function verify_chain(ledger::Ledger)::Bool
    prev = nothing
    for (i, e) in enumerate(ledger.entries)
        e.seq == i || return false
        e.prev_hash == prev || return false
        e.entry_hash == _entry_hash(e.seq, e.proposal_hash, e.decision, prev) || return false
        prev = e.entry_hash
    end
    return true
end
