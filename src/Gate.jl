# Gate.jl — the governed-action gate (WP §7.7: the command→action causal seam).
#
# A worker/LLM proposes; NOTHING reaches the world except a typed, hash-pinned Proposal that a
# SEPARATE policy consumer licenses with a 5-way Decision, its authority sourced from a manifest
# OUTSIDE the agent's own revision loop. This is distinct from MetaMo `govern!` (which chooses the
# motive/goal); this licenses whether an outbound command may execute.

using SHA: sha256
using Dates: now, UTC
import TOML

"The five governed-action dispositions (WP §7.7)."
@enum Decision Allow Deny RequireProbe RequireReview Defer

const _US = '\x1f'   # unit separator — canonical field delimiter for hashing

"""
    Proposal(action, args; actor, timestamp)

A typed, immutable, hash-pinned outbound-action proposal. `hash` is a canonical sha256 over the full
content (action ∥ args ∥ actor ∥ timestamp) — a later "approval" of a different body cannot authorize
this one (§7.7: "a vague approval … cannot authorize a different body").
"""
struct Proposal
    action::String
    args::Vector{String}
    actor::String
    timestamp::String
    hash::String
end

function _proposal_hash(action::AbstractString, args, actor::AbstractString, ts::AbstractString)::String
    buf = string(action, _US, join(args, _US), _US, actor, _US, ts)
    return bytes2hex(sha256(codeunits(buf)))
end

function Proposal(action::AbstractString, args; actor::AbstractString = "agent",
    timestamp::AbstractString = string(now(UTC)))
    a = collect(String, args)
    return Proposal(String(action), a, String(actor), String(timestamp),
        _proposal_hash(action, a, actor, timestamp))
end

"""
    Policy

The externally-rooted authority: which actions are allowed, and pattern rules that force Deny or
RequireReview. `source` records provenance (a manifest path or `"builtin-default"`) so the policy the
agent runs under is auditable and NOT written by the agent's own loop.
"""
struct Policy
    allow_actions::Set{String}
    deny_patterns::Vector{Regex}
    review_patterns::Vector{Regex}
    source::String
end

"The conservative built-in policy used when no signed manifest is supplied."
function default_policy()::Policy
    Policy(
        Set(["shell", "read-file", "http-get"]),
        Regex[r"rm\s+-rf", r"\bmkfs\b", r"dd\s+if=", r":\(\)\s*\{\s*:\|:", r">\s*/dev/",
              r"\bshutdown\b", r"\breboot\b", r"/etc/(passwd|shadow)"],
        Regex[r"\bsudo\b", r"\bcurl\b.*\|\s*sh", r"\bgit\s+push\b", r"\bssh\b"],
        "builtin-default",
    )
end

"""
    load_policy(path) -> Policy

Load a policy from a TOML manifest OUTSIDE the agent's revision loop (the §7.7 authority seam;
signature verification is a later hardening). Falls back to `default_policy()` if `path` is missing.
Expected shape: `allow_actions = [...]`, `deny_patterns = [...]`, `review_patterns = [...]`.
"""
function load_policy(path::AbstractString)::Policy
    isfile(path) || return default_policy()
    m = TOML.parsefile(path)
    _regexes(k) = Regex[Regex(String(p)) for p in get(m, k, String[])]
    return Policy(
        Set(String[String(a) for a in get(m, "allow_actions", String[])]),
        _regexes("deny_patterns"),
        _regexes("review_patterns"),
        abspath(path),
    )
end

"""
    decide(policy, proposal) -> Decision

The 5-way governed-action decision. An unlisted action or a deny-pattern match ⇒ `Deny`; a
review-pattern match ⇒ `RequireReview`; otherwise `Allow`. (`RequireProbe`/`Defer` are part of the
disposition set for richer policies; the built-in maps to Allow/Deny/RequireReview.)
"""
function decide(policy::Policy, p::Proposal)::Decision
    p.action in policy.allow_actions || return Deny
    joined = join(p.args, " ")
    for pat in policy.deny_patterns
        occursin(pat, joined) && return Deny
    end
    for pat in policy.review_patterns
        occursin(pat, joined) && return RequireReview
    end
    return Allow
end
