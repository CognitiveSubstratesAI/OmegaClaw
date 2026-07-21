# Gate.jl — the governed-action gate (WP §7.7: the command→action causal seam), hardened.
#
# A worker/LLM proposes; NOTHING reaches the world except a typed, IMMUTABLE, hash-pinned Proposal that a
# SEPARATE policy consumer licenses with a 5-way Decision. The policy's authority comes from a SIGNED
# manifest OUTSIDE the agent's revision loop (HMAC-SHA256 with a key the agent cannot read/forge), so an
# agent that rewrites its own policy file cannot re-authorize itself (fail-closed). The proposal binds
# capabilities + policy-version + evidence-snapshot + expiry; the gate TOCTOU-re-checks all of it
# immediately before execution. A cache miss / failed analysis / expiry is NEVER permission (§11.5).

using SHA: sha256, hmac_sha256
using Dates: now, UTC, datetime2unix
import TOML

"The five governed-action dispositions (WP §7.7)."
@enum Decision Allow Deny RequireProbe RequireReview Defer

const _MAX_TTL = 300.0   # default short validity interval for a live proposal (§11.5 item 7), seconds

unixnow()::Float64 = datetime2unix(now(UTC))

# ── length-prefixed canonical encoding (no field-boundary aliasing; R1, spec §7.7) ──
function _canon(fields::AbstractVector{<:AbstractString})::String
    io = IOBuffer()
    for f in fields
        b = codeunits(f)
        print(io, length(b), ':')
        write(io, b)
        print(io, ';')
    end
    return String(take!(io))
end

"""
    Proposal(action, args; actor, timestamp, capabilities, policy_version, predicted_effect, rollback, evidence_snapshot, expiry)

A typed, immutable, hash-pinned outbound-action proposal. `hash` is a canonical (length-prefixed) sha256
over the FULL change — action ∥ args ∥ actor ∥ timestamp ∥ capabilities ∥ policy_version ∥ predicted_effect
∥ rollback ∥ evidence_snapshot ∥ expiry — so an approval of a different body cannot authorize this one, and
a decision bound under one policy/world-state cannot be replayed under another (§7.7).
"""
struct Proposal
    action::String
    args::Vector{String}
    actor::String
    timestamp::String
    capabilities::Vector{String}
    policy_version::String
    predicted_effect::String
    rollback::String
    evidence_snapshot::String
    expiry::Float64
    hash::String
end

function _proposal_hash(action, args, actor, timestamp, caps, pv, pe, rb, es, expiry)::String
    payload = _canon(String[
        String(action), _canon(String.(args)), String(actor), String(timestamp),
        _canon(String.(caps)), String(pv), String(pe), String(rb), String(es), string(expiry),
    ])
    return bytes2hex(sha256(codeunits(payload)))
end

function Proposal(action::AbstractString, args; actor::AbstractString = "agent",
    timestamp::AbstractString = string(now(UTC)),
    capabilities = String[], policy_version::AbstractString = "",
    predicted_effect::AbstractString = "", rollback::AbstractString = "",
    evidence_snapshot::AbstractString = "", expiry::Real = 0.0)
    a = collect(String, args)
    caps = collect(String, capabilities)
    h = _proposal_hash(action, a, actor, timestamp, caps, policy_version, predicted_effect,
        rollback, evidence_snapshot, Float64(expiry))
    return Proposal(String(action), a, String(actor), String(timestamp), caps,
        String(policy_version), String(predicted_effect), String(rollback),
        String(evidence_snapshot), Float64(expiry), h)
end

"""
    Policy

The externally-rooted authority. `version` + `signature_valid` + `manifest_path` come from a signed
manifest; `enforce_signature` gates fail-closed behaviour. `deny`/`review`/`probe`/`defer` pattern lists
drive the 5-way decision. `source` records provenance so the policy the agent runs under is auditable and
NOT written by the agent's own loop.
"""
struct Policy
    allow_actions::Set{String}
    deny_patterns::Vector{Regex}
    review_patterns::Vector{Regex}
    probe_patterns::Vector{Regex}
    defer_patterns::Vector{Regex}
    version::String
    source::String
    signature_valid::Bool
    enforce_signature::Bool
    manifest_path::Union{String,Nothing}
end

"The conservative built-in policy (shadow/dev mode — signature not enforced)."
function default_policy()::Policy
    Policy(
        Set(["shell", "read-file", "http-get"]),
        Regex[r"rm\s+-rf", r"\bmkfs\b", r"dd\s+if=", r":\(\)\s*\{\s*:\|:", r">\s*/dev/",
              r"\bshutdown\b", r"\breboot\b", r"/etc/(passwd|shadow)"],
        Regex[r"\bsudo\b", r"\bcurl\b.*\|\s*sh", r"\bgit\s+push\b", r"\bssh\b"],
        Regex[], Regex[],
        "builtin", "builtin-default", false, false, nothing,
    )
end

# ── signed-manifest authority (HMAC-SHA256, zero new deps) ──
_ct_eq(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})::Bool =
    length(a) == length(b) && (reduce(|, (a[i] ⊻ b[i] for i in eachindex(a)); init = 0x00) == 0x00)

"Resolve the trust key (bytes) from OUTSIDE the agent's revision loop; `nothing` ⇒ shadow/dev mode."
function _trust_key()::Union{Vector{UInt8},Nothing}
    kf = get(ENV, "OMEGACLAW_TRUST_KEYFILE", "")
    isempty(kf) || (isfile(kf) && return read(kf))
    ki = get(ENV, "OMEGACLAW_TRUST_KEY", "")
    isempty(ki) || return Vector{UInt8}(codeunits(ki))
    return nothing
end

_sig_path(path::AbstractString) = string(path, ".sig")

"Operator/CI tool (run OUTSIDE the agent loop): write the detached HMAC signature sidecar for `path`."
function sign_manifest!(path::AbstractString, key::AbstractVector{UInt8})
    sig = bytes2hex(hmac_sha256(Vector{UInt8}(key), read(path)))
    write(_sig_path(path), sig)
    return sig
end

"Verify the detached HMAC signature. False on any missing key/sig/file or hex/parse error (fail-closed)."
function verify_manifest(path::AbstractString, key)::Bool
    key === nothing && return false
    sp = _sig_path(path)
    (isfile(path) && isfile(sp)) || return false
    try
        want = hmac_sha256(Vector{UInt8}(key), read(path))
        got = hex2bytes(strip(read(sp, String)))
        return _ct_eq(want, got)
    catch
        return false
    end
end

_regexes(m, k) = Regex[Regex(String(p)) for p in get(m, k, String[])]

"""
    load_policy(path; key=_trust_key()) -> Policy

Load a policy from a signed TOML manifest OUTSIDE the agent's revision loop (§7.7 authority seam).
FAIL-CLOSED: when a key is present (enforcing mode) and the signature is missing/invalid, return a LOCKED
empty-allow policy (every action Denied). With no key (shadow/dev mode), parse without enforcement.
"""
function load_policy(path::AbstractString; key = _trust_key())::Policy
    enforce = key !== nothing
    sig_ok = enforce ? verify_manifest(path, key) : false
    if enforce && !sig_ok
        return Policy(Set{String}(), Regex[], Regex[], Regex[], Regex[],
            "LOCKED", "unverified:" * abspath(path), false, true, abspath(path))
    end
    isfile(path) || return default_policy()   # shadow mode only
    m = TOML.parsefile(path)
    return Policy(
        Set(String[String(a) for a in get(m, "allow_actions", String[])]),
        _regexes(m, "deny_patterns"), _regexes(m, "review_patterns"),
        _regexes(m, "probe_patterns"), _regexes(m, "defer_patterns"),
        String(get(m, "policy_version", "unversioned")),
        abspath(path), sig_ok, enforce, abspath(path),
    )
end

"""
    decide(policy, proposal) -> Decision

The 5-way governed-action decision. Precedence: an unlisted action or a deny-pattern ⇒ `Deny`; else a
review-pattern ⇒ `RequireReview`; a probe-pattern ⇒ `RequireProbe`; a defer-pattern ⇒ `Defer`; else `Allow`.
"""
function decide(policy::Policy, p::Proposal)::Decision
    p.action in policy.allow_actions || return Deny
    joined = string(p.action, " ", join(p.args, " "))   # match against action AND args
    any(pat -> occursin(pat, joined), policy.deny_patterns) && return Deny
    any(pat -> occursin(pat, joined), policy.review_patterns) && return RequireReview
    any(pat -> occursin(pat, joined), policy.probe_patterns) && return RequireProbe
    any(pat -> occursin(pat, joined), policy.defer_patterns) && return Defer
    return Allow
end
