"""
The actual CORS probe battery and the logic for judging each response.
Each probe sends one real HTTP request with a crafted Origin header and
inspects the actual Access-Control-* response headers that come back -
there is no static rule list here, only "what did the server really do
when asked this specific question."

Why active probing instead of reading one response's headers:
a single request only shows what the server does for *that* Origin. A
server that correctly rejects a random attacker origin can still be
fully broken for a different, carefully-chosen one (a naive substring
match, a trust-null-origin bug, or a wildcard-plus-credentials
combination that only shows up when you send credentials-bearing
preflight). Each finding below corresponds to one specific crafted
request a real attacker would actually try.
"""

import requests


class CorsFinding:
    def __init__(self, severity, probe_name, message, origin_sent=None, acao_received=None, acac_received=None):
        self.severity = severity
        self.probe_name = probe_name
        self.message = message
        self.origin_sent = origin_sent
        self.acao_received = acao_received
        self.acac_received = acac_received


def _get_with_origin(url, origin, session, timeout):
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    return session.get(url, headers=headers, timeout=timeout)


def _preflight(url, origin, session, timeout, method="PUT", request_headers="X-Custom-Header"):
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": request_headers,
    }
    return session.options(url, headers=headers, timeout=timeout)


def probe_reflects_arbitrary_origin(url, session, timeout):
    """The core CORS bug: does the server reflect back ANY Origin we
    send, rather than checking it against an allowlist? Especially
    dangerous combined with Allow-Credentials: true, since that lets
    any website read authenticated responses from a victim's browser."""
    attacker_origin = "https://attacker-controlled-domain.example"
    resp = _get_with_origin(url, attacker_origin, session, timeout)
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == attacker_origin:
        if acac == "true":
            return CorsFinding("CRITICAL", "reflects_arbitrary_origin",
                "Server reflects ANY Origin back in Access-Control-Allow-Origin AND sets "
                "Access-Control-Allow-Credentials: true - any website can make an authenticated "
                "request to this API on a logged-in victim's behalf and read the response. "
                "This is the single most serious CORS misconfiguration.",
                origin_sent=attacker_origin, acao_received=acao, acac_received=acac)
        return CorsFinding("HIGH", "reflects_arbitrary_origin",
            "Server reflects ANY Origin back in Access-Control-Allow-Origin (without credentials). "
            "Any website can read this endpoint's responses in a cross-origin fetch - not as severe "
            "as with credentials, but still exposes anything not meant to be public.",
            origin_sent=attacker_origin, acao_received=acao, acac_received=acac)
    return None


def probe_null_origin_trusted(url, session, timeout):
    """Origin: null is sent by browsers in several legitimate-but-
    attacker-reachable contexts: a sandboxed iframe, a local file://
    page, some redirect chains. A server that trusts it as if it were
    a normal origin can be attacked from any of those contexts."""
    resp = _get_with_origin(url, "null", session, timeout)
    acao = resp.headers.get("Access-Control-Allow-Origin")
    if acao == "null":
        return CorsFinding("HIGH", "null_origin_trusted",
            "Server sets Access-Control-Allow-Origin: null in response to an Origin: null request. "
            "'null' is attacker-reachable (sandboxed iframes, local HTML files, some redirects), "
            "so trusting it is equivalent to trusting an arbitrary unauthenticated context.",
            origin_sent="null", acao_received=acao)
    return None


def probe_wildcard_with_credentials(url, session, timeout):
    """ACAO: * combined with Allow-Credentials: true is invalid per the
    Fetch spec and browsers reject it outright - but plenty of server
    frameworks will still happily SEND both headers, which is a real
    misconfiguration even though a browser won't act on it: it means
    whoever wrote this config didn't understand the invariant, and any
    other code path that computes these headers slightly differently
    may not have the browser's spec compliance as a safety net."""
    resp = _get_with_origin(url, "https://example-probe-origin.test", session, timeout)
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*" and acac == "true":
        return CorsFinding("MEDIUM", "wildcard_with_credentials",
            "Server sends both Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true. "
            "This combination is invalid per the Fetch spec and browsers will refuse to expose the "
            "response to script - but the server configuration itself is still broken, and shouldn't "
            "be relied upon to stay safe only because of browser-side spec enforcement.",
            origin_sent="https://example-probe-origin.test", acao_received=acao, acac_received=acac)
    return None


def probe_naive_substring_match(url, session, timeout, trusted_domain_hint):
    """Tests the classic 'endswith()'/'in' string-matching bug: if an
    allowlist check does origin.endswith("trusted.example") instead of
    a proper domain-boundary check, then "https://eviltrusted.example"
    (no separator before the trusted suffix) incorrectly passes."""
    if not trusted_domain_hint:
        return None
    bypass_origin = f"https://evil{trusted_domain_hint}"
    resp = _get_with_origin(url, bypass_origin, session, timeout)
    acao = resp.headers.get("Access-Control-Allow-Origin")
    if acao == bypass_origin:
        return CorsFinding("HIGH", "naive_substring_match",
            f"Origin '{bypass_origin}' was accepted - this looks like a naive string-suffix check "
            f"(e.g. origin.endswith('{trusted_domain_hint}')) rather than a proper domain-boundary "
            f"match, since this domain is not actually a subdomain of the trusted one, just a string "
            f"that happens to end with it.",
            origin_sent=bypass_origin, acao_received=acao)
    return None


def probe_scheme_downgrade(url, session, timeout, trusted_origin_hint):
    """If the real trusted origin is https://trusted.example, does the
    server also accept the plain-http version? Accepting http when the
    canonical origin is https widens the attack surface to anyone who
    can intercept or spoof unencrypted traffic to that same hostname."""
    if not trusted_origin_hint or not trusted_origin_hint.startswith("https://"):
        return None
    http_variant = "http://" + trusted_origin_hint[len("https://"):]
    resp = _get_with_origin(url, http_variant, session, timeout)
    acao = resp.headers.get("Access-Control-Allow-Origin")
    if acao == http_variant:
        return CorsFinding("MEDIUM", "scheme_downgrade_accepted",
            f"Server accepts '{http_variant}' (plain HTTP) even though the trusted origin is HTTPS. "
            f"Anyone who can intercept or spoof unencrypted traffic to that hostname can use this to "
            f"satisfy the origin check.",
            origin_sent=http_variant, acao_received=acao)
    return None


def probe_missing_vary_origin(url, session, timeout, trusted_origin_hint):
    """If the server computes Access-Control-Allow-Origin dynamically
    (echoing back whatever origin it decided to trust) but doesn't set
    'Vary: Origin', an intermediate cache can serve one origin's cached
    response - including the ACAO header - to a different origin,
    which can leak private data through the cache rather than through
    the CORS check itself."""
    origin = trusted_origin_hint or "https://example-probe-origin.test"
    resp = _get_with_origin(url, origin, session, timeout)
    acao = resp.headers.get("Access-Control-Allow-Origin")
    vary = resp.headers.get("Vary", "")
    if acao and acao not in ("*", "") and "origin" not in vary.lower():
        return CorsFinding("LOW", "missing_vary_origin",
            f"Access-Control-Allow-Origin is set dynamically (to '{acao}') but the response has no "
            f"'Vary: Origin' header. A caching proxy sitting in front of this server could serve a "
            f"response cached for one origin to a different origin.",
            origin_sent=origin, acao_received=acao)
    return None


def probe_preflight_mirrors_get(url, session, timeout):
    """Confirms the OPTIONS preflight handler enforces the same policy
    as the actual GET/POST handler - a server can easily end up with
    two independently-written CORS checks that disagree."""
    attacker_origin = "https://attacker-controlled-domain.example"
    resp = _preflight(url, attacker_origin, session, timeout)
    acao = resp.headers.get("Access-Control-Allow-Origin")
    if acao == attacker_origin:
        return CorsFinding("HIGH", "preflight_reflects_arbitrary_origin",
            "The OPTIONS preflight response also reflects an arbitrary Origin - confirms the "
            "misconfiguration applies to state-changing requests (PUT/POST/DELETE) that require "
            "a preflight, not just simple GETs.",
            origin_sent=attacker_origin, acao_received=acao)
    return None


# Each probe that needs the trusted-origin hint declares how to derive
# what it actually needs from it ("domain" strips the scheme, "origin"
# uses it as-is); probes that don't need the hint pass None through.
ALL_PROBES = [
    ("reflects_arbitrary_origin", lambda url, s, t, domain, origin: probe_reflects_arbitrary_origin(url, s, t)),
    ("null_origin_trusted", lambda url, s, t, domain, origin: probe_null_origin_trusted(url, s, t)),
    ("wildcard_with_credentials", lambda url, s, t, domain, origin: probe_wildcard_with_credentials(url, s, t)),
    ("naive_substring_match", lambda url, s, t, domain, origin: probe_naive_substring_match(url, s, t, domain)),
    ("scheme_downgrade_accepted", lambda url, s, t, domain, origin: probe_scheme_downgrade(url, s, t, origin)),
    ("missing_vary_origin", lambda url, s, t, domain, origin: probe_missing_vary_origin(url, s, t, origin)),
    ("preflight_reflects_arbitrary_origin", lambda url, s, t, domain, origin: probe_preflight_mirrors_get(url, s, t)),
]


def run_all_probes(url, trusted_origin_hint=None, timeout=10):
    """trusted_origin_hint: the site's real expected origin, e.g.
    'https://trusted.example' - used by probes that need to construct
    a plausible bypass attempt (scheme downgrade, substring match).
    Optional - without it, those two probes simply find nothing to flag."""
    session = requests.Session()
    trusted_domain_hint = trusted_origin_hint.split("://", 1)[-1] if trusted_origin_hint else None

    findings = []
    for name, probe_fn in ALL_PROBES:
        try:
            finding = probe_fn(url, session, timeout, trusted_domain_hint, trusted_origin_hint)
        except requests.RequestException as e:
            findings.append(CorsFinding("INFO", name, f"Probe failed to complete: {e}"))
            continue
        if finding:
            findings.append(finding)
    return findings
