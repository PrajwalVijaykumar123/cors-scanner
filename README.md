# CORS Misconfiguration Scanner

Actively probes a web server's CORS policy with a battery of crafted `Origin` headers — not just reading one response's headers, but asking the specific questions that separate a correct allowlist from a broken one. A passive scanner that makes one request can only tell you what a server does for *that* origin; this tool asks it the seven questions a real attacker actually would.

**Only scan servers you own or are authorized to test.**

## What This Project Does

Seven independent probes, each a real HTTP request with a specific crafted `Origin`:

- **Arbitrary origin reflection** — sends an unmistakably attacker-shaped origin and checks whether the server echoes it straight back. Combined with `Access-Control-Allow-Credentials: true`, this is graded CRITICAL — it lets any website make an authenticated request on a logged-in victim's behalf and read the response.
- **`Origin: null` trust** — `null` is sent by browsers in attacker-reachable contexts (sandboxed iframes, local `file://` pages, some redirects); a server that trusts it as a normal origin is trusting any of those contexts.
- **Wildcard + credentials** — `Access-Control-Allow-Origin: *` together with `Allow-Credentials: true` is invalid per the Fetch spec and browsers refuse to act on it, but plenty of server frameworks still send both — a real misconfiguration even though browser-side enforcement currently saves it.
- **Naive substring-match bypass** — tests whether `https://evil` + the trusted domain (no separator) is accepted, the signature of an `origin.endswith(trusted_domain)` check instead of a real domain-boundary match.
- **Scheme downgrade** — checks whether the plain-HTTP version of an HTTPS-only trusted origin is also accepted, widening the attack surface to anyone who can spoof unencrypted traffic to that hostname.
- **Missing `Vary: Origin`** — a server that computes `Access-Control-Allow-Origin` dynamically but doesn't vary the cache key on `Origin` can have a caching proxy serve one origin's cached response to a different origin.
- **Preflight/actual-request mismatch** — confirms whether the `OPTIONS` preflight handler enforces the same policy as the real `GET` handler, since the two are often written (and can drift) independently.

## Why active probing instead of reading one response

A server that correctly rejects a random, obviously-attacker-shaped origin can still be completely broken for a different, carefully-chosen one. The naive-substring-match bug is invisible unless you specifically send an origin engineered to exploit it; the null-origin bug is invisible unless you specifically send `Origin: null`. Each finding here corresponds to one specific request a real attacker would actually construct — not a generic "this header looks risky" heuristic.

## Example Output

```
http://127.0.0.1:28456/reflect-all-with-credentials

  [CRITICAL] reflects_arbitrary_origin
      Server reflects ANY Origin back in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true - ...
      Origin sent: https://attacker-controlled-domain.example
      Access-Control-Allow-Origin received: https://attacker-controlled-domain.example
      Access-Control-Allow-Credentials received: true

  [HIGH] null_origin_trusted
      Server sets Access-Control-Allow-Origin: null in response to an Origin: null request. ...
```

(Real output — actual HTTP responses from the test suite's local fixture server, not mocked header dictionaries.)

## Tech Stack

- Python 3.11
- `requests` for the actual HTTP probing

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```bash
python3 scanner.py https://api.example.com/some/endpoint
python3 scanner.py https://api.example.com/endpoint --trusted-origin https://app.example.com
python3 scanner.py https://api.example.com/endpoint --json report.json
python3 scanner.py https://api.example.com/endpoint --fail-on critical
```

`--trusted-origin` enables two additional probes (scheme-downgrade and naive-substring-match) that need to know what the *real* expected origin is in order to construct a plausible bypass attempt — without it, the scanner still runs the other five probes, which need no prior knowledge of the site's configuration.

## Testing

A real target's CORS configuration can't be guaranteed to stay in a specific broken state for a test, so `test_fixtures/test_server.py` implements seven real local HTTP endpoints — one per probe's exact target misconfiguration, plus one correctly configured — and run_test.sh runs the real scanner against each:

```bash
sh test_fixtures/run_test.sh
```

This verifies: the worst-case endpoint (reflection + credentials) is graded CRITICAL and also trips the null-origin and preflight-mismatch findings; the naive-suffix bypass is found with the exact bypass origin shown, and correctly *not* flagged when `--trusted-origin` isn't supplied (since the probe has nothing to construct a bypass attempt from); the scheme-downgrade and missing-`Vary` findings fire on their respective endpoints; and the properly-configured endpoint produces exactly zero findings, including under `--fail-on any`.

## Architecture

```
Target URL (+ optional --trusted-origin hint)
        |
        v
probes.py: 7 independent probes, each sending ONE crafted Origin header
            via a real GET or OPTIONS preflight request
  reflects_arbitrary_origin    null_origin_trusted    wildcard_with_credentials
  naive_substring_match        scheme_downgrade_accepted
  missing_vary_origin          preflight_reflects_arbitrary_origin
        |
        v
Each probe inspects the REAL Access-Control-* response headers that
came back and decides whether this specific question's answer is a finding
        |
        v
Findings ranked CRITICAL -> HIGH -> MEDIUM -> LOW
        |
        v
Console report + optional JSON report; exit code reflects --fail-on threshold
```

## Project Structure

```
cors-scanner/
├── scanner.py                  # CLI: runs the probe battery, reports, exit codes
├── probes.py                    # The 7 probes and their pass/fail judgment logic
├── requirements.txt               # requests
└── test_fixtures/
    ├── test_server.py          # Real local server: 7 endpoints, one per probe + one clean
    └── run_test.sh                # Runs scanner.py against each, verifies real findings
```

## What I Learned

- A single CORS check result tells you almost nothing about the policy as a whole - "rejected this one obviously-fake origin" and "has no exploitable misconfiguration" are very different claims, and the gap between them is exactly where bugs like the naive-substring-match and null-origin-trust issues live. They're invisible to anyone who doesn't specifically think to send that exact crafted value
- The wildcard-plus-credentials finding is a good example of a bug that's "safe" only because of a *different* system's defensive behavior (the browser's spec compliance) rather than the server's own correctness - worth flagging even though no browser will currently exploit it, because that safety net is external to the code that has the bug
- Preflight (`OPTIONS`) and the real request often end up checked by separately-written code paths in real frameworks, and testing them independently (rather than assuming one implies the other) caught exactly the kind of drift that would otherwise only surface in production
- `Vary: Origin` is a subtle one to explain cleanly: the CORS policy itself can be completely correct and the finding still matters, because the vulnerability lives one layer away, in how an intermediate cache treats a dynamically-computed response header

## Next Steps

- Methods/headers enumeration: check whether `Access-Control-Allow-Methods`/`Access-Control-Allow-Headers` in a preflight response are also overly permissive (reflecting back whatever was requested, rather than an explicit allowlist)
- A `--origin-list` mode to test a specific set of origins (e.g. known subdomains of the target) rather than only the built-in synthetic probe origins
- Cookie-scoping awareness: check whether a credentialed CORS endpoint's session cookie is also missing `SameSite`, since the two misconfigurations compound each other
- Multiple-endpoint crawl mode, since CORS policy can legitimately differ by route within the same application
