#!/bin/sh
# Starts a real local HTTP server with seven endpoints, each a real
# CORS policy (six deliberately broken in a specific named way, one
# correctly configured), and runs the real scanner.py against each -
# every probe sends a genuine HTTP request and inspects the real
# response headers, no mocking.
set -e
cd "$(dirname "$0")/.."

python3 -c "
import sys, time
sys.path.insert(0, 'test_fixtures')
from test_server import start_server
start_server(28456)
time.sleep(60)
" &
SERVER_PID=$!
sleep 1

BASE="http://127.0.0.1:28456"

echo "== /reflect-all-with-credentials: expect CRITICAL + credentials named =="
set +e
python3 scanner.py "$BASE/reflect-all-with-credentials" > /tmp/cors_1.txt 2>&1
EXIT1=$?
set -e
cat /tmp/cors_1.txt
grep -q "\[CRITICAL\] reflects_arbitrary_origin" /tmp/cors_1.txt && echo "PASS: arbitrary-origin-reflection-with-credentials correctly graded CRITICAL" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
[ "$EXIT1" = "1" ] && echo "PASS: exit code 1" || { echo "FAIL: expected exit 1, got $EXIT1"; kill $SERVER_PID; exit 1; }

echo
echo "== /trust-null-origin: expect null_origin_trusted =="
python3 scanner.py "$BASE/trust-null-origin" > /tmp/cors_2.txt 2>&1 || true
cat /tmp/cors_2.txt
grep -q "null_origin_trusted" /tmp/cors_2.txt && echo "PASS: null-origin trust detected" || { echo "FAIL"; kill $SERVER_PID; exit 1; }

echo
echo "== /wildcard-plus-credentials-bug: expect wildcard_with_credentials (MEDIUM, exit 0 at default --fail-on high) =="
set +e
python3 scanner.py "$BASE/wildcard-plus-credentials-bug" > /tmp/cors_3.txt 2>&1
EXIT3=$?
set -e
cat /tmp/cors_3.txt
grep -q "wildcard_with_credentials" /tmp/cors_3.txt && echo "PASS: wildcard+credentials misconfig detected" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
[ "$EXIT3" = "0" ] && echo "PASS: MEDIUM finding doesn't trigger exit 1 at default --fail-on high" || { echo "FAIL: expected exit 0, got $EXIT3"; kill $SERVER_PID; exit 1; }

echo
echo "== /naive-suffix-check: expect naive_substring_match with --trusted-origin set =="
python3 scanner.py "$BASE/naive-suffix-check" --trusted-origin https://trusted.example > /tmp/cors_4.txt 2>&1 || true
cat /tmp/cors_4.txt
grep -q "naive_substring_match" /tmp/cors_4.txt && echo "PASS: naive suffix-check bypass detected" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "eviltrusted.example" /tmp/cors_4.txt && echo "PASS: the actual bypass origin used is shown in the finding" || { echo "FAIL"; kill $SERVER_PID; exit 1; }

echo
echo "== /naive-suffix-check WITHOUT --trusted-origin: probe should find nothing to flag (needs the hint) =="
python3 scanner.py "$BASE/naive-suffix-check" > /tmp/cors_5.txt 2>&1 || true
cat /tmp/cors_5.txt
grep -q "naive_substring_match" /tmp/cors_5.txt && { echo "FAIL: should not fire without --trusted-origin"; kill $SERVER_PID; exit 1; } || echo "PASS: substring-match probe correctly skipped without a trusted-origin hint"

echo
echo "== /accepts-http-and-https: expect scheme_downgrade_accepted =="
python3 scanner.py "$BASE/accepts-http-and-https" --trusted-origin https://trusted.example > /tmp/cors_6.txt 2>&1 || true
cat /tmp/cors_6.txt
grep -q "scheme_downgrade_accepted" /tmp/cors_6.txt && echo "PASS: HTTP-downgrade acceptance detected" || { echo "FAIL"; kill $SERVER_PID; exit 1; }

echo
echo "== /dynamic-no-vary: expect missing_vary_origin (LOW) only =="
set +e
python3 scanner.py "$BASE/dynamic-no-vary" --trusted-origin https://trusted.example --fail-on any > /tmp/cors_7.txt 2>&1
EXIT7=$?
set -e
cat /tmp/cors_7.txt
grep -q "missing_vary_origin" /tmp/cors_7.txt && echo "PASS: missing Vary: Origin detected" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
[ "$EXIT7" = "1" ] && echo "PASS: --fail-on any correctly fails even on a LOW-only finding" || { echo "FAIL: expected exit 1, got $EXIT7"; kill $SERVER_PID; exit 1; }

echo
echo "== /properly-configured: expect ZERO findings, exit 0 even at --fail-on any =="
set +e
python3 scanner.py "$BASE/properly-configured" --trusted-origin https://trusted.example --fail-on any > /tmp/cors_8.txt 2>&1
EXIT8=$?
set -e
cat /tmp/cors_8.txt
grep -q "No CORS misconfigurations found" /tmp/cors_8.txt && echo "PASS: properly configured endpoint produces zero findings" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
[ "$EXIT8" = "0" ] && echo "PASS: exit code 0 on a clean, correctly-configured endpoint" || { echo "FAIL: expected exit 0, got $EXIT8"; kill $SERVER_PID; exit 1; }

kill $SERVER_PID 2>/dev/null || true
rm -f /tmp/cors_1.txt /tmp/cors_2.txt /tmp/cors_3.txt /tmp/cors_4.txt /tmp/cors_5.txt /tmp/cors_6.txt /tmp/cors_7.txt /tmp/cors_8.txt
echo
echo "All tests passed."
