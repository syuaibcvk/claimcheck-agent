#!/usr/bin/env python3
"""
ClaimCheck — a scam-screening agent for crypto claim / airdrop announcements.

Give ClaimCheck the URL (or raw text) of a claim announcement. It fetches the
page, extracts the hard facts (contract addresses, dates, outbound links) and
screens the content against a set of fraud heuristics (seed-phrase requests,
send-to-receive schemes, deposit-to-claim, lookalike domains, guaranteed
returns, manufactured urgency). It returns a structured report with a risk
level, findings with evidence snippets, and the SHA-256 of the exact content
it inspected — so anyone can re-fetch the same page and verify that the
report describes the same bytes (the "evidence hash").

Pure Python 3 standard library. No third-party dependencies.

Run:  python app.py            (binds 0.0.0.0:$PORT, default port 8000)
"""

import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

MAX_RESPONSE_BYTES = 512 * 1024          # hard cap on fetched page size
FETCH_TIMEOUT_SECONDS = 10
MAX_REQUEST_BYTES = 1 * 1024 * 1024      # hard cap on POST /check bodies
USER_AGENT = "ClaimCheck/1.0 (+https://agentgames.zkverify.io/events/wildcard)"

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# --------------------------------------------------------------------------
# Extraction patterns
# --------------------------------------------------------------------------

EVM_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
SOLANA_RE = re.compile(
    r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}"
    r"(?![1-9A-HJ-NP-Za-km-z])"
)
BTC_BECH32_RE = re.compile(r"\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,59}\b")
BTC_LEGACY_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")

_MONTHS = (
    "January|February|March|April|May|June|July|August|September|October|"
    "November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec"
)
DATE_RES = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    re.compile(r"\b(?:" + _MONTHS + r")\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b",
               re.IGNORECASE),
    re.compile(r"\b\d{1,2}(?:st|nd|rd|th)?\s+(?:" + _MONTHS + r")\s+\d{4}\b",
               re.IGNORECASE),
    re.compile(r"\b\d{1,2}/\d{1,2}/\d{4}\b"),
]

# --------------------------------------------------------------------------
# Fraud heuristics
#
# Each rule: (rule_id, severity, [compiled patterns]). Patterns run against
# the page's visible text (whitespace-normalised). A finding keeps a short
# evidence snippet around the first match.
# --------------------------------------------------------------------------

SECRET_TERMS_RE = re.compile(
    r"\b(seed phrase|recovery phrase|mnemonic|private key|secret phrase)\b",
    re.IGNORECASE,
)
NEGATION_RE = re.compile(r"\b(never|not|no one|don'?t|do not)\b", re.IGNORECASE)

SEND_TO_RECEIVE_RES = [
    re.compile(r"\bsend\b[^\n]{0,80}?\b(receive|to get|and get)\b",
               re.IGNORECASE),
    re.compile(r"\btransfer\b[^\n]{0,80}?\breceive\b", re.IGNORECASE),
]

DEPOSIT_TO_CLAIM_RES = [
    re.compile(r"\b(deposit|pay|send)\b[^\n]{0,60}?\bto (claim|unlock|activate)\b",
               re.IGNORECASE),
    re.compile(r"\bclaim\b[^\n]{0,50}?\b(requires?|after)\b[^\n]{0,40}?"
               r"\b(deposit|payment|fee)\b", re.IGNORECASE),
    re.compile(r"\bactivation fee\b|\bunlock fee\b|\bclaiming fee\b",
               re.IGNORECASE),
]

GUARANTEED_RES = [
    re.compile(r"\bguaranteed\b[^\n]{0,40}?\b(profit|return|income|win)\b",
               re.IGNORECASE),
    re.compile(r"\b100%\s*(guaranteed|profit|safe)\b", re.IGNORECASE),
    re.compile(r"\bdouble your\b[^\n]{0,30}?\b(eth|btc|sol|money|coins?|tokens?)\b",
               re.IGNORECASE),
    re.compile(r"\brisk[- ]free profit\b", re.IGNORECASE),
]

URGENCY_RES = [
    re.compile(r"\bact now\b", re.IGNORECASE),
    re.compile(r"\bhurry\b", re.IGNORECASE),
    re.compile(r"\blimited time\b", re.IGNORECASE),
    re.compile(r"\bdon'?t miss\b", re.IGNORECASE),
    re.compile(r"\bexpires? (soon|today|in \d+)\b", re.IGNORECASE),
    re.compile(r"\bonly\s+\d+\s+(spots|left|remaining|places)\b", re.IGNORECASE),
    re.compile(r"\bclaim immediately\b", re.IGNORECASE),
    re.compile(r"\blast chance\b", re.IGNORECASE),
]

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "rb.gy", "cutt.ly", "is.gd", "shorturl.at",
    "t.co", "goo.gl", "ow.ly", "s.id",
}

# Brand keywords abused by lookalike / phishing domains, with the real
# official hosts. A link whose host contains the brand but is NOT the
# official host (or a subdomain of it) is flagged.
BRAND_OFFICIAL_HOSTS = {
    "metamask": {"metamask.io"},
    "uniswap": {"uniswap.org", "uniswap.com"},
    "opensea": {"opensea.io"},
    "phantom": {"phantom.app", "phantom.com"},
    "ledger": {"ledger.com"},
    "trustwallet": {"trustwallet.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "zkverify": {"zkverify.io"},
}


def _dedupe(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _snippet(text, start, end, radius=70):
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].strip()
    if lo > 0:
        snippet = "..." + snippet
    if hi < len(text):
        snippet = snippet + "..."
    return snippet[:200]


# --------------------------------------------------------------------------
# HTML -> text + links
# --------------------------------------------------------------------------

class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.links = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip_depth += 1
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            self.text_parts.append(data)


def parse_page(content_text, base_url=None):
    """Return (visible_text, links) for an HTML document or plain text."""
    parser = _PageParser()
    try:
        parser.feed(content_text)
    except Exception:
        # Malformed HTML: fall back to treating the input as plain text.
        return content_text, _dedupe(URL_RE.findall(content_text))
    visible = " ".join(" ".join(parser.text_parts).split())
    links = list(parser.links)
    if not visible:
        visible = " ".join(content_text.split())
    # Also catch bare URLs written in the text itself.
    links.extend(URL_RE.findall(content_text))
    resolved = []
    for link in links:
        link = link.strip().rstrip(".,;")
        if not link or link.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        if base_url:
            link = urllib.parse.urljoin(base_url, link)
        resolved.append(link)
    return visible, _dedupe(resolved)


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def extract_facts(text, links):
    dates = []
    for pattern in DATE_RES:
        dates.extend(pattern.findall(text))
    return {
        "evm_addresses": _dedupe(EVM_RE.findall(text)),
        "solana_addresses": _dedupe(SOLANA_RE.findall(text)),
        "btc_addresses": _dedupe(
            BTC_BECH32_RE.findall(text) + BTC_LEGACY_RE.findall(text)
        ),
        "dates": _dedupe(dates),
        "links": links,
    }


def _first_match(patterns, text):
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match
    return None


def screen(text, links):
    """Run the fraud heuristics. Returns a list of finding dicts."""
    findings = []

    # CRITICAL — requests for wallet secrets. A match is ignored when it is
    # clearly a warning ("we will NEVER ask for your seed phrase"): a
    # negation word shortly before the term marks it as safety copy.
    for match in SECRET_TERMS_RE.finditer(text):
        context_before = text[max(0, match.start() - 60):match.start()]
        if NEGATION_RE.search(context_before):
            continue
        findings.append({
            "severity": "CRITICAL",
            "rule": "secret_request",
            "evidence": _snippet(text, match.start(), match.end()),
        })
        break

    match = _first_match(SEND_TO_RECEIVE_RES, text)
    if match:
        findings.append({
            "severity": "HIGH",
            "rule": "send_to_receive",
            "evidence": _snippet(text, match.start(), match.end()),
        })

    match = _first_match(DEPOSIT_TO_CLAIM_RES, text)
    if match:
        findings.append({
            "severity": "HIGH",
            "rule": "deposit_to_claim",
            "evidence": _snippet(text, match.start(), match.end()),
        })

    match = _first_match(GUARANTEED_RES, text)
    if match:
        findings.append({
            "severity": "HIGH",
            "rule": "guaranteed_returns",
            "evidence": _snippet(text, match.start(), match.end()),
        })

    # Link-based rules.
    shortener_hits = []
    lookalike_hits = []
    for link in links:
        host = (urllib.parse.urlparse(link).hostname or "").lower()
        if not host:
            continue
        if host in SHORTENER_HOSTS:
            shortener_hits.append(link)
            continue
        for brand, official_hosts in BRAND_OFFICIAL_HOSTS.items():
            if brand in host.replace("-", "").replace(".", "") or brand in host:
                if not any(host == h or host.endswith("." + h)
                           for h in official_hosts):
                    lookalike_hits.append(link)
                break
    if lookalike_hits:
        findings.append({
            "severity": "HIGH",
            "rule": "lookalike_domain",
            "evidence": lookalike_hits[0][:200],
        })
    if shortener_hits:
        findings.append({
            "severity": "MEDIUM",
            "rule": "url_shortener",
            "evidence": shortener_hits[0][:200],
        })

    urgency_count = 0
    urgency_evidence = None
    for pattern in URGENCY_RES:
        match = pattern.search(text)
        if match:
            urgency_count += 1
            if urgency_evidence is None:
                urgency_evidence = _snippet(text, match.start(), match.end())
    if urgency_count:
        findings.append({
            "severity": "MEDIUM" if urgency_count >= 3 else "LOW",
            "rule": "manufactured_urgency",
            "evidence": urgency_evidence,
        })

    findings.sort(key=lambda f: -SEVERITY_ORDER[f["severity"]])
    return findings


def analyze(content_bytes, source_type, source_value):
    """Build a full ClaimCheck report for raw content bytes."""
    evidence_sha256 = hashlib.sha256(content_bytes).hexdigest()
    content_text = content_bytes.decode("utf-8", errors="replace")
    base_url = source_value if source_type == "url" else None
    visible_text, links = parse_page(content_text, base_url=base_url)
    facts = extract_facts(visible_text, links)
    findings = screen(visible_text, links)
    if findings:
        risk_level = max(
            (f["severity"] for f in findings),
            key=lambda s: SEVERITY_ORDER[s],
        )
    else:
        risk_level = "LOW"
    return {
        "id": uuid.uuid4().hex,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {"type": source_type, "value": source_value},
        "extracted": facts,
        "findings": findings,
        "risk_level": risk_level,
        "evidence_sha256": evidence_sha256,
        "content_bytes": len(content_bytes),
    }


def analyze_text(text, source_type="text"):
    return analyze(text.encode("utf-8"), source_type, None)


# --------------------------------------------------------------------------
# Fetching (strict: http/https only, no credentials, capped, timed)
# --------------------------------------------------------------------------

class FetchError(Exception):
    pass


def validate_url(url):
    """Return the parsed URL or raise FetchError with a plain reason."""
    if not isinstance(url, str) or not url.strip():
        raise FetchError("URL is empty.")
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise FetchError(
            "Only http:// and https:// URLs are accepted "
            f"(got scheme '{parsed.scheme or 'none'}')."
        )
    if not parsed.hostname:
        raise FetchError("URL has no host.")
    if parsed.username or parsed.password:
        raise FetchError("URLs with embedded credentials are rejected.")
    return parsed


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme not in ("http", "https"):
            raise FetchError(
                f"Redirect to disallowed scheme '{parsed.scheme}' refused."
            )
        if parsed.username or parsed.password:
            raise FetchError("Redirect to a URL with credentials refused.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirectHandler())


def fetch_url(url):
    """Fetch a page and return its raw bytes (capped at MAX_RESPONSE_BYTES)."""
    parsed = validate_url(url)
    request = urllib.request.Request(
        parsed.geturl(),
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain,*/*"},
    )
    try:
        with _OPENER.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
    except FetchError:
        raise
    except urllib.error.HTTPError as exc:
        raise FetchError(f"Fetch failed: HTTP {exc.code} from {parsed.hostname}.")
    except urllib.error.URLError as exc:
        raise FetchError(f"Fetch failed: {exc.reason}.")
    except Exception as exc:  # timeouts, SSL errors, etc. — never crash
        raise FetchError(f"Fetch failed: {exc}.")
    if len(data) > MAX_RESPONSE_BYTES:
        data = data[:MAX_RESPONSE_BYTES]
    return data


# --------------------------------------------------------------------------
# Built-in demo fixture: a textbook scam claim page
# --------------------------------------------------------------------------

DEMO_HTML = """<!DOCTYPE html>
<html><head><title>ZKVERIFY MEGA AIRDROP — CLAIM NOW</title></head>
<body>
<h1>Official $VFY Mega Airdrop!</h1>
<p>ACT NOW! Only 17 spots left — this offer expires today, claim immediately!</p>
<p>To verify your wallet and claim, enter your seed phrase in the form below.</p>
<p>Bonus: send 0.05 ETH to 0x1234567890abcdef1234567890abcdef12345678
   and receive 0.5 ETH back — guaranteed profit, double your ETH!</p>
<p>Claim deadline: November 21, 2026.</p>
<p><a href="https://metamask-claim-airdrop.example.com/verify">Verify on MetaMask</a></p>
<p><a href="https://bit.ly/3xClaimNow">Backup claim link</a></p>
</body></html>"""

# --------------------------------------------------------------------------
# HTTP service
# --------------------------------------------------------------------------

REPORTS = {}  # in-memory only; lost on restart (documented in README)

INDEX_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClaimCheck — airdrop claim announcement screener</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.5}
 textarea,input{width:100%;padding:.5rem;margin:.25rem 0 .75rem}
 button{padding:.55rem 1.1rem;cursor:pointer}
 pre{background:#111;color:#eee;padding:1rem;overflow:auto;border-radius:6px}
 .risk{font-weight:700}
</style></head><body>
<h1>ClaimCheck</h1>
<p>ClaimCheck screens crypto <strong>claim / airdrop announcements</strong> for
scam patterns before you connect a wallet: seed-phrase requests,
send-to-receive schemes, deposit-to-claim demands, lookalike domains,
guaranteed-return promises and manufactured urgency. Every report carries the
SHA-256 of the exact page inspected, so the result can be re-verified by
anyone who fetches the same page.</p>
<p>Try it: paste an announcement URL, or use
<a href="/demo">the built-in demo</a> (a textbook scam page) or
<a href="/health">/health</a>.</p>
<form id="f">
<label>Announcement URL <input id="url" type="url" placeholder="https://example.com/claim"></label>
<label>…or paste announcement text <textarea id="text" rows="4"></textarea></label>
<button type="submit">Check</button>
</form>
<p id="summary"></p>
<pre id="out">No report yet.</pre>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = document.getElementById('url').value.trim();
  const text = document.getElementById('text').value.trim();
  const payload = url ? {url} : {text};
  document.getElementById('out').textContent = 'Checking...';
  try {
    const r = await fetch('/check', {method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    const data = await r.json();
    document.getElementById('out').textContent = JSON.stringify(data, null, 2);
    document.getElementById('summary').innerHTML = data.risk_level
      ? 'Risk level: <span class="risk">' + data.risk_level + '</span> · report id ' + data.id
      : '';
  } catch (err) {
    document.getElementById('out').textContent = 'Error: ' + err;
  }
});
</script>
</body></html>"""


class ClaimCheckHandler(BaseHTTPRequestHandler):
    server_version = "ClaimCheck/1.0"

    # -- helpers -----------------------------------------------------------
    def _send_json(self, payload, status=200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- routes ------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            self._send_html(INDEX_HTML)
        elif path == "/health":
            self._send_json({
                "status": "ok",
                "service": "claimcheck",
                "reports_stored": len(REPORTS),
                "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        elif path == "/demo":
            report = analyze(DEMO_HTML.encode("utf-8"), "demo", "built-in fixture")
            REPORTS[report["id"]] = report
            self._send_json(report)
        elif path.startswith("/report/"):
            report_id = path[len("/report/"):]
            report = REPORTS.get(report_id)
            if report is None:
                self._send_json({"error": "No report with that id."}, status=404)
            else:
                self._send_json(report)
        else:
            self._send_json({"error": "Not found."}, status=404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path != "/check":
            self._send_json({"error": "Not found."}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._send_json(
                {"error": "Request body must be JSON of at most 1 MB."},
                status=400,
            )
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json({"error": "Body is not valid JSON."}, status=400)
            return
        if not isinstance(payload, dict):
            self._send_json({"error": "JSON body must be an object."}, status=400)
            return

        url = payload.get("url")
        text = payload.get("text")
        if url:
            try:
                content = fetch_url(url)
            except FetchError as exc:
                self._send_json(
                    {"error": str(exc), "source": {"type": "url", "value": url}},
                    status=502,
                )
                return
            report = analyze(content, "url", url)
        elif text:
            if not isinstance(text, str):
                self._send_json(
                    {"error": "'text' must be a string."}, status=400)
                return
            report = analyze_text(text)
        else:
            self._send_json(
                {"error": "Provide either 'url' or 'text'."}, status=400)
            return
        REPORTS[report["id"]] = report
        self._send_json(report)


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), ClaimCheckHandler)
    print(f"ClaimCheck listening on 0.0.0.0:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
