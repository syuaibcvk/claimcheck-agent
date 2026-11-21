#!/usr/bin/env python3
"""
ClaimCheck on Vercel — WSGI adapter around the original app.py.

Vercel's Python runtime invokes the module-level `app` callable below as a
WSGI application; vercel.json rewrites every path to this file. All routing
mirrors ClaimCheckHandler in app.py, and every analysis goes through app.py's
own functions (analyze / analyze_text / fetch_url / screen) — no fraud-rule
logic is duplicated here.

Pure Python 3 standard library. No third-party dependencies.
"""

import json
import os
import sys
from datetime import datetime, timezone

# app.py lives in the repo root, one level above this file's directory.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import app as claimcheck  # noqa: E402  (the original, unmodified app.py)

_STATUS_LINES = {
    200: "200 OK",
    400: "400 Bad Request",
    404: "404 Not Found",
    501: "501 Not Implemented",
    502: "502 Bad Gateway",
}


def _json_response(start_response, payload, status=200):
    body = json.dumps(payload, indent=2).encode("utf-8")
    start_response(_STATUS_LINES[status], [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
    ])
    return [body]


def _html_response(start_response, html, status=200):
    body = html.encode("utf-8")
    start_response(_STATUS_LINES[status], [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ])
    return [body]


def _handle_get(environ, start_response):
    path = environ.get("PATH_INFO") or "/"
    if path == "/":
        return _html_response(start_response, claimcheck.INDEX_HTML)
    if path == "/health":
        return _json_response(start_response, {
            "status": "ok",
            "service": "claimcheck",
            "reports_stored": len(claimcheck.REPORTS),
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
    if path == "/demo":
        report = claimcheck.analyze(
            claimcheck.DEMO_HTML.encode("utf-8"), "demo", "built-in fixture")
        claimcheck.REPORTS[report["id"]] = report
        return _json_response(start_response, report)
    if path.startswith("/report/"):
        report_id = path[len("/report/"):]
        report = claimcheck.REPORTS.get(report_id)
        if report is None:
            return _json_response(
                start_response, {"error": "No report with that id."},
                status=404)
        return _json_response(start_response, report)
    return _json_response(start_response, {"error": "Not found."}, status=404)


def _handle_post(environ, start_response):
    path = environ.get("PATH_INFO") or "/"
    if path != "/check":
        return _json_response(
            start_response, {"error": "Not found."}, status=404)
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length <= 0 or length > claimcheck.MAX_REQUEST_BYTES:
        return _json_response(
            start_response,
            {"error": "Request body must be JSON of at most 1 MB."},
            status=400)
    raw = environ["wsgi.input"].read(length)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return _json_response(
            start_response, {"error": "Body is not valid JSON."}, status=400)
    if not isinstance(payload, dict):
        return _json_response(
            start_response, {"error": "JSON body must be an object."},
            status=400)

    url = payload.get("url")
    text = payload.get("text")
    if url:
        try:
            content = claimcheck.fetch_url(url)
        except claimcheck.FetchError as exc:
            return _json_response(
                start_response,
                {"error": str(exc), "source": {"type": "url", "value": url}},
                status=502)
        report = claimcheck.analyze(content, "url", url)
    elif text:
        if not isinstance(text, str):
            return _json_response(
                start_response, {"error": "'text' must be a string."},
                status=400)
        report = claimcheck.analyze_text(text)
    else:
        return _json_response(
            start_response, {"error": "Provide either 'url' or 'text'."},
            status=400)
    claimcheck.REPORTS[report["id"]] = report
    return _json_response(start_response, report)


def app(environ, start_response):
    """WSGI entry point (Vercel calls this for every rewritten path)."""
    method = (environ.get("REQUEST_METHOD") or "GET").upper()
    if method == "GET":
        return _handle_get(environ, start_response)
    if method == "POST":
        return _handle_post(environ, start_response)
    # The original BaseHTTPRequestHandler answers unimplemented methods
    # with 501; mirror that.
    return _json_response(
        start_response, {"error": "Not implemented."}, status=501)
