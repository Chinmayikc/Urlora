from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_PAGE_BYTES = 1_000_000
MAX_REDIRECTS = 3
VERIFY_TIMEOUT_SECONDS = float(os.getenv("URL_VERIFY_TIMEOUT_SECONDS", "4"))
SAFE_BROWSING_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


_opener = build_opener(_NoRedirectHandler())


def _public_addresses(hostname: str) -> list[str]:
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise ValueError("The hostname could not be resolved.") from error
    if not addresses:
        raise ValueError("The hostname did not resolve to an address.")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ValueError("Private, local, or reserved destinations are not scanned.")
    return sorted(addresses)


def _safe_target(raw_url: str) -> str:
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only HTTP and HTTPS URLs with a hostname can be verified.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not scanned.")
    _public_addresses(parsed.hostname)
    # Do not send a fragment or userinfo to the destination.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _base_domain(hostname: str) -> str:
    labels = [label for label in hostname.lower().rstrip(".").split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname.lower().rstrip(".")


def _read_limited(response) -> str:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_PAGE_BYTES:
        chunk = response.read(min(64 * 1024, MAX_PAGE_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)[:MAX_PAGE_BYTES].decode("utf-8", errors="replace")


def _page_signals(raw_html: str, hostname: str) -> tuple[str, list[str], str, bool]:
    lowered = raw_html.lower()
    title_match = re.search(r"<title[^>]*>(.*?)</title>", raw_html, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", title_match.group(1)))).strip() if title_match else ""
    text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw_html))).strip().lower()
    label = _base_domain(hostname).split(".")[0]
    brand_match = len(label) >= 4 and re.search(rf"(?<![a-z0-9]){re.escape(label)}(?![a-z0-9])", text) is not None
    password_form = re.search(r"<input[^>]+type\s*=\s*[\"']?password", lowered) is not None
    credential_terms = sum(text.count(term) for term in ("login", "sign in", "signin", "verify", "verification", "password", "credential", "payment"))
    external_form = False
    for action in re.findall(r"<form[^>]+action\s*=\s*[\"']([^\"']+)", raw_html, re.IGNORECASE):
        try:
            action_host = urlsplit(urljoin(f"https://{hostname}/", action)).hostname or ""
            if action_host and _base_domain(action_host) != _base_domain(hostname):
                external_form = True
                break
        except ValueError:
            continue

    signals: list[str] = []
    if password_form:
        signals.append("Page contains a password input form")
    if credential_terms >= 3:
        signals.append("Page contains multiple login, verification, or payment terms")
    if external_form:
        signals.append("A form submits to a different domain")
    if not brand_match:
        signals.append("Page content does not clearly match the hostname")

    suspicious = external_form or (password_form and credential_terms >= 4 and not brand_match)
    if suspicious:
        status = "suspicious"
    elif brand_match:
        status = "verified"
    else:
        status = "inspected"
    return status, signals or ["Page content was fetched and matched the hostname"], title, brand_match


def _safe_browsing_check(url: str) -> dict[str, object]:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "provider": "google_safe_browsing", "detail": "Reputation provider is not configured."}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = json.dumps({
        "client": {"clientId": "urlora", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": SAFE_BROWSING_THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }).encode("utf-8")
    request = Request(endpoint, data=payload, headers={"Content-Type": "application/json", "User-Agent": "Urlora/1.0"}, method="POST")
    try:
        with _opener.open(request, timeout=VERIFY_TIMEOUT_SECONDS) as response:
            body = json.loads(response.read(64 * 1024).decode("utf-8", errors="replace") or "{}")
    except Exception:
        return {"status": "unavailable", "provider": "google_safe_browsing", "detail": "Reputation check was unavailable."}
    if body.get("matches"):
        return {"status": "malicious", "provider": "google_safe_browsing", "detail": "Reputation provider reported a threat."}
    return {"status": "clean", "provider": "google_safe_browsing", "detail": "Reputation provider found no listed threat."}


def verify_url(raw_url: str) -> dict[str, object]:
    """Inspect a public URL without submitting forms or downloading executable content."""
    candidate = raw_url if re.match(r"^[a-z][a-z\d+.-]*://", raw_url, flags=re.IGNORECASE) else f"http://{raw_url}"
    reputation = _safe_browsing_check(candidate)
    result: dict[str, object] = {
        "status": "unverified",
        "domain_reputation": reputation["status"],
        "page_content": "unavailable",
        "provider": reputation["provider"],
        "signals": [],
    }
    if reputation["status"] == "malicious":
        result.update({"status": "malicious", "signals": ["Domain reputation provider reported this URL as malicious."]})
        return result
    try:
        current_url = _safe_target(candidate)
    except ValueError as error:
        result.update({"status": "blocked", "signals": [str(error)]})
        return result

    original_host = urlsplit(current_url).hostname or ""
    for _ in range(MAX_REDIRECTS + 1):
        request = Request(current_url, headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": "UrloraSecurityScanner/1.0"}, method="GET")
        try:
            response = _opener.open(request, timeout=VERIFY_TIMEOUT_SECONDS)
            status_code = response.status
        except HTTPError as error:
            response = error
            status_code = error.code
        except (URLError, TimeoutError, OSError, ValueError) as error:
            result.update({"status": "unverified", "signals": [f"Page could not be fetched: {error.reason if isinstance(error, URLError) and error.reason else 'network error'}"]})
            return result

        if status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("Location")
            if not location:
                break
            try:
                current_url = _safe_target(urljoin(current_url, location))
            except ValueError as error:
                result.update({"status": "suspicious", "signals": [f"Redirect target was blocked: {error}"]})
                return result
            continue

        content_type = response.headers.get_content_type() if hasattr(response.headers, "get_content_type") else response.headers.get("Content-Type", "").split(";", 1)[0]
        result["http_status"] = status_code
        result["final_url"] = current_url
        result["page_content_type"] = content_type
        if status_code < 200 or status_code >= 400:
            result.update({"status": "unverified", "signals": [f"Page returned HTTP {status_code}; content was not treated as verified."]})
            return result
        if content_type not in {"text/html", "application/xhtml+xml"}:
            result.update({"status": "inspected", "page_content": "non_html", "signals": [f"Page returned {content_type or 'non-HTML'} content; HTML identity checks were skipped."]})
            return result

        source = _read_limited(response)
        page_status, signals, title, brand_match = _page_signals(source, urlsplit(current_url).hostname or original_host)
        same_domain = _base_domain(original_host) == _base_domain(urlsplit(current_url).hostname or "")
        if not same_domain:
            signals.insert(0, "Page redirected to a different registrable domain")
            page_status = "suspicious"
        result.update({
            "status": "suspicious" if page_status == "suspicious" else ("verified" if page_status == "verified" else "inspected"),
            "page_content": page_status,
            "page_title": title[:160],
            "brand_match": brand_match,
            "signals": signals,
        })
        return result

    result.update({"status": "unverified", "signals": ["The URL exceeded the redirect limit."]})
    return result
