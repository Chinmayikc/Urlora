from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit


SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "verification", "secure", "account", "update", "password",
    "bank", "bonus", "free", "wallet", "confirm", "paypal", "payment", "unlock", "credential",
)
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
}
SUSPICIOUS_SYMBOLS = set("@%$!?=;{}[]<>")
FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "number_of_dots", "number_of_hyphens",
    "number_of_underscores", "number_of_digits", "number_of_special_characters", "number_of_subdirectories",
    "number_of_query_parameters", "number_of_fragments", "number_of_subdomains", "uses_https",
    "contains_ip_address", "contains_at_symbol", "contains_suspicious_symbol", "uses_url_shortener",
    "suspicious_keyword_count", "digit_ratio", "special_character_ratio",
]


def normalize_url(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("URL cannot be empty.")
    url = raw_url.strip()
    if len(url) > 4096:
        raise ValueError("URL is too long; maximum length is 4096 characters.")
    if any(character.isspace() for character in url):
        raise ValueError("URL cannot contain whitespace.")
    scheme_match = re.match(r"^([a-z][a-z\d+.-]*):", url, flags=re.IGNORECASE)
    if scheme_match and scheme_match.group(1).lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    candidate = url if re.match(r"^[a-z][a-z\d+.-]*://", url, flags=re.IGNORECASE) else f"http://{url}"
    try:
        parsed = urlsplit(candidate)
        # Accessing .port validates malformed port values that urlsplit otherwise leaves untouched.
        parsed.port
    except ValueError as error:
        raise ValueError("Enter a valid URL with a hostname.") from error
    if not parsed.hostname:
        raise ValueError("Enter a valid URL with a hostname.")
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    return url


def _hostname_is_ip(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_url_features(raw_url: str) -> dict[str, float | int]:
    """Extract the exact feature vector shared by training and prediction."""
    url = normalize_url(raw_url)
    candidate = url if re.match(r"^[a-z][a-z\d+.-]*://", url, flags=re.IGNORECASE) else f"http://{url}"
    parsed = urlsplit(candidate)
    hostname = parsed.hostname or ""
    lower_url = url.lower()
    characters = max(len(url), 1)
    special_count = sum(character in SUSPICIOUS_SYMBOLS or not character.isalnum() and character not in ":/.-_" for character in url)
    subdomain_count = max(0, len(hostname.split(".")) - 2) if not _hostname_is_ip(hostname) else 0
    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "number_of_dots": url.count("."),
        "number_of_hyphens": url.count("-"),
        "number_of_underscores": url.count("_"),
        "number_of_digits": sum(character.isdigit() for character in url),
        "number_of_special_characters": special_count,
        "number_of_subdirectories": len([part for part in parsed.path.split("/") if part]),
        "number_of_query_parameters": len(parse_qsl(parsed.query, keep_blank_values=True)),
        "number_of_fragments": int(bool(parsed.fragment)),
        "number_of_subdomains": subdomain_count,
        "uses_https": int(parsed.scheme.lower() == "https"),
        "contains_ip_address": _hostname_is_ip(hostname),
        "contains_at_symbol": int("@" in url),
        "contains_suspicious_symbol": int(any(symbol in url for symbol in SUSPICIOUS_SYMBOLS)),
        "uses_url_shortener": int(hostname.lower() in SHORTENER_HOSTS),
        "suspicious_keyword_count": sum(keyword in lower_url for keyword in SUSPICIOUS_KEYWORDS),
        "digit_ratio": sum(character.isdigit() for character in url) / characters,
        "special_character_ratio": special_count / characters,
    }


def explain_url_features(features: dict[str, float | int]) -> list[str]:
    """Return observable indicators; these are not model-attribution claims."""
    reasons: list[str] = []
    if features["contains_ip_address"]:
        reasons.append("Hostname is a raw IP address")
    if features["contains_at_symbol"]:
        reasons.append("@ symbol can obscure the destination")
    if not features["uses_https"]:
        reasons.append("Address does not use HTTPS")
    if features["uses_url_shortener"]:
        reasons.append("URL shortening service detected")
    if features["suspicious_keyword_count"]:
        reasons.append("Suspicious login, credential, payment, or verification keyword detected")
    if features["url_length"] > 75:
        reasons.append("Unusually long URL")
    if features["number_of_subdomains"] >= 3:
        reasons.append("Multiple subdomains detected")
    if features["contains_suspicious_symbol"]:
        reasons.append("Suspicious URL symbol pattern detected")
    return reasons or ["No high-signal lexical warning was found"]
