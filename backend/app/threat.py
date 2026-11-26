"""Threat signals for a URL: Safe Browsing, domain age, TLS validity, redirect chain.

Every outbound request goes through `assert_public_url`, so the API can't be
used to probe internal or cloud-metadata addresses (SSRF).
"""
import asyncio
import datetime as dt
import ipaddress
import socket
import ssl
import time
from typing import Optional
from urllib.parse import urljoin, urlsplit

import httpx
import tldextract

from .config import settings
from .schemas import ThreatReport, ThreatSignal

ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_REDIRECTS = 10
_extract = tldextract.TLDExtract(suffix_list_urls=())  # bundled list, no network fetch
_cache: dict[str, tuple[float, ThreatReport]] = {}
CACHE_TTL_S = 3600


class UnsafeURL(ValueError):
    pass


def assert_public_url(url: str) -> str:
    """Return the hostname if `url` is http(s) and resolves only to public IPs."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnsafeURL("only http(s) URLs with a hostname are allowed")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise UnsafeURL(f"port {port} is not allowed")
    try:
        infos = socket.getaddrinfo(parts.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeURL(f"cannot resolve host: {e}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise UnsafeURL(f"host resolves to a non-public address ({ip})")
    return parts.hostname


def registered_domain(host: str) -> str:
    return _extract(host).top_domain_under_public_suffix or host


# ---------------------------------------------------------------- individual signals

async def check_safe_browsing(url: str) -> ThreatSignal:
    if not settings.safe_browsing_api_key:
        return ThreatSignal(name="safe_browsing", status="unknown", detail="Not configured (no API key).")
    body = {
        "client": {"clientId": "dark-path-guardians", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=settings.threat_timeout_s) as client:
            r = await client.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                                  params={"key": settings.safe_browsing_api_key}, json=body)
            r.raise_for_status()
            matches = r.json().get("matches", [])
    except (httpx.HTTPError, ValueError) as e:
        return ThreatSignal(name="safe_browsing", status="unknown", detail=f"Lookup failed: {type(e).__name__}")
    if matches:
        types = sorted({m.get("threatType", "?") for m in matches})
        return ThreatSignal(name="safe_browsing", status="bad",
                            detail=f"Google Safe Browsing lists this URL: {', '.join(types)}.",
                            data={"threat_types": types})
    return ThreatSignal(name="safe_browsing", status="ok", detail="Not on Google Safe Browsing lists.")


def _whois_created(domain: str) -> Optional[dt.datetime]:
    import whois  # python-whois; imported lazily because it is slow to import

    created = whois.whois(domain).creation_date
    if isinstance(created, list):
        created = min((c for c in created if isinstance(c, dt.datetime)), default=None)
    if isinstance(created, dt.datetime):
        return created if created.tzinfo else created.replace(tzinfo=dt.timezone.utc)
    return None


async def check_domain_age(host: str) -> ThreatSignal:
    domain = registered_domain(host)
    try:
        created = await asyncio.wait_for(asyncio.to_thread(_whois_created, domain),
                                         timeout=settings.threat_timeout_s)
    except Exception as e:  # whois libraries raise many different errors
        return ThreatSignal(name="domain_age", status="unknown",
                            detail=f"WHOIS lookup failed for {domain} ({type(e).__name__}).")
    if created is None:
        return ThreatSignal(name="domain_age", status="unknown", detail=f"No creation date in WHOIS for {domain}.")
    days = (dt.datetime.now(dt.timezone.utc) - created).days
    data = {"domain": domain, "created": created.date().isoformat(), "age_days": days}
    if days < 30:
        return ThreatSignal(name="domain_age", status="bad", detail=f"{domain} was registered {days} days ago.", data=data)
    if days < 180:
        return ThreatSignal(name="domain_age", status="warn", detail=f"{domain} is only {days} days old.", data=data)
    return ThreatSignal(name="domain_age", status="ok", detail=f"{domain} registered {days // 365} year(s) ago.", data=data)


def _tls_cert(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=settings.threat_timeout_s) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()


async def check_ssl(url: str) -> ThreatSignal:
    parts = urlsplit(url)
    if parts.scheme != "https":
        return ThreatSignal(name="ssl", status="warn", detail="Page is not served over HTTPS.")
    try:
        cert = await asyncio.to_thread(_tls_cert, parts.hostname, parts.port or 443)
    except ssl.SSLCertVerificationError as e:
        return ThreatSignal(name="ssl", status="bad", detail=f"Certificate is invalid: {e.verify_message}.")
    except (OSError, ssl.SSLError) as e:
        return ThreatSignal(name="ssl", status="unknown", detail=f"TLS check failed ({type(e).__name__}).")
    expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
    days_left = (expires - dt.datetime.now(dt.timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "unknown")
    data = {"issuer": issuer, "expires": expires.date().isoformat(), "days_left": days_left}
    if days_left < 7:
        return ThreatSignal(name="ssl", status="warn", detail=f"Certificate expires in {days_left} days.", data=data)
    return ThreatSignal(name="ssl", status="ok", detail=f"Valid certificate from {issuer}.", data=data)


async def check_redirects(url: str) -> ThreatSignal:
    hops = [url]
    current = url
    try:
        async with httpx.AsyncClient(timeout=settings.threat_timeout_s, follow_redirects=False,
                                     headers={"User-Agent": "Mozilla/5.0 DarkPathGuardians/2.0"}) as client:
            for _ in range(MAX_REDIRECTS):
                await asyncio.to_thread(assert_public_url, current)
                r = await client.get(current)
                await r.aclose()
                if r.status_code not in (301, 302, 303, 307, 308) or "location" not in r.headers:
                    break
                current = urljoin(current, r.headers["location"])
                hops.append(current)
    except UnsafeURL as e:
        return ThreatSignal(name="redirects", status="bad", detail=f"Redirect to a blocked address: {e}.",
                            data={"chain": hops})
    except httpx.HTTPError as e:
        return ThreatSignal(name="redirects", status="unknown", detail=f"Could not follow redirects ({type(e).__name__}).",
                            data={"chain": hops})

    domains = [registered_domain(urlsplit(h).hostname or "") for h in hops]
    downgrade = any(urlsplit(a).scheme == "https" and urlsplit(b).scheme == "http" for a, b in zip(hops, hops[1:]))
    data = {"chain": hops, "domains": sorted(set(domains))}
    if downgrade:
        return ThreatSignal(name="redirects", status="bad", detail="Redirect downgrades HTTPS to HTTP.", data=data)
    if len(hops) - 1 >= 4 or len(set(domains)) > 2:
        return ThreatSignal(name="redirects", status="warn",
                            detail=f"{len(hops) - 1} redirects across {len(set(domains))} domains.", data=data)
    return ThreatSignal(name="redirects", status="ok", detail=f"{len(hops) - 1} redirect(s).", data=data)


# ---------------------------------------------------------------- report

async def threat_report(url: str) -> ThreatReport:
    """Raises UnsafeURL if the URL is not a public http(s) address."""
    host = await asyncio.to_thread(assert_public_url, url)
    cached = _cache.get(url)
    if cached and time.time() - cached[0] < CACHE_TTL_S:
        return cached[1]
    signals = await asyncio.gather(check_safe_browsing(url), check_domain_age(host),
                                   check_ssl(url), check_redirects(url))
    report = ThreatReport(url=url, signals=list(signals))
    _cache[url] = (time.time(), report)
    return report
