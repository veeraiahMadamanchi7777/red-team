#!/usr/bin/env python3
"""
System design audit harness.

Given any public website URL this tool infers the full system architecture:
frontend framework, backend/API layer, infrastructure, auth, database, CDN,
observability, third-party integrations, and more. Output includes a
Mermaid architecture diagram, per-layer findings, API surface, security
posture, and a multi-page crawl summary.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import time
import urllib.parse
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    from .analyze import analyze
    from .extract import check_robots, configure_proxy
except ImportError:
    from analyze import analyze
    from extract import check_robots, configure_proxy


SAFE_HEADERS = {
    "server", "via", "content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "referrer-policy",
    "permissions-policy", "cache-control", "x-powered-by", "content-type",
    "content-length", "etag", "last-modified", "vary", "x-content-length",
    "content-encoding", "x-vercel-id", "x-vercel-cache", "x-amz-cf-id",
    "x-amz-cf-pop", "cf-ray", "x-fastly-request-id", "x-cache",
    "alt-svc", "accept-ranges",
}


class FetchFailure(RuntimeError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


def fetch_page(url: str, user_agent: str, timeout: float, max_bytes: int) -> tuple[bytes, dict[str, Any]]:
    last_error: Exception | None = None
    for attempt in range(1, 4):
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Accept-Language": "en-US,en;q=0.8",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise ValueError(f"response exceeded {max_bytes:,} bytes")
                safe = {k.lower(): v for k, v in response.headers.items() if k.lower() in SAFE_HEADERS}
                return body, {
                    "status": response.status,
                    "content_type": response.headers.get_content_type(),
                    "content_length": response.headers.get("Content-Length"),
                    "final_url": response.geturl(),
                    "headers": safe,
                    "attempts": attempt,
                }
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {408, 425, 429, 500, 502, 503, 504}:
                raise FetchFailure(f"HTTP {exc.code}: {exc.reason}", {"status": exc.code, "final_url": exc.url, "retryable": False, "attempts": attempt}) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
        if attempt < 3:
            time.sleep(attempt * 0.5)
    raise FetchFailure(f"request failed after 3 attempts: {last_error}", {"retryable": True, "attempts": 3})


def load_har(path: Path, max_bytes: int) -> tuple[str, bytes, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    for entry in entries:
        response = entry.get("response", {})
        content = response.get("content", {})
        mime = (content.get("mimeType") or "").split(";", 1)[0].lower()
        text = content.get("text")
        if not text or mime not in {"text/html", "application/xhtml+xml", ""}:
            continue
        body = base64.b64decode(text) if content.get("encoding") == "base64" else text.encode("utf-8", errors="replace")
        if len(body) > max_bytes:
            raise ValueError(f"HAR HTML response exceeded {max_bytes:,} bytes")
        safe = {h.get("name", "").lower(): h.get("value", "") for h in response.get("headers", []) if h.get("name", "").lower() in SAFE_HEADERS}
        url = entry.get("request", {}).get("url") or entry.get("startedDateTime") or "har://captured-page"
        return url, body, {"status": response.get("status", 0), "content_type": mime or "text/html", "content_length": str(len(body)), "final_url": url, "headers": safe, "source": "HAR", "attempts": 0}
    raise ValueError("HAR contains no captured HTML response with a response body")


# ─── Sitemap and crawl helpers ─────────────────────────────────────────────────

def fetch_sitemap(base_url: str, agent: str, timeout: float) -> list[str]:
    """Fetch and parse sitemap.xml / sitemap_index.xml, return up to 200 URLs."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    urls: list[str] = []
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/sitemaps/sitemap.xml"]:
        sitemap_url = origin + path
        try:
            req = urllib.request.Request(sitemap_url, headers={"User-Agent": agent})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(2_000_000).decode("utf-8", errors="replace")
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                continue
            tag = root.tag.lower()
            if "sitemapindex" in tag:
                # index — fetch first child sitemaps
                for sitemap in root.findall("sm:sitemap", ns)[:3]:
                    loc = sitemap.findtext("sm:loc", namespaces=ns) or ""
                    if loc:
                        try:
                            req2 = urllib.request.Request(loc.strip(), headers={"User-Agent": agent})
                            with urllib.request.urlopen(req2, timeout=timeout) as resp2:
                                raw2 = resp2.read(2_000_000).decode("utf-8", errors="replace")
                            root2 = ET.fromstring(raw2)
                            for url_el in root2.findall("sm:url", ns):
                                loc2 = url_el.findtext("sm:loc", namespaces=ns) or ""
                                if loc2:
                                    urls.append(loc2.strip())
                        except Exception:
                            pass
            else:
                # plain sitemap
                for url_el in root.findall("sm:url", ns):
                    loc = url_el.findtext("sm:loc", namespaces=ns) or ""
                    if loc:
                        urls.append(loc.strip())
            if urls:
                break
        except Exception:
            continue
    return urls[:200]


def extract_internal_links(html: str, base_url: str) -> list[str]:
    """Extract href links that belong to the same origin, sorted by discovery order."""
    parsed_base = urllib.parse.urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    seen: set[str] = set()
    links: list[str] = []
    for m in re.finditer(r"""href=['"]((?:https?://[^'"#?\s]+|/[^'"#?\s]*))['"?#]?""", html, re.I):
        raw = m.group(1).rstrip("/")
        if raw.startswith("//"):
            raw = parsed_base.scheme + ":" + raw
        if raw.startswith("/"):
            absolute = origin + raw
        elif raw.startswith(origin):
            absolute = raw
        else:
            continue
        # Skip non-HTML resources
        if re.search(r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf|zip|gz|mp4|webm|json|xml)$", absolute, re.I):
            continue
        if absolute not in seen:
            seen.add(absolute)
            links.append(absolute)
    return links[:50]


def crawl_site(
    start_url: str,
    agent: str,
    max_pages: int,
    timeout: float,
    max_bytes: int,
    sitemap_urls: list[str],
) -> list[dict[str, Any]]:
    """Crawl up to max_pages pages starting from start_url plus sitemap hints."""
    parsed_base = urllib.parse.urlparse(start_url)
    origin_host = parsed_base.netloc
    queue: list[str] = [start_url]
    visited: set[str] = set()
    pages: list[dict[str, Any]] = []

    # Add diverse sitemap URLs as crawl candidates
    for su in sitemap_urls:
        if urllib.parse.urlparse(su).netloc == origin_host and su not in queue:
            queue.append(su)

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        norm = url.rstrip("/") or url
        if norm in visited:
            continue
        visited.add(norm)
        try:
            body, response = fetch_page(url, agent, timeout, max_bytes)
        except (FetchFailure, Exception):
            continue
        if response.get("content_type", "").split(";")[0].strip() not in {"text/html", "application/xhtml+xml"}:
            continue
        html = body.decode("utf-8", errors="replace")
        pages.append({"url": url, "body": body, "response": response, "html": html})
        if len(pages) < max_pages:
            for link in extract_internal_links(html, url):
                if urllib.parse.urlparse(link).netloc == origin_host and link not in visited:
                    queue.append(link)
        if len(pages) < max_pages:
            time.sleep(0.3)  # polite crawl delay

    return pages


def fetch_js_bundles(scripts: list[str], base_url: str, agent: str, timeout: float, max_bytes: int, max_bundles: int = 4) -> str:
    """Download a sample of JS bundles from the same origin and return combined text."""
    parsed_base = urllib.parse.urlparse(base_url)
    origin_host = parsed_base.netloc
    combined: list[str] = []
    fetched = 0
    for raw in scripts:
        if fetched >= max_bundles:
            break
        absolute = urllib.parse.urljoin(base_url, raw)
        if urllib.parse.urlparse(absolute).netloc != origin_host:
            continue
        # Prefer main/app/index bundles — skip tiny polyfills
        if re.search(r"polyfill|runtime|chunk-[a-f0-9]{6,}\.js$", absolute, re.I):
            continue
        try:
            req = urllib.request.Request(absolute, headers={"User-Agent": agent})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw_bytes = resp.read(min(max_bytes, 500_000))
            combined.append(raw_bytes.decode("utf-8", errors="replace")[:200_000])
            fetched += 1
        except Exception:
            pass
    return "\n".join(combined)


# ─── HTML signals ─────────────────────────────────────────────────────────────

def html_signals(html: str) -> dict[str, Any]:
    def count(pattern: str) -> int:
        return len(re.findall(pattern, html, re.I))

    headings = re.findall(r"<h([1-6])\b[^>]*>(.*?)</h\1>", html, re.I | re.S)
    heading_text = [re.sub(r"<[^>]+>", " ", v).strip() for _, v in headings]
    images = re.findall(r"<img\b([^>]*)>", html, re.I | re.S)
    missing_alt = sum(1 for attrs in images if not re.search(r"\balt\s*=", attrs, re.I))
    origins = sorted({urllib.parse.urlparse(u).netloc for u in re.findall(r'(?:src|href)=["\']([^"\']+)', html, re.I) if urllib.parse.urlparse(u).netloc})
    forms = re.findall(r"<form\b([^>]*)>", html, re.I | re.S)
    return {
        "html_bytes": len(html.encode("utf-8")),
        "counts": {tag: count(rf"<{tag}\b") for tag in ("script", "link", "img", "picture", "form", "button", "iframe", "video", "svg", "a")},
        "heading_levels": Counter(level for level, _ in headings),
        "heading_text": heading_text[:30],
        "images_missing_alt": missing_alt,
        "external_origins": origins,
        "form_actions": [
            re.search(r'action=["\']([^"\']+)', attrs, re.I).group(1)
            if re.search(r'action=["\']([^"\']+)', attrs, re.I) else ""
            for attrs in forms[:20]
        ],
        "has_json_ld": bool(re.search(r"application/ld\+json", html, re.I)),
        "has_canonical": bool(re.search(r'<link[^>]+rel=["\']canonical', html, re.I)),
        "has_description": bool(re.search(r'<meta[^>]+name=["\']description', html, re.I)),
        "has_skip_link": bool(re.search(r"skip[^\"']*(?:to|main)|SkipNav", html, re.I)),
        "has_search_control": bool(re.search(r'role=["\']search|type=["\']search|aria-label=["\'][^"\']*search', html, re.I)),
        "has_viewport": bool(re.search(r'<meta[^>]+name=["\']viewport', html, re.I)),
        "has_pwa": bool(re.search(r'<link[^>]+rel=["\']manifest|serviceWorker\.register', html, re.I)),
        "has_web_components": bool(re.search(r"customElements\.define|is=[\"'][a-z]+-[a-z]", html, re.I)),
        "has_lazyload": bool(re.search(r'loading=["\']lazy|data-src=|data-lazy', html, re.I)),
    }


# ─── System design inference ───────────────────────────────────────────────────

# Maps layer names from STACK_PATTERNS to system design categories
LAYER_CATEGORY_MAP: dict[str, str] = {
    "Frontend framework": "frontend",
    "Frontend library": "frontend",
    "JavaScript library": "frontend",
    "Web components library": "frontend",
    "CSS framework": "ui",
    "CSS-in-JS": "ui",
    "UI component library": "ui",
    "CSS component library": "ui",
    "State management": "state",
    "Data fetching / cache": "state",
    "GraphQL client": "api",
    "Build tool / bundler": "build",
    "Scaffolding": "build",
    "Full-stack framework": "build",
    "CMS": "cms",
    "Headless CMS": "cms",
    "E-commerce / CMS": "cms",
    "E-commerce": "cms",
    "Website builder": "cms",
    "No-code CMS": "cms",
    "CMS / Marketing": "cms",
    "CMS / Publishing": "cms",
    "Backend framework": "backend",
    "Backend language": "backend",
    "Backend / BaaS": "backend",
    "API layer": "api",
    "API documentation": "api",
    "Real-time / WebSocket": "api",
    "Real-time": "api",
    "Real-time messaging": "api",
    "Integration pattern": "api",
    "Database / BaaS": "database",
    "Database": "database",
    "Database ORM": "database",
    "Cache / Database": "database",
    "Authentication": "auth",
    "Authentication / SSO": "auth",
    "Enterprise SSO": "auth",
    "Cloud infrastructure": "infra",
    "Hosting / Edge": "infra",
    "Hosting": "infra",
    "Full-stack hosting": "infra",
    "CDN": "cdn",
    "Image CDN": "cdn",
    "Media / Image CDN": "cdn",
    "Error tracking": "observability",
    "Observability / APM": "observability",
    "APM / Observability": "observability",
    "Session replay": "observability",
    "Session analytics": "observability",
    "Heatmaps / session replay": "observability",
    "Product analytics": "analytics",
    "CDP / Data pipeline": "analytics",
    "CDP / Analytics": "analytics",
    "Analytics": "analytics",
    "Privacy analytics": "analytics",
    "Self-hosted analytics": "analytics",
    "Observability": "observability",
    "Payments": "payments",
    "Payments / Billing": "payments",
    "Customer support / chat": "communication",
    "Customer support": "communication",
    "Live chat": "communication",
    "Live chat / CRM": "communication",
    "Email delivery": "communication",
    "Email marketing": "communication",
    "Communications API": "communication",
    "Feature flags": "feature_flags",
    "Feature flags / experimentation": "feature_flags",
    "A/B testing": "feature_flags",
    "A/B testing / experimentation": "feature_flags",
    "Edge feature flags": "feature_flags",
    "Search": "search",
    "Maps": "maps",
    "AI / LLM": "ai",
    "AI / ML": "ai",
    "AI / ML inference": "ai",
    "AI integration": "ai",
    "AI orchestration": "ai",
    "Object storage": "storage",
    "File storage": "storage",
    "Serverless Redis / Queue": "storage",
    "Background jobs / queue": "queue",
    "Background jobs": "queue",
    "Message queue": "queue",
    "Job queue": "queue",
    "Server": "infra",
    "Backend": "backend",
    "Consent management": "consent",
    "Internationalization": "i18n",
    "Translation / L10n": "i18n",
    "Testing": "testing",
}


def infer_system_design(stack: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """Group stack findings into high-level system design categories."""
    categories: dict[str, list[dict[str, str]]] = defaultdict(list)
    for item in stack:
        category = LAYER_CATEGORY_MAP.get(item["layer"], "other")
        categories[category].append(item)
    return dict(categories)


def generate_mermaid(design: dict[str, list[dict[str, str]]], signals: dict[str, Any]) -> str:
    """Generate a Mermaid architecture diagram from detected system components."""
    lines: list[str] = ["graph TB", ""]

    def names(cat: str, limit: int = 2) -> str:
        items = design.get(cat, [])
        if not items:
            return ""
        return " + ".join(x["technology"] for x in items[:limit])

    frontend = names("frontend")
    ui_lib = names("ui", 1)
    backend = names("backend", 1)
    database = names("database", 1)
    auth = names("auth", 1)
    cdn = names("cdn", 1)
    infra = names("infra", 1)
    analytics = names("analytics", 1)
    observability = names("observability", 1)
    payments = names("payments", 1)
    search = names("search", 1)
    ai = names("ai", 1)
    cms = names("cms", 1)
    comm = names("communication", 1)
    queue = names("queue", 1)
    realtime = [x["technology"] for x in design.get("api", []) if "Real-time" in x.get("layer", "") or "Socket" in x.get("technology", "")]

    # Subgraph: User
    lines += ['    subgraph "Client"', '        Browser["👤 User / Browser"]', '    end', ""]

    # Subgraph: CDN / Edge
    if cdn or infra:
        label = cdn or infra
        lines += [f'    subgraph "Edge / CDN"', f'        CDN["⚡ {label}"]', '    end', ""]

    # Subgraph: Frontend
    if frontend or ui_lib:
        label = frontend + (f" + {ui_lib}" if ui_lib and ui_lib not in frontend else "")
        pwa_note = " (PWA)" if signals.get("has_pwa") else ""
        lines += ['    subgraph "Frontend"', f'        FE["⚛ {label}{pwa_note}"]', '    end', ""]

    # Subgraph: CMS (if present and no backend)
    if cms and not backend:
        lines += ['    subgraph "Content"', f'        CMS["📝 {cms}"]', '    end', ""]

    # Subgraph: API / Backend
    api_items = [x["technology"] for x in design.get("api", []) if "Real-time" not in x.get("layer", "")]
    api_label = ", ".join(api_items[:2]) if api_items else ""
    if backend or api_label:
        label = backend + (f" [{api_label}]" if api_label else "")
        lines += ['    subgraph "Backend / API"', f'        API["🔌 {label}"]', '    end', ""]

    # Subgraph: Auth
    if auth:
        lines += ['    subgraph "Auth"', f'        AUTH["🔐 {auth}"]', '    end', ""]

    # Subgraph: Data
    data_parts = []
    if database:
        data_parts.append(f"        DB[\"🗄 {database}\"]")
    storage_name = names("storage", 1)
    if storage_name:
        data_parts.append(f"        STORE[\"💾 {storage_name}\"]")
    if data_parts:
        lines += ['    subgraph "Data"'] + data_parts + ['    end', ""]

    # Subgraph: Real-time
    if realtime:
        lines += ['    subgraph "Real-time"', f'        RT["🔴 {realtime[0]}"]', '    end', ""]

    # Subgraph: Queue
    if queue:
        lines += ['    subgraph "Background Jobs"', f'        QUEUE["⚙ {queue}"]', '    end', ""]

    # Subgraph: Search
    if search:
        lines += ['    subgraph "Search"', f'        SRCH["🔍 {search}"]', '    end', ""]

    # Subgraph: AI
    if ai:
        lines += ['    subgraph "AI / LLM"', f'        AI["🤖 {ai}"]', '    end', ""]

    # Subgraph: Observability
    obs_parts: list[str] = []
    if observability:
        obs_parts.append(f"        ERR[\"🐛 {observability}\"]")
    if analytics:
        obs_parts.append(f"        ANALYTICS[\"📊 {analytics}\"]")
    if obs_parts:
        lines += ['    subgraph "Observability"'] + obs_parts + ['    end', ""]

    # Subgraph: External services
    ext_parts: list[str] = []
    if payments:
        ext_parts.append(f"        PAY[\"💳 {payments}\"]")
    if comm:
        ext_parts.append(f"        COMM[\"💬 {comm}\"]")
    if ext_parts:
        lines += ['    subgraph "External Services"'] + ext_parts + ['    end', ""]

    lines.append("")

    # ── Edges ─────────────────────────────────────────────────────────────────
    if cdn or infra:
        lines.append("    Browser --> CDN")
        if frontend:
            lines.append("    CDN --> FE")
        elif backend:
            lines.append("    CDN --> API")
    else:
        if frontend:
            lines.append("    Browser --> FE")
        elif backend:
            lines.append("    Browser --> API")

    if frontend and (backend or api_label):
        lines.append("    FE --> API")
    if frontend and cms and not backend:
        lines.append("    FE --> CMS")
    if frontend and auth:
        lines.append("    FE --> AUTH")
    if (backend or api_label) and database:
        lines.append("    API --> DB")
    if (backend or api_label) and auth:
        lines.append("    API --> AUTH")
    if (backend or api_label) and storage_name:
        lines.append("    API --> STORE")
    if (backend or api_label) and queue:
        lines.append("    API --> QUEUE")
    if (backend or api_label) and search:
        lines.append("    API --> SRCH")
    if frontend and search:
        lines.append("    FE --> SRCH")
    if (frontend or backend) and ai:
        lines.append(f'    {"FE" if frontend else "API"} -->|"AI calls"| AI')
    if frontend and observability:
        lines.append('    FE -->|"error events"| ERR')
    if frontend and analytics:
        lines.append('    FE -->|"analytics"| ANALYTICS')
    if (backend or api_label) and observability:
        lines.append('    API -->|"traces/errors"| ERR')
    if (frontend or backend) and payments:
        lines.append(f'    {"FE" if frontend else "API"} -->|"payment"| PAY')
    if (frontend or backend) and comm:
        lines.append(f'    {"FE" if frontend else "API"} -->|"notifications"| COMM')
    if frontend and realtime:
        lines.append('    FE <-->|"WebSocket"| RT')
        if backend:
            lines.append("    RT --> API")

    return "\n".join(lines)


# ─── Security & delivery analysis ─────────────────────────────────────────────

def security_analysis(headers: dict[str, str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    h = {k.lower(): v for k, v in headers.items()}

    if "strict-transport-security" not in h:
        findings.append({"severity": "high", "area": "Transport security", "finding": "HSTS header absent", "recommendation": "Add Strict-Transport-Security with max-age ≥ 31536000 and includeSubDomains."})
    else:
        hsts = h["strict-transport-security"]
        if "max-age=0" in hsts or not re.search(r"max-age=\d{7,}", hsts):
            findings.append({"severity": "medium", "area": "Transport security", "finding": f"HSTS max-age may be too short: {hsts}", "recommendation": "Set max-age to at least 31536000 (1 year)."})

    csp = h.get("content-security-policy", "")
    if not csp:
        findings.append({"severity": "high", "area": "Content Security Policy", "finding": "No CSP header found", "recommendation": "Implement a strict CSP with nonces or hashes to mitigate XSS."})
    else:
        if "unsafe-inline" in csp:
            findings.append({"severity": "medium", "area": "CSP", "finding": "unsafe-inline present in CSP", "recommendation": "Replace unsafe-inline with script/style nonces or hashes."})
        if "unsafe-eval" in csp:
            findings.append({"severity": "medium", "area": "CSP", "finding": "unsafe-eval present in CSP", "recommendation": "Remove unsafe-eval; refactor code that uses eval()."})
        if "default-src *" in csp or "script-src *" in csp:
            findings.append({"severity": "high", "area": "CSP", "finding": "Wildcard CSP directive detected", "recommendation": "Replace wildcards with explicit trusted origins."})

    if "x-frame-options" not in h and ("frame-ancestors" not in csp):
        findings.append({"severity": "medium", "area": "Clickjacking", "finding": "No X-Frame-Options or CSP frame-ancestors", "recommendation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."})

    if "x-content-type-options" not in h:
        findings.append({"severity": "low", "area": "MIME sniffing", "finding": "X-Content-Type-Options header absent", "recommendation": "Add X-Content-Type-Options: nosniff."})

    if "referrer-policy" not in h:
        findings.append({"severity": "low", "area": "Referrer leakage", "finding": "Referrer-Policy header absent", "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin."})

    if "permissions-policy" not in h:
        findings.append({"severity": "low", "area": "Browser features", "finding": "Permissions-Policy header absent", "recommendation": "Restrict unused browser features (camera, microphone, geolocation)."})

    cc = h.get("cache-control", "")
    if not cc:
        findings.append({"severity": "low", "area": "Caching", "finding": "Cache-Control header absent on HTML response", "recommendation": "Set explicit Cache-Control to control CDN and browser caching."})
    elif "no-store" in cc or "no-cache" in cc:
        findings.append({"severity": "positive", "area": "Caching", "finding": f"Cache-Control prevents stale HTML: {cc}", "recommendation": ""})

    # Positive findings
    if "strict-transport-security" in h:
        findings.append({"severity": "positive", "area": "Transport security", "finding": "HSTS is configured", "recommendation": ""})
    if csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp:
        findings.append({"severity": "positive", "area": "CSP", "finding": "CSP present without unsafe directives", "recommendation": ""})

    return findings


def performance_signals(headers: dict[str, str], signals: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    h = {k.lower(): v for k, v in headers.items()}
    cc = h.get("cache-control", "")
    enc = h.get("content-encoding", "")
    if enc in {"gzip", "br", "zstd"}:
        findings.append({"area": "Compression", "finding": f"Response compressed with {enc}", "impact": "positive"})
    if "immutable" in cc:
        findings.append({"area": "Asset caching", "finding": "Cache-Control immutable — long-lived asset caching active", "impact": "positive"})
    if signals.get("has_lazyload"):
        findings.append({"area": "Lazy loading", "finding": "Images or iframes use lazy loading", "impact": "positive"})
    if signals.get("has_pwa"):
        findings.append({"area": "PWA", "finding": "Web manifest or service worker detected — PWA capabilities", "impact": "positive"})
    if signals["counts"].get("iframe", 0) > 0 or signals["counts"].get("video", 0) > 0:
        findings.append({"area": "Embedded media", "finding": f"{signals['counts'].get('iframe', 0)} iframe(s), {signals['counts'].get('video', 0)} video(s) detected", "impact": "check"})
    if signals["counts"].get("img", 0) > 20:
        findings.append({"area": "Images", "finding": f"{signals['counts']['img']} <img> elements — image optimization matters", "impact": "check"})
    if signals["images_missing_alt"] > 0:
        findings.append({"area": "Accessibility", "finding": f"{signals['images_missing_alt']} images missing alt attribute", "impact": "negative"})
    return findings


def extra_findings(audit: dict[str, Any], signals: dict[str, Any]) -> list[dict[str, str]]:
    stack = audit["stack"]
    text = json.dumps(audit).lower()

    if "t4_" in text or "terminalfour" in text:
        if not any(x["technology"] == "TerminalFour" for x in stack):
            stack.append({"layer": "CMS", "technology": "TerminalFour", "evidence": "T4 asset marker in HTML", "confidence": "high"})
    if "cloudfront.net" in text or "cloudfront" in text:
        if not any(x["technology"] == "Amazon CloudFront" for x in stack):
            stack.append({"layer": "CDN", "technology": "Amazon CloudFront", "evidence": "Via header or CloudFront asset reference", "confidence": "high"})
    if not signals["has_json_ld"]:
        stack.append({"layer": "SEO", "technology": "No JSON-LD detected", "evidence": "No application/ld+json block in HTML", "confidence": "high"})

    # Mine the CSP header for additional third-party origin clues
    csp = audit["response"].get("headers", {}).get("content-security-policy", "")
    if csp:
        from analyze import evidence as _evidence
        _evidence(csp, "Content-Security-Policy header domains", stack)

    return stack


def engineering_insights(audit: dict[str, Any], signals: dict[str, Any], system_design: dict[str, Any]) -> list[dict[str, str]]:
    headers = audit["response"]["headers"]
    assets = audit["assets"]
    insights: list[dict[str, str]] = []
    script_text = " ".join(assets["scripts"])
    style_text = " ".join(assets["stylesheets"])

    if "bootstrap@5.0.2" in style_text and "bootstrap@5.2.3" in script_text:
        insights.append({"severity": "medium", "area": "Dependency consistency", "finding": "Bootstrap CSS 5.0.2 and JavaScript 5.2.3 are loaded together.", "implication": "Version mismatch may cause subtle component behavior differences.", "next_check": "Pin CSS and JS to the same Bootstrap release and regression-test menus, modals, and responsive utilities."})

    if len(signals["external_origins"]) >= 10:
        insights.append({"severity": "high", "area": "Integration blast radius", "finding": f"Page references {len(signals['external_origins'])} external origins.", "implication": "Availability, privacy, CSP, and performance depend on many separately operated systems.", "next_check": "Inventory each origin by owner, data type, SLA, consent requirement, and fallback behavior."})

    csp = headers.get("content-security-policy", "")
    if "unsafe-inline" in csp or "unsafe-eval" in csp:
        insights.append({"severity": "medium", "area": "Browser security", "finding": "CSP permits unsafe-inline and/or unsafe-eval.", "implication": "Reduced XSS protection vs. nonce/hash-based policy.", "next_check": "Migrate scripts to nonces or hashes, then remove unsafe directives incrementally."})

    if not signals["has_json_ld"]:
        insights.append({"severity": "low", "area": "Discoverability", "finding": "No JSON-LD structured data found.", "implication": "Search engines receive less explicit entity and content context.", "next_check": "Add Organization, WebSite, BreadcrumbList, and page-specific schema where applicable."})

    if signals.get("has_skip_link") and signals.get("has_search_control"):
        insights.append({"severity": "positive", "area": "Accessibility foundation", "finding": "Skip navigation and labeled search controls are present.", "implication": "Template includes deliberate keyboard and assistive-technology affordances.", "next_check": "Run axe + keyboard traversal on expanded menus, modals, and dynamic search panels."})

    if system_design.get("ai"):
        insights.append({"severity": "medium", "area": "AI integration", "finding": f"AI/LLM dependency detected: {', '.join(x['technology'] for x in system_design['ai'][:2])}.", "implication": "Latency, cost, and privacy characteristics differ from conventional API calls.", "next_check": "Review prompt injection mitigations, output validation, cost caps, and fallback behavior."})

    if system_design.get("state") and len(system_design.get("state", [])) > 2:
        techs = ", ".join(x["technology"] for x in system_design["state"][:3])
        insights.append({"severity": "medium", "area": "State management complexity", "finding": f"Multiple data-fetching/state layers detected: {techs}.", "implication": "Overlapping caching and synchronization layers can cause subtle consistency bugs.", "next_check": "Consolidate around one server-state library and one client-state library."})

    if system_design.get("auth") and len(system_design.get("auth", [])) > 1:
        techs = ", ".join(x["technology"] for x in system_design["auth"])
        insights.append({"severity": "medium", "area": "Auth provider overlap", "finding": f"Multiple auth providers detected: {techs}.", "implication": "Multiple SSO providers increases session management and token validation complexity.", "next_check": "Verify each provider serves a distinct user segment with no overlapping session state."})

    return insights


# ─── Site intelligence ────────────────────────────────────────────────────────

def extract_site_intelligence(html: str, source_url: str) -> dict[str, Any]:
    """Extract social presence, metadata, site type, and business signals."""

    # ── Open Graph & Twitter Card metadata ────────────────────────────────────
    og: dict[str, str] = {}
    for m in re.finditer(r'<meta\b[^>]+property=["\']og:([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']', html, re.I):
        og[m.group(1).strip()] = m.group(2).strip()
    for m in re.finditer(r'<meta\b[^>]+content=["\']([^"\']*)["\'][^>]+property=["\']og:([^"\']+)["\']', html, re.I):
        og[m.group(2).strip()] = m.group(1).strip()

    twitter_card: dict[str, str] = {}
    for m in re.finditer(r'<meta\b[^>]+name=["\']twitter:([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']', html, re.I):
        twitter_card[m.group(1).strip()] = m.group(2).strip()
    for m in re.finditer(r'<meta\b[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']twitter:([^"\']+)["\']', html, re.I):
        twitter_card[m.group(2).strip()] = m.group(1).strip()

    # ── Social profile links ───────────────────────────────────────────────────
    _social_patterns: list[tuple[str, str]] = [
        ("Twitter / X", r'https?://(?:www\.)?(?:twitter|x)\.com/(?!intent|share|home|status|hashtag|search|i/|)[a-zA-Z0-9_]{1,50}/?(?=["\'\s<])'),
        ("LinkedIn", r'https?://(?:www\.)?linkedin\.com/(?:company|in|school)/[^\s"\'<>#?]{2,100}'),
        ("GitHub", r'https?://(?:www\.)?github\.com/[a-zA-Z0-9_-]{1,100}(?:/[a-zA-Z0-9_.-]{1,100})?(?=["\'\s<])'),
        ("Facebook", r'https?://(?:www\.)?facebook\.com/(?!sharer|share\.php|dialog)[a-zA-Z0-9._-]{2,100}'),
        ("Instagram", r'https?://(?:www\.)?instagram\.com/[a-zA-Z0-9._]{2,50}/?(?=["\'\s<])'),
        ("YouTube", r'https?://(?:www\.)?youtube\.com/(?:channel|user|c|@)[/a-zA-Z0-9_-]{2,100}'),
        ("TikTok", r'https?://(?:www\.)?tiktok\.com/@[a-zA-Z0-9._]{1,50}'),
        ("Bluesky", r'https?://(?:www\.)?bsky\.app/profile/[a-zA-Z0-9._-]{1,100}'),
    ]
    social_links: list[dict[str, str]] = []
    seen_social: set[str] = set()
    for platform, pattern in _social_patterns:
        for m in re.finditer(pattern, html, re.I):
            norm = m.group(0).rstrip("/").strip("\"' ")
            if norm not in seen_social:
                seen_social.add(norm)
                social_links.append({"platform": platform, "url": norm})

    # ── Mobile app links ───────────────────────────────────────────────────────
    app_links: list[dict[str, str]] = []
    seen_apps: set[str] = set()
    for m in re.finditer(r'https?://apps\.apple\.com/[^\s"\'<>]{5,200}', html, re.I):
        u = m.group(0).rstrip("\"'.,>)")
        if u not in seen_apps:
            seen_apps.add(u)
            app_links.append({"store": "App Store (iOS)", "url": u})
    for m in re.finditer(r'https?://play\.google\.com/store/apps/[^\s"\'<>]{5,200}', html, re.I):
        u = m.group(0).rstrip("\"'.,>)")
        if u not in seen_apps:
            seen_apps.add(u)
            app_links.append({"store": "Google Play (Android)", "url": u})

    # ── Internationalization signals ───────────────────────────────────────────
    lang_attr_m = re.search(r'<html\b[^>]+lang=["\']([^"\']{2,20})["\']', html, re.I)
    hreflang_locales = list(dict.fromkeys(re.findall(r'hreflang=["\']([^"\']{2,20})["\']', html, re.I)))[:20]

    # ── Site type classification ───────────────────────────────────────────────
    t = html.lower()
    _site_type_clues: list[tuple[str, str, int]] = [
        ("E-commerce",          r'add.?to.?cart|shopping.?cart|checkout|buy.?now|woocommerce|shopify|product.?detail|add.?to.?bag', 3),
        ("SaaS / Product",      r'free.?trial|start.?for.?free|get.?started|per.?month|per.?year|pricing|upgrade.?plan|dashboard', 2),
        ("Blog / Content",      r'\barticle\b|\bpost\b|\bauthor\b|\bpublished\b|read.?more|tags?:|categories?:', 2),
        ("Developer Docs",      r'documentation|api.?reference|quickstart|sdk|code.?sample|getting.?started|cli', 3),
        ("Educational",         r'university|college|faculty|admissions|enrollment|academic.calendar|course.?catalog', 3),
        ("Portfolio",           r'portfolio|selected.?work|case.?stud|my.?projects|hire.?me', 2),
        ("News / Media",        r'breaking.?news|editorial|reporter|latest.?updates|press.?release|newsletter', 2),
        ("Job Board / Careers", r'\bjobs?\b.{0,30}\bopen\b|\bopen.?positions?\b|we.?are.?hiring|greenhouse\.io|lever\.co|workable\.com', 2),
        ("Government / Civic",  r'\.gov\b|official.?government|municipal|public.?service|foia', 3),
        ("Non-profit",          r'donate.?now|501\(c\)|non.?profit|ngo|charitable.?organization|volunteer', 2),
        ("Healthcare",          r'patient.?portal|hipaa|electronic.?health.?record|ehr|clinical|physician|prescription', 3),
        ("Finance / Fintech",   r'open.?account|investment|brokerage|trading|interest.?rate|apy|fdic|sec\.gov', 3),
    ]
    type_scores: Counter = Counter()
    for site_type, pattern, weight in _site_type_clues:
        if re.search(pattern, t):
            type_scores[site_type] += weight
    inferred_site_types = [st for st, _ in type_scores.most_common(3) if type_scores[st] >= 2]

    # ── Business / product signals ─────────────────────────────────────────────
    business_signals = {
        "has_pricing":     bool(re.search(r'/pricing|/plans?|/subscribe|#pricing|#plans', html, re.I)),
        "has_signup":      bool(re.search(r'/sign-?up|/register|/create-?account|/get-?started', html, re.I)),
        "has_login":       bool(re.search(r'/sign-?in|/login|/log-?in|/auth(?:/|$)', html, re.I)),
        "has_careers":     bool(re.search(r'/careers?|/jobs?|/work-?with-?us|/join-?us|greenhouse\.io|lever\.co|ashbyhq\.com|workable\.com', html, re.I)),
        "has_docs":        bool(re.search(r'/docs?/|/documentation|/developer|/api-?reference|/guides?/', html, re.I)),
        "has_status_page": bool(re.search(r'statuspage\.io|status\.io|instatus\.com|betteruptime\.com|/status/?(?:\s|")', html, re.I)),
        "has_blog":        bool(re.search(r'/blog/?(?:\s|")|/articles?/?(?:\s|")|/posts?/?(?:\s|")', html, re.I)),
        "has_changelog":   bool(re.search(r'/changelog|/releases?|/whats-?new|/updates?', html, re.I)),
        "has_privacy":     bool(re.search(r'/privacy|privacy.?policy', html, re.I)),
        "has_terms":       bool(re.search(r'/terms|terms.?of.?(?:service|use)', html, re.I)),
    }

    # ── Contact info ───────────────────────────────────────────────────────────
    # Only extract emails from visible text areas (not script/style) and cap results
    emails = list(dict.fromkeys(re.findall(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10}\b', html
    )))
    # Filter out common false positives (example.com, schema.org, etc.)
    emails = [e for e in emails if not re.search(r'@(?:example|schemata?|schema|w3\.org|test|foo|bar)\b', e, re.I)][:5]

    return {
        "open_graph":          og,
        "twitter_card":        twitter_card,
        "social_links":        social_links,
        "app_links":           app_links[:4],
        "page_language":       lang_attr_m.group(1) if lang_attr_m else None,
        "hreflang_locales":    hreflang_locales,
        "inferred_site_types": inferred_site_types,
        "business_signals":    business_signals,
        "contact_emails":      emails,
    }


# ─── Multi-page aggregation ────────────────────────────────────────────────────

def aggregate_pages(pages: list[dict[str, Any]], base_audit: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Merge technology findings from all crawled pages into the base audit."""
    seen_techs = {x["technology"] for x in base_audit["stack"]}
    seen_apis = {x["path"] for x in base_audit.get("api_endpoints", [])}
    page_summaries: list[dict[str, Any]] = []

    for page in pages[1:]:  # skip index page (already analyzed)
        try:
            page_audit = analyze(page["url"], page["body"], page["response"], max_bytes, fetch_styles=False, extra_js="")
        except Exception:
            continue
        # Merge new stack findings
        for item in page_audit["stack"]:
            if item["technology"] not in seen_techs:
                seen_techs.add(item["technology"])
                base_audit["stack"].append(item)
        # Merge new API endpoints
        for ep in page_audit.get("api_endpoints", []):
            if ep["path"] not in seen_apis:
                seen_apis.add(ep["path"])
                base_audit["api_endpoints"].append(ep)
        page_summaries.append({"url": page["url"], "status": page["response"].get("status")})

    base_audit["crawled_pages"] = page_summaries
    return base_audit


# ─── Markdown report ───────────────────────────────────────────────────────────

def markdown(result: dict[str, Any]) -> str:  # noqa: C901
    s = result["signals"]
    h = result["response"]["headers"]
    sys_design = result["system_design"]
    lines: list[str] = []

    # Header
    lines += [
        "# System Design Report",
        "",
        f"**Target:** {result['source_url']}",
        f"**Final URL:** {result['response']['final_url']}",
        f"**HTTP status:** {result['response']['status']}",
        f"**Pages crawled:** {1 + len(result.get('crawled_pages', []))}",
        "",
        "---",
        "",
    ]

    # Executive summary
    lines += [
        "## Executive Summary",
        "",
        result["executive_assessment"],
        "",
    ]

    # Architecture diagram
    mermaid_src = result.get("mermaid_diagram", "")
    if mermaid_src:
        lines += [
            "## Architecture Diagram",
            "",
            "```mermaid",
            mermaid_src,
            "```",
            "",
        ]

    # Technology stack by layer
    lines += [
        "## Technology Stack",
        "",
        "| Category | Technology | Evidence | Confidence |",
        "|---|---|---|---|",
    ]
    for item in result["stack"]:
        lines.append(f"| {item['layer']} | {item['technology']} | {item['evidence']} | {item['confidence']} |")
    lines.append("")

    # System design by category
    category_labels = {
        "frontend": "Frontend Framework",
        "ui": "UI / Design System",
        "state": "State Management & Data Fetching",
        "build": "Build Tooling",
        "backend": "Backend / Server",
        "api": "API Layer",
        "cms": "CMS / Content Platform",
        "database": "Database & Data",
        "auth": "Authentication",
        "infra": "Infrastructure / Hosting",
        "cdn": "CDN / Edge",
        "observability": "Error Tracking & Observability",
        "analytics": "Analytics & CDP",
        "payments": "Payments",
        "communication": "Communication & Support",
        "feature_flags": "Feature Flags & Experimentation",
        "search": "Search",
        "maps": "Maps",
        "ai": "AI / LLM",
        "storage": "Storage",
        "queue": "Background Jobs / Queue",
        "consent": "Consent Management",
        "i18n": "Internationalization & Translation",
        "testing": "Testing",
        "other": "Other",
    }
    lines += ["## System Design by Layer", ""]
    for cat, label in category_labels.items():
        items = sys_design.get(cat, [])
        if not items:
            continue
        lines.append(f"### {label}")
        lines.append("")
        for item in items:
            lines.append(f"- **{item['technology']}** — _{item['evidence']}_ (confidence: {item['confidence']})")
        lines.append("")

    # API surface
    api_eps = result.get("api_endpoints", [])
    if api_eps:
        lines += ["## API Surface", ""]
        lines += ["| Path | Source |", "|---|---|"]
        for ep in api_eps[:30]:
            note = f" _{ep.get('note', '')}_" if ep.get("note") else ""
            lines.append(f"| `{ep['path']}` | {ep['source']}{note} |")
        lines.append("")

    # Security posture
    sec = result.get("security_findings", [])
    if sec:
        lines += ["## Security Posture", ""]
        lines += ["| Severity | Area | Finding | Recommendation |", "|---|---|---|---|"]
        for f in sec:
            lines.append(f"| {f['severity']} | {f['area']} | {f['finding']} | {f.get('recommendation', '')} |")
        lines.append("")

    # Engineering insights
    ei = result.get("engineering_insights", [])
    if ei:
        lines += ["## Engineering Insights", ""]
        lines += ["| Severity | Area | Finding | Implication | Next check |", "|---|---|---|---|---|"]
        for f in ei:
            lines.append(f"| {f['severity']} | {f['area']} | {f['finding']} | {f['implication']} | {f['next_check']} |")
        lines.append("")

    # Performance
    perf = result.get("performance_signals", [])
    if perf:
        lines += ["## Performance & Delivery", ""]
        for f in perf:
            icon = {"positive": "✅", "negative": "⚠️", "check": "🔎"}.get(f["impact"], "•")
            lines.append(f"- {icon} **{f['area']}**: {f['finding']}")
        lines.append("")

    # Site intelligence
    si = result.get("site_intelligence")
    if si:
        lines += ["## Site Intelligence", ""]

        if si.get("inferred_site_types"):
            lines.append(f"**Inferred site type:** {', '.join(si['inferred_site_types'])}")
            lines.append("")

        og = si.get("open_graph", {})
        tc = si.get("twitter_card", {})
        if og or tc:
            lines.append("### Social Metadata")
            lines.append("")
            if og.get("title"):
                lines.append(f"- **OG title:** {og['title']}")
            if og.get("description"):
                lines.append(f"- **OG description:** {og['description']}")
            if og.get("type"):
                lines.append(f"- **OG type:** {og['type']}")
            if og.get("image"):
                lines.append(f"- **OG image:** `{og['image']}`")
            if tc.get("card"):
                lines.append(f"- **Twitter card:** {tc['card']}")
            if tc.get("site"):
                lines.append(f"- **Twitter @handle:** {tc['site']}")
            lines.append("")

        social = si.get("social_links", [])
        if social:
            lines.append("### Social Presence")
            lines.append("")
            for link in social:
                lines.append(f"- **{link['platform']}:** {link['url']}")
            lines.append("")

        apps = si.get("app_links", [])
        if apps:
            lines.append("### Mobile Apps")
            lines.append("")
            for app in apps:
                lines.append(f"- **{app['store']}:** {app['url']}")
            lines.append("")

        lang = si.get("page_language")
        hreflangs = si.get("hreflang_locales", [])
        if lang or hreflangs:
            lines.append("### Internationalization")
            lines.append("")
            if lang:
                lines.append(f"- **Page language (`<html lang>`):** `{lang}`")
            if hreflangs:
                lines.append(f"- **hreflang locales:** {', '.join(f'`{x}`' for x in hreflangs)}")
            lines.append("")

        bs = si.get("business_signals", {})
        active = [k.replace("has_", "").replace("_", " ") for k, v in bs.items() if v]
        inactive = [k.replace("has_", "").replace("_", " ") for k, v in bs.items() if not v]
        if active or inactive:
            lines.append("### Business Signals")
            lines.append("")
            if active:
                lines.append(f"- **Present:** {', '.join(active)}")
            if inactive:
                lines.append(f"- **Not detected:** {', '.join(inactive)}")
            lines.append("")

        emails = si.get("contact_emails", [])
        if emails:
            lines.append(f"**Contact emails found:** {', '.join(emails)}")
            lines.append("")

    # Design system
    design = result["design"]
    lines += [
        "## Design System",
        "",
        f"- **Palette:** {', '.join(x['value'] for x in design['palette'][:8]) or 'not detected'}",
        f"- **Fonts:** {', '.join(design['typography']['font_families']) or 'not detected'}",
        f"- **Layout systems:** {', '.join(design['layout']['layout_systems']) or 'not detected'}",
        f"- **Breakpoints:** {', '.join(design['layout']['breakpoints']) or 'not detected'}",
        f"- **Icon / SVG:** {'yes' if design['ui_clues']['icons_or_svg'] else 'no'}",
        "",
    ]

    # Page signals
    lines += [
        "## Content, SEO & Accessibility",
        "",
        f"- HTML size: {s['html_bytes']:,} bytes",
        f"- Headings: {dict(s['heading_levels'])}",
        f"- Images missing alt attribute: {s['images_missing_alt']}",
        f"- JSON-LD structured data: {'present' if s['has_json_ld'] else 'not detected'}",
        f"- Canonical URL: {'present' if s['has_canonical'] else 'not detected'}",
        f"- Meta description: {'present' if s['has_description'] else 'not detected'}",
        f"- Skip navigation: {'present' if s['has_skip_link'] else 'not detected'}",
        f"- Search control: {'present' if s['has_search_control'] else 'not detected'}",
        f"- Progressive Web App: {'yes' if s.get('has_pwa') else 'no'}",
        f"- Web components: {'detected' if s.get('has_web_components') else 'no'}",
        f"- Lazy loading: {'detected' if s.get('has_lazyload') else 'no'}",
        "",
    ]

    # Response headers
    lines += ["## Response Headers", ""]
    lines += [f"- `{k}`: {v}" for k, v in h.items()]
    lines.append("")

    # Integration map
    origins = s.get("external_origins", [])
    if origins:
        lines += ["## Integration Surface", "", f"External origins referenced: {len(origins)}", ""]
        lines += [f"- {x}" for x in origins]
        lines.append("")

    # Crawled pages
    crawled = result.get("crawled_pages", [])
    if crawled:
        lines += ["## Pages Crawled", ""]
        for p in crawled:
            lines.append(f"- [{p['url']}]({p['url']}) — HTTP {p.get('status', '?')}")
        lines.append("")

    # Caveats
    lines += [
        "## Caveats",
        "",
        "This report is based on passive evidence from public URLs only. Backend language, "
        "private API routes, database schemas, authenticated routes, and JavaScript-rendered "
        "state remain unverified. Confidence levels reflect signal strength, not certainty.",
        "",
    ]

    return "\n".join(lines)


# ─── Main ──────────────────────────────────────────────────────────────────────

def _build_executive_assessment(result: dict[str, Any]) -> str:
    sys_design = result["system_design"]
    stack = result["stack"]
    signals = result["signals"]
    parts: list[str] = []

    frontend = sys_design.get("frontend", [])
    backend = sys_design.get("backend", [])
    infra = sys_design.get("infra", []) + sys_design.get("cdn", [])
    database = sys_design.get("database", [])
    auth = sys_design.get("auth", [])
    ai = sys_design.get("ai", [])

    if frontend:
        parts.append(f"**Frontend:** {', '.join(x['technology'] for x in frontend[:3])}")
    if backend:
        parts.append(f"**Backend:** {', '.join(x['technology'] for x in backend[:2])}")
    if infra:
        parts.append(f"**Infrastructure:** {', '.join(x['technology'] for x in infra[:3])}")
    if database:
        parts.append(f"**Data:** {', '.join(x['technology'] for x in database[:2])}")
    if auth:
        parts.append(f"**Auth:** {', '.join(x['technology'] for x in auth[:2])}")
    if ai:
        parts.append(f"**AI layer:** {', '.join(x['technology'] for x in ai[:2])}")

    summary = ". ".join(parts) + "." if parts else "No clear stack signals detected from public HTML alone."
    suffix = (
        f" The page references {len(stack)} technology signals across "
        f"{len(signals.get('external_origins', []))} external origins."
    )
    return summary + suffix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url")
    parser.add_argument("--out", type=Path, default=Path("public_text_reports/latest"))
    parser.add_argument("--timeout", type=float, default=20, help="Per-request timeout in seconds (default: 20)")
    parser.add_argument("--har", type=Path, help="Analyze a user-provided Burp/browser HAR offline instead of fetching the URL")
    parser.add_argument("--proxy", default="http://127.0.0.1:8080", help="HTTP proxy URL (default: http://127.0.0.1:8080)")
    parser.add_argument("--ca-cert", type=Path, help="PEM CA certificate for intercepted HTTPS (e.g. Burp's CA)")
    parser.add_argument("--direct", action="store_true", help="Bypass the configured proxy for this run")
    parser.add_argument("--crawl", action="store_true", help="Crawl additional internal pages for richer system design detection")
    parser.add_argument("--max-pages", type=int, default=8, help="Maximum pages to crawl when --crawl is active (default: 8)")
    parser.add_argument("--no-js", action="store_true", help="Skip fetching JS bundles for deeper analysis")
    parser.add_argument("--ignore-robots", action="store_true", help="Bypass robots.txt restrictions (use only on sites you are authorized to audit)")
    parser.add_argument("--user-agent", default=None, help="Override the User-Agent header (e.g. a real browser UA to bypass bot detection)")
    args = parser.parse_args()

    _DEFAULT_AGENT = "SystemDesignAuditHarness/1.0 (passive, user-initiated, public pages only)"
    _BROWSER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    agent = args.user_agent or _DEFAULT_AGENT
    MAX_BYTES = 8_000_000

    if args.har:
        source_url, body, response = load_har(args.har, MAX_BYTES)
        allowed = None
        fetch_styles = False
        proxy_mode = "offline_har"
        crawl_pages_data: list[dict[str, Any]] = []
    else:
        configure_proxy(None if args.direct else args.proxy, str(args.ca_cert) if args.ca_cert else None)
        proxy_mode = "direct" if args.direct else args.proxy
        if args.ignore_robots:
            allowed = None  # skip robots check
        else:
            allowed = check_robots(args.url, agent)
            if allowed is False:
                parser.error("robots.txt disallows fetching this URL — use --ignore-robots to bypass")
        try:
            body, response = fetch_page(args.url, agent, args.timeout, MAX_BYTES)
            source_url = args.url
        except FetchFailure as exc:
            args.out.mkdir(parents=True, exist_ok=True)
            diagnostic = {"source_url": args.url, "collection_mode": "live_single_page", "error": str(exc), "details": exc.details}
            (args.out / "fetch_diagnostic.json").write_text(json.dumps(diagnostic, indent=2) + "\n", encoding="utf-8")
            (args.out / "fetch_diagnostic.md").write_text(f"# Fetch diagnostic\n\nTarget: {args.url}\n\n{exc}\n\nThis harness stopped without bypassing access controls or anti-bot protections.\n", encoding="utf-8")
            print(f"Fetch failed; wrote {args.out / 'fetch_diagnostic.md'} and {args.out / 'fetch_diagnostic.json'}")
            return 2
        fetch_styles = True

        # Sitemap & crawl
        sitemap_urls: list[str] = []
        if args.crawl:
            print("Fetching sitemap.xml …")
            sitemap_urls = fetch_sitemap(args.url, agent, args.timeout)
            if sitemap_urls:
                print(f"  Found {len(sitemap_urls)} URLs in sitemap")

        crawl_pages_data = []
        if args.crawl:
            print(f"Crawling up to {args.max_pages} pages …")
            crawl_pages_data = crawl_site(source_url, agent, args.max_pages, args.timeout, MAX_BYTES, sitemap_urls)
            print(f"  Crawled {len(crawl_pages_data)} page(s)")

    html = body.decode("utf-8", errors="replace")

    # Fetch JS bundles for deeper analysis
    extra_js = ""
    if not args.no_js and not args.har:
        import re as _re
        scripts = _re.findall(r'<script\b[^>]*\ssrc=["\']([^"\']+\.js[^"\']*)["\']', html, _re.I)
        if scripts:
            print(f"Fetching up to 4 JS bundles ({len(scripts)} candidates) …")
            extra_js = fetch_js_bundles(scripts, response["final_url"], agent, args.timeout, MAX_BYTES)

    # Core analysis
    audit = analyze(source_url, body, response, MAX_BYTES, fetch_styles=fetch_styles, extra_js=extra_js)

    # Merge multi-page findings
    if crawl_pages_data:
        audit = aggregate_pages(crawl_pages_data, audit, MAX_BYTES)

    signals = html_signals(html)
    audit["stack"] = extra_findings(audit, signals)
    audit["signals"] = signals
    audit["site_intelligence"] = extract_site_intelligence(html, source_url)
    audit["robots_allowed"] = allowed if not args.har else None
    audit["collection_mode"] = "offline_har" if args.har else ("live_multi_page" if args.crawl else "live_single_page")
    audit["proxy_mode"] = proxy_mode

    # System design layers
    system_design = infer_system_design(audit["stack"])
    audit["system_design"] = system_design

    # Derived outputs
    audit["mermaid_diagram"] = generate_mermaid(system_design, signals)
    audit["security_findings"] = security_analysis(audit["response"]["headers"])
    audit["performance_signals"] = performance_signals(audit["response"]["headers"], signals)
    audit["engineering_insights"] = engineering_insights(audit, signals, system_design)
    audit["executive_assessment"] = _build_executive_assessment(audit)

    # Write outputs
    args.out.mkdir(parents=True, exist_ok=True)
    audit_out = {k: v for k, v in audit.items() if k != "crawled_pages" or True}
    (args.out / "system_design.json").write_text(json.dumps(audit_out, indent=2, ensure_ascii=False, default=lambda o: str(o)) + "\n", encoding="utf-8")
    (args.out / "system_design.md").write_text(markdown(audit), encoding="utf-8")
    print(f"\nWrote {args.out / 'system_design.md'} and {args.out / 'system_design.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
