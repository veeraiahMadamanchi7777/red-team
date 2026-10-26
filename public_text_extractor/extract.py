#!/usr/bin/env python3
"""Extract readable text from one publicly accessible HTML page."""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


def configure_proxy(proxy_url: str | None, ca_cert: str | None = None) -> None:
    """Route urllib traffic through an explicit proxy, or force direct mode."""
    handler = urllib.request.ProxyHandler({} if not proxy_url else {"http": proxy_url, "https": proxy_url})
    if ca_cert:
        context = ssl.create_default_context(cafile=ca_cert)
        urllib.request.install_opener(urllib.request.build_opener(handler, urllib.request.HTTPSHandler(context=context)))
    else:
        urllib.request.install_opener(urllib.request.build_opener(handler))


SKIP_TAGS = {"script", "style", "noscript", "template", "svg", "canvas", "iframe"}
BLOCK_TAGS = {"p", "div", "article", "section", "main", "aside", "header", "footer", "li", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6", "br"}
NAV_HINTS = re.compile(r"(nav|menu|breadcrumb|cookie|banner|modal|advert|promo|social|share|footer|header)", re.I)


def clean_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.meta: dict[str, str] = {}
        self.canonical = ""
        self.headings: list[str] = []
        self._title_parts: list[str] = []
        self._in_title = False
        self._text_parts: list[str] = []
        self._heading_parts: list[str] = []
        self._skip_depth = 0
        self._skip_end_tags: list[str] = []
        self._heading_tag: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() in SKIP_TAGS or tag.lower() in {"nav", "header", "footer"} or NAV_HINTS.search(attrs_map.get("id", "") + " " + attrs_map.get("class", "")):
            self._skip_depth += 1
            self._skip_end_tags.append(tag.lower())
            return
        if tag.lower() == "title":
            self._title_parts = []
            self._in_title = True
        if tag.lower() == "meta":
            name = (attrs_map.get("name") or attrs_map.get("property")).lower()
            if name and attrs_map.get("content"):
                self.meta[name] = clean_space(attrs_map["content"])
        if tag.lower() == "link" and attrs_map.get("rel", "").lower() == "canonical":
            self.canonical = attrs_map.get("href", "")
        if tag.lower() in {f"h{i}" for i in range(1, 7)} and self._skip_depth == 0:
            self._heading_tag = tag.lower()
            self._heading_parts = []
        if tag.lower() in BLOCK_TAGS and self._skip_depth == 0:
            self._text_parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._skip_end_tags and tag == self._skip_end_tags[-1]:
            self._skip_depth -= 1
            self._skip_end_tags.pop()
            return
        if tag == "title":
            self.title = clean_space(" ".join(self._title_parts))
            self._in_title = False
        if self._heading_tag == tag:
            heading = clean_space(" ".join(self._heading_parts))
            if heading:
                self.headings.append(heading)
                self._text_parts.append(f"\n{heading}\n")
            self._heading_tag = None
            self._heading_parts = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = clean_space(data)
        if not text:
            return
        if self._in_title:
            self._title_parts.append(text)
        elif self._heading_tag:
            self._heading_parts.append(text)
        else:
            self._text_parts.append(text)

    def result(self) -> dict[str, Any]:
        text = re.sub(r"\n[ \t]*\n+", "\n\n", "\n".join(self._text_parts))
        text = "\n".join(clean_space(line) for line in text.splitlines() if clean_space(line))
        return {"title": self.title, "meta": self.meta, "canonical": self.canonical, "headings": self.headings, "text": text}


def check_robots(url: str, user_agent: str) -> bool | None:
    parsed = urllib.parse.urlparse(url)
    robots_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
    try:
        request = urllib.request.Request(robots_url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(request, timeout=10) as response:
            content = response.read(256_000).decode("utf-8", errors="replace")
        parser = urllib.robotparser.RobotFileParser()
        parser.set_url(robots_url)
        parser.parse(content.splitlines())
        return parser.can_fetch(user_agent, url)
    except (OSError, urllib.error.URLError, UnicodeError):
        return None


def fetch(url: str, timeout: float, max_bytes: int, user_agent: str) -> tuple[bytes, dict[str, Any]]:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError(f"response exceeded the {max_bytes:,}-byte limit")
        return body, {"status": response.status, "content_type": response.headers.get_content_type(), "content_length": response.headers.get("Content-Length"), "final_url": response.geturl(), "server": response.headers.get("Server"), "x_powered_by": response.headers.get("X-Powered-By")}


def write_report(result: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [f"# {result['page']['title'] or 'Untitled page'}", "", f"Source: {result['source_url']}", "", "## Page details", "", f"- Final URL: {result['response']['final_url']}", f"- HTTP status: {result['response']['status']}", f"- Content type: {result['response']['content_type']}", "", "## Extracted text", "", result["page"]["text"] or "_(No readable text found in the HTML response.)_", ""]
    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--out", type=Path, default=Path("public_text_reports/latest"))
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--max-bytes", type=int, default=5_000_000)
    args = parser.parse_args()
    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        parser.error("URL must be an absolute http:// or https:// URL")
    user_agent = "PublicTextExtractor/0.1 (single-page, user-initiated fetch)"
    allowed = check_robots(args.url, user_agent)
    if allowed is False:
        print("robots.txt disallows fetching this URL; no request was made", file=sys.stderr)
        return 2
    try:
        body, response = fetch(args.url, args.timeout, args.max_bytes, user_agent)
        content_type = response["content_type"]
        if content_type not in {"text/html", "application/xhtml+xml"}:
            raise ValueError(f"response is {content_type}, not an HTML page")
        page = PageParser()
        page.feed(body.decode("utf-8", errors="replace"))
        result = {"source_url": args.url, "robots_allowed": allowed, "response": response, "page": page.result()}
        write_report(result, args.out)
        print(f"Wrote {args.out / 'report.md'} and {args.out / 'report.json'}")
        return 0
    except (OSError, urllib.error.URLError, ValueError) as exc:
        print(f"Could not extract page: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
