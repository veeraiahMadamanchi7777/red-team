# Public Text Extractor

See the [complete repository guide](../README.md) for the current system-design harness, crawling, JavaScript analysis, Burp/HAR setup, assessment scripts, analysis history, and limitations. The current harness writes `system_design.md` and `system_design.json`; the smaller commands below retain their own output names.

A small, dependency-free Python tool for extracting readable text from a public web page.

It accepts any `http://` or `https://` URL, checks `robots.txt` when available, fetches the page once, removes scripts/styles/navigation boilerplate, and writes a Markdown report plus JSON metadata. It does not log in, bypass access controls, evade anti-bot systems, or crawl beyond the URL supplied.

## Run

```bash
python3 public_text_extractor/extract.py https://example.com
```

Choose an output directory:

```bash
python3 public_text_extractor/extract.py https://example.com --out reports/example
```

The report contains the page title, description, canonical URL, headings, extracted text, response details, and the exact source URL. A `report.json` file is also written for downstream processing.

To identify likely technologies and summarize the accessible design system:

```bash
python3 public_text_extractor/analyze.py https://example.com
```

This writes `technology_and_design.md` and `technology_and_design.json`. Technology detections include evidence and confidence; design findings are inferred from accessible CSS and HTML.

For the full lead-ready reconnaissance harness:

```bash
python3 public_text_extractor/harness.py https://example.com --out public_text_reports/example.com
```

This adds response security headers, external-origin inventory, HTML/component counts, SEO signals, accessibility checks, architecture clues, design tokens, and explicit caveats about what cannot be inferred from a public page.

Live collection uses Burp Suite by default through `http://127.0.0.1:8080`:

```bash
python3 public_text_extractor/harness.py https://example.com
```

Start Burp's proxy listener on that address first. Use `--proxy http://host:port` for another listener, or `--direct` for a direct request. HAR mode remains offline:

```bash
python3 public_text_extractor/harness.py https://example.com --har capture.har
```

For HTTPS interception, export Burp's CA certificate as PEM and pass it explicitly:

```bash
python3 public_text_extractor/harness.py https://example.com \
  --ca-cert public_text_extractor/burp-ca.pem
```

## Limits

Some pages render their content only with JavaScript, require authentication, or intentionally restrict automated requests. This tool reports those situations rather than attempting to bypass them. For those pages, save an authorized browser export or use the site's official API.
