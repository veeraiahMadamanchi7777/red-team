# Red Team — Website Reconnaissance and System Design Analysis

A Python toolkit for collecting public website evidence and generating technology, design, and architecture reports. It combines HTML and header inspection, sampled CSS and JavaScript analysis, optional page crawling, Burp proxy support, and offline HAR ingestion.

The repository also contains standalone CVE assessment scripts. These are separate from the reconnaissance command and can send active test requests.

## Quick start

Requires Python 3.10 or newer. The Python tools use the standard library; no pip installation is required for the core workflow.

```bash
git clone https://github.com/veeraiahMadamanchi7777/red-team.git
cd red-team

# Collect directly, without a proxy
python3 public_text_extractor/harness.py https://example.com \
  --direct --out public_text_reports/example
```

Open `public_text_reports/example/system_design.md` for the readable report or `system_design.json` for structured results. Use a separate output directory for each target/run to avoid overwriting an earlier result.

## What the analysis covers

| Area | Evidence and output |
|---|---|
| Technology stack | Framework, library, CMS, analytics, hosting, CDN, and service signatures in HTML, asset paths, sampled bundles, and selected headers |
| Architecture | Findings grouped into frontend, backend, infrastructure, authentication, data, storage, communications, and other detected layers |
| Diagram | Mermaid representation of inferred components; this is a hypothesis, not a verified deployment diagram |
| Design | CSS color tokens, font families, font sizes, spacing examples, breakpoints, Grid/Flexbox declarations, shadows, and radii |
| HTML structure | Headings, images, forms, buttons, scripts, stylesheets, media, and related markup signals |
| SEO and content | Canonical/description signals, JSON-LD presence, Open Graph/Twitter metadata, social links, and site intelligence |
| Accessibility signals | Alt-attribute presence, skip-navigation and labeled-control clues; not a conformance audit |
| Delivery/security | Selected response headers, cache directives, TLS-related headers, CSP, framing and content-type protections |
| Performance signals | HTML/asset counts, caching and markup observations; no browser performance measurement |
| Engineering interpretation | Findings, implications, and suggested follow-up checks |

Detection confidence describes a heuristic match. A high-confidence match is not proof of a site's full architecture or of an exploitable vulnerability.

## Collection modes

### Direct collection

```bash
python3 public_text_extractor/harness.py https://www.python.org/ \
  --direct --out public_text_reports/python
```

Even without crawling, collection includes the initial HTML plus eligible assets. The current implementation samples up to four same-host JavaScript bundles and up to five stylesheet references, fetching eligible same-host stylesheets. This is not literally a single network request.

### Burp Suite proxy

Live collection defaults to `http://127.0.0.1:8080`. Start Burp, create/open a project, enable the loopback listener, and turn **Intercept off** so automated requests can complete.

For HTTPS interception, export Burp's public CA certificate and pass a PEM file explicitly:

```bash
# If the exported certificate is DER, convert it first
openssl x509 -inform DER -in burp-ca.cer -out burp-ca.pem

python3 public_text_extractor/harness.py https://example.com \
  --ca-cert burp-ca.pem --out public_text_reports/example-burp

# A different listener
python3 public_text_extractor/harness.py https://example.com \
  --proxy http://127.0.0.1:8081 --ca-cert burp-ca.pem
```

The certificate applies to this Python process; the command does not install it into the operating system trust store. TLS verification remains enabled. Burp is a transport proxy here: the harness does not invoke Burp Scanner or automatically export Burp traffic history.

### Offline HAR

```bash
python3 public_text_extractor/harness.py https://example.com \
  --har capture.har --out public_text_reports/captured-page
```

Use a HAR containing response bodies. The importer selects the first eligible HTML response with body text, including base64-encoded bodies. It does not select by the positional URL or analyze the entire request waterfall. It does not fetch additional CSS/JS in HAR mode. Review the selected `source_url` in the result.

HAR files can contain credentials and personal information. They are excluded from Git by default.

### Optional crawl

```bash
python3 public_text_extractor/harness.py https://example.com \
  --direct --crawl --max-pages 5 --out public_text_reports/example-crawl
```

Crawl mode discovers sitemap candidates and internal links, then merges findings from additional HTML pages. The default limit is eight successfully collected pages. That limit is not a total HTTP request budget: sitemap discovery, retries, and asset fetches add requests, and the starting page may be fetched again.

The current robots check covers the initial URL. Per-page and per-asset robots checks and strict redirect-origin enforcement are not implemented. Review scope before enabling crawling; do not assume the current crawler enforces every route restriction.

## Harness command reference

```text
python3 public_text_extractor/harness.py URL [options]
```

| Option | Default / behavior |
|---|---|
| `--out PATH` | `public_text_reports/latest` |
| `--timeout SECONDS` | 20 seconds per main fetch request |
| `--proxy URL` | `http://127.0.0.1:8080` |
| `--direct` | Disable the configured proxy |
| `--ca-cert PATH` | PEM trust certificate for intercepted HTTPS |
| `--har PATH` | Analyze captured HTML offline |
| `--crawl` | Enable sitemap/link discovery and page aggregation |
| `--max-pages N` | Eight pages by default when crawling |
| `--no-js` | Skip additional JS bundle downloads; scripts are never executed |
| `--user-agent TEXT` | Override the request identification string |
| `--ignore-robots` | Skip the initial robots check; use only within an agreed audit scope |

The last two switches exist in the current code; neither grants authorization nor guarantees access to a blocked page. Requests returning non-retryable errors such as 403 produce a diagnostic.

## Output files and interpretation

| File | Purpose |
|---|---|
| `system_design.md` | Main report with architecture, design, evidence, and engineering observations |
| `system_design.json` | Structured findings, signals, selected headers, assets, inferred layers, and collection metadata |
| `fetch_diagnostic.md` | Human-readable main-fetch failure |
| `fetch_diagnostic.json` | Failure status, attempts, and error details |

Key JSON fields include `source_url`, `response`, `stack`, `assets`, `design`, `signals`, `site_intelligence`, `system_design`, `mermaid_diagram`, `security_findings`, `performance_signals`, `engineering_insights`, `collection_mode`, and `proxy_mode`.

Older runs generated `audit.md`/`audit.json`. The current harness uses `system_design.*`. The smaller `analyze.py` command writes `technology_and_design.*`, while `extract.py` writes `report.*`.

Interpret evidence carefully:

- A library version in an asset path is a version label, not runtime verification.
- A `?ver=` parameter can identify a plugin, theme, build, or cache revision. It does not necessarily identify the library inside the file.
- An `X-Powered-By: PHP/...` header is a server-reported runtime clue; WordPress paths alone do not disclose the PHP version.
- Marketing-site technology does not establish the company's product backend stack.
- Service mentions, CSP allowlists, and outbound links do not prove that a service loaded or was used during the visit.
- The current external-origin inventory includes navigation links and can include same-site hosts or case variants. Its count must not be treated as a measured third-party dependency count.
- “Not detected” means absent from sampled evidence, not absent from the site.

## Analysis performed during development

The project was exercised on university, product, documentation, and marketing sites. Historical observations are examples from earlier snapshots, not current claims or a regression-test suite.

| Target/group | Historical observation |
|---|---|
| example.com | Successful direct and Burp-routed HTTPS collection after configuring the local CA |
| python.org, wikipedia.org | Successful static report generation |
| isu.edu | TerminalFour clues, CloudFront header, Bootstrap/jQuery paths, institutional CSS tokens |
| urec.charlotte.edu | Server-reported Apache/PHP evidence, fonts/layout tokens and institutional navigation |
| illinoisstate.edu | OmniUpdate and Imgix clues; version-bearing jQuery/GSAP assets |
| vignan.ac.in | Root HTML meta-refresh shell; actual `/newvignan/` page audited separately |
| AMC Theatres | HTTP 403 observed both directly and through Burp |
| 15-company source collection | 28 unique source URLs attempted: 25 reports, one 403, one 404, and one DNS-resolution failure in that run |

The company-source batch included Botsplash, Lucid Bots, Tradier, Palmetto, Stratifyd, Aiwyn, ThreatSwitch, Fortalice, NetFoundry, Atom Power, XUP Payments, ComplianceLine, Torqata, PrecisionLender, and a shared directory source for Clinect Healthcare. Some source pages were third-party job boards, directories, or news articles; detections on those pages describe the publisher's website.

Generated reports, captures, and local assessment notes are not included in this repository. Early automated labels contained false positives and overstatements; use underlying evidence and the limitations above before reusing a result.

## Other entry points

```bash
# Readable text and metadata
python3 public_text_extractor/extract.py https://example.com

# Smaller technology/design report
python3 public_text_extractor/analyze.py https://example.com

# Current harness options
python3 public_text_extractor/harness.py --help
```

These entry points have different CLI options. Burp and crawl options belong to `harness.py`.

## Standalone CVE assessment scripts

`public_text_extractor/scripts/` contains a runner and eleven assessment modules. They are not called by `harness.py`. Some modules send crafted requests for authentication, cache, SSRF, error-response, or resource-handling tests. Run them only against your own test environment or a target within an authorized assessment scope.

The modules are named for CVE-2024-46982, CVE-2024-47831, CVE-2024-51479, CVE-2024-56332, CVE-2025-29927, CVE-2025-32421, CVE-2025-48068, CVE-2025-55173, CVE-2025-57752, CVE-2025-57822, and CVE-2026-19513.

```bash
python3 public_text_extractor/scripts/run_all.py --help

# Example: one selected assessment against a local lab
python3 public_text_extractor/scripts/run_all.py \
  --target http://localhost:3000 --cve CVE-2025-29927
```

The runner supports `--target`, `--timeout`, `--verbose`, and `--cve`. Standalone modules can differ; inspect their help and source. In particular, the Gravity Forms module currently has a public-site default, so supply an explicit lab target when using it independently.

CVE identifiers, affected ranges, severity ratings, and verdict logic in these scripts have not been independently validated as part of repository publication. A script's “VULNERABLE” or “PATCHED” label is not a validated security finding. Corroborate with the vendor advisory and reproducible evidence before reporting it.

## Reliability and known limitations

- Static analysis only: no JavaScript execution, rendered screenshots, browser DOM inspection, or live XHR/WebSocket capture.
- No measured Core Web Vitals, Lighthouse results, keyboard traversal, contrast audit, or visual layout verification.
- JS/CSS samples are bounded and mostly same-host; important CDN assets can be missed. JS samples are truncated, and asset-fetch failures may be silently skipped.
- Regex-based technology and HTML signals can misclassify text, embedded examples, or unused code.
- Initial HTTP redirects are handled by urllib; HTML meta-refresh and JavaScript redirects are not automatically resolved as browser navigation.
- HAR ingestion is one HTML response, not full network reconstruction.
- Main fetch retries selected HTTP errors and network failures up to three attempts with short delays. It does not currently honor `Retry-After`.
- Robots retrieval errors return an unknown state, which permits collection to continue. Unknown is not an explicit allow.
- UTF-8 decoding is used with replacement; other character encodings can lose information.
- Missing headers, absent JSON-LD, or multiple H1s alone do not establish a vulnerability or accessibility violation.
- Backend language, database, operating system, private services, and deployment topology usually remain unknown unless explicitly exposed.

## Troubleshooting

| Symptom | Check |
|---|---|
| Connection refused at localhost:8080 | Start Burp's listener or explicitly use `--direct` |
| TLS certificate verification failure | Export the CA from the active Burp installation and pass its PEM path |
| Request hangs through Burp | Turn Intercept off; inspect pending requests, DNS and upstream connectivity |
| 403 | Record the restriction; use an authorized captured response if available |
| DNS or operation-not-permitted error | Check local network/sandbox permissions before concluding the target is down |
| Empty design tokens | Styles may be on another host or created by JavaScript; inspect collection coverage |
| HAR has no HTML body | Export with response content; verify the capture includes the desired document |
| Old files remain after a failed run | Use a fresh output directory; success reports and diagnostics can coexist from different runs |

## Repository layout

```text
public_text_extractor/
  harness.py       Collection orchestration, architecture inference, reports
  analyze.py       Technology signatures, asset parsing, design extraction
  extract.py       Text extraction, robots helper, proxy/TLS setup
  README.md        Component entry-point guide
  scripts/         Standalone assessment modules and runner
```

`.gitignore` excludes reports, HAR captures, certificates, keys, environment files, Python caches, and local agent settings. Do not commit credentials or captured session data.

## Verification and next improvements

Publication verification compiled the Python sources; it did not execute active assessments against websites. To repeat syntax checks:

```bash
python3 -m compileall -q public_text_extractor
```

Priority improvements are reproducible fixtures and regression tests, precise evidence locations and version attribution, full HAR resource analysis, per-route scope/robots enforcement, normalization of origin inventories, browser rendering, and independently validated CVE mappings. These are future work, not current capabilities.
