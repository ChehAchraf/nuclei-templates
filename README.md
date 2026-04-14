# Advanced Nuclei Detection Templates — OWASP Top 10 + Enterprise Vulnerability Library

> **Author:** Achraf Chehboun  
> **Templates:** 35 YAML files | **Detection-only** — zero destructive payloads  
> **Targets:** Java/Spring Boot, Node.js, PHP/Laravel, SPAs, API Gateways, Cloud Infrastructure

---

## Directory Structure (35 Templates)

```
nuclei_templates/
│
├── A01-broken-access-control/           # OWASP A01
│   ├── admin-panel-exposure.yaml           40+ admin/API docs/DB tool paths
│   ├── idor-detection.yaml                 Sequential ID, GraphQL IDOR, REST resource enum
│   └── jwt-misconfiguration-detection.yaml JWT none-alg, JWKS exposure, token leakage
│
├── A02-cryptographic-failures/          # OWASP A02
│   └── sensitive-data-exposure.yaml        AWS/GCP/GitHub/Stripe keys, bcrypt hashes, missing HSTS
│
├── A03-injection/                       # OWASP A03
│   ├── sqli-error-based-detection.yaml     MySQL/PG/MSSQL/Oracle/SQLite errors (50+ signatures)
│   ├── sqli-time-based-detection.yaml      SLEEP/pg_sleep/WAITFOR with baseline comparison
│   ├── sqli-boolean-based-detection.yaml   True/false differential, arithmetic proof
│   ├── sqli-header-cookie-injection.yaml   UA/Referer/XFF/Cookie/JSON body SQLi
│   ├── nosql-injection-detection.yaml      MongoDB $ne/$gt/$regex/$where operators
│   └── ssti-detection.yaml                 Jinja2/Twig/FreeMarker/Thymeleaf/ERB/Pug/Smarty
│
├── A05-security-misconfiguration/       # OWASP A05
│   ├── spring-boot-actuator-exposure.yaml  24 endpoints, legacy + custom context paths
│   ├── framework-debug-mode-detection.yaml Nuxt/Next/Django/Laravel/Rails/ASP.NET/Flask
│   └── cors-misconfiguration.yaml          Reflected/null origin, subdomain bypass, protocol downgrade
│
├── A07-xss-detection/                   # OWASP A07
│   ├── reflected-xss-advanced.yaml         Canary + multi-context (HTML/attr/JS) injection
│   ├── xss-waf-bypass-polyglot.yaml        Polyglots, uncommon tags, encoding bypass
│   └── dom-xss-detection.yaml              Static source→sink pattern analysis
│
├── A10-ssrf/                            # OWASP A10
│   └── ssrf-detection.yaml                 Cloud metadata, IP encoding bypass, OOB DNS
│
├── sensitive-data-exposure/
│   └── sensitive-files-exposure.yaml       .env/.git/config/SQL dumps/archives (36 paths)
│
│ ─── ADVANCED ENTERPRISE TEMPLATES ─────────────────────────────────────
│
├── jwt-advanced/
│   ├── jwt-none-alg-deep.yaml              6 case variants + stripped-sig + multi-path probing
│   └── jwt-weak-secret-detection.yaml      Pre-signed weak HMAC tokens + JKU/X5U SSRF via interactsh
│
├── http-smuggling/
│   └── request-smuggling-detection.yaml    CL.TE, TE.CL, TE.TE, H2 downgrade (unsafe mode)
│
├── prototype-pollution/
│   └── prototype-pollution-detection.yaml  __proto__/constructor.prototype JSON+query + client patterns
│
├── ssti-advanced/
│   ├── ssti-java-engines.yaml              Thymeleaf SpEL, FreeMarker, Velocity, Pebble
│   └── ssti-php-twig-blade.yaml            Twig filters, Blade directives, Smarty conditionals
│
├── xxe-oob/
│   └── xxe-oob-blind-detection.yaml        Standard/parameter entity/SOAP/SVG/XInclude via interactsh
│
├── cloud-misconfig/
│   └── cloud-identity-misconfig.yaml       AWS Cognito pools, Firebase rules, OAuth state, SAML metadata
│
├── api-bola-idor/
│   └── bola-idor-rest-graphql.yaml         REST sequential ID + GraphQL node IDOR + method override
│
├── php-laravel-critical/
│   ├── laravel-critical-exposures.yaml     Ignition/Telescope/Horizon/Log Viewer + CVE-2021-3129
│   └── php-object-injection-detection.yaml Blind unserialize via interactsh + type confusion
│
├── blind-ssrf/
│   └── blind-ssrf-interactsh.yaml          Headers/params/webhooks/PDF render/URL unfurl via OOB
│
├── spring-boot-advanced/
│   └── spring-boot-deep-misconfig.yaml     /env secrets, /heapdump, Jolokia, Gateway RCE, CVE-2022-22963
│
├── cache-poisoning/
│   └── web-cache-poisoning-detection.yaml  X-Forwarded-Host, scheme override, fat GET, cache key norm
│
├── graphql/
│   └── graphql-introspection-abuse.yaml    Full introspection, alternate endpoints, batch queries, IDEs
│
└── high-impact-cves/
    ├── spring4shell-variants.yaml          CVE-2022-22965/22963/22947 + WebFlux traversal
    ├── atlassian-critical-cves.yaml        CVE-2023-22515/22518/22527 Confluence + Jira fingerprinting
    └── api-gateway-cves.yaml              APISIX/Kong/Traefik/HAProxy/Envoy admin + CVE-2022-24112
```

## Quick Start

```bash
# Install nuclei (v3.0+)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Run everything (with interactsh for OOB detection)
nuclei -t ./nuclei_templates/ -u https://target.com -interactsh-server oast.pro

# Run specific attack surface
nuclei -t ./nuclei_templates/jwt-advanced/ -u https://target.com
nuclei -t ./nuclei_templates/high-impact-cves/ -u https://target.com
nuclei -t ./nuclei_templates/php-laravel-critical/ -u https://target.com

# Run all blind/OOB templates (require interactsh)
nuclei -t ./nuclei_templates/xxe-oob/,./nuclei_templates/blind-ssrf/,./nuclei_templates/php-laravel-critical/php-object-injection-detection.yaml -u https://target.com

# HTTP request smuggling (requires -unsafe flag)
nuclei -t ./nuclei_templates/http-smuggling/ -u https://target.com -unsafe

# Output as JSON with verbose
nuclei -t ./nuclei_templates/ -u https://target.com -json -o results.json -v

# Through Burp Suite proxy
nuclei -t ./nuclei_templates/ -u https://target.com -proxy http://127.0.0.1:8080

# Bulk scan from target list
nuclei -t ./nuclei_templates/ -l targets.txt -rl 100 -c 25
```

## Template Reference

### OWASP Core Templates (18)

| Category | Template | Key Technique | Severity |
|----------|----------|---------------|----------|
| A01 | `admin-panel-exposure` | 40+ forced browsing paths | High |
| A01 | `idor-detection` | Sequential ID + GraphQL IDOR | High |
| A01 | `jwt-misconfiguration-detection` | None-alg, JWKS, token leak | High |
| A02 | `sensitive-data-exposure` | API key regex, bcrypt/argon2, conn strings | High |
| A03 | `sqli-error-based-detection` | 50+ error sigs across 5 DB engines | Critical |
| A03 | `sqli-time-based-detection` | SLEEP/pg_sleep/WAITFOR + baseline | Critical |
| A03 | `sqli-boolean-based-detection` | True/false diff, arithmetic proof | Critical |
| A03 | `sqli-header-cookie-injection` | UA/Referer/XFF/Cookie/JSON body | High |
| A03 | `nosql-injection-detection` | MongoDB operators, $where JS injection | High |
| A03 | `ssti-detection` | 9 template engines, math-only probes | Critical |
| A05 | `spring-boot-actuator-exposure` | 24 paths, v1.x + v2.x + custom | High |
| A05 | `framework-debug-mode-detection` | 7 frameworks, version extraction | Medium |
| A05 | `cors-misconfiguration` | 6 bypass techniques + preflight | High |
| A07 | `reflected-xss-advanced` | Canary → context-aware → WAF bypass | High |
| A07 | `xss-waf-bypass-polyglot` | Polyglots, encoding, uncommon tags | High |
| A07 | `dom-xss-detection` | Static source→sink regex analysis | Medium |
| A10 | `ssrf-detection` | Cloud metadata, IP encoding, OOB | Critical |
| — | `sensitive-files-exposure` | .env/.git/config/SQL dumps (36 paths) | High |

### Advanced Enterprise Templates (17)

| Category | Template | Key Technique | Severity |
|----------|----------|---------------|----------|
| JWT | `jwt-none-alg-deep` | 6 case variants + multi-API-path | Critical |
| JWT | `jwt-weak-secret-detection` | Pre-signed tokens + JKU/X5U SSRF (OOB) | Critical |
| Smuggling | `request-smuggling-detection` | CL.TE/TE.CL/TE.TE/H2 (unsafe) | Critical |
| Proto Pollution | `prototype-pollution-detection` | __proto__/constructor JSON+query+DOM | High |
| SSTI | `ssti-java-engines` | Thymeleaf SpEL/FreeMarker/Velocity/Pebble | Critical |
| SSTI | `ssti-php-twig-blade` | Twig filters/Blade directives/Smarty | Critical |
| XXE | `xxe-oob-blind-detection` | 8 vectors: entity/SOAP/SVG/XInclude (OOB) | Critical |
| Cloud | `cloud-identity-misconfig` | Cognito/Firebase/OAuth/SAML | High |
| API | `bola-idor-rest-graphql` | REST enum + GraphQL node + method override | High |
| PHP | `laravel-critical-exposures` | Ignition/Telescope/Horizon + CVE-2021-3129 | Critical |
| PHP | `php-object-injection-detection` | Blind unserialize + type confusion (OOB) | Critical |
| SSRF | `blind-ssrf-interactsh` | 12 vectors: headers/webhooks/render (OOB) | High |
| Spring | `spring-boot-deep-misconfig` | /env secrets/heapdump/Jolokia/Gateway RCE | Critical |
| Cache | `web-cache-poisoning-detection` | XFH/scheme/fat GET/path param | High |
| GraphQL | `graphql-introspection-abuse` | Full schema dump + batch + alt endpoints | Medium |
| CVEs | `spring4shell-variants` | CVE-2022-22965/22963/22947 | Critical |
| CVEs | `atlassian-critical-cves` | CVE-2023-22515/22518/22527 | Critical |
| CVEs | `api-gateway-cves` | APISIX/Kong/Traefik/HAProxy/Envoy | Critical |

## Detection Philosophy

**SQL Injection** — All payloads are read-only. No INSERT/UPDATE/DELETE/DROP/ALTER. Error-based triggers parser errors via quote imbalance. Time-based uses native sleep functions. Boolean-based compares true/false condition response differentials.

**XSS** — Layered approach: canary reflection confirmation, then context-aware probing (HTML body, attribute breakout, JS context, URL context), then WAF evasion (case mixing, whitespace insertion, encoding tricks, uncommon HTML5 tags).

**OOB/Blind Detection** — Templates using interactsh (XXE, SSRF, PHP deserialization, JWT JKU/X5U) require Nuclei's built-in OOB server. Run with `-interactsh-server` for custom servers.

**HTTP Smuggling** — Requires the `-unsafe` flag. Uses timing differentials and response splitting to detect CL.TE/TE.CL/TE.TE desync without hijacking other users' requests.

**CVE Detection** — All CVE templates detect vulnerability surface (accessible endpoints, version fingerprinting, error responses) without executing actual exploitation payloads.

## Flags Reference

| Flag | When Required |
|------|--------------|
| `-unsafe` | HTTP request smuggling templates |
| `-interactsh-server` | XXE OOB, blind SSRF, PHP deserialization, JWT JKU/X5U |
| `-proxy` | Route through Burp Suite for manual verification |
| `-json -o results.json` | Structured output for report generation |
| `-rl 100 -c 25` | Rate limit + concurrency for bulk scans |

## Validation

```bash
nuclei -validate -t ./nuclei_templates/
```
