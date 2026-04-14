# Advanced Nuclei Templates — OWASP Top 10 2025 & Beyond

**Author:** achraf-chehboun  
**Templates:** 36 | **Categories:** 18 | **False Positive Rate:** Minimal (v2.0 hardened)

## v2.0 Anti-False-Positive Architecture

Every template in this collection has been hardened against false positives using battle-tested techniques proven in real-world bug bounty scans. The key design principles:

### 1. Canary-Wrapped Payloads (SSTI)
Instead of matching bare numbers like `49` or `71823` that appear naturally in HTML:
```
OLD: /?name={{7*7}}     → matches "49" anywhere on page (FP!)
NEW: /?name=xnlbz{{267*269}}qwfkj → matches "xnlbz71823qwfkj" (globally unique)
```

### 2. Baseline Differential (JWT, Boolean SQLi, NoSQL)
Every test includes a control request to eliminate catch-all routes:
```
Request 1: Invalid token → MUST get 401/403 (proves endpoint validates auth)
Request 2: None-alg token → if 200 + JSON, confirmed bypass
```

### 3. Three-Request Differentials (Boolean SQLi)
```
Request 1: Normal value (id=1)
Request 2: True condition (id=1 AND 1=1)  → must match Request 1
Request 3: False condition (id=1 AND 1=2) → must DIFFER from Request 1
```
Catch-all routes return identical responses for all three → no false positive.

### 4. Content-Type Enforcement (API tests)
All API-targeting templates require `application/json` content-type and reject HTML:
```yaml
dsl:
  - 'contains(content_type, "json") && !contains(body, "<html")'
```

### 5. Structural JSON Matching (Actuator, JWKS)
Instead of `status_code == 200`, require framework-specific JSON fields:
```yaml
dsl:
  - 'contains(body, "propertySources") && contains(body, "spring.datasource")'
```

### 6. Differential Timing (Time-Based SQLi)
```yaml
dsl:
  - 'duration_2 >= 8 && duration_1 < 5 && (duration_2 - duration_1) >= 6'
```
8-second sleep with 6-second minimum differential eliminates slow-server FPs.

---

## Template Categories

### OWASP A01 — Broken Access Control
| Template | Detection |
|---|---|
| `A01-broken-access-control/admin-panel-exposure.yaml` | Common admin paths with auth bypass |
| `A01-broken-access-control/idor-detection.yaml` | Sequential ID enumeration with JSON + differential |
| `A01-broken-access-control/jwt-misconfiguration-detection.yaml` | None-alg with baseline rejection check |

### OWASP A02 — Cryptographic Failures
| Template | Detection |
|---|---|
| `A02-cryptographic-failures/sensitive-data-exposure.yaml` | Exposed API keys, tokens, hashes in responses |

### OWASP A03 — Injection
| Template | Detection |
|---|---|
| `A03-injection/sqli-error-based-detection.yaml` | MySQL/PostgreSQL/MSSQL/Oracle/SQLite error signatures |
| `A03-injection/sqli-time-based-detection.yaml` | 8s sleep + 6s differential (MySQL/PG/MSSQL/Oracle) |
| `A03-injection/sqli-boolean-based-detection.yaml` | 3-request differential (normal/true/false) |
| `A03-injection/sqli-header-cookie-injection.yaml` | SQLi in HTTP headers and cookies |
| `A03-injection/nosql-injection-detection.yaml` | MongoDB $ne/$regex with baseline comparison |
| `A03-injection/ssti-detection.yaml` | Multi-engine canary detection (Jinja2/Twig/FreeMarker/etc.) |

### OWASP A05 — Security Misconfiguration
| Template | Detection |
|---|---|
| `A05-security-misconfiguration/spring-boot-actuator-exposure.yaml` | Actuator endpoints with structural JSON validation |
| `A05-security-misconfiguration/framework-debug-mode-detection.yaml` | Debug modes in 10+ frameworks |
| `A05-security-misconfiguration/cors-misconfiguration.yaml` | Origin reflection + credentials with evil origin verification |

### OWASP A07 — XSS
| Template | Detection |
|---|---|
| `A07-xss-detection/reflected-xss-advanced.yaml` | Context-aware payloads (HTML/JS/attribute) |
| `A07-xss-detection/xss-waf-bypass-polyglot.yaml` | WAF evasion with encoding + obfuscation |
| `A07-xss-detection/dom-xss-detection.yaml` | DOM sink/source pattern detection |

### OWASP A10 — SSRF
| Template | Detection |
|---|---|
| `A10-ssrf/ssrf-detection.yaml` | Cloud metadata (multi-field), OOB interactsh, filter bypass differential |

### Sensitive Data Exposure
| Template | Detection |
|---|---|
| `sensitive-data-exposure/sensitive-files-exposure.yaml` | .env, .git, config, backup files |

### JWT Advanced
| Template | Detection |
|---|---|
| `jwt-advanced/jwt-none-alg-deep.yaml` | All case variants with mandatory baseline rejection |
| `jwt-advanced/jwt-weak-secret-detection.yaml` | Common secrets + JKU/X5U SSRF via interactsh |

### HTTP Request Smuggling
| Template | Detection |
|---|---|
| `http-smuggling/request-smuggling-detection.yaml` | CL.TE, TE.CL, TE.TE patterns |

### Prototype Pollution
| Template | Detection |
|---|---|
| `prototype-pollution/prototype-pollution-detection.yaml` | Server-side Node.js + client-side |

### SSTI Advanced
| Template | Detection |
|---|---|
| `ssti-advanced/ssti-java-engines.yaml` | Thymeleaf/FreeMarker/Velocity/Pebble with canaries |
| `ssti-advanced/ssti-php-twig-blade.yaml` | Twig/Blade/Smarty with canaries |

### OOB XXE
| Template | Detection |
|---|---|
| `xxe-oob/xxe-oob-blind-detection.yaml` | Blind XXE with interactsh DNS/HTTP callbacks |

### Cloud & Identity Misconfigurations
| Template | Detection |
|---|---|
| `cloud-misconfig/cloud-identity-misconfig.yaml` | AWS Cognito, Firebase, OAuth/SAML |

### API BOLA/IDOR
| Template | Detection |
|---|---|
| `api-bola-idor/bola-idor-rest-graphql.yaml` | REST + GraphQL with JSON enforcement + 3-request control |

### PHP & Laravel Critical
| Template | Detection |
|---|---|
| `php-laravel-critical/laravel-critical-exposures.yaml` | Ignition/Telescope/Horizon with content validation |
| `php-laravel-critical/php-object-injection-detection.yaml` | Blind deserialization via interactsh |

### Blind SSRF
| Template | Detection |
|---|---|
| `blind-ssrf/blind-ssrf-interactsh.yaml` | OOB SSRF in headers and parameters |

### Spring Boot Advanced
| Template | Detection |
|---|---|
| `spring-boot-advanced/spring-boot-deep-misconfig.yaml` | /env, /heapdump, /jolokia, Gateway RCE with JSON validation |

### Web Cache Poisoning
| Template | Detection |
|---|---|
| `cache-poisoning/web-cache-poisoning-detection.yaml` | Unkeyed headers (X-Forwarded-Host) |

### GraphQL
| Template | Detection |
|---|---|
| `graphql/graphql-introspection-abuse.yaml` | Introspection enabled + schema extraction |

### High-Impact CVEs (2022-2025)
| Template | Detection |
|---|---|
| `high-impact-cves/spring4shell-variants.yaml` | CVE-2022-22965/22963/22947 with content validation |
| `high-impact-cves/atlassian-critical-cves.yaml` | CVE-2023-22515/22518/22527 with Confluence content checks |
| `high-impact-cves/api-gateway-cves.yaml` | Apache APISIX, Kong, Traefik CVEs |

---

## Usage

```bash
# Run all templates against a single target
nuclei -u https://target.com -t /path/to/nuclei_templates/ -rl 10

# Run specific category
nuclei -u https://target.com -t /path/to/nuclei_templates/A03-injection/

# With interactsh for blind detection (recommended)
nuclei -u https://target.com -t /path/to/nuclei_templates/ -iserver oast.online

# From a target list
nuclei -l targets.txt -t /path/to/nuclei_templates/ -rl 5 -c 3

# Validate templates before scanning
nuclei -t /path/to/nuclei_templates/ -validate
```

## Key Flags

| Flag | Purpose |
|---|---|
| `-rl 10` | Rate limit (requests/second) — be respectful |
| `-c 3` | Concurrency — parallel template execution |
| `-iserver oast.online` | Interactsh server for OOB detection |
| `-severity critical,high` | Filter by severity |
| `-validate` | Check template syntax before running |
| `-debug` | Verbose output for troubleshooting |

## Detection Philosophy

All templates are **detection-only**. No data modification, no file writes, no account creation. Every payload resolves to arithmetic operations, string transformations, or safe read-only probes. Designed for authorized bug bounty and penetration testing.
