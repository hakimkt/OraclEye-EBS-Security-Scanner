# OraclEye — Oracle EBS Security Scanner

A professional-grade web-based security scanner for Oracle E-Business Suite (EBS) implementations.

## Features

- **8 built-in check modules** covering the major Oracle EBS attack surface
- **4 intrusivity levels**: Passive → Low → Medium → Aggressive
- **Live streaming results** via Server-Sent Events
- **Risk scoring** with CVSS-based severity ratings
- **Export** to JSON and HTML reports
- **Easy to extend** — drop a new Python file into `scanner/plugins/`

## Quick Start

<img width="1423" height="928" alt="image" src="https://github.com/user-attachments/assets/351bd442-ee9d-4c94-a4a1-910d967ff74d" />


```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

## Built-in Modules

| ID | Module | Intrusivity | Coverage |
|----|--------|-------------|----------|
| `ebs_endpoint_enum` | EBS Endpoint Enumeration | Passive | 20+ known EBS paths |
| `cve_2022_21500` | CVE-2022-21500 / Unauthenticated Access | Passive | BNE Excel, RF.jsp, banners |
| `tls_config` | TLS/SSL Configuration | Passive | Cert validity, weak protocols |
| `auth_session` | Auth & Session Security | Low | Headers, cookies, CSRF, login |
| `oracle_reports_forms` | Oracle Reports & Forms | Low | CVE-2012-3152, Discoverer |
| `sql_injection` | SQL / XSS Injection | Medium | SQL errors, reflected XSS |
| `ssrf_traversal` | SSRF, Path Traversal | Medium | File disclosure, open redirect |
| `aggressive_deep_scan` | Default Creds & Deep Enum | Aggressive | Default passwords, port scan |

### Severity Levels
`critical` · `high` · `medium` · `low` · `info`

## Architecture

```
oracle_ebs_scanner/
├── app.py                    # Flask application + API routes
├── scanner/
│   ├── engine.py             # Orchestrates plugin execution
│   ├── registry.py           # Auto-discovers and loads plugins
│   ├── http_client.py        # Shared requests session
│   ├── base_plugin.py        # Base class all plugins inherit
│   └── plugins/
│       ├── p01_endpoint_enum.py
│       ├── p02_cve_2022_21500.py
│       ├── p03_sql_injection.py
│       ├── p04_auth_session.py
│       ├── p05_reports_forms.py
│       ├── p06_ssrf_traversal.py
│       ├── p07_aggressive.py
│       └── p08_tls_config.py
├── templates/
│   └── index.html            # Full single-page UI
└── requirements.txt
```

## CVE Coverage

| CVE | Description |
|-----|-------------|
| CVE-2022-21500 | Oracle EBS unauthenticated data exposure via BNE Excel Integrator |
| CVE-2012-3152 | Oracle Reports Server RCE via rwservlet |
| CVE-2012-3153 | Oracle Reports showenv information disclosure |
| CVE-2019-2725 | Oracle WebLogic WSAT deserialization RCE |
| CVE-2014-3566 | POODLE — SSLv3/TLSv1.0 weakness |
| CVE-2017-10268 | Oracle DB information disclosure |

---
**⚠ AUTHORIZED USE ONLY** — Only use against systems you own or have explicit written permission to test.
