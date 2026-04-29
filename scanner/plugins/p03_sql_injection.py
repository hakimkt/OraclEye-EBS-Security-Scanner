"""
Plugin: SQL Injection & Injection Vulnerability Checks
Tests Oracle EBS endpoints for SQL injection, LDAP injection, and OS command injection.
Intrusivity: medium (sends payloads to endpoints)
"""

from scanner.base_plugin import BasePlugin

# Error signatures indicating SQL injection
SQL_ERROR_SIGNATURES = [
    "ORA-", "Oracle error", "oracle.jdbc", "java.sql.SQLException",
    "PLS-", "TNS:", "quoted string not properly terminated",
    "SQL command not properly ended", "missing expression",
    "invalid identifier", "table or view does not exist",
    "ORA-00907", "ORA-00933", "ORA-01756", "ORA-04063",
]

# SQL injection test payloads (safe, detection-only)
SQL_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "1' AND 1=1--",
    "' AND 1=2--",
    "1; SELECT 1 FROM DUAL--",
    "' UNION SELECT NULL FROM DUAL--",
]

# Endpoints that accept user input — common EBS injection points
INJECTABLE_ENDPOINTS = [
    {
        "path": "/OA_HTML/OA.jsp",
        "params": {"page": "/oracle/apps/fnd/sso/login/webui/MainLoginPG", "OAHP": "INJECT"},
        "label": "OAF Main Login Page",
    },
    {
        "path": "/OA_HTML/RF.jsp",
        "params": {"function_id": "INJECT", "resp_id": "1", "resp_appl_id": "1"},
        "label": "RF.jsp Function Router",
    },
    {
        "path": "/forms/frmservlet",
        "params": {"config": "INJECT"},
        "label": "Oracle Forms Servlet",
    },
    {
        "path": "/reports/rwservlet",
        "params": {"report": "INJECT", "userid": "apps/INJECT"},
        "label": "Oracle Reports Servlet",
    },
    {
        "path": "/OA_HTML/BneExcelIntegrator.jsp",
        "params": {"bne:page": "INJECT", "bne:nls_language": "INJECT"},
        "label": "BNE Excel Integrator",
    },
    {
        "path": "/OA_HTML/OAErrorPage.jsp",
        "params": {"type": "INJECT", "Description": "INJECT"},
        "label": "Error Page Params",
    },
]

# XSS payloads for reflected XSS checks
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "'><svg/onload=alert(1)>",
]

XSS_REFLECTED_INDICATORS = [
    "<script>alert(1)</script>",
    'onerror=alert(1)',
    'onload=alert(1)',
    'javascript:alert(1)',
]


class SQLInjectionPlugin(BasePlugin):
    PLUGIN_ID = "sql_injection"
    PLUGIN_NAME = "SQL / XSS Injection Testing"
    PLUGIN_DESC = "Tests EBS input parameters for SQL injection and reflected XSS vulnerabilities."
    CATEGORY = "Injection"
    MIN_INTRUSIVITY = "medium"
    BASE_SEVERITY = "critical"
    CVE_REFS = ["CVE-2012-3152", "CVE-2006-0257"]

    def run(self):
        for endpoint in INJECTABLE_ENDPOINTS:
            self._test_sqli(endpoint)
            self._test_xss(endpoint)
        return self.findings

    def _test_sqli(self, endpoint):
        path = endpoint["path"]
        base_params = endpoint.get("params", {})
        label = endpoint["label"]

        for payload in SQL_PAYLOADS:
            params = {k: (payload if v == "INJECT" else v) for k, v in base_params.items()}
            resp, err = self.probe(path, params=params)
            if err or not resp:
                continue

            body = resp.text
            matched = [sig for sig in SQL_ERROR_SIGNATURES if sig in body]
            if matched:
                self.find(
                    title=f"SQL Injection Evidence: {label}",
                    severity="critical",
                    description=(
                        f"The endpoint {path} returns Oracle database error messages when "
                        f"supplied with SQL injection payload. This indicates unsanitized input "
                        f"reaching the Oracle database layer."
                    ),
                    url=self.target + path,
                    evidence=f"Payload: {repr(payload[:50])} | Oracle errors: {', '.join(matched[:3])}",
                    remediation=(
                        "Use parameterized queries / bind variables throughout EBS custom code. "
                        "Apply input validation on all user-supplied data. "
                        "Review Oracle EBS GSCC standards for secure coding."
                    ),
                    cvss=9.8,
                )
                break  # One finding per endpoint is enough

    def _test_xss(self, endpoint):
        path = endpoint["path"]
        base_params = endpoint.get("params", {})
        label = endpoint["label"]

        for payload in XSS_PAYLOADS:
            params = {k: (payload if v == "INJECT" else v) for k, v in base_params.items()}
            resp, err = self.probe(path, params=params)
            if err or not resp:
                continue

            body = resp.text
            reflected = [i for i in XSS_REFLECTED_INDICATORS if i.lower() in body.lower()]
            if reflected:
                self.find(
                    title=f"Reflected XSS: {label}",
                    severity="high",
                    description=(
                        f"User-supplied input is reflected without proper HTML encoding in {path}. "
                        f"This can allow attackers to steal EBS session cookies or perform actions "
                        f"on behalf of authenticated users."
                    ),
                    url=self.target + path,
                    evidence=f"Payload reflected: {repr(payload[:80])}",
                    remediation=(
                        "Encode all output using Oracle's HTML encoding utilities. "
                        "Implement Content-Security-Policy headers. "
                        "Apply Oracle EBS security patches."
                    ),
                    cvss=7.4,
                )
                break
