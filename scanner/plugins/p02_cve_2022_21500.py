"""
Plugin: CVE-2022-21500 - Oracle EBS Unauthenticated Data Exposure
Checks for the critical vulnerability allowing unauthenticated access to sensitive data.
Intrusivity: passive
"""

from scanner.base_plugin import BasePlugin

# Affected endpoints from CVE-2022-21500 and related EBS information disclosure issues
UNAUTHENTICATED_CHECKS = [
    {
        "path": "/OA_HTML/BneExcelIntegrator.jsp",
        "method": "GET",
        "indicators": ["BneExcelIntegrator", "oracle.apps", "spreadsheet"],
        "title": "CVE-2022-21500: BNE Excel Integrator Unauthenticated Access",
        "severity": "critical",
        "description": (
            "CVE-2022-21500 allows unauthenticated attackers to access the BNE Excel Integrator, "
            "potentially exposing sensitive EBS data without any credentials."
        ),
        "remediation": "Apply Oracle Critical Patch Update April 2022 or later. Restrict /OA_HTML/BneExcelIntegrator.jsp.",
        "cvss": 9.8,
        "cve": "CVE-2022-21500",
    },
    {
        "path": "/OA_HTML/OACollaboration.jsp",
        "method": "GET",
        "indicators": ["Collaboration", "oracle.apps.fnd"],
        "title": "EBS Collaboration Module Unauthenticated Access",
        "severity": "high",
        "description": "The OACollaboration JSP is accessible without authentication, potentially exposing collaboration data.",
        "remediation": "Restrict access to authenticated sessions only via Apache/OHS configuration.",
        "cvss": 7.5,
        "cve": "",
    },
    {
        "path": "/OA_HTML/OAErrorPage.jsp",
        "method": "GET",
        "indicators": ["oracle.apps", "FND", "stack", "exception", "OracleJSP", "javax.servlet"],
        "title": "EBS Error Page Stack Trace Disclosure",
        "severity": "medium",
        "description": "The OAF error page may expose internal stack traces, package names, and application paths to unauthenticated users.",
        "remediation": "Configure CustomErrorPage in Apache/OHS to redirect generic errors. Disable detailed error output.",
        "cvss": 5.3,
        "cve": "",
    },
    {
        "path": "/OA_HTML/RF.jsp?function_id=1016060&resp_id=-1&resp_appl_id=-1&security_group_id=0&lang_code=US&oas=fBd4WMsOMGoFxn2Hm9FBKA..&params=E0LlElFtB2AdMGGmNPDqDg..",
        "method": "GET",
        "indicators": ["oracle", "ebs", "function", "response"],
        "title": "EBS RF.jsp with Crafted Parameters — Potential Auth Bypass",
        "severity": "high",
        "description": "RF.jsp with pre-crafted function parameters may allow access to internal EBS functions without proper session validation.",
        "remediation": "Apply latest Oracle EBS patches. Ensure RF.jsp validates session tokens server-side.",
        "cvss": 8.1,
        "cve": "CVE-2022-21500",
    },
]

# Header/server banner checks
BANNER_CHECKS = [
    ("Server", ["Oracle", "OracleAS", "Oracle-Application-Server", "Oracle HTTP Server"]),
    ("X-Powered-By", ["JSP", "Oracle", "Servlet"]),
    ("X-Oracle-Dms-Rid", None),
    ("Oracle-Atg-Remote-Ip", None),
    ("Osvc-Crest-Version", None),
]


class CVE202221500Plugin(BasePlugin):
    PLUGIN_ID = "cve_2022_21500"
    PLUGIN_NAME = "CVE-2022-21500 / Unauthenticated Data Exposure"
    PLUGIN_DESC = "Tests for CVE-2022-21500 and related unauthenticated EBS data disclosure vulnerabilities."
    CATEGORY = "Authentication"
    MIN_INTRUSIVITY = "passive"
    BASE_SEVERITY = "critical"
    CVE_REFS = ["CVE-2022-21500"]

    def run(self):
        # Check server banners
        root, err = self.probe("/")
        if root and not err:
            self._check_banners(root)

        # Run endpoint checks
        for check in UNAUTHENTICATED_CHECKS:
            resp, err = self.probe(check["path"], method=check["method"])
            if err or not resp:
                continue
            body = resp.text.lower()
            indicators_hit = [i for i in check["indicators"] if i.lower() in body]
            if resp.status_code == 200 and indicators_hit:
                self.find(
                    title=check["title"],
                    severity=check["severity"],
                    description=check["description"],
                    url=self.target + check["path"],
                    evidence=f"HTTP 200 — Matched indicators: {', '.join(indicators_hit[:3])}",
                    remediation=check["remediation"],
                    cve=check.get("cve", ""),
                    cvss=check.get("cvss", 0.0),
                )
            elif resp.status_code in (302, 301):
                loc = resp.headers.get("Location", "")
                # Check if redirect goes to login (expected) vs internal page (bad)
                if "AppsLocalLogin" not in loc and "login" not in loc.lower():
                    self.find(
                        title=f"Suspicious redirect from {check['path']}",
                        severity="medium",
                        description=f"Endpoint redirects to unexpected location: {loc}",
                        url=self.target + check["path"],
                        evidence=f"HTTP {resp.status_code} → Location: {loc}",
                        remediation="Verify redirect logic enforces authentication before redirecting to internal pages.",
                    )

        return self.findings

    def _check_banners(self, resp):
        headers = resp.headers
        for header, patterns in BANNER_CHECKS:
            val = headers.get(header, "")
            if not val:
                continue
            if patterns is None:
                self.find(
                    title=f"Oracle-Specific Header Exposed: {header}",
                    severity="low",
                    description=f"The response header '{header}: {val}' reveals Oracle EBS technology fingerprint.",
                    url=self.target + "/",
                    evidence=f"{header}: {val}",
                    remediation="Strip Oracle-specific headers in Apache/OHS configuration using Header unset directives.",
                )
            else:
                for pattern in patterns:
                    if pattern.lower() in val.lower():
                        self.find(
                            title=f"Technology Disclosure via {header} Header",
                            severity="low",
                            description=f"Server reveals technology stack via {header} header: {val}",
                            url=self.target + "/",
                            evidence=f"{header}: {val}",
                            remediation="Remove or obfuscate server banner headers.",
                        )
                        break
