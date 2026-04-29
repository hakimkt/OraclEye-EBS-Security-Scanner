"""
Plugin: Oracle Reports & Forms Vulnerabilities
CVE-2012-3152 (Oracle Reports Server RCE) and Forms servlet checks.
Intrusivity: low
"""

from scanner.base_plugin import BasePlugin

REPORTS_PATHS = [
    "/reports/rwservlet",
    "/reports/rwservlet?report=",
    "/reports/rwservlet/getserverinfo",
    "/reports/rwservlet/showjobs",
    "/reports/rwservlet/killjob?job=1",
    "/reports/rwservlet/showenv",
    "/reports/rwservlet?server=rep_server&report=test.rdf&destype=cache&desformat=html",
]

FORMS_PATHS = [
    "/forms/frmservlet",
    "/forms/frmservlet?config=",
    "/forms/frmservlet?ifcmd=getinfo",
    "/forms/lservlet",
    "/forms/java/oracle/forms/engine/Main.class",
]

DISCOVERER_PATHS = [
    "/discoverer/viewer",
    "/discoverer/plus",
    "/discoverer/portlet",
    "/discoverer/viewer?nlsLanguage=&eul=",
    "/discoverer/viewer?cn=Worksheet&handlerType=xml",
]

REPORTS_ERROR_INDICATORS = [
    "REP-", "Oracle Reports", "rwservlet", "Oracle9iAS Reports",
    "getserverinfo", "showjobs", "killjob", "showenv",
    "Reports Server", "Oracle Report",
]

FORMS_INDICATORS = [
    "Oracle Forms", "frmservlet", "Oracle Application Server Forms",
    "OracleJSP", "oracle.forms",
]


class OracleReportsPlugin(BasePlugin):
    PLUGIN_ID = "oracle_reports_forms"
    PLUGIN_NAME = "Oracle Reports & Forms Vulnerabilities"
    PLUGIN_DESC = "Tests for CVE-2012-3152 (Reports RCE), Forms servlet exposure, and Discoverer vulnerabilities."
    CATEGORY = "Legacy Components"
    MIN_INTRUSIVITY = "low"
    BASE_SEVERITY = "high"
    CVE_REFS = ["CVE-2012-3152", "CVE-2012-3153"]

    def run(self):
        self._check_reports()
        self._check_forms()
        self._check_discoverer()
        self._check_concurrent_manager()
        return self.findings

    def _check_reports(self):
        for path in REPORTS_PATHS:
            resp, err = self.probe(path)
            if err or not resp:
                continue
            if resp.status_code in (200, 302, 301):
                body = resp.text
                matched = [i for i in REPORTS_ERROR_INDICATORS if i.lower() in body.lower()]
                severity = "critical" if any(x in path for x in ["showenv", "getserverinfo", "showjobs"]) else "high"
                if matched or resp.status_code == 200:
                    self.find(
                        title=f"Oracle Reports Server Exposed: {path.split('?')[0]}",
                        severity=severity,
                        description=(
                            "CVE-2012-3152: Oracle Reports rwservlet is accessible. "
                            "This can allow unauthenticated remote code execution by supplying "
                            "a malicious report URL via the 'report' parameter."
                        ) if "rwservlet" in path else (
                            f"Oracle Reports endpoint accessible at {path}"
                        ),
                        url=self.target + path,
                        evidence=f"HTTP {resp.status_code}" + (f" | Indicators: {', '.join(matched[:3])}" if matched else ""),
                        remediation=(
                            "Apply Oracle CPU patches from July 2012 or later. "
                            "Restrict /reports/ via Apache ACL. "
                            "Disable showenv, showjobs, getserverinfo in rwservlet.properties."
                        ),
                        cve="CVE-2012-3152",
                        cvss=9.0,
                    )

    def _check_forms(self):
        for path in FORMS_PATHS:
            resp, err = self.probe(path)
            if err or not resp:
                continue
            if resp.status_code in (200, 302, 301):
                body = resp.text
                matched = [i for i in FORMS_INDICATORS if i.lower() in body.lower()]
                if matched or resp.status_code == 200:
                    self.find(
                        title=f"Oracle Forms Servlet Exposed: {path.split('?')[0]}",
                        severity="medium",
                        description=(
                            "Oracle Forms servlet is accessible from the internet. "
                            "Exposed Forms servlets may reveal application structure and are "
                            "attack vectors for session hijacking and parameter tampering."
                        ),
                        url=self.target + path,
                        evidence=f"HTTP {resp.status_code}" + (f" | Indicators: {', '.join(matched[:3])}" if matched else ""),
                        remediation=(
                            "Restrict /forms/ to internal networks via Apache/OHS ACLs. "
                            "Apply Oracle Forms patches. Consider migrating to OAF/ADF."
                        ),
                    )

    def _check_discoverer(self):
        for path in DISCOVERER_PATHS:
            resp, err = self.probe(path)
            if err or not resp:
                continue
            if resp.status_code in (200, 302, 301):
                self.find(
                    title=f"Oracle Discoverer Exposed: {path.split('?')[0]}",
                    severity="medium",
                    description=(
                        "Oracle Discoverer is accessible externally. Discoverer can expose sensitive "
                        "business intelligence data and is no longer supported by Oracle."
                    ),
                    url=self.target + path,
                    evidence=f"HTTP {resp.status_code}",
                    remediation=(
                        "Restrict /discoverer/ to internal networks. "
                        "Consider migrating to Oracle OBIEE or OAC. "
                        "Oracle Discoverer reached end-of-life in 2014."
                    ),
                )

    def _check_concurrent_manager(self):
        paths = [
            "/OA_HTML/OAConcurrent.jsp",
            "/OA_HTML/OA.jsp?page=/oracle/apps/fnd/cp/gsf/webui/ProgramLOVPG",
        ]
        for path in paths:
            resp, err = self.probe(path)
            if err or not resp:
                continue
            if resp.status_code == 200:
                self.find(
                    title="Concurrent Manager Interface Reachable",
                    severity="medium",
                    description=(
                        "The Oracle Concurrent Manager web interface is accessible. "
                        "Unauthenticated or weakly authenticated access could allow manipulation "
                        "of scheduled jobs and concurrent programs."
                    ),
                    url=self.target + path,
                    evidence=f"HTTP {resp.status_code}",
                    remediation="Ensure Concurrent Manager UI requires valid EBS session. Apply role-based access controls.",
                )
