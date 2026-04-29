"""
Plugin: EBS Endpoint Enumeration
Checks for exposed Oracle EBS endpoints, admin panels, and sensitive paths.
Intrusivity: passive (read-only probing)
"""

from scanner.base_plugin import BasePlugin

ENDPOINTS = [
    ("/OA_HTML/AppsLocalLogin.jsp",        "EBS Local Login Page",         "info",   "Login page exposed"),
    ("/OA_HTML/OALogout.jsp",              "EBS Logout Endpoint",          "info",   "Logout endpoint reachable"),
    ("/OA_HTML/OA.jsp",                    "Self-Service Framework (OAF)",  "info",   "OAF entry point exposed"),
    ("/OA_HTML/RF.jsp",                    "SSO Redirect Framework",        "medium", "SSO redirect page exposed — potential open redirect"),
    ("/OA_HTML/BneExcelIntegrator.jsp",    "BNE Excel Integrator",          "high",   "Excel integrator exposed — CVE-2022-21500 class"),
    ("/OA_HTML/OAErrorPage.jsp",           "OAF Error Page",                "low",    "Error page reveals stack traces"),
    ("/OA_HTML/cabo/jsLibs/",             "Client-Side JS Library Dir",    "medium", "Directory listing of JS libraries"),
    ("/forms/frmservlet",                  "Oracle Forms Servlet",          "medium", "Oracle Forms servlet exposed"),
    ("/reports/rwservlet",                 "Oracle Reports Servlet",        "high",   "Oracle Reports servlet — known RCE vectors (CVE-2012-3152)"),
    ("/discoverer/viewer",                 "Oracle Discoverer Viewer",      "medium", "Discoverer viewer exposed"),
    ("/discoverer/plus",                   "Oracle Discoverer Plus",        "medium", "Discoverer Plus exposed"),
    ("/webservices/",                      "EBS Web Services Root",         "medium", "Web services root reachable"),
    ("/OA_HTML/XMLGateway",               "XML Gateway",                   "high",   "XML Gateway exposed — unauthenticated XML injection risk"),
    ("/OA_HTML/IrcVisitor.jsp",           "iRecruitment Visitor Page",     "low",    "iRecruitment module exposed"),
    ("/OA_HTML/OAErrorPage.jsp?type=Error","Error diagnostic page",        "low",    "Error diagnostic endpoint accessible"),
    ("/OA_HTML/cabo/images/",            "Static image directory",         "info",   "Static asset directory browsable"),
    ("/OA_HTML/OAButton.gif",            "EBS Static Asset",               "info",   "Confirms OA_HTML path is accessible"),
    ("/OA_HTML/fnd/adfAuthentication",   "ADF Authentication Endpoint",    "medium", "ADF auth endpoint exposed"),
    ("/OA_HTML/adfAuthentication",       "ADF Auth (alt path)",            "medium", "Alternative ADF auth path found"),
    ("/OA_HTML/OABrowse.jsp",           "OABrowse JSP",                   "medium", "Browse JSP accessible — potential data exposure"),
    ("/oa_servlets/AppsServlet",         "AppsServlet",                    "medium", "Core apps servlet reachable"),
    ("/oa_servlets/oracle.apps.fnd.sso.AppsLoginRedirect", "SSO Redirect Servlet", "medium", "SSO redirect servlet exposed"),
]

SENSITIVE_ADMIN = [
    ("/OA_HTML/OADiagnostic.jsp",        "Diagnostic Framework",          "high",   "Diagnostic JSP accessible — may expose system info"),
    ("/OA_HTML/rf.jsp?function_id=1016060","Admin Function Link",         "high",   "Admin function reachable without auth check"),
    ("/OA_HTML/OALogout.jsp?page=/OA_HTML/AppsLocalLogin.jsp", "Logout chaining", "low", "Logout chaining path present"),
]


class EBSEndpointEnumPlugin(BasePlugin):
    PLUGIN_ID = "ebs_endpoint_enum"
    PLUGIN_NAME = "EBS Endpoint Enumeration"
    PLUGIN_DESC = "Enumerates known Oracle EBS URLs and checks for exposed admin/sensitive endpoints."
    CATEGORY = "Discovery"
    MIN_INTRUSIVITY = "passive"
    BASE_SEVERITY = "info"
    CVE_REFS = ["CVE-2022-21500", "CVE-2012-3152"]

    def run(self):
        paths = ENDPOINTS + SENSITIVE_ADMIN
        for path, label, severity, desc in paths:
            resp, err = self.probe(path)
            if err:
                continue
            if resp.status_code in (200, 302, 301, 403):
                actual_sev = severity
                # Elevate if truly open (200)
                if resp.status_code == 200 and severity == "low":
                    actual_sev = "medium"
                evidence = f"HTTP {resp.status_code} — Content-Length: {len(resp.content)} bytes"
                self.find(
                    title=f"Exposed: {label}",
                    severity=actual_sev,
                    description=desc,
                    url=self.target + path,
                    evidence=evidence,
                    remediation="Restrict access via web server ACLs or firewall rules. Apply Oracle EBS patching guidelines.",
                )
        return self.findings
