"""
Plugin: Aggressive - Default Credential Testing & Deep Enumeration
Tests actual login with known default credentials.
WARNING: Only runs at aggressive intrusivity level — may trigger account lockouts.
Intrusivity: aggressive
"""

from scanner.base_plugin import BasePlugin
import re

DEFAULT_CREDS = [
    ("SYSADMIN",  "sysadmin",  "EBS System Administrator default"),
    ("SYSADMIN",  "SYSADMIN",  "EBS System Administrator uppercase"),
    ("GUEST",     "oracle",    "EBS Guest user default"),
    ("GUEST",     "GUEST",     "EBS Guest uppercase"),
    ("APPSMGR",   "appsmgr",   "Application Manager default"),
    ("OPERATIONS","welcome1",  "Oracle default welcome password"),
    ("OPERATIONS","Welcome1",  "Oracle welcome password variant"),
    ("SYSADMIN",  "welcome",   "Oracle welcome default"),
]

BRUTE_FORCE_ENDPOINTS = [
    "/OA_HTML/AppsLocalLogin.jsp",
]

ADMIN_FUNCTION_PATHS = [
    "/OA_HTML/OA.jsp?page=/oracle/apps/fnd/sysadmin/webui/SysAdminMenuPG",
    "/OA_HTML/OA.jsp?page=/oracle/apps/fnd/sysadmin/webui/UserMaintPG",
    "/OA_HTML/OA.jsp?page=/oracle/apps/fnd/security/webui/FndUserPG",
    "/OA_HTML/OA.jsp?page=/oracle/apps/fnd/setup/webui/SetupMenuPG",
    "/OA_HTML/OA.jsp?page=/oracle/apps/fnd/function/webui/FunctionPG",
    "/OA_HTML/rf.jsp?function_id=1016060",
    "/OA_HTML/rf.jsp?function_id=1019415",
]

DB_PORTS = [1521, 1522, 1526, 2483, 2484]
MGMT_PORTS = [7001, 7002, 4848, 8080, 9200, 8443, 1156, 6003]


class AggressiveDeepScanPlugin(BasePlugin):
    PLUGIN_ID = "aggressive_deep_scan"
    PLUGIN_NAME = "Default Credentials & Deep Enumeration"
    PLUGIN_DESC = "Tests default EBS credentials and enumerates admin functions. WARNING: May trigger account lockout."
    CATEGORY = "Authentication"
    MIN_INTRUSIVITY = "aggressive"
    BASE_SEVERITY = "critical"
    CVE_REFS = []

    def run(self):
        self._check_default_creds()
        self._check_admin_functions()
        self._check_port_exposure()
        self._check_weblogic()
        return self.findings

    def _check_default_creds(self):
        # First, identify the login form action and fields
        resp, err = self.probe("/OA_HTML/AppsLocalLogin.jsp")
        if err or not resp:
            return

        body = resp.text
        # Find form action
        action_match = re.search(r'action=["\']([^"\']+)["\']', body)
        if not action_match:
            return

        action = action_match.group(1)
        if not action.startswith("http"):
            action = "/OA_HTML/" + action.lstrip("/")

        # Find username/password field names
        user_field = "usernameField"
        pass_field = "passwordField"
        for name_pattern in [r'name=["\'](\w*[Uu]ser\w*)["\']', r'name=["\'](\w*[Ll]ogin\w*)["\']']:
            m = re.search(name_pattern, body)
            if m:
                user_field = m.group(1)
                break
        for name_pattern in [r'name=["\'](\w*[Pp]ass\w*)["\']', r'name=["\'](\w*[Pp]wd\w*)["\']']:
            m = re.search(name_pattern, body)
            if m:
                pass_field = m.group(1)
                break

        # Try only first 3 credentials to avoid lockout
        for username, password, note in DEFAULT_CREDS[:3]:
            try:
                r = self.http.post(
                    action,
                    data={user_field: username, pass_field: password, "submit": "Login"},
                    allow_redirects=True,
                )
                # Detect successful login
                body_r = r.text.lower()
                is_logged_in = any([
                    "logout" in body_r,
                    "welcome" in body_r and username.lower() in body_r,
                    "home" in body_r and "oracle" in body_r,
                    r.url and "OALogout" in r.url,
                    "dashboard" in body_r,
                ])
                is_fail = any([
                    "invalid" in body_r,
                    "incorrect" in body_r,
                    "failed" in body_r,
                    "error" in body_r,
                    "try again" in body_r,
                ])
                if is_logged_in and not is_fail:
                    self.find(
                        title=f"Default Credentials Work: {username}/{password}",
                        severity="critical",
                        description=(
                            f"The default Oracle EBS credential {username}/{password} ({note}) "
                            f"successfully authenticated. This allows full EBS access with default privileges."
                        ),
                        url=self.target + "/OA_HTML/AppsLocalLogin.jsp",
                        evidence=f"POST to {action} with {username}/{password} → HTTP {r.status_code}, login indicators detected",
                        remediation=(
                            "Immediately change all default Oracle EBS passwords. "
                            "Run Oracle EBS Security Assessment Tool. "
                            "Enforce strong password policy via FND_USER_RESP."
                        ),
                        cvss=10.0,
                    )
            except Exception:
                pass

    def _check_admin_functions(self):
        for path in ADMIN_FUNCTION_PATHS:
            resp, err = self.probe(path)
            if err or not resp:
                continue
            if resp.status_code == 200:
                body = resp.text.lower()
                if any(x in body for x in ["sysadmin", "user maintenance", "setup", "function", "responsibility"]):
                    self.find(
                        title=f"Admin Function Accessible Without Auth: {path.split('?')[0]}",
                        severity="critical",
                        description=(
                            f"An Oracle EBS administrative function at {path} is accessible without proper authentication. "
                            f"This could allow privilege escalation or unauthorized system configuration."
                        ),
                        url=self.target + path,
                        evidence=f"HTTP 200 with admin content indicators",
                        remediation="Ensure all EBS admin functions require valid authenticated sessions with appropriate responsibilities.",
                        cvss=9.8,
                    )

    def _check_port_exposure(self):
        import socket
        host = self.target.split("://")[-1].split("/")[0].split(":")[0]

        for port in DB_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, port))
                s.close()
                if result == 0:
                    self.find(
                        title=f"Oracle Database Port Exposed: {port}",
                        severity="critical",
                        description=(
                            f"Port {port} (Oracle TNS Listener / DB) is accessible from the network. "
                            f"Exposed database listeners are direct attack surfaces for authentication bypass, "
                            f"TNS poison attacks, and SID enumeration."
                        ),
                        url=f"{host}:{port}",
                        evidence=f"TCP connect to {host}:{port} successful",
                        remediation="Restrict Oracle DB ports to application servers only. Never expose DB ports to internet.",
                        cvss=9.8,
                    )
            except Exception:
                pass

        for port in MGMT_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, port))
                s.close()
                if result == 0:
                    self.find(
                        title=f"Management Port Exposed: {port}",
                        severity="high",
                        description=(
                            f"Port {port} is accessible. This may be WebLogic Admin Console (7001/7002), "
                            f"GlassFish (4848), or another management interface."
                        ),
                        url=f"{host}:{port}",
                        evidence=f"TCP connect to {host}:{port} successful",
                        remediation="Firewall management ports to internal networks only.",
                    )
            except Exception:
                pass

    def _check_weblogic(self):
        wl_paths = [
            ("/:7001/console", "WebLogic Admin Console HTTP"),
            ("/:7002/console", "WebLogic Admin Console HTTPS"),
            ("/:7001/wls-wsat/CoordinatorPortType", "CVE-2019-2725 WebLogic WSAT"),
            ("/:7001/bea_wls_internal/", "WebLogic internal endpoint"),
        ]
        host = self.target.split("://")[-1].split("/")[0].split(":")[0]
        scheme = "https" if self.target.startswith("https") else "http"

        for path_suffix, label in wl_paths:
            port = path_suffix.split(":")[1].split("/")[0]
            path = "/" + "/".join(path_suffix.split("/")[1:])
            test_url = f"{scheme}://{host}:{port}{path}"

            resp, err = self.http.probe(test_url)
            if err or not resp:
                continue
            if resp.status_code in (200, 302, 301, 403):
                sev = "critical" if "wsat" in path.lower() else "high"
                self.find(
                    title=f"WebLogic Endpoint Exposed: {label}",
                    severity=sev,
                    description=(
                        f"WebLogic endpoint '{label}' is reachable. "
                        f"CVE-2019-2725, CVE-2020-14882, and other critical WebLogic RCE vulnerabilities "
                        f"target these endpoints."
                    ),
                    url=test_url,
                    evidence=f"HTTP {resp.status_code}",
                    remediation=(
                        "Apply Oracle WebLogic patches immediately. "
                        "Restrict admin console to internal networks. "
                        "Disable T3 protocol from internet-facing interfaces."
                    ),
                    cve="CVE-2019-2725",
                    cvss=9.8,
                )
