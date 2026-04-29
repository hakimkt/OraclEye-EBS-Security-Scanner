"""
Plugin: Authentication & Session Security
Checks for weak authentication, default credentials, session token issues,
SSO misconfigurations, and missing security headers.
Intrusivity: low (reads responses, checks headers, tests known defaults)
"""

from scanner.base_plugin import BasePlugin

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS not set", "medium",
     "Force HTTPS by adding: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("X-Frame-Options", "Clickjacking protection missing", "medium",
     "Add header: X-Frame-Options: DENY or SAMEORIGIN"),
    ("X-Content-Type-Options", "MIME sniffing protection missing", "low",
     "Add header: X-Content-Type-Options: nosniff"),
    ("Content-Security-Policy", "CSP not configured", "medium",
     "Implement a Content-Security-Policy header to restrict script/resource sources."),
    ("X-XSS-Protection", "Legacy XSS filter not set", "low",
     "Add header: X-XSS-Protection: 1; mode=block (legacy browsers)"),
    ("Referrer-Policy", "Referrer policy not set", "low",
     "Add header: Referrer-Policy: strict-origin-when-cross-origin"),
    ("Permissions-Policy", "Permissions policy not set", "info",
     "Consider adding Permissions-Policy header to restrict browser features."),
    ("Cache-Control", "Caching policy not enforced on auth pages", "low",
     "Add Cache-Control: no-store, no-cache to authenticated responses."),
]

# Default credentials to try (non-invasive — just checks form presence)
DEFAULT_CREDS_TO_NOTE = [
    ("SYSADMIN", "SYSADMIN", "Oracle EBS default SYSADMIN account"),
    ("GUEST", "ORACLE", "Oracle EBS Guest account"),
    ("APPLSYS", "FND", "APPLSYS application schema default"),
    ("APPS", "APPS", "APPS schema default credential"),
    ("APPSRO", "APPSRO", "Read-only APPS credential"),
]

COOKIE_SECURITY_CHECKS = [
    ("HttpOnly", "Session cookie missing HttpOnly flag"),
    ("Secure", "Session cookie missing Secure flag"),
    ("SameSite", "Session cookie missing SameSite attribute"),
]

ICX_COOKIE_NAMES = ["ICX_SESSION_COOKIE", "JSESSIONID", "ORA_UCM_INFO", "oracle.uix"]


class AuthSessionPlugin(BasePlugin):
    PLUGIN_ID = "auth_session"
    PLUGIN_NAME = "Authentication & Session Security"
    PLUGIN_DESC = "Checks EBS login page security, session cookies, security headers, and authentication configuration."
    CATEGORY = "Authentication"
    MIN_INTRUSIVITY = "low"
    BASE_SEVERITY = "high"
    CVE_REFS = []

    def run(self):
        # Check security headers on main page
        root, err = self.probe("/")
        if root and not err:
            self._check_headers(root, "/")

        # Check login page specifically
        login_resp, err = self.probe("/OA_HTML/AppsLocalLogin.jsp")
        if login_resp and not err:
            self._check_headers(login_resp, "/OA_HTML/AppsLocalLogin.jsp")
            self._check_cookies(login_resp)
            self._check_login_form(login_resp)
            self._check_autocomplete(login_resp)

        # SSL/TLS check
        self._check_ssl()

        # Check password policy hints
        self._check_password_policy()

        # Check for default guest access
        self._check_guest_access()

        return self.findings

    def _check_headers(self, resp, path):
        headers = resp.headers
        for header, desc, severity, remediation in SECURITY_HEADERS:
            if header not in headers:
                self.find(
                    title=f"Missing Security Header: {header}",
                    severity=severity,
                    description=f"{desc} on {path}. This leaves the application vulnerable to related attacks.",
                    url=self.target + path,
                    evidence=f"Header '{header}' absent from response",
                    remediation=remediation,
                )

    def _check_cookies(self, resp):
        raw_cookies = resp.headers.get("Set-Cookie", "")
        all_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, 'getlist') else [raw_cookies]

        ebs_cookies = []
        for cookie_str in all_cookies:
            for name in ICX_COOKIE_NAMES:
                if name.lower() in cookie_str.lower():
                    ebs_cookies.append(cookie_str)

        for cookie_str in ebs_cookies:
            for flag, desc in COOKIE_SECURITY_CHECKS:
                if flag.lower() not in cookie_str.lower():
                    self.find(
                        title=f"Session Cookie Security: {desc}",
                        severity="high" if flag in ("HttpOnly", "Secure") else "medium",
                        description=(
                            f"An EBS session cookie is missing the {flag} attribute. "
                            f"This could allow cookie theft via XSS or transmission over HTTP."
                        ),
                        url=self.target + "/OA_HTML/AppsLocalLogin.jsp",
                        evidence=f"Cookie header: {cookie_str[:200]}",
                        remediation=f"Configure {flag} flag on all session cookies via Oracle HTTP Server or web.xml.",
                    )

    def _check_login_form(self, resp):
        body = resp.text
        if "AppsLocalLogin" in body or "username" in body.lower():
            # Check for CSRF token
            if "csrf" not in body.lower() and "_token" not in body.lower() and "authenticity_token" not in body.lower():
                self.find(
                    title="Login Form Missing CSRF Protection",
                    severity="medium",
                    description=(
                        "The EBS login page does not appear to include a CSRF token. "
                        "This may allow cross-site request forgery attacks against the login flow."
                    ),
                    url=self.target + "/OA_HTML/AppsLocalLogin.jsp",
                    evidence="No CSRF token pattern found in form HTML",
                    remediation="Implement CSRF tokens in all EBS form submissions. Review Oracle EBS security configuration.",
                )

    def _check_autocomplete(self, resp):
        body = resp.text
        if 'autocomplete="off"' not in body.lower() and 'autocomplete="new-password"' not in body.lower():
            if "password" in body.lower() or "passwd" in body.lower():
                self.find(
                    title="Login Form Allows Password Autocomplete",
                    severity="low",
                    description="The password field does not have autocomplete=off, which may cause credentials to be stored in browser history.",
                    url=self.target + "/OA_HTML/AppsLocalLogin.jsp",
                    evidence="autocomplete='off' not found on password input",
                    remediation="Add autocomplete='off' or autocomplete='new-password' to the password field.",
                )

    def _check_ssl(self):
        if self.target.startswith("http://"):
            self.find(
                title="EBS Running Over HTTP (Unencrypted)",
                severity="critical",
                description=(
                    "Oracle EBS is accessible over unencrypted HTTP. All data including credentials, "
                    "session tokens, and ERP data is transmitted in plaintext and can be intercepted."
                ),
                url=self.target,
                evidence="Target URL uses http:// scheme",
                remediation="Configure SSL/TLS via Oracle HTTP Server. Redirect all HTTP to HTTPS. Use minimum TLS 1.2.",
                cvss=9.1,
            )
        # Check if HTTPS target also responds on HTTP
        if self.target.startswith("https://"):
            http_url = self.target.replace("https://", "http://")
            try:
                import requests
                r = requests.get(http_url + "/OA_HTML/AppsLocalLogin.jsp",
                                 timeout=5, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    self.find(
                        title="EBS Also Accessible via HTTP (Redirect Missing)",
                        severity="high",
                        description="The HTTP version of EBS does not redirect to HTTPS, allowing unencrypted access.",
                        url=http_url,
                        evidence=f"HTTP {r.status_code} response on http:// version",
                        remediation="Force HTTPS redirect in Oracle HTTP Server virtual host configuration.",
                    )
            except Exception:
                pass

    def _check_password_policy(self):
        resp, err = self.probe("/OA_HTML/AppsLocalLogin.jsp")
        if err or not resp:
            return
        body = resp.text
        if "password" in body.lower():
            if "minlength" not in body.lower() and "pattern" not in body.lower():
                self.find(
                    title="No Client-Side Password Policy Enforcement Visible",
                    severity="info",
                    description="No client-side password length or complexity pattern constraints detected on the login form. Ensure server-side password policies are enforced in FND_USER.",
                    url=self.target + "/OA_HTML/AppsLocalLogin.jsp",
                    evidence="No minlength/pattern attributes found on password fields",
                    remediation="Configure FND_USER password policy via Oracle EBS System Administrator > Security.",
                )

    def _check_guest_access(self):
        resp, err = self.probe("/OA_HTML/OA.jsp?page=/oracle/apps/fnd/sso/login/webui/GuestPG")
        if err or not resp:
            return
        if resp.status_code == 200 and "guest" in resp.text.lower():
            self.find(
                title="EBS Guest/Anonymous Access Enabled",
                severity="high",
                description="The EBS guest login page is accessible and may allow unauthenticated browsing of public EBS pages.",
                url=self.target + "/OA_HTML/OA.jsp?page=/oracle/apps/fnd/sso/login/webui/GuestPG",
                evidence=f"HTTP 200 with 'guest' in response body",
                remediation="Disable guest access in EBS System Administrator profile options (FND: Guest User Password).",
            )
