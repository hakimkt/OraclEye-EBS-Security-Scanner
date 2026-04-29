"""
HTTP Client - Shared requests session with EBS-specific helpers.
"""

import requests
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; EBS-SecurityScanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

EBS_PATHS = {
    "login":         "/OA_HTML/AppsLocalLogin.jsp",
    "login_sso":     "/OA_HTML/RF.jsp",
    "guest":         "/OA_HTML/Guest",
    "oacore":        "/oa_servlets/AppsServlet",
    "forms":         "/forms/frmservlet",
    "admin":         "/OA_HTML/OAErrorPage.jsp",
    "diagnostic":    "/OA_HTML/BneExcelIntegrator.jsp",
    "webservices":   "/webservices/",
    "xmlgateway":    "/OA_HTML/XMLGateway",
    "selfservice":   "/OA_HTML/OA.jsp",
    "discoverer":    "/discoverer/viewer",
    "reports":       "/reports/rwservlet",
    "db_listener":   "/:8080/",
    "ias_console":   "/:1156/",
    "opmn":          "/:6003/",
    "joc":           "/:8888/",
    "concurrent":    "/OA_HTML/OAErrorPage.jsp?type=Error",
}


class HTTPClient:
    def __init__(self, target, options=None):
        self.target = target.rstrip("/")
        self.options = options or {}
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.session.verify = False
        timeout_opt = self.options.get("timeout", 10)
        self.timeout = int(timeout_opt) if timeout_opt else 10
        proxy = self.options.get("proxy", "")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def url(self, path):
        if path.startswith("http"):
            return path
        return self.target + path

    def get(self, path, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        return self.session.get(self.url(path), **kwargs)

    def post(self, path, data=None, json=None, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return self.session.post(self.url(path), data=data, json=json, **kwargs)

    def head(self, path, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return self.session.head(self.url(path), **kwargs)

    def ebs_path(self, key):
        return EBS_PATHS.get(key, "/")

    def probe(self, path, method="GET", **kwargs):
        """Safe probe - returns (response, error) tuple."""
        try:
            fn = getattr(self.session, method.lower())
            kwargs.setdefault("timeout", self.timeout)
            kwargs.setdefault("allow_redirects", False)
            r = fn(self.url(path), **kwargs)
            return r, None
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {e}"
        except requests.exceptions.Timeout:
            return None, "Request timed out"
        except Exception as e:
            return None, str(e)
