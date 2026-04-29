"""
Base Plugin - All scanner modules inherit from this.

To add a new vulnerability check:
1. Create a new file in scanner/plugins/
2. Subclass BasePlugin
3. Set PLUGIN_ID, PLUGIN_NAME, PLUGIN_DESC, CATEGORY, MIN_INTRUSIVITY
4. Implement run() -> list[Finding]
5. That's it — auto-discovered on startup.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, List
import time


def finding(title, severity, description, url="", evidence="",
            remediation="", cve="", cvss=0.0, plugin_id=""):
    """Helper to create a standardized finding dict."""
    return {
        "title": title,
        "severity": severity,       # critical | high | medium | low | info
        "description": description,
        "url": url,
        "evidence": evidence,
        "remediation": remediation,
        "cve": cve,
        "cvss": cvss,
        "plugin_id": plugin_id,
    }


class BasePlugin:
    PLUGIN_ID = "base"
    PLUGIN_NAME = "Base Plugin"
    PLUGIN_DESC = "Base class — do not use directly."
    CATEGORY = "general"
    MIN_INTRUSIVITY = "passive"   # passive | low | medium | aggressive
    CVE_REFS = []
    BASE_SEVERITY = "info"

    def __init__(self, http, target, options=None):
        self.http = http
        self.target = target
        self.options = options or {}
        self.findings = []

    def run(self):
        raise NotImplementedError

    def find(self, **kwargs):
        kwargs["plugin_id"] = self.PLUGIN_ID
        self.findings.append(finding(**kwargs))

    def probe(self, path, method="GET", **kwargs):
        return self.http.probe(path, method=method, **kwargs)

    def get(self, path, **kwargs):
        return self.http.get(path, **kwargs)

    def post(self, path, **kwargs):
        return self.http.post(path, **kwargs)
