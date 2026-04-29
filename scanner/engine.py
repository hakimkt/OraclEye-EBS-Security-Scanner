"""
Scan Engine - Orchestrates plugin execution, manages findings and progress.
"""

import time
import traceback
import requests
from datetime import datetime
from scanner.registry import PluginRegistry
from scanner.http_client import HTTPClient

SEVERITY_SCORE = {"critical": 10, "high": 7, "medium": 5, "low": 2, "info": 0}


class ScanEngine:
    def __init__(self, target, intrusivity, modules, options, job):
        self.target = target.rstrip("/")
        self.intrusivity = intrusivity
        self.modules = modules
        self.options = options
        self.job = job
        self.registry = PluginRegistry()
        self.http = HTTPClient(target=self.target, options=options)

    def log(self, msg, level="info"):
        entry = {"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
        self.job["log"].append(entry)

    def add_finding(self, finding):
        finding.setdefault("id", f"FIND-{len(self.job['findings'])+1:04d}")
        finding.setdefault("ts", datetime.now().isoformat())
        self.job["findings"].append(finding)
        sev = finding.get("severity", "info")
        self.job["stats"][sev] = self.job["stats"].get(sev, 0) + 1
        self.job["stats"]["total"] += 1

    def run(self):
        self.log(f"Starting scan against {self.target}", "info")
        self.log(f"Intrusivity level: {self.intrusivity}", "info")

        # Connectivity check
        self.log("Performing connectivity check...", "info")
        try:
            r = self.http.get("/")
            self.log(f"Target reachable — HTTP {r.status_code}", "success")
            self._detect_ebs_version(r)
        except Exception as e:
            self.log(f"Connectivity check failed: {e}", "error")
            self.job["status"] = "error"
            return

        plugins = self.registry.get_plugins_for_intrusivity(self.intrusivity, self.modules or None)
        total = len(plugins)
        self.log(f"Loaded {total} check modules for intrusivity={self.intrusivity}", "info")

        for i, plugin_cls in enumerate(plugins):
            self.log(f"[{i+1}/{total}] Running: {plugin_cls.PLUGIN_NAME}", "info")
            try:
                plugin = plugin_cls(http=self.http, target=self.target, options=self.options)
                findings = plugin.run()
                for f in (findings or []):
                    self.add_finding(f)
                    self.log(f"  ↳ [{f['severity'].upper()}] {f['title']}", f['severity'])
            except Exception as e:
                self.log(f"  ↳ Plugin error: {e}", "error")
                traceback.print_exc()

            self.job["progress"] = int(((i + 1) / total) * 100)
            time.sleep(0.05)

        # Compute risk score
        score = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in self.job["findings"])
        self.job["risk_score"] = min(score, 100)
        self.job["risk_rating"] = self._risk_rating(score)
        self.log(f"Scan complete. Risk Score: {score} ({self.job['risk_rating']})", "success")

    def _detect_ebs_version(self, resp):
        headers = dict(resp.headers)
        body = resp.text[:3000]
        indicators = []
        if "Oracle" in body or "oracle" in body:
            indicators.append("Oracle branding detected")
        if "E-Business Suite" in body or "OAF" in body:
            indicators.append("Oracle EBS/OAF confirmed")
        if "ICX" in body or "FND" in body:
            indicators.append("EBS Framework tokens (ICX/FND) found")
        if "AppsLocalLogin" in body or "OA_HTML" in body:
            indicators.append("EBS login endpoint detected")
        for h in ["X-Oracle-Dms-Rid", "Oracle-Atg-Remote-Ip"]:
            if h in headers:
                indicators.append(f"EBS header: {h}")
        if indicators:
            self.job["target_info"] = {"indicators": indicators}
            for ind in indicators:
                self.log(f"  Target fingerprint: {ind}", "info")
        else:
            self.log("  No definitive EBS fingerprint found — may be behind proxy", "warn")

    def _risk_rating(self, score):
        if score >= 30:
            return "CRITICAL"
        if score >= 20:
            return "HIGH"
        if score >= 10:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "CLEAN"
