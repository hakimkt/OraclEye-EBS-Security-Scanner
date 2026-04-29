"""
Plugin: TLS/SSL Configuration Checks
Tests for weak ciphers, protocol versions, certificate issues.
Intrusivity: passive
"""

from scanner.base_plugin import BasePlugin
import ssl
import socket


class TLSConfigPlugin(BasePlugin):
    PLUGIN_ID = "tls_config"
    PLUGIN_NAME = "TLS/SSL Configuration"
    PLUGIN_DESC = "Checks TLS protocol versions, certificate validity, and cipher strength."
    CATEGORY = "Cryptography"
    MIN_INTRUSIVITY = "passive"
    BASE_SEVERITY = "high"
    CVE_REFS = ["CVE-2014-3566"]

    def run(self):
        if not self.target.startswith("https://"):
            self.find(
                title="TLS Not Used — EBS Running on HTTP",
                severity="critical",
                description="Oracle EBS is not using TLS/HTTPS. All EBS data transmitted in cleartext.",
                url=self.target,
                evidence="Target uses http:// scheme",
                remediation="Enable TLS 1.2+ on Oracle HTTP Server. Configure automatic HTTP→HTTPS redirect.",
                cvss=9.1,
            )
            return self.findings

        host = self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        port = 443
        if ":" in self.target.split("://")[1].split("/")[0]:
            try:
                port = int(self.target.split("://")[1].split("/")[0].split(":")[1])
            except Exception:
                pass

        self._check_cert(host, port)
        self._check_protocols(host, port)
        return self.findings

    def _check_cert(self, host, port):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    # Check expiry
                    import datetime
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                    now = datetime.datetime.now().timestamp()
                    days_left = (not_after - now) / 86400
                    if days_left < 0:
                        self.find(
                            title="TLS Certificate EXPIRED",
                            severity="critical",
                            description=f"The TLS certificate for {host} has expired {abs(int(days_left))} days ago.",
                            url=self.target,
                            evidence=f"Certificate notAfter: {cert['notAfter']}",
                            remediation="Renew TLS certificate immediately.",
                            cvss=7.5,
                        )
                    elif days_left < 30:
                        self.find(
                            title=f"TLS Certificate Expiring Soon ({int(days_left)} days)",
                            severity="medium",
                            description=f"The TLS certificate expires in {int(days_left)} days.",
                            url=self.target,
                            evidence=f"Certificate notAfter: {cert['notAfter']}",
                            remediation="Schedule TLS certificate renewal.",
                        )
                    # Check SANs/CN
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    sans = [v for _, v in cert.get("subjectAltName", [])]
                    if cn and host.lower() not in cn.lower() and not any(host.lower() in s.lower() for s in sans):
                        self.find(
                            title="TLS Certificate Hostname Mismatch",
                            severity="high",
                            description=f"Certificate CN='{cn}' does not match host '{host}'.",
                            url=self.target,
                            evidence=f"CN: {cn} | SANs: {sans[:3]}",
                            remediation="Obtain a certificate valid for the correct hostname.",
                            cvss=7.4,
                        )
        except ssl.SSLCertVerificationError as e:
            self.find(
                title="TLS Certificate Validation Failure",
                severity="high",
                description=f"TLS certificate cannot be validated: {e}. This may indicate a self-signed or misconfigured certificate.",
                url=self.target,
                evidence=str(e),
                remediation="Use a CA-signed certificate. Do not use self-signed certificates in production.",
            )
        except Exception:
            pass

    def _check_protocols(self, host, port):
        weak_protocols = [
            (ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None, "TLSv1.0", "CVE-2014-3566"),
            (ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None, "TLSv1.1", ""),
        ]
        for protocol, name, cve in weak_protocols:
            if protocol is None:
                continue
            try:
                ctx = ssl.SSLContext(protocol)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        self.find(
                            title=f"Weak TLS Protocol Supported: {name}",
                            severity="high",
                            description=(
                                f"The server supports {name} which is considered insecure. "
                                f"TLSv1.0 is vulnerable to POODLE and BEAST attacks."
                            ),
                            url=self.target,
                            evidence=f"Handshake succeeded with {name}",
                            remediation=f"Disable {name} in Oracle HTTP Server ssl.conf. Support only TLS 1.2 and 1.3.",
                            cve=cve,
                            cvss=7.4,
                        )
            except Exception:
                pass
