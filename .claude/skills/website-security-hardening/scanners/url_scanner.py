"""
URL-based security scanner for HTTP/HTTPS websites.

Performs security checks via HTTP requests without requiring authentication.
Suitable for scanning any publicly accessible website.
"""

import re
import socket
import ssl
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, SSLError

from .base_scanner import (
    BaseSecurityConnector,
    NormalizedSecurityReport,
    PlatformType,
    SeverityLevel,
    Vulnerability,
    Misconfiguration
)


class URLSecurityScanner(BaseSecurityConnector):
    """
    HTTP-based security scanner for websites.

    Checks for:
    - Security headers
    - SSL/TLS configuration
    - Information disclosure
    - Common vulnerable paths
    - Dangerous HTTP methods
    """

    def __init__(self, target: str, timeout: int = 10, **kwargs):
        """
        Initialize URL scanner.

        Args:
            target: Target URL (https://example.com)
            timeout: Request timeout in seconds
            **kwargs: Additional configuration
        """
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        super().__init__(target, **kwargs)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security-Scanner/1.0 (Security Audit)'
        })

    def _detect_platform(self) -> PlatformType:
        """Detect platform type from URL scan."""
        return PlatformType.GENERIC_URL

    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to target URL."""
        try:
            response = self.session.get(self.target, timeout=self.timeout, allow_redirects=True)
            return True, f"Connected successfully (Status: {response.status_code})"
        except SSLError as e:
            return False, f"SSL Error: {str(e)}"
        except RequestException as e:
            return False, f"Connection failed: {str(e)}"

    def scan(self) -> NormalizedSecurityReport:
        """Perform comprehensive security scan."""
        start_time = time.time()
        report = self._create_report()

        # Run all security checks
        self._check_security_headers(report)
        self._check_ssl_tls(report)
        self._check_information_disclosure(report)
        self._check_common_paths(report)
        self._check_http_methods(report)

        # Calculate risk score
        report.risk_score = self._calculate_risk_score(report)
        report.scan_duration = time.time() - start_time

        return report

    def _check_security_headers(self, report: NormalizedSecurityReport):
        """Check for presence of security headers."""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Define required security headers
            security_headers = {
                'strict-transport-security': 'HSTS',
                'x-frame-options': 'Clickjacking Protection',
                'x-content-type-options': 'MIME Sniffing Protection',
                'content-security-policy': 'Content Security Policy',
                'x-xss-protection': 'XSS Protection',
                'referrer-policy': 'Referrer Policy',
                'permissions-policy': 'Permissions Policy',
            }

            for header, name in security_headers.items():
                present = header in headers
                report.security_headers[name] = present

                if not present:
                    severity = SeverityLevel.HIGH if header in ['strict-transport-security', 'content-security-policy'] else SeverityLevel.MEDIUM

                    report.misconfigurations.append(
                        Misconfiguration(
                            severity=severity,
                            category="headers",
                            issue=f"Missing {name} header",
                            recommendation=self._get_header_recommendation(header),
                            config_file=".htaccess or nginx.conf"
                        )
                    )

            # Check for dangerous headers
            if 'server' in headers:
                report.misconfigurations.append(
                    Misconfiguration(
                        severity=SeverityLevel.LOW,
                        category="headers",
                        issue=f"Server header exposed: {headers['server']}",
                        recommendation="Remove or obscure Server header to prevent version disclosure",
                        config_file=".htaccess or server config"
                    )
                )

            if 'x-powered-by' in headers:
                report.misconfigurations.append(
                    Misconfiguration(
                        severity=SeverityLevel.LOW,
                        category="headers",
                        issue=f"X-Powered-By header exposed: {headers['x-powered-by']}",
                        recommendation="Remove X-Powered-By header to prevent technology disclosure",
                        config_file="php.ini or application config"
                    )
                )

        except RequestException as e:
            report.vulnerabilities.append(
                Vulnerability(
                    severity=SeverityLevel.INFO,
                    title="Could not check security headers",
                    description=str(e),
                    affected_component="HTTP Headers"
                )
            )

    def _check_ssl_tls(self, report: NormalizedSecurityReport):
        """Check SSL/TLS configuration."""
        parsed = urlparse(self.target)

        if parsed.scheme != 'https':
            report.misconfigurations.append(
                Misconfiguration(
                    severity=SeverityLevel.CRITICAL,
                    category="ssl",
                    issue="Site not using HTTPS",
                    recommendation="Enable HTTPS with valid SSL/TLS certificate",
                    config_file="Web server configuration"
                )
            )
            return

        try:
            hostname = parsed.hostname
            port = parsed.port or 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    # Store SSL info
                    report.ssl_tls_status = {
                        'protocol': protocol,
                        'cipher': cipher[0] if cipher else None,
                        'cert_valid': True
                    }

                    # Check certificate expiration
                    if cert:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %GMT')
                        days_until_expiry = (not_after - datetime.now()).days

                        report.ssl_tls_status['expires_in_days'] = days_until_expiry

                        if days_until_expiry < 0:
                            report.vulnerabilities.append(
                                Vulnerability(
                                    severity=SeverityLevel.CRITICAL,
                                    title="SSL certificate expired",
                                    description=f"Certificate expired {abs(days_until_expiry)} days ago",
                                    affected_component="SSL Certificate",
                                    remediation="Renew SSL certificate immediately"
                                )
                            )
                        elif days_until_expiry < 30:
                            report.vulnerabilities.append(
                                Vulnerability(
                                    severity=SeverityLevel.HIGH,
                                    title="SSL certificate expiring soon",
                                    description=f"Certificate expires in {days_until_expiry} days",
                                    affected_component="SSL Certificate",
                                    remediation="Renew SSL certificate before expiration"
                                )
                            )

                    # Check protocol version
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        report.vulnerabilities.append(
                            Vulnerability(
                                severity=SeverityLevel.HIGH,
                                title=f"Weak TLS protocol: {protocol}",
                                description="Using outdated TLS protocol version",
                                affected_component="SSL/TLS Configuration",
                                remediation="Disable old protocols, use TLS 1.2 or higher",
                                references=["https://owasp.org/www-project-web-security-testing-guide/"]
                            )
                        )

        except ssl.SSLError as e:
            report.vulnerabilities.append(
                Vulnerability(
                    severity=SeverityLevel.CRITICAL,
                    title="SSL/TLS Error",
                    description=str(e),
                    affected_component="SSL Certificate",
                    remediation="Fix SSL configuration and ensure valid certificate"
                )
            )
            report.ssl_tls_status['cert_valid'] = False

        except Exception as e:
            report.ssl_tls_status['error'] = str(e)

    def _check_information_disclosure(self, report: NormalizedSecurityReport):
        """Check for information disclosure vulnerabilities."""
        # Check for exposed sensitive files
        sensitive_paths = [
            '/.git/config',
            '/.git/HEAD',
            '/.env',
            '/.env.production',
            '/config.php',
            '/wp-config.php',
            '/backup.sql',
            '/database.sql',
            '/.htaccess',
            '/phpinfo.php',
        ]

        for path in sensitive_paths:
            try:
                url = f"{self.target.rstrip('/')}{path}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)

                if response.status_code == 200:
                    report.vulnerabilities.append(
                        Vulnerability(
                            severity=SeverityLevel.CRITICAL,
                            title=f"Sensitive file exposed: {path}",
                            description=f"File accessible at {url}",
                            affected_component="File Permissions",
                            remediation=f"Remove or restrict access to {path}"
                        )
                    )
            except RequestException:
                pass  # File not accessible (good)

        # Check for directory listing
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            if 'Index of /' in response.text or '<title>Index of' in response.text:
                report.vulnerabilities.append(
                    Vulnerability(
                        severity=SeverityLevel.MEDIUM,
                        title="Directory listing enabled",
                        description="Server allows browsing of directory contents",
                        affected_component="Web Server Configuration",
                        remediation="Disable directory listing in web server config"
                    )
                )
        except RequestException:
            pass

    def _check_common_paths(self, report: NormalizedSecurityReport):
        """Check for exposed admin panels and common paths."""
        admin_paths = [
            '/admin',
            '/administrator',
            '/wp-admin',
            '/ghost/admin',
            '/phpmyadmin',
            '/cpanel',
        ]

        for path in admin_paths:
            try:
                url = f"{self.target.rstrip('/')}{path}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)

                if response.status_code == 200:
                    report.misconfigurations.append(
                        Misconfiguration(
                            severity=SeverityLevel.MEDIUM,
                            category="authentication",
                            issue=f"Admin panel accessible: {path}",
                            recommendation="Add IP whitelist or additional authentication for admin areas"
                        )
                    )
            except RequestException:
                pass

    def _check_http_methods(self, report: NormalizedSecurityReport):
        """Check for dangerous HTTP methods."""
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']

        for method in dangerous_methods:
            try:
                response = self.session.request(method, self.target, timeout=self.timeout)

                if response.status_code not in [405, 501]:  # Method not allowed
                    report.vulnerabilities.append(
                        Vulnerability(
                            severity=SeverityLevel.HIGH,
                            title=f"Dangerous HTTP method enabled: {method}",
                            description=f"{method} method returned status {response.status_code}",
                            affected_component="Web Server Configuration",
                            remediation=f"Disable {method} method in web server config"
                        )
                    )
            except RequestException:
                pass

    def _calculate_risk_score(self, report: NormalizedSecurityReport) -> int:
        """Calculate risk score (100 = perfect, 0 = critical)."""
        score = 100

        # Deduct points based on severity
        severity_points = {
            SeverityLevel.CRITICAL: 25,
            SeverityLevel.HIGH: 15,
            SeverityLevel.MEDIUM: 10,
            SeverityLevel.LOW: 5,
            SeverityLevel.INFO: 1
        }

        for vuln in report.vulnerabilities:
            score -= severity_points.get(vuln.severity, 0)

        for config in report.misconfigurations:
            score -= severity_points.get(config.severity, 0)

        return max(0, score)

    def _get_header_recommendation(self, header: str) -> str:
        """Get remediation recommendation for missing header."""
        recommendations = {
            'strict-transport-security': 'Add: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            'x-frame-options': 'Add: Header always set X-Frame-Options "SAMEORIGIN"',
            'x-content-type-options': 'Add: Header always set X-Content-Type-Options "nosniff"',
            'content-security-policy': 'Add: Header always set Content-Security-Policy "default-src \'self\'"',
            'x-xss-protection': 'Add: Header always set X-XSS-Protection "1; mode=block"',
            'referrer-policy': 'Add: Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            'permissions-policy': 'Add: Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
        }
        return recommendations.get(header, f"Add {header} header to server configuration")
