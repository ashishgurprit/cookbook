"""
Configuration auditing module.

Audits security configurations and compliance with best practices.
"""

from typing import List, Dict

# Import from scanners module (assumes parent directory is in path)
try:
    from scanners.base_scanner import (
        Misconfiguration,
        SeverityLevel,
        NormalizedSecurityReport
    )
except ImportError:
    # Fallback for relative imports
    from ..scanners.base_scanner import (
        Misconfiguration,
        SeverityLevel,
        NormalizedSecurityReport
    )


class ConfigurationAuditor:
    """
    Audits security configurations.

    Checks for:
    - Security headers compliance (OWASP recommendations)
    - Cookie security settings
    - HTTPS enforcement
    - CORS misconfigurations
    """

    def __init__(self):
        """Initialize configuration auditor."""
        self.version = "1.0.0"

    def audit(self, report: NormalizedSecurityReport) -> List[Misconfiguration]:
        """
        Audit security configurations.

        Args:
            report: Normalized security report

        Returns:
            List[Misconfiguration]: Configuration issues
        """
        misconfigurations = []

        # Audit security headers
        misconfigurations.extend(self._audit_security_headers(report))

        # Audit SSL/TLS
        misconfigurations.extend(self._audit_ssl_tls(report))

        # Audit cookies (if data available)
        if report.raw_data and 'cookies' in report.raw_data:
            misconfigurations.extend(self._audit_cookies(report.raw_data['cookies']))

        # Audit CORS (if data available)
        if report.raw_data and 'cors_headers' in report.raw_data:
            misconfigurations.extend(self._audit_cors(report.raw_data['cors_headers']))

        return misconfigurations

    def _audit_security_headers(self, report: NormalizedSecurityReport) -> List[Misconfiguration]:
        """Audit security headers compliance."""
        misconfigurations = []

        # OWASP recommended headers
        required_headers = {
            'HSTS': {
                'severity': SeverityLevel.HIGH,
                'recommendation': 'Add Strict-Transport-Security header',
                'fix_code': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
            },
            'Content Security Policy': {
                'severity': SeverityLevel.HIGH,
                'recommendation': 'Add Content-Security-Policy header to prevent XSS',
                'fix_code': 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'"'
            },
            'X-Frame-Options': {
                'severity': SeverityLevel.MEDIUM,
                'recommendation': 'Add X-Frame-Options to prevent clickjacking',
                'fix_code': 'Header always set X-Frame-Options "SAMEORIGIN"'
            },
            'X-Content-Type-Options': {
                'severity': SeverityLevel.MEDIUM,
                'recommendation': 'Add X-Content-Type-Options to prevent MIME sniffing',
                'fix_code': 'Header always set X-Content-Type-Options "nosniff"'
            },
            'Referrer Policy': {
                'severity': SeverityLevel.LOW,
                'recommendation': 'Add Referrer-Policy header',
                'fix_code': 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'
            },
            'Permissions Policy': {
                'severity': SeverityLevel.LOW,
                'recommendation': 'Add Permissions-Policy header',
                'fix_code': 'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"'
            }
        }

        for header, config in required_headers.items():
            if not report.security_headers.get(header, False):
                misconfigurations.append(
                    Misconfiguration(
                        severity=config['severity'],
                        category='headers',
                        issue=f"Missing {header} header",
                        recommendation=config['recommendation'],
                        config_file='.htaccess or nginx.conf',
                        fix_code=config['fix_code']
                    )
                )

        return misconfigurations

    def _audit_ssl_tls(self, report: NormalizedSecurityReport) -> List[Misconfiguration]:
        """Audit SSL/TLS configuration."""
        misconfigurations = []

        # Check if HTTPS is enforced
        if not report.target_url.startswith('https://'):
            misconfigurations.append(
                Misconfiguration(
                    severity=SeverityLevel.CRITICAL,
                    category='ssl',
                    issue='HTTPS not enforced',
                    recommendation='Redirect all HTTP traffic to HTTPS',
                    config_file='Web server configuration',
                    fix_code='RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]'
                )
            )

        # Check HSTS
        if not report.security_headers.get('HSTS', False):
            misconfigurations.append(
                Misconfiguration(
                    severity=SeverityLevel.HIGH,
                    category='ssl',
                    issue='HSTS not configured',
                    recommendation='Enable HTTP Strict Transport Security',
                    config_file='.htaccess or nginx.conf',
                    fix_code='Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
                )
            )

        # Check certificate expiration
        ssl_status = report.ssl_tls_status
        if 'expires_in_days' in ssl_status:
            days = ssl_status['expires_in_days']
            if 0 < days < 30:
                misconfigurations.append(
                    Misconfiguration(
                        severity=SeverityLevel.MEDIUM,
                        category='ssl',
                        issue=f'SSL certificate expires in {days} days',
                        recommendation='Renew SSL certificate soon to avoid expiration',
                        config_file='SSL certificate management'
                    )
                )

        return misconfigurations

    def _audit_cookies(self, cookies: List[Dict]) -> List[Misconfiguration]:
        """Audit cookie security settings."""
        misconfigurations = []

        for cookie in cookies:
            cookie_name = cookie.get('name', 'unknown')

            # Check Secure flag
            if not cookie.get('secure', False):
                misconfigurations.append(
                    Misconfiguration(
                        severity=SeverityLevel.MEDIUM,
                        category='cookies',
                        issue=f"Cookie '{cookie_name}' missing Secure flag",
                        recommendation='Set Secure flag to ensure cookie is only sent over HTTPS',
                        config_file='Application configuration',
                        fix_code='Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict'
                    )
                )

            # Check HttpOnly flag
            if not cookie.get('httponly', False):
                misconfigurations.append(
                    Misconfiguration(
                        severity=SeverityLevel.MEDIUM,
                        category='cookies',
                        issue=f"Cookie '{cookie_name}' missing HttpOnly flag",
                        recommendation='Set HttpOnly flag to prevent JavaScript access',
                        config_file='Application configuration',
                        fix_code='Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict'
                    )
                )

            # Check SameSite
            if not cookie.get('samesite'):
                misconfigurations.append(
                    Misconfiguration(
                        severity=SeverityLevel.LOW,
                        category='cookies',
                        issue=f"Cookie '{cookie_name}' missing SameSite attribute",
                        recommendation='Set SameSite attribute to prevent CSRF attacks',
                        config_file='Application configuration',
                        fix_code='Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict'
                    )
                )

        return misconfigurations

    def _audit_cors(self, cors_headers: Dict) -> List[Misconfiguration]:
        """Audit CORS configuration."""
        misconfigurations = []

        # Check for overly permissive CORS
        origin = cors_headers.get('Access-Control-Allow-Origin')

        if origin == '*':
            misconfigurations.append(
                Misconfiguration(
                    severity=SeverityLevel.HIGH,
                    category='cors',
                    issue='Overly permissive CORS policy (Access-Control-Allow-Origin: *)',
                    recommendation='Restrict CORS to specific trusted domains',
                    config_file='Web server or application configuration',
                    fix_code='Header set Access-Control-Allow-Origin "https://trusted-domain.com"'
                )
            )

        # Check for credentials with wildcard origin
        allow_credentials = cors_headers.get('Access-Control-Allow-Credentials')

        if origin == '*' and allow_credentials == 'true':
            misconfigurations.append(
                Misconfiguration(
                    severity=SeverityLevel.CRITICAL,
                    category='cors',
                    issue='Dangerous CORS configuration: credentials allowed with wildcard origin',
                    recommendation='Never use wildcard origin with credentials enabled',
                    config_file='Web server or application configuration'
                )
            )

        return misconfigurations
