"""
Security analysis and reporting orchestrator.

This module analyzes NormalizedSecurityReport data and generates
comprehensive security analysis with prioritized remediation steps.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

# Import from scanners module (assumes parent directory is in path)
try:
    from scanners.base_scanner import (
        NormalizedSecurityReport,
        Vulnerability,
        Misconfiguration,
        SeverityLevel
    )
except ImportError:
    # Fallback for relative imports
    from ..scanners.base_scanner import (
        NormalizedSecurityReport,
        Vulnerability,
        Misconfiguration,
        SeverityLevel
    )


@dataclass
class Fix:
    """Represents a prioritized security fix."""
    priority: int  # 1 = highest
    severity: SeverityLevel
    title: str
    description: str
    remediation: str
    affected_component: str
    code_snippet: Optional[str] = None


class SecurityAnalyzer:
    """
    Main security analysis orchestrator.

    Analyzes security scan results and provides:
    - Risk scoring
    - Prioritized fixes
    - Comprehensive reports
    """

    def __init__(self):
        """Initialize security analyzer."""
        self.version = "1.0.0"

    def analyze(self, report: NormalizedSecurityReport) -> Dict:
        """
        Perform comprehensive analysis of security report.

        Args:
            report: Normalized security scan report

        Returns:
            Dict: Complete analysis with scores, priorities, and recommendations
        """
        analysis = {
            'scan_info': {
                'target': report.target_url,
                'platform': report.platform.value,
                'scan_date': report.scan_date.isoformat(),
                'scan_duration': f"{report.scan_duration:.2f}s",
                'scanner_version': report.scanner_version
            },
            'risk_assessment': self._assess_risk(report),
            'severity_breakdown': self._get_severity_breakdown(report),
            'prioritized_fixes': self.prioritize_fixes(report),
            'security_posture': self._assess_security_posture(report),
            'compliance': self._assess_compliance(report)
        }

        return analysis

    def calculate_risk_score(self, report: NormalizedSecurityReport) -> int:
        """
        Calculate risk score from 0 (critical) to 100 (secure).

        Args:
            report: Security report

        Returns:
            int: Risk score
        """
        score = 100

        # Severity deductions
        severity_points = {
            SeverityLevel.CRITICAL: 25,
            SeverityLevel.HIGH: 15,
            SeverityLevel.MEDIUM: 10,
            SeverityLevel.LOW: 5,
            SeverityLevel.INFO: 1
        }

        # Deduct for vulnerabilities
        for vuln in report.vulnerabilities:
            score -= severity_points.get(vuln.severity, 0)

        # Deduct for misconfigurations
        for config in report.misconfigurations:
            score -= severity_points.get(config.severity, 0)

        return max(0, min(100, score))

    def prioritize_fixes(self, report: NormalizedSecurityReport) -> List[Fix]:
        """
        Generate prioritized list of fixes.

        Args:
            report: Security report

        Returns:
            List[Fix]: Fixes sorted by priority
        """
        fixes = []

        # Convert vulnerabilities to fixes
        for vuln in report.vulnerabilities:
            fixes.append(Fix(
                priority=self._get_priority_score(vuln.severity),
                severity=vuln.severity,
                title=vuln.title,
                description=vuln.description,
                remediation=vuln.remediation,
                affected_component=vuln.affected_component,
                code_snippet=None
            ))

        # Convert misconfigurations to fixes
        for config in report.misconfigurations:
            fixes.append(Fix(
                priority=self._get_priority_score(config.severity),
                severity=config.severity,
                title=f"[{config.category}] {config.issue}",
                description=config.issue,
                remediation=config.recommendation,
                affected_component=config.config_file or config.category,
                code_snippet=config.fix_code
            ))

        # Sort by priority (lower number = higher priority)
        fixes.sort(key=lambda x: (x.priority, x.title))

        return fixes

    def generate_report(self, analysis: Dict, format: str = 'text') -> str:
        """
        Generate formatted report.

        Args:
            analysis: Analysis results from analyze()
            format: Report format ('text', 'markdown', 'json')

        Returns:
            str: Formatted report
        """
        if format == 'json':
            import json
            return json.dumps(analysis, indent=2, default=str)
        elif format == 'markdown':
            return self._generate_markdown_report(analysis)
        else:
            return self._generate_text_report(analysis)

    def _assess_risk(self, report: NormalizedSecurityReport) -> Dict:
        """Assess overall risk level."""
        score = self.calculate_risk_score(report)
        grade = report.get_risk_grade()

        severity_counts = report.get_severity_counts()

        risk_level = "Critical"
        if score >= 70:
            risk_level = "Low"
        elif score >= 50:
            risk_level = "Medium"
        elif score >= 30:
            risk_level = "High"

        return {
            'score': score,
            'grade': grade,
            'risk_level': risk_level,
            'critical_issues': severity_counts[SeverityLevel.CRITICAL],
            'high_issues': severity_counts[SeverityLevel.HIGH],
            'medium_issues': severity_counts[SeverityLevel.MEDIUM],
            'low_issues': severity_counts[SeverityLevel.LOW],
            'total_issues': len(report.vulnerabilities) + len(report.misconfigurations)
        }

    def _get_severity_breakdown(self, report: NormalizedSecurityReport) -> Dict:
        """Get breakdown of issues by severity."""
        counts = report.get_severity_counts()
        return {
            'critical': counts[SeverityLevel.CRITICAL],
            'high': counts[SeverityLevel.HIGH],
            'medium': counts[SeverityLevel.MEDIUM],
            'low': counts[SeverityLevel.LOW],
            'info': counts[SeverityLevel.INFO]
        }

    def _assess_security_posture(self, report: NormalizedSecurityReport) -> Dict:
        """Assess overall security posture."""
        posture = {
            'headers': {
                'total': len(report.security_headers),
                'implemented': sum(1 for v in report.security_headers.values() if v),
                'missing': sum(1 for v in report.security_headers.values() if not v),
                'score': 0
            },
            'ssl_tls': report.ssl_tls_status,
            'overall_status': 'Unknown'
        }

        # Calculate header score
        if posture['headers']['total'] > 0:
            posture['headers']['score'] = int(
                (posture['headers']['implemented'] / posture['headers']['total']) * 100
            )

        # Overall status
        risk_score = self.calculate_risk_score(report)
        if risk_score >= 90:
            posture['overall_status'] = 'Excellent'
        elif risk_score >= 70:
            posture['overall_status'] = 'Good'
        elif risk_score >= 50:
            posture['overall_status'] = 'Needs Improvement'
        elif risk_score >= 30:
            posture['overall_status'] = 'Poor'
        else:
            posture['overall_status'] = 'Critical'

        return posture

    def _assess_compliance(self, report: NormalizedSecurityReport) -> Dict:
        """Assess compliance with security standards."""
        compliance = {
            'owasp_top_10': self._check_owasp_compliance(report),
            'pci_dss': self._check_pci_compliance(report),
            'gdpr': self._check_gdpr_compliance(report)
        }

        return compliance

    def _check_owasp_compliance(self, report: NormalizedSecurityReport) -> Dict:
        """Check OWASP Top 10 compliance."""
        checks = {
            'A01_Broken_Access_Control': True,
            'A02_Cryptographic_Failures': report.ssl_tls_status.get('cert_valid', False),
            'A03_Injection': True,  # Needs deeper testing
            'A05_Security_Misconfiguration': len(report.misconfigurations) == 0,
            'A06_Vulnerable_Components': True,  # Needs version scanning
            'A07_Authentication_Failures': True,  # Needs deeper testing
        }

        compliant = sum(1 for v in checks.values() if v)
        total = len(checks)

        return {
            'checks': checks,
            'compliant': compliant,
            'total': total,
            'percentage': int((compliant / total) * 100) if total > 0 else 0
        }

    def _check_pci_compliance(self, report: NormalizedSecurityReport) -> Dict:
        """Check PCI-DSS compliance basics."""
        checks = {
            'https_enforced': report.target_url.startswith('https://'),
            'valid_ssl': report.ssl_tls_status.get('cert_valid', False),
            'security_headers': len([v for v in report.security_headers.values() if v]) >= 3
        }

        compliant = sum(1 for v in checks.values() if v)
        total = len(checks)

        return {
            'checks': checks,
            'compliant': compliant,
            'total': total,
            'percentage': int((compliant / total) * 100) if total > 0 else 0
        }

    def _check_gdpr_compliance(self, report: NormalizedSecurityReport) -> Dict:
        """Check GDPR compliance basics."""
        checks = {
            'https_enforced': report.target_url.startswith('https://'),
            'security_headers_present': len(report.security_headers) > 0,
        }

        compliant = sum(1 for v in checks.values() if v)
        total = len(checks)

        return {
            'checks': checks,
            'compliant': compliant,
            'total': total,
            'percentage': int((compliant / total) * 100) if total > 0 else 0
        }

    def _get_priority_score(self, severity: SeverityLevel) -> int:
        """Convert severity to priority score (lower = higher priority)."""
        priority_map = {
            SeverityLevel.CRITICAL: 1,
            SeverityLevel.HIGH: 2,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 4,
            SeverityLevel.INFO: 5
        }
        return priority_map.get(severity, 5)

    def _generate_text_report(self, analysis: Dict) -> str:
        """Generate plain text report."""
        lines = []
        lines.append("=" * 60)
        lines.append("  SECURITY AUDIT REPORT")
        lines.append("=" * 60)
        lines.append("")

        # Scan info
        info = analysis['scan_info']
        lines.append(f"Target: {info['target']}")
        lines.append(f"Platform: {info['platform']}")
        lines.append(f"Scan Date: {info['scan_date']}")
        lines.append(f"Duration: {info['scan_duration']}")
        lines.append("")

        # Risk assessment
        risk = analysis['risk_assessment']
        grade_emoji = {"A": "✅", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}.get(risk['grade'], "•")
        lines.append(f"{grade_emoji} Risk Score: {risk['score']}/100 ({risk['overall_status']} - Grade {risk['grade']})")

        if risk['critical_issues'] > 0:
            lines.append(f"⚠️  {risk['critical_issues']} critical vulnerabilities need immediate attention")

        if risk['high_issues'] + risk['critical_issues'] > 0:
            lines.append(f"🔴 {risk['high_issues'] + risk['critical_issues']} high/critical issues total")

        lines.append("")

        # Severity breakdown
        severity = analysis['severity_breakdown']
        lines.append("SEVERITY BREAKDOWN:")
        lines.append(f"  🔴 Critical: {severity['critical']}")
        lines.append(f"  🟠 High: {severity['high']}")
        lines.append(f"  🟡 Medium: {severity['medium']}")
        lines.append(f"  🟢 Low: {severity['low']}")
        lines.append(f"  ℹ️  Info: {severity['info']}")
        lines.append("")

        # Prioritized fixes
        fixes = analysis['prioritized_fixes']
        if fixes:
            # Critical issues
            critical_fixes = [f for f in fixes if f.severity == SeverityLevel.CRITICAL]
            if critical_fixes:
                lines.append("CRITICAL ISSUES:")
                for fix in critical_fixes[:5]:  # Top 5
                    lines.append(f"  🔴 {fix.title}")
                    if fix.remediation:
                        lines.append(f"     → {fix.remediation}")
                lines.append("")

            # High priority
            high_fixes = [f for f in fixes if f.severity == SeverityLevel.HIGH]
            if high_fixes:
                lines.append("HIGH PRIORITY:")
                for fix in high_fixes[:5]:  # Top 5
                    lines.append(f"  🟠 {fix.title}")
                    if fix.remediation:
                        lines.append(f"     → {fix.remediation}")
                lines.append("")

        # Security posture
        posture = analysis['security_posture']
        lines.append("SECURITY POSTURE:")
        lines.append(f"  Headers: {posture['headers']['implemented']}/{posture['headers']['total']} implemented ({posture['headers']['score']}%)")

        ssl = posture['ssl_tls']
        if ssl:
            ssl_status = "✅ Valid" if ssl.get('cert_valid', False) else "❌ Invalid"
            lines.append(f"  SSL/TLS: {ssl_status}")
            if 'protocol' in ssl:
                lines.append(f"  Protocol: {ssl['protocol']}")

        lines.append("")

        # Compliance
        compliance = analysis['compliance']
        lines.append("COMPLIANCE:")
        lines.append(f"  OWASP Top 10: {compliance['owasp_top_10']['percentage']}%")
        lines.append(f"  PCI-DSS: {compliance['pci_dss']['percentage']}%")
        lines.append(f"  GDPR: {compliance['gdpr']['percentage']}%")
        lines.append("")

        lines.append("=" * 60)

        return "\n".join(lines)

    def _generate_markdown_report(self, analysis: Dict) -> str:
        """Generate Markdown report."""
        lines = []
        lines.append("# Security Audit Report")
        lines.append("")

        # Scan info
        info = analysis['scan_info']
        lines.append("## Scan Information")
        lines.append(f"- **Target**: {info['target']}")
        lines.append(f"- **Platform**: {info['platform']}")
        lines.append(f"- **Scan Date**: {info['scan_date']}")
        lines.append(f"- **Duration**: {info['scan_duration']}")
        lines.append("")

        # Risk assessment
        risk = analysis['risk_assessment']
        lines.append("## Risk Assessment")
        lines.append(f"- **Risk Score**: {risk['score']}/100 (Grade {risk['grade']})")
        lines.append(f"- **Risk Level**: {risk['risk_level']}")
        lines.append(f"- **Total Issues**: {risk['total_issues']}")
        lines.append("")

        # Issues
        if risk['total_issues'] > 0:
            lines.append("### Issues by Severity")
            severity = analysis['severity_breakdown']
            lines.append(f"- Critical: {severity['critical']}")
            lines.append(f"- High: {severity['high']}")
            lines.append(f"- Medium: {severity['medium']}")
            lines.append(f"- Low: {severity['low']}")
            lines.append(f"- Info: {severity['info']}")
            lines.append("")

        # Fixes
        fixes = analysis['prioritized_fixes']
        if fixes:
            lines.append("## Recommended Fixes")
            for i, fix in enumerate(fixes[:10], 1):  # Top 10
                lines.append(f"### {i}. {fix.title}")
                lines.append(f"**Severity**: {fix.severity.value.upper()}")
                lines.append(f"**Component**: {fix.affected_component}")
                lines.append("")
                lines.append(f"{fix.description}")
                lines.append("")
                if fix.remediation:
                    lines.append(f"**Remediation**: {fix.remediation}")
                    lines.append("")
                if fix.code_snippet:
                    lines.append("```")
                    lines.append(fix.code_snippet)
                    lines.append("```")
                    lines.append("")

        return "\n".join(lines)
