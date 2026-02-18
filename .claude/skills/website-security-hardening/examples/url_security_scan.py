#!/usr/bin/env python3
"""
URL Security Scanner Example

Demonstrates how to use the URL security scanner to audit any website.

Usage:
    python examples/url_security_scan.py https://example.com
    python examples/url_security_scan.py https://example.com --format markdown
    python examples/url_security_scan.py https://example.com --format json
"""

import sys
import os
import io

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners import URLSecurityScanner, SeverityLevel
from core import SecurityAnalyzer


def print_separator(char="=", length=60):
    """Print a separator line."""
    print(char * length)


def print_issue(issue, index=None):
    """Print a single issue with formatting."""
    severity_emoji = {
        SeverityLevel.CRITICAL: "🔴",
        SeverityLevel.HIGH: "🟠",
        SeverityLevel.MEDIUM: "🟡",
        SeverityLevel.LOW: "🟢",
        SeverityLevel.INFO: "ℹ️"
    }

    emoji = severity_emoji.get(issue.severity, "•")
    prefix = f"{index}. " if index else ""

    # Handle both Vulnerability and Misconfiguration objects
    title = getattr(issue, 'title', getattr(issue, 'issue', 'Unknown Issue'))
    component = getattr(issue, 'affected_component', getattr(issue, 'category', 'Unknown'))
    fix = getattr(issue, 'remediation', getattr(issue, 'recommendation', None))

    print(f"{prefix}{emoji} {title}")
    print(f"   Component: {component}")
    if fix:
        print(f"   Fix: {fix}")
    print()


def main():
    """Main execution function."""
    if len(sys.argv) < 2:
        print("Usage: python url_security_scan.py <URL> [--format text|markdown|json]")
        print("\nExamples:")
        print("  python url_security_scan.py https://example.com")
        print("  python url_security_scan.py https://wordpress.org --format markdown")
        sys.exit(1)

    target_url = sys.argv[1]
    output_format = 'text'

    # Parse format argument
    if len(sys.argv) > 2 and sys.argv[2] == '--format' and len(sys.argv) > 3:
        output_format = sys.argv[3]

    print(f"🔒 Security Scan: {target_url}")
    print()

    # Step 1: Test connection
    print("[1/3] Testing connection...")
    scanner = URLSecurityScanner(target_url)
    success, message = scanner.test_connection()

    if not success:
        print(f"❌ Connection failed: {message}")
        sys.exit(1)

    print(f"✅ {message}")
    print()

    # Step 2: Run security scan
    print("[2/3] Running security scan...")
    try:
        report = scanner.scan()
        print(f"✅ Scan complete ({report.scan_duration:.2f}s)")
        print()
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        sys.exit(1)

    # Step 3: Analyze results
    print("[3/3] Analyzing findings...")
    analyzer = SecurityAnalyzer()
    analysis = analyzer.analyze(report)

    severity_counts = report.get_severity_counts()
    total_issues = len(report.vulnerabilities) + len(report.misconfigurations)

    print(f"✅ Found {total_issues} issues (", end="")
    issue_parts = []
    if severity_counts[SeverityLevel.CRITICAL] > 0:
        issue_parts.append(f"{severity_counts[SeverityLevel.CRITICAL]} critical")
    if severity_counts[SeverityLevel.HIGH] > 0:
        issue_parts.append(f"{severity_counts[SeverityLevel.HIGH]} high")
    if severity_counts[SeverityLevel.MEDIUM] > 0:
        issue_parts.append(f"{severity_counts[SeverityLevel.MEDIUM]} medium")
    if severity_counts[SeverityLevel.LOW] > 0:
        issue_parts.append(f"{severity_counts[SeverityLevel.LOW]} low")

    print(", ".join(issue_parts) + ")")
    print()

    # Generate and display report
    if output_format in ['markdown', 'json']:
        # Output formatted report
        report_text = analyzer.generate_report(analysis, format=output_format)
        print(report_text)
    else:
        # Display interactive text report
        print_separator()
        print("  SECURITY AUDIT REPORT")
        print_separator()
        print()

        # Risk score
        risk = analysis['risk_assessment']
        grade_emoji = {
            "A": "✅",
            "B": "🟢",
            "C": "🟡",
            "D": "🟠",
            "F": "🔴"
        }.get(risk['grade'], "•")

        print(f"{grade_emoji} Risk Score: {risk['score']}/100 ({risk['risk_level']} Risk - Grade {risk['grade']})")

        if risk['critical_issues'] > 0:
            print(f"⚠️  {risk['critical_issues']} critical vulnerabilities need immediate attention")

        if risk['high_issues'] + risk['critical_issues'] > 0:
            print(f"🔴 {risk['high_issues'] + risk['critical_issues']} high/critical issues total")

        print()

        # Critical issues
        critical_issues = report.get_critical_issues()
        if critical_issues:
            print("CRITICAL ISSUES:")
            for i, issue in enumerate(critical_issues, 1):
                print_issue(issue, i)

        # High priority issues
        high_priority = report.get_high_priority_issues()
        high_only = [i for i in high_priority if i.severity == SeverityLevel.HIGH]

        if high_only:
            print("HIGH PRIORITY:")
            for i, issue in enumerate(high_only[:5], 1):  # Top 5
                print_issue(issue, i)

        # Security posture
        posture = analysis['security_posture']
        print("SECURITY POSTURE:")
        print(f"  Headers: {posture['headers']['implemented']}/{posture['headers']['total']} implemented ({posture['headers']['score']}%)")

        ssl = posture['ssl_tls']
        if ssl:
            ssl_status = "✅ Valid" if ssl.get('cert_valid', False) else "❌ Invalid"
            print(f"  SSL/TLS: {ssl_status}")
            if 'protocol' in ssl:
                print(f"  Protocol: {ssl['protocol']}")
            if 'expires_in_days' in ssl:
                days = ssl['expires_in_days']
                if days > 30:
                    print(f"  Certificate: ✅ Valid ({days} days until expiry)")
                else:
                    print(f"  Certificate: ⚠️  Expires in {days} days")

        print()

        # Compliance summary
        compliance = analysis['compliance']
        print("COMPLIANCE:")
        print(f"  OWASP Top 10: {compliance['owasp_top_10']['percentage']}%")
        print(f"  PCI-DSS: {compliance['pci_dss']['percentage']}%")
        print(f"  GDPR: {compliance['gdpr']['percentage']}%")
        print()

        print_separator()

        # Recommendations summary
        if risk['score'] < 70:
            print()
            print("⚠️  RECOMMENDATIONS:")
            print("   1. Address critical and high priority issues immediately")
            print("   2. Implement missing security headers")
            print("   3. Ensure HTTPS is properly configured")
            print("   4. Review and update security configurations regularly")
            print()

    # Exit with appropriate code
    if severity_counts[SeverityLevel.CRITICAL] > 0:
        sys.exit(2)  # Critical issues found
    elif severity_counts[SeverityLevel.HIGH] > 0:
        sys.exit(1)  # High priority issues found
    else:
        sys.exit(0)  # No critical/high issues


if __name__ == '__main__':
    main()
