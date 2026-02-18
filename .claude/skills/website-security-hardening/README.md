# Website Security Hardening

**Multi-platform security auditing and hardening system**

Scan websites for security vulnerabilities and misconfigurations across multiple platforms including WordPress, Ghost, generic URLs, static sites, and more.

## Features

### Phase 1: Core Foundation + URL Scanner ✅ (Current)

- **HTTP/HTTPS Security Scanning**: Audit any website without authentication
- **Security Headers Analysis**: Check for OWASP-recommended headers
- **SSL/TLS Validation**: Certificate validity, protocol versions, cipher strength
- **Information Disclosure Detection**: Exposed files, directory listing, server headers
- **Common Path Scanning**: Admin panels, sensitive endpoints
- **HTTP Method Testing**: Dangerous methods (PUT, DELETE, TRACE)
- **Risk Scoring**: 0-100 score with A-F grading
- **Compliance Checking**: OWASP Top 10, PCI-DSS, GDPR basics
- **Multiple Report Formats**: Text, Markdown, JSON

### Coming Soon

- **Phase 2**: WordPress & Ghost CMS-specific scanners with automated hardening
- **Phase 3**: SSH server security auditing and hardening
- **Phase 4**: Advanced reporting (HTML, PDF) and comprehensive documentation

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Basic URL Scan

```bash
python examples/url_security_scan.py https://example.com
```

### Output Formats

```bash
# Plain text (default)
python examples/url_security_scan.py https://example.com

# Markdown
python examples/url_security_scan.py https://example.com --format markdown

# JSON
python examples/url_security_scan.py https://example.com --format json
```

## Usage Examples

### Example 1: Scan Your Website

```bash
python examples/url_security_scan.py https://mywebsite.com
```

**Output:**
```
🔒 Security Scan: https://mywebsite.com

[1/3] Testing connection...
✅ Connected successfully (Status: 200)

[2/3] Running security scan...
✅ Scan complete (4.23s)

[3/3] Analyzing findings...
✅ Found 8 issues (2 critical, 3 high, 2 medium, 1 low)

============================================================
  SECURITY AUDIT REPORT
============================================================

🟠 Risk Score: 45/100 (Needs Improvement - Grade D)
⚠️  2 critical vulnerabilities need immediate attention
🔴 5 high/critical issues total

CRITICAL ISSUES:
  1. 🔴 Missing HSTS header
     → Add: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

  2. 🔴 Missing Content Security Policy header
     → Add: Header always set Content-Security-Policy "default-src 'self'"

HIGH PRIORITY:
  1. 🟠 SSL certificate expires in 15 days
     → Renew SSL certificate before expiration

  2. 🟠 Missing X-Frame-Options header
     → Add: Header always set X-Frame-Options "SAMEORIGIN"
```

### Example 2: Scan WordPress Site

```bash
python examples/url_security_scan.py https://wordpress-site.com
```

The scanner automatically detects exposed WordPress paths like `/wp-admin`, `/wp-config.php`, and checks for common WordPress vulnerabilities.

### Example 3: Generate Markdown Report

```bash
python examples/url_security_scan.py https://example.com --format markdown > report.md
```

## Architecture

The system follows a **connector pattern** similar to the website-seo-optimizer:

```
[Security Connector] → [NormalizedSecurityReport] → [Security Analyzers] → [Report]
```

### Core Components

1. **BaseSecurityConnector** (Abstract Class)
   - Defines interface for all scanners
   - `scan()` → Returns NormalizedSecurityReport
   - `test_connection()` → Validates target accessibility

2. **NormalizedSecurityReport** (Data Class)
   - Standardized format for all security data
   - Vulnerabilities, misconfigurations, security headers
   - SSL/TLS status, risk score, metadata

3. **SecurityAnalyzer**
   - Analyzes normalized reports
   - Calculates risk scores (0-100)
   - Prioritizes fixes by severity
   - Generates formatted reports

4. **VulnerabilityScanner**
   - Detects known vulnerabilities
   - CVE checking (when versions detected)
   - Weak encryption detection
   - Default credentials indicators

5. **ConfigurationAuditor**
   - Audits security configurations
   - OWASP header compliance
   - Cookie security (Secure, HttpOnly, SameSite)
   - CORS misconfigurations

## Security Checks

### URL Scanner (Phase 1)

#### Security Headers (15 checks)
- ✅ Strict-Transport-Security (HSTS)
- ✅ Content-Security-Policy (CSP)
- ✅ X-Frame-Options
- ✅ X-Content-Type-Options
- ✅ X-XSS-Protection
- ✅ Referrer-Policy
- ✅ Permissions-Policy

#### SSL/TLS (10 checks)
- ✅ Certificate validity
- ✅ Certificate expiration
- ✅ Protocol version (TLS 1.2+)
- ✅ Cipher suite strength

#### Information Disclosure (8 checks)
- ✅ Server header exposure
- ✅ X-Powered-By header
- ✅ Directory listing
- ✅ Exposed `.git` directory
- ✅ Exposed `.env` files
- ✅ Exposed backup files

#### HTTP Methods (5 checks)
- ✅ PUT method
- ✅ DELETE method
- ✅ TRACE method (XST attack)

## Risk Scoring System

### Score Calculation (0-100)

**Starting Score**: 100 (perfect security)

**Deductions**:
- Critical vulnerability: -25 points
- High vulnerability: -15 points
- Medium vulnerability: -10 points
- Low vulnerability: -5 points
- Info: -1 point

**Minimum**: 0 points

### Grade System

- **90-100**: Excellent (A) ✅
- **70-89**: Good (B) 🟢
- **50-69**: Needs Improvement (C) 🟡
- **30-49**: Poor (D) 🟠
- **0-29**: Critical (F) 🔴

## Exit Codes

The scanner uses exit codes to indicate scan results:

- `0`: No critical/high issues found
- `1`: High priority issues found
- `2`: Critical issues found

This makes it easy to integrate into CI/CD pipelines:

```bash
python examples/url_security_scan.py https://example.com
if [ $? -eq 0 ]; then
    echo "Security check passed!"
else
    echo "Security issues detected!"
    exit 1
fi
```

## Python API

### Basic Usage

```python
from scanners import URLSecurityScanner
from core import SecurityAnalyzer

# Create scanner
scanner = URLSecurityScanner('https://example.com')

# Test connection
success, message = scanner.test_connection()
if not success:
    print(f"Connection failed: {message}")
    exit(1)

# Run scan
report = scanner.scan()

# Analyze results
analyzer = SecurityAnalyzer()
analysis = analyzer.analyze(report)

# Generate report
report_text = analyzer.generate_report(analysis, format='text')
print(report_text)
```

### Advanced Usage

```python
from scanners import URLSecurityScanner, SeverityLevel
from core import SecurityAnalyzer

scanner = URLSecurityScanner('https://example.com', timeout=15)
report = scanner.scan()

# Get critical issues only
critical = report.get_critical_issues()
for issue in critical:
    print(f"CRITICAL: {issue.title}")
    print(f"Fix: {issue.remediation}")

# Get high priority issues
high_priority = report.get_high_priority_issues()

# Calculate custom risk score
analyzer = SecurityAnalyzer()
risk_score = analyzer.calculate_risk_score(report)
print(f"Risk Score: {risk_score}/100")

# Get prioritized fixes
fixes = analyzer.prioritize_fixes(report)
for fix in fixes[:5]:  # Top 5 fixes
    print(f"{fix.severity.value.upper()}: {fix.title}")
    print(f"Remediation: {fix.remediation}")
    if fix.code_snippet:
        print(f"Code:\n{fix.code_snippet}")
```

## Roadmap

### ✅ Phase 1: Core Foundation + URL Scanner (Complete)
- HTTP/HTTPS security scanning
- Security headers analysis
- SSL/TLS validation
- Information disclosure detection
- Risk scoring and reporting

### 🚧 Phase 2: WordPress & Ghost Scanners (Coming Soon)
- WordPress-specific vulnerability detection
- Plugin and theme security scanning
- Ghost CMS security analysis
- Automated hardening functions

### 📋 Phase 3: SSH Server Scanner (Planned)
- Server-level security auditing
- Firewall configuration checks
- User account security
- Web server configuration audit

### 📋 Phase 4: Advanced Reporting (Planned)
- HTML report generation
- PDF executive summaries
- Unified CLI interface
- Comprehensive testing suite

## Security Best Practices

### 1. Always Use HTTPS
- Redirect HTTP to HTTPS
- Enable HSTS with preload
- Use valid SSL certificates
- Renew certificates before expiration

### 2. Implement Security Headers
```apache
# .htaccess example
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
```

### 3. Secure Cookies
```
Set-Cookie: sessionid=xyz; Secure; HttpOnly; SameSite=Strict
```

### 4. Remove Information Disclosure
- Hide server version headers
- Disable directory listing
- Remove exposed `.git`, `.env` files
- Turn off debug mode in production

### 5. Regular Updates
- Keep software up to date
- Monitor CVE databases
- Apply security patches promptly

## Compliance

### OWASP Top 10 Coverage

The scanner checks for several OWASP Top 10 vulnerabilities:

- ✅ A02: Cryptographic Failures (SSL/TLS checks)
- ✅ A05: Security Misconfiguration (headers, settings)
- ✅ A06: Vulnerable and Outdated Components (version detection)

### PCI-DSS

Basic PCI-DSS compliance checks:
- HTTPS enforcement
- Valid SSL certificate
- Security headers present

### GDPR

Basic GDPR compliance checks:
- HTTPS enforcement
- Security measures in place

## Troubleshooting

### Connection Timeouts

Increase timeout:
```python
scanner = URLSecurityScanner('https://slow-site.com', timeout=30)
```

### SSL Certificate Errors

The scanner validates SSL certificates. If you encounter self-signed certificate errors:
```python
# For testing only - NOT recommended for production
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

### Rate Limiting

Add delay between checks:
```python
import time
time.sleep(2)  # Wait 2 seconds between scans
```

## Contributing

This is part of the Streamlined Development centralized learning system. To contribute:

1. Make changes in this skill directory
2. Test thoroughly
3. Update VERSION and CHANGELOG.md
4. Submit changes to master repository

## Version

**Current Version**: 1.0.0 (Phase 1 - URL Scanner)

## License

Part of the Streamlined Development project.

## Support

For issues or questions:
- Check this README
- Review example scripts
- Examine test cases

## Acknowledgments

Built following OWASP security guidelines and industry best practices.

**Security Standards**:
- OWASP Top 10
- Mozilla Observatory
- SSL Labs Best Practices
- PCI-DSS Guidelines
