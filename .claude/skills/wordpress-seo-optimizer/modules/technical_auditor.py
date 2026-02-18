"""
Technical SEO Auditor Module

Performs technical SEO audits including mobile-friendliness,
schema markup detection, HTTPS checks, and basic Core Web Vitals.
"""

import re
import json
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse


class TechnicalAuditor:
    """Audit technical SEO elements."""

    def __init__(self):
        """Initialize technical auditor."""
        pass

    def audit(self, url: str, html_content: str) -> Dict:
        """
        Perform comprehensive technical SEO audit.

        Args:
            url: Page URL
            html_content: Full HTML content of the page

        Returns:
            Technical audit results with scores and recommendations
        """
        soup = BeautifulSoup(html_content, 'html.parser')

        # Run all audits
        https_check = self._check_https(url)
        mobile_check = self._check_mobile_friendly(soup)
        schema_check = self._check_schema_markup(soup)
        canonical_check = self._check_canonical(soup, url)
        meta_robots_check = self._check_meta_robots(soup)

        # Calculate score (max 15 points for MVP)
        score = 0
        score += 3 if https_check['passed'] else 0
        score += 3 if mobile_check['passed'] else 0
        score += 5 if schema_check['has_schema'] else 0
        score += 2 if canonical_check['passed'] else 0
        score += 2 if meta_robots_check['passed'] else 0

        # Collect issues and recommendations
        issues = []
        recommendations = []

        if not https_check['passed']:
            issues.append(https_check['message'])
            recommendations.append("Enable HTTPS (SSL certificate required)")

        if not mobile_check['passed']:
            issues.extend(mobile_check['issues'])
            recommendations.extend(mobile_check['recommendations'])

        if not schema_check['has_schema']:
            issues.append("No schema markup found")
            recommendations.append("Add structured data (Article, FAQPage, etc.)")
        elif schema_check['issues']:
            issues.extend(schema_check['issues'])
            recommendations.extend(schema_check['recommendations'])

        if not canonical_check['passed']:
            issues.append(canonical_check['message'])
            recommendations.append("Add canonical tag to prevent duplicate content")

        if not meta_robots_check['passed']:
            issues.append(meta_robots_check['message'])

        return {
            'score': score,
            'max_score': 15,
            'https': https_check,
            'mobile': mobile_check,
            'schema': schema_check,
            'canonical': canonical_check,
            'meta_robots': meta_robots_check,
            'issues': issues,
            'recommendations': recommendations,
            'passed': score >= 12
        }

    def _check_https(self, url: str) -> Dict:
        """Check if URL uses HTTPS."""
        parsed = urlparse(url)
        is_https = parsed.scheme == 'https'

        return {
            'passed': is_https,
            'protocol': parsed.scheme,
            'message': '✅ HTTPS enabled' if is_https else '⚠️ Site not using HTTPS'
        }

    def _check_mobile_friendly(self, soup: BeautifulSoup) -> Dict:
        """
        Check for mobile-friendly indicators.

        For MVP: Basic checks. Future: Use Google Mobile-Friendly Test API
        """
        issues = []
        recommendations = []

        # Check viewport meta tag
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        has_viewport = viewport is not None

        if not has_viewport:
            issues.append("Missing viewport meta tag")
            recommendations.append("Add <meta name='viewport' content='width=device-width, initial-scale=1.0'>")

        # Check for responsive indicators
        has_responsive_css = False
        for style in soup.find_all('style'):
            if '@media' in style.get_text():
                has_responsive_css = True
                break

        # Check for mobile-unfriendly elements
        # Flash content
        has_flash = soup.find('object', attrs={'type': 'application/x-shockwave-flash'}) is not None
        if has_flash:
            issues.append("Flash content detected (not mobile-friendly)")
            recommendations.append("Remove Flash content")

        # Small text
        small_fonts = soup.find_all('font', attrs={'size': lambda x: x and int(x) < 3})
        if small_fonts:
            issues.append("Small font sizes detected")
            recommendations.append("Use minimum 16px font size for mobile")

        # Overall assessment
        passed = has_viewport and not has_flash

        return {
            'passed': passed,
            'has_viewport': has_viewport,
            'has_responsive_css': has_responsive_css,
            'has_flash': has_flash,
            'issues': issues,
            'recommendations': recommendations,
            'message': '✅ Mobile-friendly' if passed else '⚠️ Mobile issues detected'
        }

    def _check_schema_markup(self, soup: BeautifulSoup) -> Dict:
        """Check for structured data / schema markup."""
        schemas_found = []
        issues = []
        recommendations = []

        # Look for JSON-LD scripts
        json_ld_scripts = soup.find_all('script', attrs={'type': 'application/ld+json'})

        for script in json_ld_scripts:
            try:
                data = json.loads(script.string)
                schema_type = data.get('@type', 'Unknown')
                schemas_found.append(schema_type)
            except (json.JSONDecodeError, AttributeError):
                issues.append("Invalid JSON-LD schema detected")

        # Look for microdata
        microdata_items = soup.find_all(attrs={'itemtype': True})
        for item in microdata_items:
            itemtype = item.get('itemtype', '')
            if 'schema.org' in itemtype:
                schema_type = itemtype.split('/')[-1]
                if schema_type not in schemas_found:
                    schemas_found.append(f"{schema_type} (microdata)")

        # Recommendations based on what's missing
        if 'Article' not in schemas_found and 'BlogPosting' not in schemas_found:
            recommendations.append("Add Article or BlogPosting schema for blog posts")

        if not any('FAQ' in s for s in schemas_found):
            recommendations.append("Consider adding FAQPage schema if you have Q&A content")

        if not any('BreadcrumbList' in s for s in schemas_found):
            recommendations.append("Add BreadcrumbList schema for navigation")

        return {
            'has_schema': len(schemas_found) > 0,
            'schemas': schemas_found,
            'schema_count': len(schemas_found),
            'issues': issues,
            'recommendations': recommendations,
            'message': f'✅ Schema found: {", ".join(schemas_found[:3])}' if schemas_found else '⚠️ No schema markup'
        }

    def _check_canonical(self, soup: BeautifulSoup, url: str) -> Dict:
        """Check canonical tag."""
        canonical = soup.find('link', attrs={'rel': 'canonical'})

        if not canonical:
            return {
                'passed': False,
                'has_canonical': False,
                'canonical_url': None,
                'message': '⚠️ Missing canonical tag'
            }

        canonical_url = canonical.get('href', '')
        is_self_referencing = canonical_url == url

        return {
            'passed': True,
            'has_canonical': True,
            'canonical_url': canonical_url,
            'is_self_referencing': is_self_referencing,
            'message': f'✅ Canonical tag present'
        }

    def _check_meta_robots(self, soup: BeautifulSoup) -> Dict:
        """Check meta robots tag."""
        meta_robots = soup.find('meta', attrs={'name': 'robots'})

        if not meta_robots:
            # No robots tag is fine (defaults to index, follow)
            return {
                'passed': True,
                'content': 'index, follow (default)',
                'message': '✅ Indexable (no robots restriction)'
            }

        content = meta_robots.get('content', '').lower()

        # Check for problematic directives
        is_noindex = 'noindex' in content
        is_nofollow = 'nofollow' in content

        if is_noindex:
            return {
                'passed': False,
                'content': content,
                'message': '⚠️ Page set to noindex (will not appear in search)'
            }

        return {
            'passed': True,
            'content': content,
            'message': f'✅ Robots meta: {content}'
        }

    def check_page_speed_basic(self, html_content: str) -> Dict:
        """
        Basic page speed checks.

        For MVP: Simple checks. Future: Integrate with PageSpeed Insights API
        """
        soup = BeautifulSoup(html_content, 'html.parser')

        issues = []
        recommendations = []

        # Count resources
        images = soup.find_all('img')
        scripts = soup.find_all('script')
        stylesheets = soup.find_all('link', attrs={'rel': 'stylesheet'})

        # Check for optimization opportunities
        # Images without loading="lazy"
        images_without_lazy = [img for img in images if not img.get('loading')]
        if len(images_without_lazy) > 3:
            issues.append(f"{len(images_without_lazy)} images without lazy loading")
            recommendations.append("Add loading='lazy' to below-fold images")

        # Inline scripts (blocking)
        inline_scripts = [s for s in scripts if not s.get('src')]
        if len(inline_scripts) > 5:
            issues.append(f"{len(inline_scripts)} inline scripts (may block rendering)")
            recommendations.append("Move inline scripts to external files or defer")

        # Render-blocking resources
        render_blocking_css = [
            link for link in stylesheets
            if not link.get('media') or link.get('media') == 'all'
        ]
        if len(render_blocking_css) > 3:
            recommendations.append("Consider inlining critical CSS and deferring non-critical styles")

        return {
            'resource_counts': {
                'images': len(images),
                'scripts': len(scripts),
                'stylesheets': len(stylesheets),
                'inline_scripts': len(inline_scripts)
            },
            'optimization_opportunities': {
                'images_without_lazy': len(images_without_lazy),
                'inline_scripts': len(inline_scripts),
                'render_blocking_css': len(render_blocking_css)
            },
            'issues': issues,
            'recommendations': recommendations
        }


class SchemaValidator:
    """Validate schema markup."""

    @staticmethod
    def validate_article_schema(schema_data: Dict) -> Dict:
        """Validate Article schema."""
        required_fields = ['headline', 'author', 'datePublished']
        recommended_fields = ['image', 'publisher', 'dateModified']

        missing_required = [f for f in required_fields if f not in schema_data]
        missing_recommended = [f for f in recommended_fields if f not in schema_data]

        is_valid = len(missing_required) == 0

        return {
            'valid': is_valid,
            'missing_required': missing_required,
            'missing_recommended': missing_recommended,
            'message': '✅ Valid Article schema' if is_valid else f'❌ Missing required fields: {", ".join(missing_required)}'
        }

    @staticmethod
    def validate_faq_schema(schema_data: Dict) -> Dict:
        """Validate FAQPage schema."""
        has_main_entity = 'mainEntity' in schema_data

        if not has_main_entity:
            return {
                'valid': False,
                'message': '❌ FAQPage missing mainEntity'
            }

        questions = schema_data.get('mainEntity', [])
        if not isinstance(questions, list):
            questions = [questions]

        valid_questions = 0
        for q in questions:
            if '@type' in q and q['@type'] == 'Question':
                if 'name' in q and 'acceptedAnswer' in q:
                    valid_questions += 1

        is_valid = valid_questions > 0

        return {
            'valid': is_valid,
            'question_count': len(questions),
            'valid_questions': valid_questions,
            'message': f'✅ {valid_questions} valid FAQ questions' if is_valid else '❌ No valid FAQ questions found'
        }


if __name__ == "__main__":
    # Test technical auditor
    auditor = TechnicalAuditor()

    test_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="canonical" href="https://example.com/test">
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "Article",
            "headline": "Test Article",
            "author": {"@type": "Person", "name": "John Doe"},
            "datePublished": "2026-02-11"
        }
        </script>
    </head>
    <body>
        <h1>Test Page</h1>
        <img src="test.jpg" alt="Test" loading="lazy">
    </body>
    </html>
    """

    result = auditor.audit('https://example.com/test', test_html)

    print("Technical SEO Audit Results:")
    print(f"Score: {result['score']}/{result['max_score']}")
    print(f"\nHTTPS: {result['https']['message']}")
    print(f"Mobile: {result['mobile']['message']}")
    print(f"Schema: {result['schema']['message']}")
    print(f"Canonical: {result['canonical']['message']}")

    if result['issues']:
        print(f"\nIssues:")
        for issue in result['issues']:
            print(f"  ⚠️  {issue}")

    if result['recommendations']:
        print(f"\nRecommendations:")
        for rec in result['recommendations']:
            print(f"  • {rec}")
