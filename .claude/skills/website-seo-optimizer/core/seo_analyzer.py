"""
SEO Analyzer - Main Orchestrator

Combines all analysis modules to provide comprehensive SEO analysis
and scoring for any website content.

ADAPTED FOR MULTI-PLATFORM: Works with NormalizedContent from any connector.
"""

from typing import Dict, List, Optional, Union
from .keyword_analyzer import KeywordAnalyzer, extract_keywords_from_title
from .onpage_optimizer import OnPageOptimizer


class SEOAnalyzer:
    """Main SEO analyzer that orchestrates all analysis modules."""

    def __init__(self):
        """Initialize SEO analyzer with all sub-analyzers."""
        self.keyword_analyzer = KeywordAnalyzer()
        self.onpage_optimizer = OnPageOptimizer()

    def analyze(self, content: Union[Dict, 'NormalizedContent'], target_keyword: Optional[str] = None) -> Dict:
        """
        Perform comprehensive SEO analysis.

        Args:
            content: Either:
                - NormalizedContent object from connector
                - Dictionary with keys: title, content, meta_description, url_slug
            target_keyword: Primary keyword (optional, will auto-detect if not provided)

        Returns:
            Comprehensive SEO analysis report with:
                - overall_score: 0-100
                - keyword_analysis: Keyword analysis results
                - onpage_analysis: On-page SEO results
                - issues: List of issues found
                - recommendations: Prioritized recommendations
                - score_breakdown: Detailed score breakdown
        """
        # Handle both NormalizedContent and dict
        if hasattr(content, 'title'):
            # NormalizedContent object
            post_data = {
                'title': content.title,
                'content': content.content,
                'meta_description': content.meta_description,
                'url_slug': content.url_slug,
            }
        else:
            post_data = content

        # Auto-detect target keyword if not provided
        if not target_keyword:
            target_keyword = self._detect_primary_keyword(post_data)

        # Prepare data for analysis
        title = post_data.get('title', '')
        html_content = post_data.get('content', '')
        meta_description = post_data.get('meta_description', '')
        url_slug = post_data.get('url_slug', '')

        # Extract headings from content
        headings = self._extract_headings(html_content)

        # Run keyword analysis
        keyword_analysis = self.keyword_analyzer.analyze_content(
            content=html_content,
            target_keyword=target_keyword,
            title=title,
            meta_description=meta_description,
            headings=headings
        )

        # Run on-page analysis
        onpage_data = {
            'title': title,
            'content': html_content,
            'meta_description': meta_description,
            'url_slug': url_slug,
            'target_keyword': target_keyword
        }
        onpage_analysis = self.onpage_optimizer.analyze_onpage(onpage_data)

        # Calculate overall score (0-100)
        keyword_score = keyword_analysis['score']  # Out of 100
        onpage_score = onpage_analysis['overall_score']  # Out of 70

        # Normalize to 100-point scale
        overall_score = int(
            (keyword_score * 0.15) +  # 15% weight
            (onpage_score / 70 * 85)  # 85% weight
        )

        # Collect all issues
        all_issues = []
        all_issues.extend(keyword_analysis.get('recommendations', []))
        all_issues.extend(onpage_analysis.get('issues', []))

        # Collect recommendations with priority
        recommendations = self._prioritize_recommendations(
            keyword_analysis,
            onpage_analysis
        )

        # Score breakdown for visualization
        score_breakdown = {
            'keyword': {
                'score': keyword_score,
                'max': 100,
                'percentage': keyword_score,
                'status': self._get_status(keyword_score, 100)
            },
            'title': {
                'score': onpage_analysis['title']['score'],
                'max': onpage_analysis['title']['max_score'],
                'percentage': int(onpage_analysis['title']['score'] / onpage_analysis['title']['max_score'] * 100),
                'status': 'optimal' if onpage_analysis['title']['optimal'] else 'needs work'
            },
            'meta_description': {
                'score': onpage_analysis['meta_description']['score'],
                'max': onpage_analysis['meta_description']['max_score'],
                'percentage': int(onpage_analysis['meta_description']['score'] / onpage_analysis['meta_description']['max_score'] * 100),
                'status': 'optimal' if onpage_analysis['meta_description']['optimal'] else 'needs work'
            },
            'headers': {
                'score': onpage_analysis['headers']['score'],
                'max': onpage_analysis['headers']['max_score'],
                'percentage': int(onpage_analysis['headers']['score'] / onpage_analysis['headers']['max_score'] * 100),
                'status': 'optimal' if onpage_analysis['headers']['optimal'] else 'needs work'
            },
            'content': {
                'score': onpage_analysis['content']['score'],
                'max': onpage_analysis['content']['max_score'],
                'percentage': int(onpage_analysis['content']['score'] / onpage_analysis['content']['max_score'] * 100),
                'status': 'optimal' if onpage_analysis['content']['optimal'] else 'needs work'
            },
            'images': {
                'score': onpage_analysis['images']['score'],
                'max': onpage_analysis['images']['max_score'],
                'percentage': int(onpage_analysis['images']['score'] / onpage_analysis['images']['max_score'] * 100),
                'status': 'optimal' if onpage_analysis['images']['optimal'] else 'needs work'
            }
        }

        # Count critical issues
        critical_issues = len([
            r for r in all_issues
            if 'critical' in r.lower() or 'missing' in r.lower()
        ])

        return {
            'overall_score': overall_score,
            'target_keyword': target_keyword,
            'keyword_analysis': keyword_analysis,
            'onpage_analysis': onpage_analysis,
            'issues': all_issues,
            'critical_issues': critical_issues,
            'recommendations': recommendations,
            'score_breakdown': score_breakdown,
            'summary': self._generate_summary(overall_score, critical_issues, len(recommendations))
        }

    def _detect_primary_keyword(self, post_data: Dict) -> str:
        """Auto-detect primary keyword from title."""
        title = post_data.get('title', '')
        candidates = extract_keywords_from_title(title)

        # Return first 2-3 word phrase
        for candidate in candidates:
            if len(candidate.split()) >= 2 and len(candidate.split()) <= 3:
                return candidate

        # Fallback: return first phrase or first word
        return candidates[0] if candidates else "main topic"

    def _extract_headings(self, html_content: str) -> List[str]:
        """Extract all heading text from HTML content."""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        headings = []

        for tag in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            for heading in soup.find_all(tag):
                headings.append(heading.get_text())

        return headings

    def _prioritize_recommendations(
        self,
        keyword_analysis: Dict,
        onpage_analysis: Dict
    ) -> List[Dict]:
        """
        Prioritize recommendations by impact.

        Returns list of recommendations with priority levels:
        - CRITICAL: Must fix (missing H1, missing meta description)
        - HIGH: Important optimizations (keyword density, image alt)
        - MEDIUM: Helpful improvements (readability, internal links)
        - LOW: Nice to have (URL optimization, etc.)
        """
        recommendations = []

        # CRITICAL: Missing essential elements
        if onpage_analysis['meta_description']['score'] == 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Meta Description',
                'issue': 'Meta description missing',
                'action': 'Add meta description (150-160 characters)',
                'impact': '+10 points'
            })

        if onpage_analysis['headers']['h1_count'] == 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Headers',
                'issue': 'No H1 heading',
                'action': f"Add H1 heading with '{keyword_analysis['target_keyword']}'",
                'impact': '+5 points'
            })

        # HIGH: Keyword optimization
        if not keyword_analysis['placement']['in_title']:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Keywords',
                'issue': 'Target keyword not in title',
                'action': f"Include '{keyword_analysis['target_keyword']}' in title tag",
                'impact': '+15 points'
            })

        if keyword_analysis['density'] < 1.0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Keywords',
                'issue': f"Keyword density too low ({keyword_analysis['density']}%)",
                'action': f"Increase to 1.5%",
                'impact': '+5-10 points'
            })

        # HIGH: Image optimization
        if onpage_analysis['images']['total_images'] > 0:
            if onpage_analysis['images']['alt_percentage'] < 100:
                missing = onpage_analysis['images']['total_images'] - onpage_analysis['images']['images_with_alt']
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Images',
                    'issue': f"{missing} images missing alt text",
                    'action': 'Add descriptive alt text to all images',
                    'impact': f'+{10 - onpage_analysis["images"]["score"]} points'
                })

        # MEDIUM: Content quality
        if onpage_analysis['content']['word_count'] < 1000:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Content',
                'issue': f"Content too short ({onpage_analysis['content']['word_count']} words)",
                'action': 'Expand content to 1000+ words',
                'impact': '+5 points'
            })

        # MEDIUM: Header structure
        if onpage_analysis['headers']['h2_count'] < 2:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Headers',
                'issue': 'Insufficient H2 headings',
                'action': 'Add more H2 headings to structure content',
                'impact': '+3 points'
            })

        # LOW: URL optimization
        if not onpage_analysis['url']['has_keyword']:
            recommendations.append({
                'priority': 'LOW',
                'category': 'URL',
                'issue': 'Keyword not in URL',
                'action': f"Include '{keyword_analysis['target_keyword']}' in URL slug",
                'impact': '+3 points'
            })

        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        recommendations.sort(key=lambda x: priority_order[x['priority']])

        return recommendations

    def _get_status(self, score: int, max_score: int) -> str:
        """Get status label based on score percentage."""
        percentage = score / max_score * 100
        if percentage >= 90:
            return 'excellent'
        elif percentage >= 70:
            return 'good'
        elif percentage >= 50:
            return 'needs work'
        else:
            return 'poor'

    def _generate_summary(
        self,
        overall_score: int,
        critical_issues: int,
        total_recommendations: int
    ) -> str:
        """Generate human-readable summary."""
        if overall_score >= 90:
            grade = "Excellent"
            emoji = "✅"
        elif overall_score >= 70:
            grade = "Good"
            emoji = "✅"
        elif overall_score >= 50:
            grade = "Needs Work"
            emoji = "⚠️"
        else:
            grade = "Poor"
            emoji = "❌"

        summary = f"{emoji} SEO Score: {overall_score}/100 ({grade})\n"

        if critical_issues > 0:
            summary += f"⚠️  {critical_issues} critical issue(s) need immediate attention\n"

        summary += f"📋 {total_recommendations} optimization opportunities identified"

        return summary

    def generate_report(self, analysis: Dict, format: str = 'text') -> str:
        """
        Generate formatted analysis report.

        Args:
            analysis: Analysis results from analyze()
            format: Output format ('text', 'markdown', 'json')

        Returns:
            Formatted report string
        """
        if format == 'text' or format == 'markdown':
            return self._generate_text_report(analysis)
        elif format == 'json':
            import json
            return json.dumps(analysis, indent=2)
        else:
            raise ValueError(f"Unknown format: {format}")

    def _generate_text_report(self, analysis: Dict) -> str:
        """Generate text/markdown formatted report."""
        report = []

        # Header
        report.append("="*60)
        report.append("  SEO ANALYSIS REPORT")
        report.append("="*60)
        report.append("")

        # Summary
        report.append(analysis['summary'])
        report.append("")

        # Target keyword
        report.append(f"Target Keyword: \"{analysis['target_keyword']}\"")
        report.append("")

        # Score breakdown
        report.append("SCORE BREAKDOWN:")
        report.append("-"*60)
        for category, data in analysis['score_breakdown'].items():
            bar = self._create_progress_bar(data['percentage'])
            status_icon = "✅" if data['status'] == 'optimal' else "⚠️"
            report.append(f"  {status_icon} {category.replace('_', ' ').title()}: {bar} {data['score']}/{data['max']}")
        report.append("")

        # Keyword analysis
        ka = analysis['keyword_analysis']
        report.append("KEYWORDS:")
        report.append(f"  Density: {ka['density']}% (Target: {ka['target_density']}%)")
        report.append(f"  Keyword Count: {ka['keyword_count']}")
        report.append(f"  Word Count: {ka['word_count']}")
        report.append(f"  Placement:")
        for key, value in ka['placement'].items():
            icon = "✅" if value else "❌"
            report.append(f"    {icon} {key.replace('_', ' ').title()}")

        if ka.get('lsi_keywords'):
            report.append(f"  LSI Keywords: {', '.join(ka['lsi_keywords'][:3])}")
        report.append("")

        # Recommendations
        recommendations = analysis['recommendations']
        if recommendations:
            report.append("RECOMMENDATIONS:")
            report.append("-"*60)

            # Group by priority
            for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                priority_recs = [r for r in recommendations if r['priority'] == priority]
                if priority_recs:
                    icon = "🔴" if priority == 'CRITICAL' else "🟠" if priority == 'HIGH' else "🟡" if priority == 'MEDIUM' else "🟢"
                    report.append(f"\n{icon} {priority} PRIORITY:")
                    for i, rec in enumerate(priority_recs, 1):
                        report.append(f"  {i}. {rec['category']}: {rec['action']}")
                        if rec.get('impact'):
                            report.append(f"     Impact: {rec['impact']}")

        report.append("")
        report.append("="*60)

        return "\n".join(report)

    def _create_progress_bar(self, percentage: int, width: int = 20) -> str:
        """Create ASCII progress bar."""
        filled = int(width * percentage / 100)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {percentage}%"
