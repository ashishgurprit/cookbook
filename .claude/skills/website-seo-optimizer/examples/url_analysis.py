#!/usr/bin/env python3
"""
URL Analysis Example

Demonstrates end-to-end SEO analysis of any public URL.

Usage:
    python examples/url_analysis.py https://example.com
    python examples/url_analysis.py https://github.com --keyword "open source"
"""

import sys
import os
import io

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from connectors import create_url_connector, ConnectorError
from core import SEOAnalyzer


def main():
    """Main analysis workflow."""
    # Parse arguments
    if len(sys.argv) < 2:
        print("Usage: python url_analysis.py <url> [--keyword <keyword>]")
        print("\nExamples:")
        print("  python url_analysis.py https://example.com")
        print("  python url_analysis.py https://github.com --keyword 'open source'")
        sys.exit(1)

    url = sys.argv[1]
    target_keyword = None

    # Parse optional keyword argument
    if len(sys.argv) >= 4 and sys.argv[2] == '--keyword':
        target_keyword = sys.argv[3]

    print(f"Analyzing URL: {url}")
    if target_keyword:
        print(f"Target Keyword: {target_keyword}")
    print()

    try:
        # Step 1: Create connector and fetch content
        print("[1/3] Fetching content...")
        connector = create_url_connector()
        content = connector.fetch(url)
        print(f"✅ Fetched: {content.title}")
        print(f"   Word count: {content.word_count}")
        print(f"   Images: {len(content.images)}")
        print(f"   Links: {len(content.links)}")
        print()

        # Step 2: Analyze SEO
        print("[2/3] Analyzing SEO...")
        analyzer = SEOAnalyzer()
        analysis = analyzer.analyze(content, target_keyword=target_keyword)
        print("✅ Analysis complete")
        print()

        # Step 3: Generate and display report
        print("[3/3] Generating report...")
        report = analyzer.generate_report(analysis, format='text')
        print()
        print(report)

        # Display optimization suggestions if score < 80
        if analysis['overall_score'] < 80:
            print("\n" + "="*60)
            print("  OPTIMIZATION SUGGESTIONS")
            print("="*60)
            print()

            # Generate optimized title if needed
            if analysis['onpage_analysis']['title']['score'] < 13:
                optimized_title = analyzer.onpage_optimizer.generate_optimized_title(
                    content.title,
                    analysis['target_keyword']
                )
                print(f"Optimized Title:")
                print(f"  Current:  {content.title}")
                print(f"  Suggest:  {optimized_title}")
                print()

            # Generate optimized meta description if needed
            if analysis['onpage_analysis']['meta_description']['score'] < 9:
                optimized_meta = analyzer.onpage_optimizer.generate_optimized_meta_description(
                    content.content,
                    analysis['target_keyword']
                )
                print(f"Optimized Meta Description:")
                print(f"  Current:  {content.meta_description or '(none)'}")
                print(f"  Suggest:  {optimized_meta}")
                print()

    except ConnectorError as e:
        print(f"❌ Error fetching URL: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
