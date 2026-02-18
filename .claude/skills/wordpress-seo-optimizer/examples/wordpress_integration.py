"""
WordPress Integration Example - Phase 2

Demonstrates full WordPress REST API integration including:
1. Connecting to WordPress
2. Fetching and analyzing posts
3. Generating schema markup
4. Applying optimizations
5. Technical SEO audits
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import (
    SEOAnalyzer,
    WordPressConnector,
    create_connector,
    WordPressNotAvailableError,
    TechnicalAuditor,
    SchemaGenerator
)


def example_wordpress_connection():
    """Example 1: Connect to WordPress and list posts."""
    print("="*70)
    print("EXAMPLE 1: Connect to WordPress")
    print("="*70)
    print()

    try:
        # Create connection (will prompt for credentials)
        connector = create_connector()

        # Get SEO plugin info
        plugin_info = connector.get_seo_plugin_info()
        print(f"\n✅ SEO Plugin Detected: {plugin_info['name']}")

        # List recent posts
        print("\n📋 Recent Posts:")
        posts = connector.list_posts(per_page=5, status='publish')

        for i, post in enumerate(posts, 1):
            print(f"\n  {i}. {post['title']}")
            print(f"     ID: {post['id']} | Status: {post['status']}")
            print(f"     Modified: {post['modified']}")

        return connector

    except WordPressNotAvailableError as e:
        print(f"⚠️  {e}")
        return None


def example_analyze_wordpress_post(connector: WordPressConnector, post_id: int):
    """Example 2: Analyze a WordPress post."""
    print("\n" + "="*70)
    print(f"EXAMPLE 2: Analyze WordPress Post {post_id}")
    print("="*70)
    print()

    # Fetch post from WordPress
    print(f"Fetching post {post_id}...")
    post_data = connector.fetch_post(post_id)

    print(f"✅ Retrieved: {post_data['title']}")
    print(f"   Status: {post_data['status']}")
    print(f"   URL: {post_data['link']}")
    print()

    # Analyze SEO
    print("Analyzing SEO...")
    analyzer = SEOAnalyzer()

    # Prepare data for analysis
    analysis_data = {
        'title': post_data['title'],
        'content': post_data['content'],
        'meta_description': post_data['meta_description'],
        'url_slug': post_data['slug'],
        'target_keyword': post_data.get('focus_keyword') or None
    }

    analysis = analyzer.analyze(analysis_data)

    # Generate report
    report = analyzer.generate_report(analysis, format='text')
    print(report)

    return post_data, analysis


def example_technical_audit(connector: WordPressConnector, post_id: int):
    """Example 3: Technical SEO audit of WordPress post."""
    print("\n" + "="*70)
    print(f"EXAMPLE 3: Technical SEO Audit")
    print("="*70)
    print()

    # Fetch post
    post_data = connector.fetch_post(post_id)

    # Create full HTML page (simplified - real implementation would fetch the actual rendered page)
    full_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{post_data['title']}</title>
        <link rel="canonical" href="{post_data['link']}">
    </head>
    <body>
        {post_data['content']}
    </body>
    </html>
    """

    # Run technical audit
    auditor = TechnicalAuditor()
    tech_audit = auditor.audit(post_data['link'], full_html)

    print("TECHNICAL SEO AUDIT")
    print("-"*70)
    print(f"Score: {tech_audit['score']}/{tech_audit['max_score']}")
    print()
    print(f"HTTPS: {tech_audit['https']['message']}")
    print(f"Mobile: {tech_audit['mobile']['message']}")
    print(f"Schema: {tech_audit['schema']['message']}")
    print(f"Canonical: {tech_audit['canonical']['message']}")
    print()

    if tech_audit['issues']:
        print("Issues Found:")
        for issue in tech_audit['issues']:
            print(f"  ⚠️  {issue}")
        print()

    if tech_audit['recommendations']:
        print("Recommendations:")
        for rec in tech_audit['recommendations']:
            print(f"  • {rec}")

    return tech_audit


def example_generate_schema(post_data: dict):
    """Example 4: Generate and display schema markup."""
    print("\n" + "="*70)
    print("EXAMPLE 4: Generate Schema Markup")
    print("="*70)
    print()

    generator = SchemaGenerator()

    # Generate Article schema
    article_schema = generator.generate_article_schema(
        headline=post_data['title'],
        author_name="Your Name",  # In real implementation, get from post
        date_published=post_data['date'],
        date_modified=post_data['modified'],
        description=post_data.get('excerpt', ''),
        image_url=post_data.get('featured_image_url'),
        publisher_name="Your Site Name",
        publisher_logo="https://yoursite.com/logo.png"
    )

    print("Article Schema (JSON-LD):")
    print("-"*70)
    print(generator.to_json_ld(article_schema))

    # Check if content has FAQ
    faqs = generator.extract_faq_from_content(post_data['content'])

    if len(faqs) >= 2:
        print("\n\nFAQ Schema (JSON-LD):")
        print("-"*70)
        faq_schema = generator.generate_faq_schema(faqs)
        print(generator.to_json_ld(faq_schema))
        print(f"\n✅ Found {len(faqs)} FAQ questions in content")
    else:
        print("\n⚠️  No FAQ content detected (need at least 2 Q&A pairs)")

    # Show HTML script tag
    print("\n\nHTML Script Tag to Insert:")
    print("-"*70)
    print(generator.to_html_script(article_schema))

    return article_schema


def example_apply_optimizations(
    connector: WordPressConnector,
    post_id: int,
    analysis: dict
):
    """Example 5: Apply SEO optimizations to WordPress post."""
    print("\n" + "="*70)
    print("EXAMPLE 5: Apply SEO Optimizations")
    print("="*70)
    print()

    # Generate optimizations
    analyzer = SEOAnalyzer()

    post_data = connector.fetch_post(post_id)

    optimized_title = analyzer.onpage_optimizer.generate_optimized_title(
        post_data['title'],
        analysis['target_keyword']
    )

    optimized_meta = analyzer.onpage_optimizer.generate_optimized_meta_description(
        post_data['content'],
        analysis['target_keyword']
    )

    print("PROPOSED OPTIMIZATIONS:")
    print("-"*70)
    print(f"\nCurrent Title:")
    print(f"  {post_data['title']}")
    print(f"\nOptimized Title:")
    print(f"  {optimized_title}")
    print()
    print(f"Current Meta Description:")
    print(f"  {post_data['meta_description'] or '(empty)'}")
    print(f"\nOptimized Meta Description:")
    print(f"  {optimized_meta}")
    print()

    # Ask for confirmation
    apply = input("\nApply these optimizations? (yes/no): ").strip().lower()

    if apply == 'yes':
        print("\nApplying optimizations...")

        # Update post via WordPress REST API
        result = connector.update_post_seo(
            post_id=post_id,
            title=optimized_title if optimized_title != post_data['title'] else None,
            meta_description=optimized_meta,
            focus_keyword=analysis['target_keyword']
        )

        print("✅ Optimizations applied successfully!")
        print(f"\nView updated post: {post_data['link']}")
    else:
        print("❌ Optimizations not applied")


def example_batch_analysis(connector: WordPressConnector):
    """Example 6: Batch analyze multiple posts."""
    print("\n" + "="*70)
    print("EXAMPLE 6: Batch Analysis")
    print("="*70)
    print()

    # Get recent posts
    posts = connector.list_posts(per_page=10, status='publish')

    print(f"Analyzing {len(posts)} posts...\n")

    analyzer = SEOAnalyzer()
    results = []

    for post in posts:
        try:
            # Fetch full post data
            post_data = connector.fetch_post(post['id'])

            # Analyze
            analysis = analyzer.analyze({
                'title': post_data['title'],
                'content': post_data['content'],
                'meta_description': post_data['meta_description'],
                'url_slug': post_data['slug']
            })

            results.append({
                'id': post['id'],
                'title': post['title'],
                'score': analysis['overall_score'],
                'critical_issues': analysis['critical_issues'],
                'recommendations': len(analysis['recommendations'])
            })

            print(f"  {post['id']}: {post['title'][:50]}")
            print(f"       Score: {analysis['overall_score']}/100 | Issues: {analysis['critical_issues']}")

        except Exception as e:
            print(f"  ❌ Error analyzing post {post['id']}: {e}")

    # Summary
    print("\n" + "="*70)
    print("BATCH SUMMARY")
    print("="*70)

    avg_score = sum(r['score'] for r in results) / len(results) if results else 0
    total_critical = sum(r['critical_issues'] for r in results)

    print(f"Total Posts Analyzed: {len(results)}")
    print(f"Average SEO Score: {avg_score:.1f}/100")
    print(f"Total Critical Issues: {total_critical}")

    # Posts needing attention
    needs_work = [r for r in results if r['score'] < 70]
    if needs_work:
        print(f"\nPosts Needing Attention ({len(needs_work)}):")
        for post in needs_work:
            print(f"  • ID {post['id']}: {post['title'][:50]} (Score: {post['score']}/100)")


def main():
    """Main execution."""
    print("\n" + "="*70)
    print("WORDPRESS SEO OPTIMIZER - PHASE 2")
    print("Full WordPress Integration Example")
    print("="*70)
    print()

    # Example 1: Connect to WordPress
    connector = example_wordpress_connection()

    if not connector:
        print("\n⚠️  WordPress connection not available")
        print("Examples require WordPress connection")
        return

    # Get a post ID to work with
    posts = connector.list_posts(per_page=1)
    if not posts:
        print("\n⚠️  No posts found in WordPress")
        return

    post_id = posts[0]['id']

    # Example 2: Analyze post
    post_data, analysis = example_analyze_wordpress_post(connector, post_id)

    # Example 3: Technical audit
    tech_audit = example_technical_audit(connector, post_id)

    # Example 4: Generate schema
    schema = example_generate_schema(post_data)

    # Example 5: Apply optimizations
    example_apply_optimizations(connector, post_id, analysis)

    # Example 6: Batch analysis
    batch = input("\n\nRun batch analysis of all posts? (yes/no): ").strip().lower()
    if batch == 'yes':
        example_batch_analysis(connector)

    print("\n" + "="*70)
    print("✅ WordPress Integration Examples Complete!")
    print("="*70)


if __name__ == "__main__":
    main()
