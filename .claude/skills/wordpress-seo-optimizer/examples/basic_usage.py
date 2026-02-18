"""
Basic Usage Example for WordPress SEO Optimizer

Demonstrates how to:
1. Connect to WordPress via REST API
2. Fetch a post
3. Analyze SEO
4. Apply optimizations
"""

import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.seo_analyzer import SEOAnalyzer


# EXAMPLE 1: Analyze Post SEO (without WordPress connection)
# ========================================================

def example_analyze_local():
    """Analyze SEO of local post data."""
    print("="*70)
    print("EXAMPLE 1: Analyze Local Post Data")
    print("="*70)
    print()

    # Sample post data (would normally come from WordPress REST API)
    post_data = {
        'id': 123,
        'title': 'Dog Training Tips',
        'content': '''
            <h2>Introduction to Dog Training</h2>
            <p>Dog training is essential for new dog owners. Whether you have a puppy
            or adult dog, effective dog training techniques can transform your relationship
            with your pet.</p>

            <img src="dog1.jpg" alt="Golden retriever during training session">

            <h2>Basic Dog Training Commands</h2>
            <p>Start with basic commands like sit, stay, and come. These dog training
            fundamentals are crucial for safety and obedience.</p>

            <img src="dog2.jpg">

            <h3>The Sit Command</h3>
            <p>Teaching your dog to sit is often the first command trainers recommend.
            It's simple and effective for dog training beginners.</p>

            <h2>Positive Reinforcement Training</h2>
            <p>Always use positive reinforcement when training your dog. Reward good behavior
            with treats and praise. This dog training method builds trust and cooperation.</p>

            <img src="dog3.jpg" alt="Dog treats for positive reinforcement">
        ''',
        'meta_description': '',
        'url_slug': 'dog-training-tips',
    }

    # Initialize analyzer
    analyzer = SEOAnalyzer()

    # Run analysis
    print("Analyzing post...")
    analysis = analyzer.analyze(post_data, target_keyword='dog training')

    # Generate and display report
    report = analyzer.generate_report(analysis)
    print(report)

    print()
    print("="*70)
    print("OPTIMIZATION SUGGESTIONS")
    print("="*70)
    print()

    # Generate optimized versions
    optimized_title = analyzer.onpage_optimizer.generate_optimized_title(
        post_data['title'],
        analysis['target_keyword']
    )

    optimized_meta = analyzer.onpage_optimizer.generate_optimized_meta_description(
        post_data['content'],
        analysis['target_keyword']
    )

    print(f"Current Title:    {post_data['title']}")
    print(f"Optimized Title:  {optimized_title}")
    print()
    print(f"Current Meta:     (empty)")
    print(f"Optimized Meta:   {optimized_meta}")
    print()


# EXAMPLE 2: WordPress Integration (requires wordpress-publisher module)
# =====================================================================

def example_wordpress_integration():
    """
    Analyze and optimize a WordPress post via REST API.

    NOTE: This requires the wordpress-publisher module to be available.
    """
    print("="*70)
    print("EXAMPLE 2: WordPress REST API Integration")
    print("="*70)
    print()

    try:
        # Import WordPress client
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'modules', 'wordpress-publisher', 'src'))
        from wordpress_publisher import WordPressClient
    except ImportError:
        print("⚠️  wordpress-publisher module not found")
        print("This example requires the wordpress-publisher module")
        print("Install it from: modules/wordpress-publisher/")
        return

    # WordPress credentials
    print("WordPress Connection Required:")
    print("Enter your WordPress site details...")
    print()

    base_url = input("WordPress URL (e.g., https://yoursite.com): ").strip()
    if not base_url:
        print("Skipping WordPress integration example")
        return

    username = input("Username: ").strip()
    app_password = input("Application Password: ").strip()
    post_id = input("Post ID to analyze: ").strip()

    if not all([base_url, username, app_password, post_id]):
        print("Missing required information, skipping example")
        return

    # Connect to WordPress
    print()
    print("Connecting to WordPress...")
    wp = WordPressClient(
        base_url=base_url,
        username=username,
        app_password=app_password
    )

    # Fetch post
    print(f"Fetching post {post_id}...")
    try:
        post = wp.get_post(int(post_id))
    except Exception as e:
        print(f"❌ Error fetching post: {e}")
        return

    print(f"✅ Retrieved: {post['title']['rendered']}")
    print()

    # Prepare data for analysis
    post_data = {
        'id': post['id'],
        'title': post['title']['rendered'],
        'content': post['content']['rendered'],
        'meta_description': post.get('meta', {}).get('_yoast_wpseo_metadesc', ''),
        'url_slug': post['slug'],
    }

    # Analyze
    print("Analyzing SEO...")
    analyzer = SEOAnalyzer()
    analysis = analyzer.analyze(post_data)

    # Display report
    report = analyzer.generate_report(analysis)
    print(report)

    # Ask if user wants to apply optimizations
    print()
    print("="*70)
    print("APPLY OPTIMIZATIONS?")
    print("="*70)
    print()

    apply = input("Apply recommended optimizations? (yes/no): ").strip().lower()

    if apply == 'yes':
        print()
        print("Applying optimizations...")

        # Generate optimizations
        optimized_title = analyzer.onpage_optimizer.generate_optimized_title(
            post_data['title'],
            analysis['target_keyword']
        )

        optimized_meta = analyzer.onpage_optimizer.generate_optimized_meta_description(
            post_data['content'],
            analysis['target_keyword']
        )

        # Apply via WordPress REST API
        updates = {}

        # Update title
        if optimized_title != post_data['title']:
            updates['title'] = optimized_title
            print(f"✅ Title updated")

        # Update meta description (Yoast SEO)
        if optimized_meta != post_data['meta_description']:
            updates['meta'] = {
                '_yoast_wpseo_metadesc': optimized_meta,
                '_yoast_wpseo_focuskw': analysis['target_keyword']
            }
            print(f"✅ Meta description updated")

        # Save changes
        if updates:
            try:
                wp.update_post(int(post_id), updates)
                print()
                print("✅ Optimizations applied successfully!")
                print(f"View post: {post['link']}")
            except Exception as e:
                print(f"❌ Error applying optimizations: {e}")
        else:
            print("No changes needed")
    else:
        print("Optimizations not applied")


# EXAMPLE 3: Batch Analysis
# ==========================

def example_batch_analysis():
    """Analyze multiple posts and generate summary report."""
    print("="*70)
    print("EXAMPLE 3: Batch Analysis")
    print("="*70)
    print()

    # Sample posts
    posts = [
        {
            'id': 1,
            'title': 'Best Practices',
            'content': '<h2>Introduction</h2><p>Some content here.</p>',
            'meta_description': '',
            'url_slug': 'best-practices'
        },
        {
            'id': 2,
            'title': 'Complete Guide to SEO',
            'content': '<h1>SEO Guide</h1><h2>Introduction</h2><p>SEO is important. Learn about SEO best practices.</p>' * 20,
            'meta_description': 'Learn SEO with our comprehensive guide',
            'url_slug': 'seo-guide'
        },
        {
            'id': 3,
            'title': 'WordPress Tips',
            'content': '<h2>WordPress Tips</h2><p>WordPress is great for blogging.</p>' * 5,
            'meta_description': '',
            'url_slug': 'wp-tips'
        }
    ]

    analyzer = SEOAnalyzer()
    results = []

    print(f"Analyzing {len(posts)} posts...")
    print()

    for post in posts:
        analysis = analyzer.analyze(post)
        results.append({
            'id': post['id'],
            'title': post['title'],
            'score': analysis['overall_score'],
            'critical_issues': analysis['critical_issues'],
            'recommendations': len(analysis['recommendations'])
        })

        print(f"Post {post['id']}: {post['title']}")
        print(f"  Score: {analysis['overall_score']}/100")
        print(f"  Critical Issues: {analysis['critical_issues']}")
        print(f"  Recommendations: {len(analysis['recommendations'])}")
        print()

    # Summary
    avg_score = sum(r['score'] for r in results) / len(results)
    total_critical = sum(r['critical_issues'] for r in results)

    print("="*70)
    print("BATCH SUMMARY")
    print("="*70)
    print(f"Total Posts Analyzed: {len(results)}")
    print(f"Average SEO Score: {avg_score:.1f}/100")
    print(f"Total Critical Issues: {total_critical}")
    print()

    # Posts needing attention
    needs_work = [r for r in results if r['score'] < 70]
    if needs_work:
        print("Posts Needing Attention:")
        for post in needs_work:
            print(f"  • Post {post['id']}: {post['title']} (Score: {post['score']}/100)")


# Run examples
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='WordPress SEO Optimizer Examples')
    parser.add_argument(
        'example',
        choices=['local', 'wordpress', 'batch', 'all'],
        nargs='?',
        default='local',
        help='Which example to run'
    )

    args = parser.parse_args()

    if args.example == 'local' or args.example == 'all':
        example_analyze_local()
        print("\n\n")

    if args.example == 'wordpress' or args.example == 'all':
        example_wordpress_integration()
        print("\n\n")

    if args.example == 'batch' or args.example == 'all':
        example_batch_analysis()
