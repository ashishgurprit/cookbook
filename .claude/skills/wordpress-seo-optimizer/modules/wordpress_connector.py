"""
WordPress Connector Module

Handles WordPress REST API integration for fetching and updating posts.
Integrates with wordpress-publisher module and detects SEO plugins.
"""

import sys
import os
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class WordPressConnector:
    """Connect to WordPress and manage SEO operations via REST API."""

    def __init__(self, base_url: str, username: str, app_password: str):
        """
        Initialize WordPress connector.

        Args:
            base_url: WordPress site URL (e.g., https://yoursite.com)
            username: WordPress username
            app_password: WordPress Application Password
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.app_password = app_password
        self.wp_client = None
        self.seo_plugin = None

        # Try to import wordpress-publisher
        self._import_wordpress_client()

    def _import_wordpress_client(self):
        """Import WordPress client from wordpress-publisher module."""
        try:
            # Try to import from modules directory
            modules_dir = Path(__file__).parent.parent.parent.parent / 'modules' / 'wordpress-publisher' / 'src'
            if modules_dir.exists():
                sys.path.insert(0, str(modules_dir))

            from wordpress_publisher import WordPressClient

            self.wp_client = WordPressClient(
                base_url=self.base_url,
                username=self.username,
                app_password=self.app_password
            )

            # Detect SEO plugin
            self.seo_plugin = self._detect_seo_plugin()

        except ImportError as e:
            raise ImportError(
                "wordpress-publisher module not found. "
                "Please install it from modules/wordpress-publisher/ "
                f"Error: {e}"
            )

    def _detect_seo_plugin(self) -> Optional[str]:
        """
        Detect which SEO plugin is active.

        Returns:
            'yoast', 'rankmath', 'aioseo', 'seopress', or None
        """
        try:
            # Try to fetch a post and check meta fields
            posts = self.wp_client.list_posts(per_page=1)
            if not posts:
                return None

            post = self.wp_client.get_post(posts[0]['id'])
            meta = post.get('meta', {})

            # Check for plugin-specific meta fields
            if '_yoast_wpseo_title' in meta or '_yoast_wpseo_metadesc' in meta:
                return 'yoast'
            elif 'rank_math_title' in meta or 'rank_math_description' in meta:
                return 'rankmath'
            elif '_aioseo_title' in meta or '_aioseo_description' in meta:
                return 'aioseo'
            elif '_seopress_titles_title' in meta:
                return 'seopress'

            return None

        except Exception as e:
            print(f"Warning: Could not detect SEO plugin: {e}")
            return None

    def fetch_post(self, post_id: int) -> Dict:
        """
        Fetch post data from WordPress.

        Args:
            post_id: WordPress post ID

        Returns:
            Dictionary with post data suitable for SEO analysis
        """
        # Fetch post via REST API
        post = self.wp_client.get_post(post_id)

        # Extract SEO meta based on detected plugin
        meta = post.get('meta', {})
        meta_description = self._extract_meta_description(meta)
        focus_keyword = self._extract_focus_keyword(meta)

        # Parse content for analysis
        return {
            'id': post['id'],
            'title': post['title']['rendered'],
            'content': post['content']['rendered'],
            'excerpt': post['excerpt']['rendered'],
            'slug': post['slug'],
            'url_slug': post['slug'],
            'link': post['link'],
            'meta_description': meta_description,
            'focus_keyword': focus_keyword,
            'status': post['status'],
            'date': post['date'],
            'modified': post['modified'],
            'categories': post.get('categories', []),
            'tags': post.get('tags', []),
            'featured_media': post.get('featured_media', 0),
            'meta': meta  # Raw meta for custom processing
        }

    def _extract_meta_description(self, meta: Dict) -> str:
        """Extract meta description based on SEO plugin."""
        if self.seo_plugin == 'yoast':
            return meta.get('_yoast_wpseo_metadesc', '')
        elif self.seo_plugin == 'rankmath':
            return meta.get('rank_math_description', '')
        elif self.seo_plugin == 'aioseo':
            return meta.get('_aioseo_description', '')
        elif self.seo_plugin == 'seopress':
            return meta.get('_seopress_titles_desc', '')
        return ''

    def _extract_focus_keyword(self, meta: Dict) -> str:
        """Extract focus keyword based on SEO plugin."""
        if self.seo_plugin == 'yoast':
            return meta.get('_yoast_wpseo_focuskw', '')
        elif self.seo_plugin == 'rankmath':
            keywords = meta.get('rank_math_focus_keyword', '')
            # RankMath stores comma-separated keywords
            return keywords.split(',')[0].strip() if keywords else ''
        elif self.seo_plugin == 'aioseo':
            return meta.get('_aioseo_keyphrases', '')
        elif self.seo_plugin == 'seopress':
            return meta.get('_seopress_analysis_target_kw', '')
        return ''

    def update_post_seo(
        self,
        post_id: int,
        title: Optional[str] = None,
        meta_description: Optional[str] = None,
        focus_keyword: Optional[str] = None,
        content: Optional[str] = None
    ) -> Dict:
        """
        Update post SEO elements.

        Args:
            post_id: WordPress post ID
            title: New title (optional)
            meta_description: New meta description (optional)
            focus_keyword: New focus keyword (optional)
            content: New content (optional)

        Returns:
            Updated post data
        """
        updates = {}

        # Update title
        if title:
            updates['title'] = title

        # Update content
        if content:
            updates['content'] = content

        # Update SEO meta fields based on plugin
        meta_updates = {}

        if meta_description:
            if self.seo_plugin == 'yoast':
                meta_updates['_yoast_wpseo_metadesc'] = meta_description
            elif self.seo_plugin == 'rankmath':
                meta_updates['rank_math_description'] = meta_description
            elif self.seo_plugin == 'aioseo':
                meta_updates['_aioseo_description'] = meta_description
            elif self.seo_plugin == 'seopress':
                meta_updates['_seopress_titles_desc'] = meta_description

        if focus_keyword:
            if self.seo_plugin == 'yoast':
                meta_updates['_yoast_wpseo_focuskw'] = focus_keyword
            elif self.seo_plugin == 'rankmath':
                meta_updates['rank_math_focus_keyword'] = focus_keyword
            elif self.seo_plugin == 'aioseo':
                meta_updates['_aioseo_keyphrases'] = focus_keyword
            elif self.seo_plugin == 'seopress':
                meta_updates['_seopress_analysis_target_kw'] = focus_keyword

        if meta_updates:
            updates['meta'] = meta_updates

        # Apply updates via REST API
        if updates:
            return self.wp_client.update_post(post_id, updates)

        return {'message': 'No updates to apply'}

    def list_posts(
        self,
        per_page: int = 10,
        status: str = 'publish',
        orderby: str = 'modified',
        order: str = 'desc'
    ) -> List[Dict]:
        """
        List WordPress posts.

        Args:
            per_page: Number of posts to retrieve
            status: Post status (publish, draft, etc.)
            orderby: Sort by (date, modified, title, etc.)
            order: Sort order (asc, desc)

        Returns:
            List of post summaries
        """
        posts = self.wp_client.list_posts(
            per_page=per_page,
            status=status,
            orderby=orderby,
            order=order
        )

        # Simplify post data
        return [
            {
                'id': p['id'],
                'title': p['title']['rendered'],
                'slug': p['slug'],
                'status': p['status'],
                'date': p['date'],
                'modified': p['modified'],
                'link': p['link']
            }
            for p in posts
        ]

    def get_seo_plugin_info(self) -> Dict:
        """
        Get information about detected SEO plugin.

        Returns:
            Dictionary with plugin info
        """
        plugin_names = {
            'yoast': 'Yoast SEO',
            'rankmath': 'Rank Math',
            'aioseo': 'All in One SEO',
            'seopress': 'SEOPress',
            None: 'No SEO plugin detected'
        }

        plugin_fields = {
            'yoast': {
                'title': '_yoast_wpseo_title',
                'description': '_yoast_wpseo_metadesc',
                'keyword': '_yoast_wpseo_focuskw'
            },
            'rankmath': {
                'title': 'rank_math_title',
                'description': 'rank_math_description',
                'keyword': 'rank_math_focus_keyword'
            },
            'aioseo': {
                'title': '_aioseo_title',
                'description': '_aioseo_description',
                'keyword': '_aioseo_keyphrases'
            },
            'seopress': {
                'title': '_seopress_titles_title',
                'description': '_seopress_titles_desc',
                'keyword': '_seopress_analysis_target_kw'
            }
        }

        return {
            'detected': self.seo_plugin,
            'name': plugin_names.get(self.seo_plugin, 'Unknown'),
            'fields': plugin_fields.get(self.seo_plugin, {}),
            'can_update': self.seo_plugin is not None
        }

    def test_connection(self) -> Tuple[bool, str]:
        """
        Test WordPress connection.

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Try to list posts
            posts = self.wp_client.list_posts(per_page=1)

            plugin_info = self.get_seo_plugin_info()

            return (
                True,
                f"✅ Connected to {self.base_url}\n"
                f"SEO Plugin: {plugin_info['name']}"
            )
        except Exception as e:
            return (False, f"❌ Connection failed: {str(e)}")


class WordPressNotAvailableError(Exception):
    """Raised when WordPress connection is not available."""
    pass


def create_connector(
    base_url: Optional[str] = None,
    username: Optional[str] = None,
    app_password: Optional[str] = None
) -> WordPressConnector:
    """
    Create WordPress connector with credentials.

    If credentials are not provided, will prompt user.

    Args:
        base_url: WordPress URL
        username: WordPress username
        app_password: Application password

    Returns:
        WordPressConnector instance
    """
    if not all([base_url, username, app_password]):
        print("WordPress Connection Required")
        print("-" * 60)

        base_url = base_url or input("WordPress URL (e.g., https://yoursite.com): ").strip()
        username = username or input("Username: ").strip()
        app_password = app_password or input("Application Password: ").strip()

    if not all([base_url, username, app_password]):
        raise ValueError("WordPress credentials required")

    connector = WordPressConnector(base_url, username, app_password)

    # Test connection
    success, message = connector.test_connection()
    print(message)

    if not success:
        raise WordPressNotAvailableError(message)

    return connector


if __name__ == "__main__":
    # Test WordPress connector
    print("WordPress Connector Test")
    print("=" * 60)

    try:
        connector = create_connector()

        print("\n📋 Listing recent posts...")
        posts = connector.list_posts(per_page=5)

        for post in posts:
            print(f"\n  ID: {post['id']}")
            print(f"  Title: {post['title']}")
            print(f"  Status: {post['status']}")
            print(f"  Modified: {post['modified']}")

        if posts:
            print(f"\n🔍 Fetching full post data for ID {posts[0]['id']}...")
            post_data = connector.fetch_post(posts[0]['id'])

            print(f"\n  Title: {post_data['title']}")
            print(f"  Slug: {post_data['slug']}")
            print(f"  Meta Description: {post_data['meta_description'][:100] if post_data['meta_description'] else '(empty)'}...")
            print(f"  Focus Keyword: {post_data['focus_keyword'] or '(not set)'}")
            print(f"  Content Length: {len(post_data['content'])} chars")

        print("\n✅ WordPress connector test successful!")

    except WordPressNotAvailableError as e:
        print(f"\n⚠️  {e}")
        print("Skipping WordPress integration test")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
