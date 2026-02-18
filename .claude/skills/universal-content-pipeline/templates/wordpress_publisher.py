"""
WordPress Publisher - Automated WordPress Publishing

Publishes blog posts to WordPress with full metadata, SEO optimization,
image upload, and scheduling support.
"""

import os
import requests
import base64
from typing import Dict, List, Optional
from datetime import datetime
import mimetypes
from urllib.parse import urljoin
from pathlib import Path


class WordPressPublisher:
    """WordPress REST API publisher with full metadata support"""

    def __init__(
        self,
        site_url: str,
        username: str,
        app_password: str
    ):
        """
        Initialize WordPress publisher.

        Args:
            site_url: WordPress site URL (e.g., https://myblog.com)
            username: WordPress username
            app_password: WordPress application password
        """
        self.site_url = site_url.rstrip('/')
        self.api_base = f"{self.site_url}/wp-json/wp/v2"
        self.username = username
        self.app_password = app_password

        # Create authentication header
        credentials = f"{username}:{app_password}"
        token = base64.b64encode(credentials.encode()).decode()
        self.headers = {
            'Authorization': f'Basic {token}',
            'Content-Type': 'application/json'
        }

    def publish_post(
        self,
        title: str,
        content: str,
        excerpt: str = '',
        status: str = 'draft',
        categories: List[str] = None,
        tags: List[str] = None,
        featured_image: str = None,
        meta: Dict = None,
        schedule_date: str = None,
        author: int = None
    ) -> Dict:
        """
        Publish a single post to WordPress.

        Args:
            title: Post title
            content: Post content (HTML)
            excerpt: Post excerpt
            status: 'draft', 'publish', or 'future' (for scheduled)
            categories: List of category names
            tags: List of tag names
            featured_image: Path to featured image
            meta: Custom metadata (SEO fields, etc.)
            schedule_date: Schedule date (YYYY-MM-DD HH:MM:SS) for future posts
            author: Author ID

        Returns:
            Published post data including ID and URL
        """

        # Get/create categories
        category_ids = self._get_or_create_categories(categories or [])

        # Get/create tags
        tag_ids = self._get_or_create_tags(tags or [])

        # Upload featured image if provided
        featured_media_id = None
        if featured_image and Path(featured_image).exists():
            featured_media_id = self._upload_image(featured_image)

        # Prepare post data
        post_data = {
            'title': title,
            'content': content,
            'excerpt': excerpt,
            'status': 'future' if schedule_date else status,
            'categories': category_ids,
            'tags': tag_ids
        }

        # Add featured image
        if featured_media_id:
            post_data['featured_media'] = featured_media_id

        # Add schedule date
        if schedule_date:
            post_data['date'] = schedule_date

        # Add author
        if author:
            post_data['author'] = author

        # Add meta fields (Yoast SEO, etc.)
        if meta:
            post_data['meta'] = self._prepare_meta(meta)

        # Create post
        response = requests.post(
            f"{self.api_base}/posts",
            headers=self.headers,
            json=post_data
        )

        if response.status_code not in [200, 201]:
            raise Exception(f"Failed to create post: {response.status_code} - {response.text}")

        result = response.json()

        return {
            'post_id': result['id'],
            'url': result['link'],
            'status': result['status'],
            'publish_date': result.get('date', None),
            'title': result['title']['rendered']
        }

    def publish_series(
        self,
        posts: List[Dict],
        schedule_strategy: str = 'spread',
        posts_per_week: int = 3,
        start_date: str = None,
        category: str = None
    ) -> List[Dict]:
        """
        Publish a series of posts with scheduling.

        Args:
            posts: List of post dictionaries
            schedule_strategy: 'spread', 'burst', or 'custom'
            posts_per_week: Posts per week for 'spread' strategy
            start_date: Start date for scheduling
            category: Parent category for series

        Returns:
            List of published post results
        """

        results = []

        # Calculate schedule
        if schedule_strategy == 'spread':
            schedule_dates = self._calculate_spread_schedule(
                len(posts),
                posts_per_week,
                start_date
            )
        else:
            schedule_dates = [None] * len(posts)

        # Create parent category if needed
        if category:
            category_id = self._get_or_create_categories([category])[0]
        else:
            category_id = None

        # Publish posts
        for i, post in enumerate(posts):
            print(f"Publishing post {i+1}/{len(posts)}...", end='\r')

            # Add series category
            categories = post.get('categories', [])
            if category and category not in categories:
                categories.append(category)

            result = self.publish_post(
                title=post['title'],
                content=post['content'],
                excerpt=post.get('excerpt', ''),
                status='future' if schedule_dates[i] else post.get('status', 'draft'),
                categories=categories,
                tags=post.get('tags', []),
                featured_image=post.get('featured_image'),
                meta=post.get('meta'),
                schedule_date=schedule_dates[i]
            )

            results.append(result)

        print(f"\n✓ Published {len(results)} posts")

        return results

    def _get_or_create_categories(self, category_names: List[str]) -> List[int]:
        """Get or create categories by name"""

        category_ids = []

        for name in category_names:
            # Check if category exists
            response = requests.get(
                f"{self.api_base}/categories",
                params={'search': name}
            )

            categories = response.json()

            if categories:
                # Use existing category
                category_ids.append(categories[0]['id'])
            else:
                # Create new category
                response = requests.post(
                    f"{self.api_base}/categories",
                    headers=self.headers,
                    json={'name': name}
                )

                if response.status_code in [200, 201]:
                    category_ids.append(response.json()['id'])

        return category_ids

    def _get_or_create_tags(self, tag_names: List[str]) -> List[int]:
        """Get or create tags by name"""

        tag_ids = []

        for name in tag_names:
            # Check if tag exists
            response = requests.get(
                f"{self.api_base}/tags",
                params={'search': name}
            )

            tags = response.json()

            if tags:
                # Use existing tag
                tag_ids.append(tags[0]['id'])
            else:
                # Create new tag
                response = requests.post(
                    f"{self.api_base}/tags",
                    headers=self.headers,
                    json={'name': name}
                )

                if response.status_code in [200, 201]:
                    tag_ids.append(response.json()['id'])

        return tag_ids

    def _upload_image(self, image_path: str) -> int:
        """Upload image to WordPress media library"""

        path = Path(image_path)

        if not path.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")

        # Get MIME type
        mime_type, _ = mimetypes.guess_type(image_path)
        if not mime_type:
            mime_type = 'image/jpeg'

        # Read image
        with open(image_path, 'rb') as f:
            image_data = f.read()

        # Upload
        headers = {
            'Authorization': self.headers['Authorization'],
            'Content-Type': mime_type,
            'Content-Disposition': f'attachment; filename="{path.name}"'
        }

        response = requests.post(
            f"{self.api_base}/media",
            headers=headers,
            data=image_data
        )

        if response.status_code not in [200, 201]:
            raise Exception(f"Failed to upload image: {response.status_code}")

        return response.json()['id']

    def _prepare_meta(self, meta: Dict) -> Dict:
        """Prepare meta fields for WordPress (Yoast SEO format)"""

        wordpress_meta = {}

        # Yoast SEO fields
        if 'seo_title' in meta:
            wordpress_meta['_yoast_wpseo_title'] = meta['seo_title']

        if 'meta_description' in meta:
            wordpress_meta['_yoast_wpseo_metadesc'] = meta['meta_description']

        if 'focus_keyword' in meta:
            wordpress_meta['_yoast_wpseo_focuskw'] = meta['focus_keyword']

        # Custom fields
        for key, value in meta.items():
            if key not in ['seo_title', 'meta_description', 'focus_keyword']:
                wordpress_meta[key] = value

        return wordpress_meta

    def _calculate_spread_schedule(
        self,
        post_count: int,
        posts_per_week: int,
        start_date: str = None
    ) -> List[str]:
        """Calculate spread schedule for posts"""

        from datetime import datetime, timedelta

        if start_date:
            current_date = datetime.strptime(start_date, '%Y-%m-%d')
        else:
            current_date = datetime.now()

        # Default publish days (Mon, Wed, Fri)
        publish_days = [0, 2, 4]  # Monday=0, Wednesday=2, Friday=4
        publish_time = "09:00:00"

        schedule = []

        for i in range(post_count):
            # Find next publish day
            while current_date.weekday() not in publish_days:
                current_date += timedelta(days=1)

            schedule.append(f"{current_date.strftime('%Y-%m-%d')} {publish_time}")
            current_date += timedelta(days=1)

        return schedule

    def get_post(self, post_id: int) -> Dict:
        """Get post by ID"""

        response = requests.get(
            f"{self.api_base}/posts/{post_id}",
            headers=self.headers
        )

        if response.status_code != 200:
            raise Exception(f"Failed to get post: {response.status_code}")

        return response.json()

    def update_post(self, post_id: int, updates: Dict) -> Dict:
        """Update existing post"""

        response = requests.post(
            f"{self.api_base}/posts/{post_id}",
            headers=self.headers,
            json=updates
        )

        if response.status_code not in [200, 201]:
            raise Exception(f"Failed to update post: {response.status_code}")

        return response.json()

    def delete_post(self, post_id: int, force: bool = False) -> bool:
        """Delete post (or move to trash)"""

        params = {'force': 'true'} if force else {}

        response = requests.delete(
            f"{self.api_base}/posts/{post_id}",
            headers=self.headers,
            params=params
        )

        return response.status_code == 200


# Example usage
if __name__ == '__main__':
    # Initialize publisher
    publisher = WordPressPublisher(
        site_url='https://yourblog.com',
        username='admin',
        app_password='xxxx xxxx xxxx xxxx'
    )

    # Publish single post
    result = publisher.publish_post(
        title='5 Leadership Principles That Transform Teams',
        content='<p>Leadership isn\'t about authority...</p>',
        excerpt='Discover the five core principles...',
        status='draft',
        categories=['Leadership', 'Management'],
        tags=['leadership', 'team building', 'management'],
        meta={
            'seo_title': '5 Leadership Principles | Expert Guide',
            'meta_description': 'Learn 5 proven leadership principles...',
            'focus_keyword': 'leadership principles'
        }
    )

    print(f"Published: {result['url']}")
    print(f"Post ID: {result['post_id']}")
