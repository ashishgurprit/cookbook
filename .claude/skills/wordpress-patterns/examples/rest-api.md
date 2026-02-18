# WordPress REST API Pattern Examples

Complete examples for WordPress REST API integration with error handling, rate limiting, and best practices.

---

## Table of Contents

1. [Basic REST API Client](#basic-rest-api-client)
2. [Slug-Based Post Lookup](#slug-based-post-lookup)
3. [Image Upload and Management](#image-upload-and-management)
4. [Content Manipulation](#content-manipulation)
5. [Batch Operations](#batch-operations)
6. [Error Handling](#error-handling)

---

## Basic REST API Client

```python
import requests
import base64
import time
from typing import Dict, Optional, List
import logging

logger = logging.getLogger(__name__)

class WordPressClient:
    """Production-ready WordPress REST API client."""

    def __init__(
        self,
        url: str,
        username: str,
        app_password: str,
        requests_per_minute: int = 60,
        timeout: int = 30
    ):
        """
        Initialize WordPress client.

        Args:
            url: WordPress site URL (e.g., 'https://yourblog.com')
            username: WordPress username
            app_password: WordPress application password
            requests_per_minute: Rate limit for API calls
            timeout: Default timeout for requests (seconds)
        """
        self.url = url.rstrip('/')
        self.api_base = f"{self.url}/wp-json/wp/v2"
        self.timeout = timeout

        # Create Basic Auth header
        credentials = f"{username}:{app_password}"
        token = base64.b64encode(credentials.encode()).decode()
        self.headers = {
            'Authorization': f'Basic {token}',
            'Content-Type': 'application/json'
        }

        # Rate limiting
        self.min_interval = 60.0 / requests_per_minute
        self.last_request_time = None

    def _enforce_rate_limit(self):
        """Sleep if needed to respect rate limit."""
        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                logger.debug(f"Rate limit: sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> requests.Response:
        """
        Make rate-limited request with error handling.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., '/posts' or '/posts/123')
            **kwargs: Additional arguments for requests

        Returns:
            Response object

        Raises:
            requests.exceptions.HTTPError: For non-2xx responses
        """
        self._enforce_rate_limit()

        url = f"{self.api_base}{endpoint}"
        kwargs.setdefault('headers', self.headers)
        kwargs.setdefault('timeout', self.timeout)

        logger.info(f"{method} {endpoint}")

        response = requests.request(method, url, **kwargs)

        # Log response
        logger.info(f"Response: {response.status_code}")
        if response.status_code >= 400:
            logger.error(f"Error body: {response.text[:500]}")

        response.raise_for_status()
        return response

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """GET request."""
        response = self._request('GET', endpoint, params=params)
        return response.json()

    def post(self, endpoint: str, data: Dict) -> Dict:
        """POST request."""
        response = self._request('POST', endpoint, json=data)
        return response.json()

    def put(self, endpoint: str, data: Dict) -> Dict:
        """PUT request (update)."""
        response = self._request('PUT', endpoint, json=data)
        return response.json()

    def delete(self, endpoint: str) -> Dict:
        """DELETE request."""
        response = self._request('DELETE', endpoint)
        return response.json()


# Usage Example
if __name__ == '__main__':
    # Initialize client
    client = WordPressClient(
        url='https://yourblog.com',
        username='admin',
        app_password='xxxx xxxx xxxx xxxx xxxx xxxx'
    )

    # Get posts
    posts = client.get('/posts', params={'per_page': 10, 'status': 'publish'})
    print(f"Found {len(posts)} posts")

    # Create post
    new_post = client.post('/posts', {
        'title': 'Test Post',
        'content': '<p>This is a test post.</p>',
        'status': 'draft'
    })
    print(f"Created post: {new_post['id']}")
```

---

## Slug-Based Post Lookup

```python
from typing import Optional
import urllib.parse

class WordPressPostManager(WordPressClient):
    """Extended client with post management features."""

    def extract_slug_from_url(self, url: str) -> str:
        """
        Extract post slug from WordPress URL.

        Args:
            url: Full post URL (e.g., 'https://site.com/2026/01/12/post-title/')

        Returns:
            Post slug (e.g., 'post-title')

        Examples:
            >>> manager.extract_slug_from_url('https://site.com/2026/01/12/my-post/')
            'my-post'
            >>> manager.extract_slug_from_url('https://site.com/category/my-post/')
            'my-post'
        """
        url = url.rstrip('/')  # Remove trailing slash
        slug = url.split('/')[-1]  # Get last part
        return urllib.parse.unquote(slug)  # Decode URL encoding

    def get_post_by_slug(self, slug: str) -> Optional[Dict]:
        """
        Fetch post by slug.

        Args:
            slug: Post slug

        Returns:
            Post data dict or None if not found

        Example:
            >>> post = manager.get_post_by_slug('my-post-title')
            >>> print(post['id'], post['title']['rendered'])
            123 "My Post Title"
        """
        try:
            posts = self.get('/posts', params={'slug': slug})

            if posts:
                post = posts[0]  # Slug is unique, returns array with 1 item
                return {
                    'id': post['id'],
                    'title': post['title']['rendered'],
                    'content': post['content']['rendered'],
                    'excerpt': post['excerpt']['rendered'],
                    'slug': post['slug'],
                    'url': post['link'],
                    'date': post['date'],
                    'modified': post['modified'],
                    'status': post['status'],
                    'categories': post['categories'],
                    'tags': post['tags'],
                    'featured_media': post['featured_media']
                }

            return None

        except requests.exceptions.HTTPError as e:
            logger.error(f"Failed to get post by slug '{slug}': {e}")
            return None

    def get_post_by_url(self, url: str) -> Optional[Dict]:
        """
        Fetch post by full URL.

        Args:
            url: Full post URL

        Returns:
            Post data dict or None if not found

        Example:
            >>> post = manager.get_post_by_url('https://site.com/2026/01/12/my-post/')
            >>> print(post['id'])
            123
        """
        slug = self.extract_slug_from_url(url)
        return self.get_post_by_slug(slug)

    def get_posts_by_urls(self, urls: List[str]) -> List[Dict]:
        """
        Fetch multiple posts by URLs (batch operation).

        Args:
            urls: List of post URLs

        Returns:
            List of post data dicts (excludes not found)

        Example:
            >>> urls = [
                'https://site.com/post-1/',
                'https://site.com/post-2/',
                'https://site.com/post-3/'
            ]
            >>> posts = manager.get_posts_by_urls(urls)
            >>> print(f"Found {len(posts)}/{len(urls)} posts")
        """
        posts = []

        for url in urls:
            post = self.get_post_by_url(url)
            if post:
                posts.append(post)
                logger.info(f"Found: {post['title']} (ID: {post['id']})")
            else:
                logger.warning(f"Not found: {url}")

        return posts


# Usage Example
if __name__ == '__main__':
    manager = WordPressPostManager(
        url='https://yourblog.com',
        username='admin',
        app_password='xxxx xxxx xxxx xxxx xxxx xxxx'
    )

    # Single URL lookup
    url = 'https://yourblog.com/2026/01/12/my-story-title/'
    post = manager.get_post_by_url(url)
    if post:
        print(f"Post ID: {post['id']}")
        print(f"Title: {post['title']}")

    # Batch URL lookup
    urls = [
        'https://yourblog.com/2026/01/10/story-1/',
        'https://yourblog.com/2026/01/11/story-2/',
        'https://yourblog.com/2026/01/12/story-3/'
    ]
    posts = manager.get_posts_by_urls(urls)
    print(f"Found {len(posts)} posts")
```

---

## Image Upload and Management

```python
import os
from pathlib import Path
from typing import List, Dict

class WordPressMediaManager(WordPressClient):
    """WordPress media upload and management."""

    def upload_image(
        self,
        image_path: str,
        title: Optional[str] = None,
        alt_text: Optional[str] = None,
        caption: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Upload image to WordPress media library.

        Args:
            image_path: Path to image file
            title: Image title (default: filename)
            alt_text: Alt text for accessibility
            caption: Image caption

        Returns:
            Media data dict with id, url, etc. or None on failure

        Example:
            >>> media = manager.upload_image(
                'scene1.png',
                title='Scene 1: Opening',
                alt_text='Story opening scene'
            )
            >>> print(media['id'], media['url'])
            456 https://site.com/wp-content/uploads/2026/01/scene1.png
        """
        if not os.path.exists(image_path):
            logger.error(f"Image not found: {image_path}")
            return None

        filename = os.path.basename(image_path)
        title = title or Path(image_path).stem

        # Determine content type
        ext = Path(image_path).suffix.lower()
        content_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp'
        }
        content_type = content_types.get(ext, 'image/jpeg')

        try:
            with open(image_path, 'rb') as img:
                # Prepare headers
                media_headers = {
                    'Authorization': self.headers['Authorization'],
                    'Content-Disposition': f'attachment; filename="{filename}"',
                    'Content-Type': content_type
                }

                # Upload image
                self._enforce_rate_limit()
                response = requests.post(
                    f'{self.api_base}/media',
                    headers=media_headers,
                    data=img,
                    timeout=120  # Longer timeout for large images
                )

                if response.status_code == 201:
                    media = response.json()

                    # Update alt text and caption if provided
                    if alt_text or caption:
                        update_data = {}
                        if alt_text:
                            update_data['alt_text'] = alt_text
                        if caption:
                            update_data['caption'] = caption

                        self.post(f'/media/{media["id"]}', update_data)

                    logger.info(f"Uploaded: {filename} (ID: {media['id']})")

                    return {
                        'id': media['id'],
                        'url': media['source_url'],
                        'filename': filename,
                        'title': media['title']['rendered'],
                        'mime_type': media['mime_type'],
                        'width': media['media_details']['width'],
                        'height': media['media_details']['height']
                    }

                else:
                    logger.error(f"Upload failed: {response.status_code} - {response.text}")
                    return None

        except Exception as e:
            logger.error(f"Upload exception: {e}")
            return None

    def upload_images_batch(
        self,
        image_paths: List[str],
        titles: Optional[List[str]] = None,
        alt_texts: Optional[List[str]] = None
    ) -> List[Dict]:
        """
        Upload multiple images.

        Args:
            image_paths: List of image file paths
            titles: Optional list of titles (same order as paths)
            alt_texts: Optional list of alt texts

        Returns:
            List of uploaded media data dicts

        Example:
            >>> images = manager.upload_images_batch(
                ['scene1.png', 'scene2.png', 'scene3.png'],
                titles=['Opening', 'Middle', 'Conclusion']
            )
            >>> print(f"Uploaded {len(images)} images")
        """
        uploaded = []

        for i, image_path in enumerate(image_paths):
            title = titles[i] if titles and i < len(titles) else None
            alt_text = alt_texts[i] if alt_texts and i < len(alt_texts) else None

            media = self.upload_image(image_path, title, alt_text)
            if media:
                uploaded.append(media)

        logger.info(f"Uploaded {len(uploaded)}/{len(image_paths)} images")
        return uploaded

    def delete_media(self, media_id: int, force: bool = True) -> bool:
        """
        Delete media from library.

        Args:
            media_id: Media ID to delete
            force: If True, permanently delete (skip trash)

        Returns:
            True if successful

        Example:
            >>> manager.delete_media(456)
            True
        """
        try:
            endpoint = f'/media/{media_id}'
            if force:
                endpoint += '?force=true'

            self.delete(endpoint)
            logger.info(f"Deleted media: {media_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete media {media_id}: {e}")
            return False


# Usage Example
if __name__ == '__main__':
    manager = WordPressMediaManager(
        url='https://yourblog.com',
        username='admin',
        app_password='xxxx xxxx xxxx xxxx xxxx xxxx'
    )

    # Upload single image
    media = manager.upload_image(
        'featured-image.png',
        title='Featured Image',
        alt_text='Blog post featured image'
    )
    print(f"Uploaded: {media['url']}")

    # Upload batch
    image_files = ['scene1.png', 'scene2.png', 'scene3.png']
    uploaded = manager.upload_images_batch(
        image_files,
        titles=['Scene 1: Opening', 'Scene 2: Middle', 'Scene 3: Conclusion']
    )

    # Use in post
    image_ids = [img['id'] for img in uploaded]
    print(f"Image IDs: {image_ids}")
```

---

## Content Manipulation

```python
import re
from bs4 import BeautifulSoup
from typing import List

class WordPressContentManager(WordPressPostManager):
    """WordPress content manipulation with HTML cleanup."""

    def clean_html_content(self, html: str) -> str:
        """
        Remove WordPress-specific markup and clean HTML.

        Args:
            html: Raw HTML content

        Returns:
            Cleaned HTML

        Example:
            >>> clean = manager.clean_html_content(post['content'])
        """
        clean = html

        # Remove Gutenberg block comments
        clean = re.sub(
            r'<!-- wp:.*?-->.*?<!-- /wp:.*?-->',
            '',
            clean,
            flags=re.DOTALL
        )

        # Remove figure tags
        clean = re.sub(
            r'<figure.*?</figure>',
            '',
            clean,
            flags=re.DOTALL
        )

        # Remove standalone img tags
        clean = re.sub(r'<img[^>]*>', '', clean)

        # Remove empty paragraphs
        clean = re.sub(r'<p>\s*</p>', '', clean)

        # Remove extra whitespace
        clean = re.sub(r'\n\s*\n', '\n\n', clean)

        return clean.strip()

    def remove_images_from_content(self, html: str) -> str:
        """
        Remove all images from HTML content.

        Args:
            html: HTML content with images

        Returns:
            HTML without images

        Example:
            >>> clean_content = manager.remove_images_from_content(post['content'])
        """
        # Remove block editor image markup
        clean = re.sub(
            r'<!-- wp:image.*?-->.*?<!-- /wp:image -->',
            '',
            html,
            flags=re.DOTALL
        )

        # Remove figure tags
        clean = re.sub(
            r'<figure class="wp-block-image.*?</figure>',
            '',
            clean,
            flags=re.DOTALL
        )

        # Remove standalone img tags
        clean = re.sub(r'<img[^>]*>', '', clean)

        # Remove empty paragraphs
        clean = re.sub(r'<p>\s*</p>', '', clean)

        return clean

    def build_image_html(
        self,
        images: List[Dict],
        scene_names: Optional[List[str]] = None
    ) -> str:
        """
        Build WordPress-compatible image HTML.

        Args:
            images: List of image dicts with 'id' and 'url'
            scene_names: Optional scene descriptions

        Returns:
            HTML string with figure tags

        Example:
            >>> images = [
                {'id': 123, 'url': 'https://site.com/image1.png'},
                {'id': 124, 'url': 'https://site.com/image2.png'}
            ]
            >>> html = manager.build_image_html(images, ['Opening', 'Conclusion'])
        """
        html = ""

        for i, img in enumerate(images):
            scene = scene_names[i] if scene_names and i < len(scene_names) else f"Scene {i+1}"

            html += f'''<figure class="wp-block-image size-full">
<img loading="lazy" decoding="async" width="2048" height="2048"
     src="{img['url']}"
     alt="{scene}"
     class="wp-image-{img['id']}" />
<figcaption class="wp-element-caption">{scene}</figcaption>
</figure>

'''

        return html

    def update_post_content_with_images(
        self,
        post_id: int,
        new_images: List[Dict],
        prepend: bool = True,
        scene_names: Optional[List[str]] = None
    ) -> bool:
        """
        Replace post images and update content.

        Args:
            post_id: Post ID to update
            new_images: List of new image dicts
            prepend: If True, add images before content; if False, after
            scene_names: Optional scene descriptions

        Returns:
            True if successful

        Example:
            >>> success = manager.update_post_content_with_images(
                post_id=123,
                new_images=[
                    {'id': 456, 'url': 'https://site.com/new1.png'},
                    {'id': 457, 'url': 'https://site.com/new2.png'}
                ],
                scene_names=['Opening Scene', 'Conclusion']
            )
        """
        try:
            # Get current post
            post = self.get(f'/posts/{post_id}')
            current_content = post['content']['raw']

            # Remove old images
            clean_content = self.remove_images_from_content(current_content)

            # Build new image HTML
            image_html = self.build_image_html(new_images, scene_names)

            # Combine content
            if prepend:
                new_content = image_html + clean_content
            else:
                new_content = clean_content + image_html

            # Update post
            update_data = {
                'content': new_content,
                'featured_media': new_images[0]['id'] if new_images else 0
            }

            self.post(f'/posts/{post_id}', update_data)

            logger.info(f"Updated post {post_id} with {len(new_images)} images")
            return True

        except Exception as e:
            logger.error(f"Failed to update post {post_id}: {e}")
            return False


# Usage Example
if __name__ == '__main__':
    manager = WordPressContentManager(
        url='https://yourblog.com',
        username='admin',
        app_password='xxxx xxxx xxxx xxxx xxxx xxxx'
    )

    # Get post
    post = manager.get_post_by_slug('my-story')

    # Upload new images
    new_images = manager.upload_images_batch(
        ['scene1-new.png', 'scene2-new.png', 'scene3-new.png'],
        titles=['Opening', 'Middle', 'Conclusion']
    )

    # Replace images in post
    success = manager.update_post_content_with_images(
        post_id=post['id'],
        new_images=new_images,
        scene_names=['Scene 1: Opening', 'Scene 2: Middle', 'Scene 3: Conclusion']
    )

    print(f"Update {'successful' if success else 'failed'}")
```

---

## Batch Operations

```python
from typing import Callable, List
import csv

class WordPressBatchProcessor(WordPressContentManager):
    """Batch operations with progress tracking."""

    def process_posts_batch(
        self,
        post_ids: List[int],
        process_fn: Callable[[Dict], bool],
        batch_size: int = 10
    ) -> Dict:
        """
        Process multiple posts with progress tracking.

        Args:
            post_ids: List of post IDs to process
            process_fn: Function to process each post (returns True on success)
            batch_size: Number of posts per batch

        Returns:
            Results dict with success/failure counts

        Example:
            >>> def add_tag(post):
                    # Add 'reviewed' tag
                    return manager.add_post_tag(post['id'], 'reviewed')

            >>> results = manager.process_posts_batch(
                post_ids=[1, 2, 3, 4, 5],
                process_fn=add_tag
            )
            >>> print(f"Success: {results['successful']}, Failed: {results['failed']}")
        """
        successful = 0
        failed = 0
        failed_ids = []

        for i in range(0, len(post_ids), batch_size):
            batch = post_ids[i:i+batch_size]

            for post_id in batch:
                try:
                    # Get post
                    post = self.get(f'/posts/{post_id}')

                    # Process
                    success = process_fn(post)

                    if success:
                        successful += 1
                    else:
                        failed += 1
                        failed_ids.append(post_id)

                except Exception as e:
                    logger.error(f"Failed to process post {post_id}: {e}")
                    failed += 1
                    failed_ids.append(post_id)

            # Progress
            progress = (i + len(batch)) / len(post_ids) * 100
            logger.info(f"Progress: {progress:.1f}% ({successful} successful, {failed} failed)")

        return {
            'total': len(post_ids),
            'successful': successful,
            'failed': failed,
            'failed_ids': failed_ids
        }

    def export_posts_to_csv(
        self,
        post_ids: List[int],
        output_file: str,
        fields: List[str] = None
    ):
        """
        Export posts to CSV file.

        Args:
            post_ids: List of post IDs to export
            output_file: Output CSV file path
            fields: List of fields to export (default: id, title, url, status)

        Example:
            >>> manager.export_posts_to_csv(
                post_ids=[1, 2, 3],
                output_file='posts.csv',
                fields=['id', 'title', 'url', 'status', 'date']
            )
        """
        if fields is None:
            fields = ['id', 'title', 'url', 'status', 'date']

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()

            for post_id in post_ids:
                try:
                    post = self.get(f'/posts/{post_id}')

                    row = {
                        'id': post['id'],
                        'title': post['title']['rendered'],
                        'url': post['link'],
                        'status': post['status'],
                        'date': post['date']
                    }

                    writer.writerow(row)
                    logger.info(f"Exported: {post['title']['rendered']}")

                except Exception as e:
                    logger.error(f"Failed to export post {post_id}: {e}")

        logger.info(f"Exported {len(post_ids)} posts to {output_file}")


# Usage Example
if __name__ == '__main__':
    manager = WordPressBatchProcessor(
        url='https://yourblog.com',
        username='admin',
        app_password='xxxx xxxx xxxx xxxx xxxx xxxx'
    )

    # Get all published posts
    all_posts = manager.get('/posts', params={'per_page': 100, 'status': 'publish'})
    post_ids = [post['id'] for post in all_posts]

    # Batch update: add category
    def add_category(post):
        categories = post.get('categories', [])
        if 5 not in categories:  # Add category ID 5
            categories.append(5)
            manager.post(f'/posts/{post["id"]}', {'categories': categories})
            return True
        return False

    results = manager.process_posts_batch(post_ids, add_category)
    print(f"Added category to {results['successful']} posts")

    # Export to CSV
    manager.export_posts_to_csv(
        post_ids=post_ids,
        output_file='all_posts.csv'
    )
```

---

## Error Handling

```python
import time
from functools import wraps

def retry_on_failure(max_retries=3, backoff_factor=2):
    """
    Decorator for retrying failed operations with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        backoff_factor: Multiplier for wait time between retries

    Example:
        @retry_on_failure(max_retries=3, backoff_factor=2)
        def upload_image(path):
            return manager.upload_image(path)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.Timeout:
                    if attempt < max_retries - 1:
                        wait_time = backoff_factor ** attempt
                        logger.warning(f"Timeout, retrying in {wait_time}s (attempt {attempt+1}/{max_retries})")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"Failed after {max_retries} attempts")
                        raise
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 403:
                        logger.error("Blocked by firewall - use WP-CLI fallback")
                        raise
                    elif e.response.status_code >= 500:
                        # Server error, retry
                        if attempt < max_retries - 1:
                            wait_time = backoff_factor ** attempt
                            logger.warning(f"Server error, retrying in {wait_time}s")
                            time.sleep(wait_time)
                        else:
                            raise
                    else:
                        # Client error, don't retry
                        raise
        return wrapper
    return decorator


class ResilientWordPressClient(WordPressContentManager):
    """WordPress client with robust error handling."""

    @retry_on_failure(max_retries=3)
    def safe_upload_image(self, image_path: str, **kwargs) -> Optional[Dict]:
        """Upload image with retry logic."""
        return self.upload_image(image_path, **kwargs)

    @retry_on_failure(max_retries=3)
    def safe_create_post(self, post_data: Dict) -> Optional[Dict]:
        """Create post with retry logic."""
        return self.post('/posts', post_data)

    def create_post_with_validation(
        self,
        title: str,
        content: str,
        **kwargs
    ) -> Optional[Dict]:
        """
        Create post with input validation.

        Args:
            title: Post title (required, max 200 chars)
            content: Post content (required, min 100 chars)
            **kwargs: Additional post fields

        Returns:
            Created post dict or None on failure
        """
        # Validate inputs
        if not title or len(title) > 200:
            logger.error(f"Invalid title length: {len(title)}")
            return None

        if not content or len(content) < 100:
            logger.error(f"Content too short: {len(content)} chars")
            return None

        # Build post data
        post_data = {
            'title': title,
            'content': content,
            'status': kwargs.get('status', 'draft'),
            **kwargs
        }

        try:
            return self.safe_create_post(post_data)
        except Exception as e:
            logger.error(f"Failed to create post: {e}")
            return None


# Usage Example
if __name__ == '__main__':
    client = ResilientWordPressClient(
        url='https://yourblog.com',
        username='admin',
        app_password='xxxx xxxx xxxx xxxx xxxx xxxx'
    )

    # Upload with retry
    media = client.safe_upload_image('large-image.png')

    # Create post with validation
    post = client.create_post_with_validation(
        title='My Blog Post',
        content='<p>' + 'Lorem ipsum ' * 50 + '</p>',  # At least 100 chars
        status='publish',
        categories=[1, 2]
    )

    if post:
        print(f"Created post: {post['link']}")
```

---

**End of REST API Examples**

See `SKILL.md` for complete WordPress patterns documentation.
