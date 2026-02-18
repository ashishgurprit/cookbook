"""
URL connector for analyzing any website via HTTP/HTTPS.

This connector fetches content from any public URL and normalizes it
for SEO analysis. No authentication required.
"""

import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .base_connector import (
    BaseConnector,
    NormalizedContent,
    PlatformType,
    ConnectorError,
    NotFoundError,
)


class URLConnector(BaseConnector):
    """Fetch and analyze content from any public URL."""

    def __init__(self, timeout: int = 30, user_agent: str = None):
        """
        Initialize URL connector.

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent string (optional)
        """
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    @property
    def platform_type(self) -> PlatformType:
        return PlatformType.URL

    def fetch(self, identifier: str) -> NormalizedContent:
        """
        Fetch and normalize content from a URL.

        Args:
            identifier: Full URL (http:// or https://)

        Returns:
            NormalizedContent with extracted data

        Raises:
            ConnectorError: If fetch fails
            NotFoundError: If URL returns 404
        """
        url = self._normalize_url(identifier)

        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise NotFoundError(f"URL not found: {url}")
            raise ConnectorError(f"HTTP error fetching {url}: {e}")
        except requests.exceptions.RequestException as e:
            raise ConnectorError(f"Failed to fetch {url}: {e}")

        # Parse HTML
        soup = BeautifulSoup(response.text, "html.parser")

        # Extract content
        title = self._extract_title(soup)
        meta_description = self._extract_meta_description(soup)
        meta_keywords = self._extract_meta_keywords(soup)
        canonical_url = self._extract_canonical(soup, url)
        headings = self._extract_headings(soup)
        images = self._extract_images(soup, url)
        links = self._extract_links(soup, url)
        content = self._extract_main_content(soup)

        # Generate URL slug from path
        parsed = urlparse(url)
        url_slug = parsed.path.strip("/") or "index"

        return NormalizedContent(
            title=title,
            content=content,
            url_slug=url_slug,
            url=url,
            meta_description=meta_description,
            meta_keywords=meta_keywords,
            canonical_url=canonical_url,
            headings=headings,
            images=images,
            links=links,
            platform=PlatformType.URL,
            raw_data={
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "response_time": response.elapsed.total_seconds(),
            },
        )

    def list_items(self, **filters) -> List[Dict[str, Any]]:
        """
        URL connector doesn't support listing (no index/sitemap parsing).

        To analyze multiple URLs, call fetch() for each URL.

        Raises:
            NotImplementedError: Always (URLs have no parent index)
        """
        raise NotImplementedError(
            "URL connector does not support listing. "
            "Provide explicit URLs to analyze."
        )

    def test_connection(self) -> Tuple[bool, str]:
        """
        Test if we can make HTTP requests.

        Returns:
            (True, message) if requests work
        """
        try:
            response = self.session.get(
                "https://www.google.com", timeout=10
            )
            response.raise_for_status()
            return True, "HTTP client is working"
        except Exception as e:
            return False, f"HTTP client error: {e}"

    # --- PRIVATE EXTRACTION METHODS ---

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has a scheme."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract page title."""
        # Try <title> tag first
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            return title_tag.string.strip()

        # Fallback to <h1>
        h1_tag = soup.find("h1")
        if h1_tag:
            return h1_tag.get_text(strip=True)

        return "Untitled Page"

    def _extract_meta_description(self, soup: BeautifulSoup) -> str:
        """Extract meta description."""
        meta = soup.find("meta", attrs={"name": "description"})
        if meta and meta.get("content"):
            return meta["content"].strip()
        return ""

    def _extract_meta_keywords(self, soup: BeautifulSoup) -> str:
        """Extract meta keywords."""
        meta = soup.find("meta", attrs={"name": "keywords"})
        if meta and meta.get("content"):
            return meta["content"].strip()
        return ""

    def _extract_canonical(self, soup: BeautifulSoup, base_url: str) -> str:
        """Extract canonical URL."""
        link = soup.find("link", attrs={"rel": "canonical"})
        if link and link.get("href"):
            return urljoin(base_url, link["href"])
        return base_url

    def _extract_headings(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract all headings (h1-h6)."""
        headings = []
        for level in range(1, 7):
            for tag in soup.find_all(f"h{level}"):
                text = tag.get_text(strip=True)
                if text:
                    headings.append({"level": f"h{level}", "text": text})
        return headings

    def _extract_images(
        self, soup: BeautifulSoup, base_url: str
    ) -> List[Dict[str, str]]:
        """Extract all images with alt text."""
        images = []
        for img in soup.find_all("img"):
            src = img.get("src", "")
            if src:
                images.append({
                    "src": urljoin(base_url, src),
                    "alt": img.get("alt", ""),
                    "title": img.get("title", ""),
                })
        return images

    def _extract_links(
        self, soup: BeautifulSoup, base_url: str
    ) -> List[Dict[str, str]]:
        """Extract all links."""
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            text = a.get_text(strip=True)
            rel = a.get("rel", [])
            if isinstance(rel, list):
                rel = " ".join(rel)

            links.append({
                "href": urljoin(base_url, href),
                "text": text,
                "rel": rel,
            })
        return links

    def _extract_main_content(self, soup: BeautifulSoup) -> str:
        """
        Extract main content HTML.

        Tries to identify the main content area and exclude navigation,
        headers, footers, sidebars, etc.
        """
        # Remove unwanted elements
        for tag in soup.find_all(["script", "style", "nav", "header", "footer"]):
            tag.decompose()

        # Try to find main content container
        main_content = None

        # Look for semantic HTML5 tags
        for selector in ["main", "article", '[role="main"]']:
            main_content = soup.select_one(selector)
            if main_content:
                break

        # Fallback: use body or entire soup
        if not main_content:
            main_content = soup.find("body") or soup

        # Return HTML string
        return str(main_content)


def create_url_connector(**kwargs) -> URLConnector:
    """
    Factory function to create a URL connector.

    Args:
        **kwargs: Passed to URLConnector constructor

    Returns:
        Configured URLConnector instance
    """
    connector = URLConnector(**kwargs)

    # Test connection
    success, message = connector.test_connection()
    if not success:
        raise ConnectorError(f"Failed to initialize URL connector: {message}")

    return connector
