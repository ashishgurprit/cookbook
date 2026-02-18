"""
Base connector interface for multi-platform SEO analysis.

All platform connectors must implement this interface to work with the
core SEO analysis modules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any


class PlatformType(Enum):
    """Supported platform types."""
    URL = "url"
    WORDPRESS = "wordpress"
    SHOPIFY = "shopify"
    GHOST = "ghost"
    STATIC = "static"
    DJANGO = "django"
    FLASK = "flask"
    FASTAPI = "fastapi"


@dataclass
class NormalizedContent:
    """
    Standardized content format that all connectors must return.

    This normalized structure allows core SEO analysis modules to work
    with content from any platform without knowing platform-specific details.
    """

    # REQUIRED FIELDS
    title: str
    content: str  # HTML content
    url_slug: str  # URL path component (e.g., "my-blog-post")
    url: str  # Full URL

    # OPTIONAL SEO FIELDS
    meta_description: str = ""
    meta_keywords: str = ""
    canonical_url: str = ""

    # STRUCTURED CONTENT
    headings: List[Dict[str, str]] = field(default_factory=list)
    # Format: [{"level": "h1", "text": "Main Heading"}, ...]

    images: List[Dict[str, str]] = field(default_factory=list)
    # Format: [{"src": "url", "alt": "text", "title": "text"}, ...]

    links: List[Dict[str, str]] = field(default_factory=list)
    # Format: [{"href": "url", "text": "anchor", "rel": "nofollow"}, ...]

    # METADATA
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    author: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # PLATFORM-SPECIFIC
    platform: PlatformType = PlatformType.URL
    raw_data: Optional[Dict[str, Any]] = None
    # Store platform-specific data here for special handling

    # CONTENT METRICS
    word_count: int = 0
    reading_time_minutes: int = 0

    def __post_init__(self):
        """Calculate derived fields."""
        if not self.word_count and self.content:
            # Simple word count from HTML content
            import re
            text = re.sub(r'<[^>]+>', '', self.content)
            self.word_count = len(text.split())

        if not self.reading_time_minutes and self.word_count:
            # Average reading speed: 200 words/minute
            self.reading_time_minutes = max(1, self.word_count // 200)


class BaseConnector(ABC):
    """
    Abstract base class for all platform connectors.

    Each connector must implement these methods to enable:
    - Fetching content from the platform
    - Listing available content items
    - Testing connectivity
    - (Optional) Updating content with SEO optimizations
    """

    @abstractmethod
    def fetch(self, identifier: str) -> NormalizedContent:
        """
        Fetch a single content item and normalize it.

        Args:
            identifier: Platform-specific identifier
                - URL connector: "https://example.com/page"
                - WordPress: "post:123" or "page:456"
                - Shopify: "product:789" or "page:123"
                - Ghost: "post:abc123" or "page:def456"
                - Static: "blog/post.html"
                - Django: "app.Model:123"

        Returns:
            NormalizedContent with all available fields populated

        Raises:
            ConnectorError: If fetch fails or item not found
        """
        pass

    @abstractmethod
    def list_items(self, **filters) -> List[Dict[str, Any]]:
        """
        List available content items.

        Args:
            **filters: Platform-specific filters
                - type: Content type (e.g., "post", "page", "product")
                - status: Status filter (e.g., "published", "draft")
                - limit: Maximum items to return
                - offset: Pagination offset

        Returns:
            List of dicts with at minimum:
                - id: Platform identifier
                - title: Content title
                - url: Full URL (if available)
                - type: Content type

        Raises:
            ConnectorError: If listing fails
        """
        pass

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """
        Test if the connector can communicate with the platform.

        Returns:
            (success, message) tuple:
                - success: True if connection works
                - message: Human-readable status message
        """
        pass

    def update(self, identifier: str, **updates) -> bool:
        """
        Update content with SEO optimizations (optional).

        Not all platforms support programmatic updates. Override this
        method only if the platform allows modifications.

        Args:
            identifier: Platform-specific identifier
            **updates: Fields to update (platform-specific)
                Common fields:
                - meta_description: New meta description
                - meta_keywords: New meta keywords
                - title: Updated title
                - canonical_url: Canonical URL

        Returns:
            True if update succeeded, False otherwise

        Raises:
            NotImplementedError: If platform doesn't support updates
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support content updates"
        )

    @property
    @abstractmethod
    def platform_type(self) -> PlatformType:
        """Return the platform type this connector handles."""
        pass


class ConnectorError(Exception):
    """Base exception for connector-related errors."""
    pass


class AuthenticationError(ConnectorError):
    """Raised when authentication fails."""
    pass


class NotFoundError(ConnectorError):
    """Raised when requested content is not found."""
    pass


class RateLimitError(ConnectorError):
    """Raised when rate limit is exceeded."""
    pass
