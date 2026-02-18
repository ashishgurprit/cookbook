"""
Connectors package for multi-platform SEO analysis.

Exports all connector classes and base interfaces.
"""

from .base_connector import (
    BaseConnector,
    NormalizedContent,
    PlatformType,
    ConnectorError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
)

from .url_connector import URLConnector, create_url_connector

__all__ = [
    # Base classes
    'BaseConnector',
    'NormalizedContent',
    'PlatformType',

    # Exceptions
    'ConnectorError',
    'AuthenticationError',
    'NotFoundError',
    'RateLimitError',

    # Connectors
    'URLConnector',
    'create_url_connector',
]
