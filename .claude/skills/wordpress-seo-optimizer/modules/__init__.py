"""
WordPress SEO Optimizer Modules

Core analysis and optimization modules for WordPress SEO.
"""

from .keyword_analyzer import KeywordAnalyzer, extract_keywords_from_title
from .onpage_optimizer import OnPageOptimizer
from .seo_analyzer import SEOAnalyzer
from .technical_auditor import TechnicalAuditor, SchemaValidator
from .schema_generator import SchemaGenerator
from .wordpress_connector import WordPressConnector, create_connector, WordPressNotAvailableError

__all__ = [
    'KeywordAnalyzer',
    'OnPageOptimizer',
    'SEOAnalyzer',
    'TechnicalAuditor',
    'SchemaValidator',
    'SchemaGenerator',
    'WordPressConnector',
    'create_connector',
    'WordPressNotAvailableError',
    'extract_keywords_from_title'
]

__version__ = '0.2.0'  # Phase 2: WordPress Integration + Technical SEO + Schema
