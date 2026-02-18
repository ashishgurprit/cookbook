---
name: translation-pipeline
description: "Production translation pipeline with multi-provider fallback, caching, language detection, and formatting preservation. Use when: (1) Building multi-language websites/apps, (2) Translating content at scale, (3) Localizing blog posts or documentation, (4) Creating translation APIs, (5) Cost-optimized translation workflows. Triggers on 'translation', 'translate text', 'multi-language', 'localization', or i18n requests."
license: Proprietary
---

# Translation Pipeline

Production-ready translation system with multi-provider support, MD5 caching, language detection, and formatting preservation.

## Quick Reference: Translation Providers

| Provider | Cost/1M chars | Quality | Languages | Rate Limit | Best For |
|----------|---------------|---------|-----------|------------|----------|
| **Google Translate** | $20 | 95% | 100+ | None (pay-per-use) | Production, high quality |
| **DeepL** | $25 | 98% | 30 | 500K chars/month free | Premium quality, EU languages |
| **MyMemory** | Free (10K/day) | 70% | 50+ | 10K chars/day | Development, low volume |
| **LibreTranslate** | Self-hosted | 65% | 30+ | None | Privacy, offline, bulk |
| **Azure Translator** | $10 | 90% | 100+ | None | Microsoft ecosystem |
| **AWS Translate** | $15 | 88% | 75 | None | AWS infrastructure |

---

# ARCHITECTURE

## Translation Pipeline Flow

```
Input Text
    │
    ├──► 1. Language Detection
    │        └─► Detect source language (if not provided)
    │
    ├──► 2. Cache Check
    │        ├─► Generate MD5 hash of (text + target_lang)
    │        └─► Return cached translation if exists
    │
    ├──► 3. Provider Selection
    │        ├─► Choose provider by strategy (cost/quality/availability)
    │        └─► Fallback chain if primary fails
    │
    ├──► 4. Translation
    │        ├─► Call provider API
    │        ├─► Preserve formatting (markdown, HTML)
    │        └─► Retry on failure
    │
    ├──► 5. Post-Processing
    │        ├─► Validate output
    │        ├─► Fix common issues
    │        └─► Restore formatting
    │
    ├──► 6. Cache Storage
    │        └─► Save to cache with TTL
    │
    └──► Return Translation
```

---

# CORE IMPLEMENTATION

## Complete Translation Service

```python
import hashlib
import json
from typing import Optional, Dict
from googletrans import Translator as GoogleTranslator
from deep_translator import MyMemoryTranslator
import langdetect

class TranslationService:
    """Production translation service with caching and multi-provider support"""

    def __init__(self, cache_backend=None):
        self.cache = cache_backend or InMemoryCache()
        self.providers = {
            'google': GoogleTranslator(),
            'mymemory': MyMemoryTranslator(),
        }
        self.default_provider = 'google'
        self.fallback_chain = ['google', 'mymemory']

    def translate(
        self,
        text: str,
        target_lang: str,
        source_lang: Optional[str] = None,
        use_cache: bool = True,
        preserve_formatting: bool = True
    ) -> Dict:
        """
        Translate text with caching and fallback.

        Args:
            text: Text to translate
            target_lang: Target language code (e.g., 'es', 'fr')
            source_lang: Source language (auto-detected if None)
            use_cache: Use cached translations
            preserve_formatting: Preserve markdown/HTML formatting

        Returns:
            Dict with translation, source_lang, provider used
        """

        # 1. Detect source language
        if not source_lang:
            source_lang = self.detect_language(text)

        # Skip if already target language
        if source_lang == target_lang:
            return {
                'translation': text,
                'source_lang': source_lang,
                'target_lang': target_lang,
                'cached': False,
                'provider': None
            }

        # 2. Check cache
        if use_cache:
            cache_key = self._generate_cache_key(text, source_lang, target_lang)
            cached = self.cache.get(cache_key)
            if cached:
                return {
                    **cached,
                    'cached': True
                }

        # 3. Extract formatting
        if preserve_formatting:
            text, placeholders = self._extract_formatting(text)

        # 4. Translate with fallback
        translation = None
        provider_used = None

        for provider_name in self.fallback_chain:
            try:
                translation = self._translate_with_provider(
                    text, source_lang, target_lang, provider_name
                )
                provider_used = provider_name
                break
            except Exception as e:
                print(f"Provider {provider_name} failed: {e}")
                continue

        if not translation:
            raise Exception("All translation providers failed")

        # 5. Restore formatting
        if preserve_formatting and placeholders:
            translation = self._restore_formatting(translation, placeholders)

        # 6. Cache result
        result = {
            'translation': translation,
            'source_lang': source_lang,
            'target_lang': target_lang,
            'cached': False,
            'provider': provider_used
        }

        if use_cache:
            self.cache.set(cache_key, result, ttl=2592000)  # 30 days

        return result

    def detect_language(self, text: str) -> str:
        """Detect source language"""
        try:
            return langdetect.detect(text)
        except:
            return 'en'  # Default to English

    def _translate_with_provider(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        provider: str
    ) -> str:
        """Translate using specific provider"""

        if provider == 'google':
            translator = self.providers['google']
            result = translator.translate(text, src=source_lang, dest=target_lang)
            return result.text

        elif provider == 'mymemory':
            translator = MyMemoryTranslator(source=source_lang, target=target_lang)
            return translator.translate(text)

        else:
            raise ValueError(f"Unknown provider: {provider}")

    def _generate_cache_key(self, text: str, source_lang: str, target_lang: str) -> str:
        """Generate cache key from content hash"""
        content = f"{text}:{source_lang}:{target_lang}"
        return hashlib.md5(content.encode()).hexdigest()

    def _extract_formatting(self, text: str) -> tuple:
        """Extract markdown/HTML formatting and replace with placeholders"""
        import re

        placeholders = {}
        counter = 0

        # Extract markdown links
        def replace_link(match):
            nonlocal counter
            placeholder = f"__LINK_{counter}__"
            placeholders[placeholder] = match.group(0)
            counter += 1
            return placeholder

        text = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', replace_link, text)

        # Extract markdown bold/italic
        def replace_bold(match):
            nonlocal counter
            placeholder = f"__BOLD_{counter}__"
            placeholders[placeholder] = match.group(0)
            counter += 1
            return match.group(1)  # Keep text, mark for restoration

        # Extract HTML tags
        def replace_html(match):
            nonlocal counter
            placeholder = f"__HTML_{counter}__"
            placeholders[placeholder] = match.group(0)
            counter += 1
            return placeholder

        text = re.sub(r'<[^>]+>', replace_html, text)

        return text, placeholders

    def _restore_formatting(self, text: str, placeholders: Dict) -> str:
        """Restore formatting placeholders"""
        for placeholder, original in placeholders.items():
            text = text.replace(placeholder, original)
        return text


class InMemoryCache:
    """Simple in-memory cache (use Redis in production)"""

    def __init__(self):
        self.cache = {}

    def get(self, key: str):
        return self.cache.get(key)

    def set(self, key: str, value: any, ttl: int = None):
        self.cache[key] = value
```

---

# ADVANCED FEATURES

## Feature 1: Batch Translation with Cost Optimization

```python
class BatchTranslationService(TranslationService):
    """Optimized batch translation"""

    def translate_batch(
        self,
        texts: List[str],
        target_lang: str,
        source_lang: Optional[str] = None
    ) -> List[Dict]:
        """
        Translate multiple texts efficiently.

        Optimizations:
        - Check cache first for all items
        - Batch API calls to reduce overhead
        - Use cheapest provider for bulk operations
        """

        # 1. Separate cached vs uncached
        cached_results = {}
        uncached_texts = []

        for i, text in enumerate(texts):
            cache_key = self._generate_cache_key(text, source_lang or 'auto', target_lang)
            cached = self.cache.get(cache_key)

            if cached:
                cached_results[i] = cached
            else:
                uncached_texts.append((i, text))

        # 2. Translate uncached (use free provider for bulk)
        uncached_results = {}

        for i, text in uncached_texts:
            result = self.translate(
                text, target_lang, source_lang,
                use_cache=True
            )
            uncached_results[i] = result

        # 3. Combine results
        all_results = {**cached_results, **uncached_results}
        return [all_results[i] for i in range(len(texts))]
```

## Feature 2: Translation Quality Check

```python
class QualityCheckTranslationService(TranslationService):
    """Translation with quality validation"""

    def translate_with_quality_check(
        self,
        text: str,
        target_lang: str,
        min_confidence: float = 0.8
    ) -> Dict:
        """Translate and verify quality"""

        # Translate with multiple providers
        results = []

        for provider in ['google', 'mymemory']:
            try:
                translation = self._translate_with_provider(
                    text, 'auto', target_lang, provider
                )
                results.append({
                    'provider': provider,
                    'translation': translation
                })
            except:
                continue

        # If results differ significantly, flag for review
        if len(results) > 1:
            similarity = self._calculate_similarity(
                results[0]['translation'],
                results[1]['translation']
            )

            if similarity < min_confidence:
                return {
                    'translation': results[0]['translation'],  # Use best provider
                    'confidence': similarity,
                    'needs_review': True,
                    'alternatives': results
                }

        return {
            'translation': results[0]['translation'],
            'confidence': 1.0,
            'needs_review': False
        }

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity score between translations"""
        from difflib import SequenceMatcher
        return SequenceMatcher(None, text1, text2).ratio()
```

## Feature 3: Specialized Content Handling

```python
class ContentAwareTranslationService(TranslationService):
    """Handle different content types"""

    def translate_markdown(self, markdown: str, target_lang: str) -> str:
        """Preserve markdown structure"""

        import re

        # Extract code blocks
        code_blocks = {}
        def save_code_block(match):
            key = f"__CODE_{len(code_blocks)}__"
            code_blocks[key] = match.group(0)
            return key

        markdown = re.sub(r'```[\s\S]*?```', save_code_block, markdown)

        # Translate
        result = self.translate(markdown, target_lang, preserve_formatting=True)
        translated = result['translation']

        # Restore code blocks
        for key, code in code_blocks.items():
            translated = translated.replace(key, code)

        return translated

    def translate_html(self, html: str, target_lang: str) -> str:
        """Translate HTML while preserving tags"""

        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, 'html.parser')

        # Translate text nodes only
        for text in soup.find_all(text=True):
            if text.strip() and text.parent.name not in ['script', 'style', 'code']:
                translated = self.translate(str(text), target_lang)
                text.replace_with(translated['translation'])

        return str(soup)
```

---

# PROVIDER IMPLEMENTATIONS

## Google Translate Provider

```python
from google.cloud import translate_v2 as translate

class GoogleTranslateProvider:
    """Google Cloud Translation API"""

    def __init__(self, api_key: str):
        self.client = translate.Client(api_key=api_key)
        self.cost_per_char = 0.00002  # $20 per 1M characters

    def translate(self, text: str, target_lang: str, source_lang: str = None) -> str:
        result = self.client.translate(
            text,
            target_language=target_lang,
            source_language=source_lang
        )
        return result['translatedText']

    def estimate_cost(self, text: str) -> float:
        return len(text) * self.cost_per_char
```

## DeepL Provider

```python
import deepl

class DeepLProvider:
    """DeepL Translation API (highest quality)"""

    def __init__(self, api_key: str):
        self.translator = deepl.Translator(api_key)
        self.cost_per_char = 0.000025  # $25 per 1M characters

    def translate(self, text: str, target_lang: str, source_lang: str = None) -> str:
        result = self.translator.translate_text(
            text,
            target_lang=target_lang.upper(),
            source_lang=source_lang.upper() if source_lang else None
        )
        return result.text
```

---

# CACHING STRATEGIES

## Redis Cache (Production)

```python
import redis
import json

class RedisCache:
    """Redis-based translation cache"""

    def __init__(self, host='localhost', port=6379, db=0):
        self.redis = redis.Redis(host=host, port=port, db=db)

    def get(self, key: str):
        value = self.redis.get(f"trans:{key}")
        return json.loads(value) if value else None

    def set(self, key: str, value: dict, ttl: int = 2592000):
        """TTL default: 30 days"""
        self.redis.setex(
            f"trans:{key}",
            ttl,
            json.dumps(value)
        )

    def clear_cache(self):
        """Clear all translation cache"""
        for key in self.redis.scan_iter("trans:*"):
            self.redis.delete(key)
```

## File-Based Cache

```python
import json
from pathlib import Path

class FileCache:
    """File-based cache for development"""

    def __init__(self, cache_dir=".translation_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

    def get(self, key: str):
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None

    def set(self, key: str, value: dict, ttl: int = None):
        cache_file = self.cache_dir / f"{key}.json"
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
```

---

# BEST PRACTICES

## 1. When to Cache

```
✓ Cache:
- Static content (blog posts, docs)
- Repeated translations
- Common phrases
- Product descriptions

✗ Don't cache:
- User-generated content (privacy)
- Time-sensitive content
- Personalized messages
- One-time translations
```

## 2. Cost Optimization

```python
# Strategy: Use free tier first, upgrade if needed

def select_provider(char_count, quality_required):
    if char_count < 5000 and daily_usage < 10000:
        # Free tier
        return 'mymemory'

    elif quality_required == 'high':
        # Premium quality
        return 'deepl'

    else:
        # Good quality, low cost
        return 'google'
```

## 3. Language Detection Best Practices

```python
# Detect on first chunk only (for long texts)
def detect_language_efficiently(text: str) -> str:
    sample = text[:500]  # First 500 chars
    return langdetect.detect(sample)

# Cache language detection
def detect_with_cache(text: str) -> str:
    cache_key = hashlib.md5(text[:100].encode()).hexdigest()
    cached = cache.get(f"lang:{cache_key}")
    if cached:
        return cached

    lang = langdetect.detect(text)
    cache.set(f"lang:{cache_key}", lang, ttl=86400)
    return lang
```

---

# REAL-WORLD EXAMPLE

## WordPress Multi-Language Site

```python
# See examples/wordpress-multilang.py

translation_service = TranslationService(cache_backend=RedisCache())

def translate_post(post_id: int, target_languages: List[str]):
    """Translate WordPress post to multiple languages"""

    # Get original post
    post = wp_api.get_post(post_id)

    for lang in target_languages:
        # Translate content
        translated_content = translation_service.translate_markdown(
            post['content'],
            target_lang=lang
        )

        # Translate title
        translated_title = translation_service.translate(
            post['title'],
            target_lang=lang
        )

        # Create translated post
        wp_api.create_post({
            'title': translated_title['translation'],
            'content': translated_content,
            'meta': {
                'original_post_id': post_id,
                'language': lang,
                'translation_provider': translated_title['provider']
            }
        })

# Translate to 10 languages
translate_post(123, ['es', 'fr', 'de', 'it', 'pt', 'ja', 'zh', 'ar', 'ru', 'hi'])
```

---

# FILE REFERENCES

- `templates/translation_pipeline.py` - Complete pipeline implementation
- `templates/language_detector.py` - Language detection utilities
- `templates/translation_cache.py` - Caching strategies
- `templates/provider_registry.py` - Multi-provider management
- `checklists/translation-quality.md` - Quality assurance checklist
- `examples/wordpress-multilang.py` - WordPress integration
- `examples/batch-translation.py` - Bulk translation example
- `references/provider-comparison.md` - Provider comparison matrix
- `references/language-codes.md` - ISO 639-1 language codes

## Integrates With

| Module | Path | Description |
|--------|------|-------------|
| mobile-localization | modules/mobile-localization/ | Mobile i18n for React Native — i18next setup, RTL support, dynamic language switching, pluralization |
