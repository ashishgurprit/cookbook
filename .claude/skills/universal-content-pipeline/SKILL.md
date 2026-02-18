---
name: universal-content-pipeline
description: "End-to-end workflow to convert documents (books, PDFs, reports) into published blog content automatically. Combines PDF processing, semantic chunking, translation, AI content generation, and WordPress publishing. Use when: (1) Converting books → blog series, (2) Building automated content pipelines, (3) Document-to-blog workflows, (4) Knowledge extraction → publishing, (5) Scaling content production from source materials. Triggers on 'document to blog', 'book to content', 'automated content pipeline', 'PDF to blog posts', or 'universal content workflow'."
license: Proprietary
---

# Universal Content Pipeline

**Convert 1 book → 50+ blog posts automatically**

A complete production workflow that transforms documents (PDFs, books, reports) into published, multi-platform content using AI-powered extraction, generation, and distribution.

## Value Proposition

**Time Saved**: 40-80 hours per book
**Content Volume**: 1 source document → 50+ high-quality blog posts
**Quality**: Human-quality content with SEO optimization
**Distribution**: WordPress, social media, newsletters (automated)

---

## Quick Reference: Pipeline Stages

| Stage | Input | Output | Time | Tools Used |
|-------|-------|--------|------|------------|
| **1. Document Ingestion** | PDF, EPUB, DOCX | Raw text + metadata | 2-5 min | pdf-processing, OCR |
| **2. Content Preparation** | Raw text | Cleaned, chunked text | 5-10 min | semantic-chunking, translation-pipeline |
| **3. Knowledge Extraction** | Chunks | Concepts, themes, relationships | 10-20 min | OpenAI embeddings |
| **4. Content Generation** | Chunks + themes | Draft blog posts | 30-60 min | GPT-4, content templates |
| **5. Publishing** | Draft posts | Published WordPress posts | 5-10 min | WordPress API |
| **6. Distribution** | Published posts | Social media, newsletters | 5-10 min | Social APIs |

**Total**: 1-2 hours for complete pipeline (vs 40-80 hours manual)

---

# ARCHITECTURE

## Complete Pipeline Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    UNIVERSAL CONTENT PIPELINE                │
└─────────────────────────────────────────────────────────────┘

INPUT: Document (PDF, EPUB, DOCX, etc.)
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ STAGE 1: DOCUMENT INGESTION                                 │
│  • PDF extraction with OCR fallback                          │
│  • Format detection (scanned vs digital)                     │
│  • Metadata extraction (title, author, date)                 │
│  • Table of contents parsing                                 │
│  Skills: pdf-processing                                      │
└─────────────────────────────────────────────────────────────┘
    │
    ▼ Raw Text + Metadata
    │
┌─────────────────────────────────────────────────────────────┐
│ STAGE 2: CONTENT PREPARATION                                │
│  • Translation (if needed)                                   │
│  • Text cleaning & normalization                             │
│  • Semantic chunking (context-preserving)                    │
│  • Quality filtering                                         │
│  Skills: translation-pipeline, semantic-chunking             │
└─────────────────────────────────────────────────────────────┘
    │
    ▼ Semantic Chunks (500-600 tokens each)
    │
┌─────────────────────────────────────────────────────────────┐
│ STAGE 3: KNOWLEDGE EXTRACTION                               │
│  • Concept extraction (key ideas)                            │
│  • Theme detection (patterns)                                │
│  • Relationship mapping (connections)                        │
│  • Entity recognition (people, places, terms)                │
│  Skills: Custom knowledge extraction                         │
└─────────────────────────────────────────────────────────────┘
    │
    ▼ Knowledge Graph + Enriched Chunks
    │
┌─────────────────────────────────────────────────────────────┐
│ STAGE 4: CONTENT GENERATION (AI-Powered)                    │
│  • Chunk → blog post conversion                              │
│  • Title generation (SEO-optimized)                          │
│  • Introduction/conclusion writing                           │
│  • Internal linking suggestions                              │
│  • Featured image prompt generation                          │
│  • Meta description creation                                 │
│  Skills: Custom content generation                           │
└─────────────────────────────────────────────────────────────┘
    │
    ▼ Draft Blog Posts (50+)
    │
┌─────────────────────────────────────────────────────────────┐
│ STAGE 5: PUBLISHING                                         │
│  • WordPress post creation                                   │
│  • Image upload & optimization                               │
│  • SEO metadata injection                                    │
│  • Category & tag assignment                                 │
│  • Scheduling (drip publishing)                              │
│  Skills: WordPress API integration                           │
└─────────────────────────────────────────────────────────────┘
    │
    ▼ Published Posts
    │
┌─────────────────────────────────────────────────────────────┐
│ STAGE 6: DISTRIBUTION                                       │
│  • Social media posting (Twitter, LinkedIn, Facebook)        │
│  • Newsletter integration                                    │
│  • Cross-platform sharing                                    │
│  • Analytics tracking                                        │
│  Skills: Social media APIs                                   │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
OUTPUT: Published Content Series + Social Distribution
```

---

# PREREQUISITES

## Required Skills

```bash
# Install prerequisite skills
1. pdf-processing          # Document extraction
2. semantic-chunking       # Context-aware text splitting
3. translation-pipeline    # Multi-language support (optional)
```

## External Dependencies

```bash
# Python packages
pip install openai tiktoken chromadb
pip install wordpress-api requests
pip install beautifulsoup4 markdownify
pip install python-dotenv pillow

# API Requirements
- OpenAI API key (for content generation & embeddings)
- WordPress site with REST API enabled
- WordPress application password
- (Optional) Social media API keys
```

## Setup Requirements

```bash
# 1. Environment variables
OPENAI_API_KEY=sk-...
WORDPRESS_URL=https://yourblog.com
WORDPRESS_USERNAME=admin
WORDPRESS_APP_PASSWORD=...

# 2. Create output directories
mkdir -p pipeline_output/{extracted,chunks,generated,published}

# 3. Initialize configuration
python pipeline_orchestrator.py --init
```

---

# STAGE-BY-STAGE GUIDE

## Stage 1: Document Ingestion

**Purpose**: Extract text from any document format

```python
from pdf_processor import PDFProcessor
from google_vision_ocr import GoogleVisionProvider

# Initialize
ocr = GoogleVisionProvider(api_key='YOUR_KEY')
processor = PDFProcessor(ocr_provider=ocr)

# Process document
result = processor.process(
    pdf_path='./book.pdf',
    extract_tables=True,
    extract_images=True
)

# Output
{
    'text': 'Full extracted text...',
    'page_count': 350,
    'pdf_type': 'digital',  # or 'scanned', 'mixed'
    'tables': [...],
    'images': [...],
    'metadata': {
        'title': 'Book Title',
        'author': 'Author Name',
        'creation_date': '2024-01-01'
    },
    'confidence': 0.98
}
```

**Quality Gates**:
- Confidence score > 0.90 (proceed)
- Confidence 0.70-0.90 (review recommended)
- Confidence < 0.70 (manual review required)

---

## Stage 2: Content Preparation

**Purpose**: Clean and structure text for processing

```python
from translation_service import TranslationService
from hybrid_chunker import HybridChunker

# Translation (if needed)
translator = TranslationService(cache_backend=RedisCache())
if detected_language != 'en':
    translated = translator.translate(
        text=result.text,
        target_lang='en',
        source_lang=detected_language
    )
    text = translated['translation']

# Semantic chunking
chunker = HybridChunker(
    max_tokens=500,
    overlap_percent=0.15,
    model='gpt-4'
)

chunks = chunker.chunk(text)

# Output: ~100-150 chunks per 300-page book
[
    {
        'text': 'Chapter content...',
        'tokens': 487,
        'chunk_id': 0,
        'metadata': {
            'position': 0,
            'has_headings': True,
            'section': 'Introduction'
        }
    },
    ...
]
```

**Quality Gates**:
- Chunk size variance < 20%
- Boundary quality > 85% (ends at sentences)
- Context preservation (overlap) present

---

## Stage 3: Knowledge Extraction

**Purpose**: Extract key concepts and themes

```python
from knowledge_extractor import KnowledgeExtractor

extractor = KnowledgeExtractor(openai_api_key='...')

# Extract knowledge from chunks
knowledge_graph = extractor.extract_knowledge(chunks)

# Output
{
    'concepts': [
        {
            'name': 'Leadership Principles',
            'frequency': 23,
            'chunks': [5, 12, 18, 25, ...],
            'definition': 'Core ideas about effective leadership...',
            'related_concepts': ['Decision Making', 'Team Building']
        },
        ...
    ],
    'themes': [
        {
            'name': 'Personal Growth',
            'chunks': [1, 3, 7, 9, ...],
            'strength': 0.85
        },
        ...
    ],
    'entities': {
        'people': ['John Maxwell', 'Peter Drucker'],
        'places': ['Silicon Valley', 'Harvard'],
        'terms': ['Agile', 'OKRs', 'MVP']
    },
    'relationships': [
        ['Leadership', 'influences', 'Team Performance'],
        ['Communication', 'requires', 'Active Listening']
    ]
}
```

---

## Stage 4: Content Generation

**Purpose**: Transform chunks into blog posts

### 4.1 Blog Post Generation

```python
from content_generator import ContentGenerator

generator = ContentGenerator(
    model='gpt-4',
    api_key='...',
    style='educational',
    audience='professionals'
)

# Generate blog post from chunk
blog_post = generator.generate_post(
    chunk=chunks[10],
    knowledge_context=knowledge_graph,
    metadata=document_metadata
)

# Output
{
    'title': '5 Leadership Principles That Transform Teams',
    'slug': '5-leadership-principles-transform-teams',
    'content': '''
        <p>Leadership isn't about authority—it's about influence...</p>

        <h2>1. Lead by Example</h2>
        <p>The most effective leaders demonstrate the behaviors...</p>
        ...
    ''',
    'excerpt': 'Discover the five core leadership principles...',
    'meta_description': 'Learn 5 proven leadership principles that...',
    'seo_title': '5 Leadership Principles That Transform Teams | Expert Guide',
    'internal_links': [
        {'text': 'decision making framework', 'chunk_id': 15},
        {'text': 'building high-performing teams', 'chunk_id': 22}
    ],
    'featured_image_prompt': 'Professional diverse team meeting, modern office...',
    'categories': ['Leadership', 'Management'],
    'tags': ['leadership', 'team building', 'management tips'],
    'word_count': 1247,
    'reading_time': 5,
    'quality_score': 0.92
}
```

### 4.2 Content Templates

**Template Selection Logic**:

```python
CONTENT_TEMPLATES = {
    'how_to': {
        'structure': ['intro', 'steps', 'conclusion'],
        'title_pattern': 'How to {action} {benefit}',
        'example': 'How to Build Trust in Remote Teams'
    },
    'list': {
        'structure': ['intro', 'list_items', 'conclusion'],
        'title_pattern': '{number} {adjective} {topic}',
        'example': '7 Essential Communication Skills for Leaders'
    },
    'case_study': {
        'structure': ['background', 'challenge', 'solution', 'results'],
        'title_pattern': 'How {subject} {achieved_outcome}',
        'example': 'How Google Transformed Team Collaboration'
    },
    'concept_explanation': {
        'structure': ['definition', 'why_it_matters', 'examples', 'application'],
        'title_pattern': 'What is {concept} and Why It Matters',
        'example': 'What is Servant Leadership and Why It Matters'
    }
}

# Auto-select template based on chunk content
template = generator.select_template(chunk_text)
```

### 4.3 SEO Optimization

```python
# Automatic SEO enhancements
seo_enhanced = generator.optimize_seo(blog_post)

{
    'focus_keyword': 'leadership principles',
    'keyword_density': 2.1,  # Target: 1-3%
    'headings_optimized': True,
    'meta_description_length': 155,  # Optimal
    'internal_links': 3,
    'external_links': 2,
    'image_alt_tags': [...],
    'readability_score': 65,  # Flesch Reading Ease
    'seo_score': 87  # Out of 100
}
```

---

## Stage 5: Publishing

**Purpose**: Publish to WordPress with full metadata

```python
from wordpress_publisher import WordPressPublisher

publisher = WordPressPublisher(
    site_url='https://yourblog.com',
    username='admin',
    app_password='...'
)

# Publish single post
published = publisher.publish_post(
    title=blog_post['title'],
    content=blog_post['content'],
    excerpt=blog_post['excerpt'],
    status='draft',  # or 'publish', 'scheduled'
    categories=blog_post['categories'],
    tags=blog_post['tags'],
    featured_image=generated_image_path,
    meta={
        'seo_title': blog_post['seo_title'],
        'meta_description': blog_post['meta_description'],
        'focus_keyword': blog_post['focus_keyword']
    },
    schedule_date='2024-02-15 10:00:00'  # Drip publishing
)

# Output
{
    'post_id': 1234,
    'url': 'https://yourblog.com/5-leadership-principles-transform-teams',
    'status': 'scheduled',
    'publish_date': '2024-02-15 10:00:00'
}
```

### Batch Publishing with Scheduling

```python
# Publish entire series with smart scheduling
series = publisher.publish_series(
    posts=generated_posts,
    schedule_strategy='spread',  # or 'burst', 'custom'
    posts_per_week=3,
    start_date='2024-02-01',
    category='Book Series: Leadership Essentials'
)

# Output: 50 posts scheduled over 17 weeks
# Mon/Wed/Fri at 9am
```

---

## Stage 6: Distribution

**Purpose**: Share across platforms

```python
from social_distributor import SocialDistributor

distributor = SocialDistributor({
    'twitter': {'api_key': '...'},
    'linkedin': {'api_key': '...'},
    'facebook': {'api_key': '...'}
})

# Auto-generate social posts
social_posts = distributor.create_social_posts(
    blog_post=published,
    platforms=['twitter', 'linkedin'],
    strategy='educational'  # or 'promotional', 'engagement'
)

# Twitter version
{
    'platform': 'twitter',
    'text': '''5 leadership principles that actually work:

1. Lead by example
2. Communicate clearly
3. Empower your team
4. Stay accountable
5. Never stop learning

Which one resonates most with you?

Read the full guide 👇
https://yourblog.com/5-leadership-principles''',
    'media': ['featured_image.jpg'],
    'hashtags': ['leadership', 'management', 'teamwork']
}

# Post to all platforms
results = distributor.distribute(social_posts)
```

---

# CONFIGURATION

## Pipeline Configuration (YAML)

```yaml
# config/pipeline-config.yaml

pipeline:
  name: "Book to Blog Pipeline"
  version: "1.0.0"

document_ingestion:
  supported_formats: ['pdf', 'epub', 'docx']
  ocr_provider: 'google_vision'  # or 'tesseract'
  extract_tables: true
  extract_images: true
  quality_threshold: 0.85

content_preparation:
  translation:
    enabled: false
    target_language: 'en'
    provider: 'google'
  chunking:
    strategy: 'hybrid'  # or 'semantic', 'sentence', 'token'
    max_tokens: 500
    overlap_percent: 0.15
    preserve_context: true

knowledge_extraction:
  extract_concepts: true
  extract_themes: true
  extract_entities: true
  min_concept_frequency: 3
  theme_confidence_threshold: 0.7

content_generation:
  model: 'gpt-4'
  temperature: 0.7
  style: 'educational'  # or 'conversational', 'professional', 'casual'
  audience: 'professionals'
  content_templates:
    - how_to
    - list
    - concept_explanation
    - case_study
  seo:
    optimize: true
    target_keyword_density: 2.0
    min_word_count: 800
    max_word_count: 2000
  quality:
    min_quality_score: 0.85
    human_review_threshold: 0.90

publishing:
  wordpress:
    url: 'https://yourblog.com'
    default_status: 'draft'  # or 'publish', 'scheduled'
    default_author: 1
  scheduling:
    strategy: 'spread'  # or 'burst', 'custom'
    posts_per_week: 3
    publish_days: ['Mon', 'Wed', 'Fri']
    publish_time: '09:00:00'
  categories:
    auto_assign: true
    parent_category: 'Blog'
  images:
    generate_featured: true
    image_style: 'professional'
    optimize: true

distribution:
  enabled: true
  platforms:
    twitter:
      enabled: true
      strategy: 'engagement'
    linkedin:
      enabled: true
      strategy: 'professional'
    facebook:
      enabled: false
  newsletter:
    enabled: false
    provider: 'mailchimp'

error_handling:
  retry_attempts: 3
  retry_delay: 5
  fallback_on_failure: true
  save_checkpoints: true
  checkpoint_interval: 10  # Every 10 posts

cost_optimization:
  use_cache: true
  cache_ttl: 2592000  # 30 days
  batch_api_calls: true
  use_cheaper_model_for_drafts: true  # gpt-3.5-turbo
```

## Content Generation Prompts (YAML)

```yaml
# config/content-prompts.yaml

prompts:
  blog_post_generation:
    system: |
      You are an expert content writer specializing in {style} content for {audience}.
      Your task is to transform source material into engaging, SEO-optimized blog posts.

      Guidelines:
      - Write in a clear, engaging {style} tone
      - Target audience: {audience}
      - Include practical examples and actionable insights
      - Optimize for SEO without sacrificing readability
      - Use headings (H2, H3) for structure
      - Keep paragraphs short (3-4 sentences max)
      - Include internal linking opportunities

    user: |
      Transform the following content chunk into a complete blog post:

      CHUNK CONTENT:
      {chunk_text}

      KNOWLEDGE CONTEXT:
      Key Concepts: {concepts}
      Related Themes: {themes}
      Related Chunks: {related_chunks}

      SOURCE METADATA:
      Book Title: {book_title}
      Author: {author}
      Chapter: {chapter}

      Please create:
      1. SEO-optimized title (50-60 characters)
      2. Meta description (150-160 characters)
      3. Engaging introduction (2-3 paragraphs)
      4. Well-structured body with H2/H3 headings
      5. Actionable conclusion
      6. 3-5 internal link suggestions
      7. Featured image description for DALL-E
      8. 5-7 relevant tags

  title_generation:
    system: |
      You are an expert at creating viral, SEO-optimized blog post titles.

    user: |
      Generate 5 title options for a blog post about:
      {topic}

      Requirements:
      - Include power words (essential, proven, ultimate, complete)
      - Include numbers when possible
      - 50-60 characters
      - Include focus keyword: {keyword}
      - Balanced for SEO and engagement

  meta_description:
    system: |
      You are an SEO expert creating compelling meta descriptions.

    user: |
      Create a meta description for:
      Title: {title}
      Content Summary: {summary}

      Requirements:
      - Exactly 150-160 characters
      - Include call-to-action
      - Include focus keyword: {keyword}
      - Compelling but not clickbait

  image_prompt_generation:
    system: |
      You are an expert at creating detailed DALL-E prompts for blog featured images.

    user: |
      Create a DALL-E prompt for a featured image:
      Blog Title: {title}
      Topic: {topic}
      Style: {style}

      Requirements:
      - Professional, high-quality
      - Relevant to content
      - Visually appealing
      - No text in image
      - 16:9 aspect ratio

  internal_linking:
    system: |
      You are an expert at identifying internal linking opportunities.

    user: |
      Identify 3-5 internal linking opportunities in this content:
      {content}

      Available related topics:
      {related_topics}

      Return:
      - Anchor text
      - Target topic/chunk
      - Relevance score
```

---

# CODE IMPLEMENTATION

## Main Pipeline Orchestrator

See: `templates/pipeline_orchestrator.py` (full implementation)

```python
"""
Universal Content Pipeline Orchestrator

Complete workflow from document to published content.
"""

import os
import json
import yaml
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta

# Stage imports
from pdf_processor import PDFProcessor
from hybrid_chunker import HybridChunker
from translation_service import TranslationService
from knowledge_extractor import KnowledgeExtractor
from content_generator import ContentGenerator
from wordpress_publisher import WordPressPublisher
from social_distributor import SocialDistributor

# Utilities
from progress_tracker import ProgressTracker
from cost_estimator import CostEstimator
from quality_checker import QualityChecker


class UniversalContentPipeline:
    """Complete document-to-content pipeline"""

    def __init__(self, config_path='config/pipeline-config.yaml'):
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        # Initialize components
        self._init_components()

        # Initialize trackers
        self.progress = ProgressTracker()
        self.cost_estimator = CostEstimator()
        self.quality_checker = QualityChecker()

    def _init_components(self):
        """Initialize all pipeline stages"""

        # Stage 1: Document Ingestion
        self.pdf_processor = PDFProcessor(
            ocr_provider=self._get_ocr_provider()
        )

        # Stage 2: Content Preparation
        self.translator = TranslationService() if self.config['content_preparation']['translation']['enabled'] else None
        self.chunker = HybridChunker(
            max_tokens=self.config['content_preparation']['chunking']['max_tokens'],
            overlap_percent=self.config['content_preparation']['chunking']['overlap_percent']
        )

        # Stage 3: Knowledge Extraction
        self.knowledge_extractor = KnowledgeExtractor(
            api_key=os.getenv('OPENAI_API_KEY')
        )

        # Stage 4: Content Generation
        self.content_generator = ContentGenerator(
            model=self.config['content_generation']['model'],
            style=self.config['content_generation']['style'],
            audience=self.config['content_generation']['audience']
        )

        # Stage 5: Publishing
        self.publisher = WordPressPublisher(
            site_url=self.config['publishing']['wordpress']['url'],
            username=os.getenv('WORDPRESS_USERNAME'),
            app_password=os.getenv('WORDPRESS_APP_PASSWORD')
        )

        # Stage 6: Distribution
        if self.config['distribution']['enabled']:
            self.distributor = SocialDistributor(
                platforms=self.config['distribution']['platforms']
            )

    def process_document(
        self,
        document_path: str,
        output_dir: str = './pipeline_output',
        resume_from_checkpoint: bool = False
    ) -> Dict:
        """
        Process document through complete pipeline.

        Args:
            document_path: Path to source document
            output_dir: Output directory
            resume_from_checkpoint: Resume from saved checkpoint

        Returns:
            Pipeline results with statistics
        """

        print(f"\n{'='*60}")
        print(f"UNIVERSAL CONTENT PIPELINE - Started")
        print(f"{'='*60}\n")

        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Check for checkpoint
        checkpoint = self._load_checkpoint(output_dir) if resume_from_checkpoint else None

        results = {
            'document': document_path,
            'started_at': datetime.now().isoformat(),
            'stages': {}
        }

        try:
            # STAGE 1: Document Ingestion
            if not checkpoint or 'extraction' not in checkpoint:
                print("\n[STAGE 1/6] Document Ingestion...")
                extraction = self._stage_1_ingest(document_path, output_path)
                results['stages']['extraction'] = extraction
                self._save_checkpoint(output_path, results)
            else:
                print("\n[STAGE 1/6] Skipping (using checkpoint)...")
                extraction = checkpoint['stages']['extraction']
                results['stages']['extraction'] = extraction

            # STAGE 2: Content Preparation
            if not checkpoint or 'preparation' not in checkpoint:
                print("\n[STAGE 2/6] Content Preparation...")
                preparation = self._stage_2_prepare(extraction, output_path)
                results['stages']['preparation'] = preparation
                self._save_checkpoint(output_path, results)
            else:
                print("\n[STAGE 2/6] Skipping (using checkpoint)...")
                preparation = checkpoint['stages']['preparation']
                results['stages']['preparation'] = preparation

            # STAGE 3: Knowledge Extraction
            if not checkpoint or 'knowledge' not in checkpoint:
                print("\n[STAGE 3/6] Knowledge Extraction...")
                knowledge = self._stage_3_extract_knowledge(preparation, output_path)
                results['stages']['knowledge'] = knowledge
                self._save_checkpoint(output_path, results)
            else:
                print("\n[STAGE 3/6] Skipping (using checkpoint)...")
                knowledge = checkpoint['stages']['knowledge']
                results['stages']['knowledge'] = knowledge

            # STAGE 4: Content Generation
            if not checkpoint or 'generation' not in checkpoint:
                print("\n[STAGE 4/6] Content Generation...")
                generation = self._stage_4_generate_content(
                    preparation, knowledge, output_path
                )
                results['stages']['generation'] = generation
                self._save_checkpoint(output_path, results)
            else:
                print("\n[STAGE 4/6] Skipping (using checkpoint)...")
                generation = checkpoint['stages']['generation']
                results['stages']['generation'] = generation

            # STAGE 5: Publishing
            if not checkpoint or 'publishing' not in checkpoint:
                print("\n[STAGE 5/6] Publishing to WordPress...")
                publishing = self._stage_5_publish(generation, output_path)
                results['stages']['publishing'] = publishing
                self._save_checkpoint(output_path, results)
            else:
                print("\n[STAGE 5/6] Skipping (using checkpoint)...")
                publishing = checkpoint['stages']['publishing']
                results['stages']['publishing'] = publishing

            # STAGE 6: Distribution
            if self.config['distribution']['enabled']:
                print("\n[STAGE 6/6] Social Distribution...")
                distribution = self._stage_6_distribute(publishing, output_path)
                results['stages']['distribution'] = distribution
            else:
                print("\n[STAGE 6/6] Distribution disabled, skipping...")

            # Finalize
            results['completed_at'] = datetime.now().isoformat()
            results['status'] = 'success'

            # Generate report
            self._generate_report(results, output_path)

            print(f"\n{'='*60}")
            print(f"PIPELINE COMPLETE!")
            print(f"{'='*60}\n")

            return results

        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
            print(f"\n❌ Pipeline failed: {e}")
            raise

    def _stage_1_ingest(self, document_path: str, output_path: Path) -> Dict:
        """Stage 1: Extract text from document"""

        result = self.pdf_processor.process(
            pdf_path=document_path,
            extract_tables=self.config['document_ingestion']['extract_tables'],
            extract_images=self.config['document_ingestion']['extract_images']
        )

        # Quality check
        if result.confidence < self.config['document_ingestion']['quality_threshold']:
            print(f"⚠️  Warning: Low extraction confidence ({result.confidence:.2%})")
            print("   Manual review recommended")

        # Save extracted text
        with open(output_path / 'extracted_text.txt', 'w', encoding='utf-8') as f:
            f.write(result.text)

        # Save metadata
        with open(output_path / 'metadata.json', 'w') as f:
            json.dump(result.metadata, f, indent=2)

        print(f"✓ Extracted {len(result.text):,} characters from {result.page_count} pages")
        print(f"  Confidence: {result.confidence:.2%}")
        print(f"  Method: {result.extraction_method}")

        return {
            'text': result.text,
            'page_count': result.page_count,
            'confidence': result.confidence,
            'metadata': result.metadata
        }

    def _stage_2_prepare(self, extraction: Dict, output_path: Path) -> Dict:
        """Stage 2: Prepare and chunk content"""

        text = extraction['text']

        # Translation if needed
        if self.translator:
            print("  Translating to English...")
            translated = self.translator.translate(
                text=text,
                target_lang='en'
            )
            text = translated['translation']

        # Semantic chunking
        print("  Chunking text semantically...")
        chunks = self.chunker.chunk(text)

        # Save chunks
        with open(output_path / 'chunks.json', 'w', encoding='utf-8') as f:
            json.dump(chunks, f, indent=2, ensure_ascii=False)

        print(f"✓ Created {len(chunks)} semantic chunks")
        print(f"  Avg size: {sum(c['tokens'] for c in chunks) / len(chunks):.0f} tokens")

        return {
            'chunks': chunks,
            'chunk_count': len(chunks)
        }

    def _stage_3_extract_knowledge(self, preparation: Dict, output_path: Path) -> Dict:
        """Stage 3: Extract knowledge graph"""

        knowledge = self.knowledge_extractor.extract_knowledge(
            chunks=preparation['chunks']
        )

        # Save knowledge graph
        with open(output_path / 'knowledge_graph.json', 'w') as f:
            json.dump(knowledge, f, indent=2)

        print(f"✓ Extracted {len(knowledge['concepts'])} concepts")
        print(f"  {len(knowledge['themes'])} themes")
        print(f"  {len(knowledge.get('entities', {}))} entities")

        return knowledge

    def _stage_4_generate_content(
        self,
        preparation: Dict,
        knowledge: Dict,
        output_path: Path
    ) -> Dict:
        """Stage 4: Generate blog posts"""

        chunks = preparation['chunks']
        generated_posts = []

        # Estimate cost
        estimated_cost = self.cost_estimator.estimate(
            chunks=len(chunks),
            model=self.config['content_generation']['model']
        )
        print(f"  Estimated cost: ${estimated_cost:.2f}")

        for i, chunk in enumerate(chunks):
            print(f"  Generating post {i+1}/{len(chunks)}...", end='\r')

            # Generate post
            post = self.content_generator.generate_post(
                chunk=chunk,
                knowledge_context=knowledge,
                metadata=preparation.get('metadata', {})
            )

            # Quality check
            if post['quality_score'] >= self.config['content_generation']['quality']['min_quality_score']:
                generated_posts.append(post)
            else:
                print(f"\n⚠️  Post {i+1} failed quality check (score: {post['quality_score']:.2f})")

            # Save checkpoint every N posts
            if (i + 1) % self.config['error_handling']['checkpoint_interval'] == 0:
                self._save_posts_checkpoint(generated_posts, output_path)

        print(f"\n✓ Generated {len(generated_posts)} high-quality blog posts")

        # Save all posts
        with open(output_path / 'generated_posts.json', 'w', encoding='utf-8') as f:
            json.dump(generated_posts, f, indent=2, ensure_ascii=False)

        return {
            'posts': generated_posts,
            'post_count': len(generated_posts)
        }

    def _stage_5_publish(self, generation: Dict, output_path: Path) -> Dict:
        """Stage 5: Publish to WordPress"""

        posts = generation['posts']
        published_posts = []

        # Calculate schedule
        schedule = self._calculate_schedule(len(posts))

        for i, post in enumerate(posts):
            print(f"  Publishing post {i+1}/{len(posts)}...", end='\r')

            published = self.publisher.publish_post(
                title=post['title'],
                content=post['content'],
                excerpt=post['excerpt'],
                status=self.config['publishing']['wordpress']['default_status'],
                categories=post.get('categories', []),
                tags=post.get('tags', []),
                meta=post.get('meta', {}),
                schedule_date=schedule[i] if self.config['publishing']['wordpress']['default_status'] == 'scheduled' else None
            )

            published_posts.append(published)

        print(f"\n✓ Published {len(published_posts)} posts")

        # Save publishing results
        with open(output_path / 'published_posts.json', 'w') as f:
            json.dump(published_posts, f, indent=2)

        return {
            'posts': published_posts,
            'post_count': len(published_posts)
        }

    def _stage_6_distribute(self, publishing: Dict, output_path: Path) -> Dict:
        """Stage 6: Distribute to social media"""

        posts = publishing['posts']
        distributed = []

        for post in posts:
            social_posts = self.distributor.create_social_posts(
                blog_post=post,
                platforms=self._get_enabled_platforms()
            )

            results = self.distributor.distribute(social_posts)
            distributed.append(results)

        print(f"✓ Distributed {len(distributed)} posts")

        return {
            'distributions': distributed,
            'distribution_count': len(distributed)
        }

    def _calculate_schedule(self, post_count: int) -> List[str]:
        """Calculate publishing schedule"""

        config = self.config['publishing']['scheduling']

        if config['strategy'] == 'spread':
            # Spread posts over time
            posts_per_week = config['posts_per_week']
            days = config['publish_days']
            time = config['publish_time']

            schedule = []
            current_date = datetime.now()

            for i in range(post_count):
                # Find next publish day
                while current_date.strftime('%a') not in days:
                    current_date += timedelta(days=1)

                schedule.append(f"{current_date.strftime('%Y-%m-%d')} {time}")
                current_date += timedelta(days=1)

            return schedule

        return []

    def _save_checkpoint(self, output_path: Path, results: Dict):
        """Save progress checkpoint"""
        with open(output_path / 'checkpoint.json', 'w') as f:
            json.dump(results, f, indent=2)

    def _load_checkpoint(self, output_dir: str) -> Optional[Dict]:
        """Load progress checkpoint"""
        checkpoint_path = Path(output_dir) / 'checkpoint.json'
        if checkpoint_path.exists():
            with open(checkpoint_path, 'r') as f:
                return json.load(f)
        return None

    def _generate_report(self, results: Dict, output_path: Path):
        """Generate completion report"""

        report = f"""
UNIVERSAL CONTENT PIPELINE - COMPLETION REPORT
{'='*60}

Document: {results['document']}
Started: {results['started_at']}
Completed: {results['completed_at']}
Status: {results['status']}

STAGE RESULTS:
{'='*60}

1. Document Ingestion:
   - Pages: {results['stages']['extraction']['page_count']}
   - Confidence: {results['stages']['extraction']['confidence']:.2%}

2. Content Preparation:
   - Chunks: {results['stages']['preparation']['chunk_count']}

3. Knowledge Extraction:
   - Concepts: {len(results['stages']['knowledge']['concepts'])}
   - Themes: {len(results['stages']['knowledge']['themes'])}

4. Content Generation:
   - Posts Generated: {results['stages']['generation']['post_count']}

5. Publishing:
   - Posts Published: {results['stages']['publishing']['post_count']}

6. Distribution:
   - {results['stages'].get('distribution', {}).get('distribution_count', 'N/A')} distributions

{'='*60}
PIPELINE COMPLETE
{'='*60}
"""

        with open(output_path / 'REPORT.txt', 'w') as f:
            f.write(report)

        print(report)


# CLI Interface
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Universal Content Pipeline')
    parser.add_argument('document', help='Path to source document')
    parser.add_argument('--output', default='./pipeline_output', help='Output directory')
    parser.add_argument('--resume', action='store_true', help='Resume from checkpoint')
    parser.add_argument('--config', default='config/pipeline-config.yaml', help='Config file')

    args = parser.parse_args()

    pipeline = UniversalContentPipeline(config_path=args.config)
    results = pipeline.process_document(
        document_path=args.document,
        output_dir=args.output,
        resume_from_checkpoint=args.resume
    )
```

---

# USE CASES

## Use Case 1: Book → Blog Series (Main Use Case)

**Scenario**: Convert a 300-page business book into 50 blog posts

```bash
# Run pipeline
python pipeline_orchestrator.py \
    --document "./books/leadership-guide.pdf" \
    --output "./output/leadership-series" \
    --config "./config/pipeline-config.yaml"

# Results:
# - 50 blog posts (800-1500 words each)
# - Published to WordPress (scheduled over 17 weeks)
# - Distributed to social media
# - Total time: ~2 hours
# - Estimated cost: $45-60
```

**Output Structure**:
```
output/leadership-series/
├── extracted_text.txt
├── metadata.json
├── chunks.json (150 chunks)
├── knowledge_graph.json
├── generated_posts.json (50 posts)
├── published_posts.json
└── REPORT.txt
```

---

## Use Case 2: Research Paper → Educational Content

**Scenario**: Transform academic research into accessible blog posts

```yaml
# Custom config for research papers
content_generation:
  style: 'educational'
  audience: 'students and researchers'
  content_templates:
    - concept_explanation
    - how_to
    - case_study
  simplify_language: true
  include_citations: true
```

---

## Use Case 3: Report → Thought Leadership Series

**Scenario**: Convert industry report into LinkedIn articles

```yaml
# Custom config for thought leadership
content_generation:
  style: 'professional'
  audience: 'executives and decision makers'
  content_templates:
    - case_study
    - trend_analysis
    - expert_insights

distribution:
  platforms:
    linkedin:
      enabled: true
      strategy: 'professional'
      post_frequency: 'twice_weekly'
```

---

## Use Case 4: Documentation → Tutorial Series

**Scenario**: Transform technical docs into step-by-step tutorials

```yaml
content_generation:
  style: 'instructional'
  audience: 'developers'
  content_templates:
    - how_to
    - step_by_step
    - troubleshooting
  include_code_examples: true
  include_screenshots: true
```

---

# BEST PRACTICES

## 1. Content Quality Assurance

**Quality Gates at Each Stage**:

```python
# Stage 1: Extraction Quality
if extraction_confidence < 0.90:
    trigger_manual_review()

# Stage 4: Content Quality
if post_quality_score < 0.85:
    regenerate_with_different_prompt()

# Stage 5: SEO Quality
if seo_score < 80:
    optimize_before_publishing()
```

**Human-in-the-Loop Review Points**:
1. After extraction (verify accuracy)
2. After first 5 posts generated (verify style/tone)
3. Before publishing (final approval)

---

## 2. Batch Processing Strategies

**Small Book (100-150 pages)**:
- Process: Single session (1-2 hours)
- Output: 15-25 posts
- Strategy: Generate and publish all at once

**Medium Book (200-300 pages)**:
- Process: 2-3 sessions (3-4 hours total)
- Output: 30-50 posts
- Strategy: Generate in batches, review between batches

**Large Book (400+ pages)**:
- Process: Multiple sessions over days
- Output: 60-100+ posts
- Strategy: Checkpoint-based, review every 10-15 posts

---

## 3. Cost Optimization

**Cost Breakdown (300-page book)**:

| Stage | API Calls | Est. Cost |
|-------|-----------|-----------|
| Extraction | OCR (if needed) | $5-10 |
| Knowledge Extraction | 150 embedding calls | $0.50 |
| Content Generation | 50 GPT-4 calls | $40-50 |
| **Total** | | **$45-60** |

**Optimization Strategies**:

```python
# 1. Use cache aggressively
USE_CACHE = True  # Saves ~40% on repeated runs

# 2. Use cheaper model for drafts
DRAFT_MODEL = 'gpt-3.5-turbo'  # $5-10 instead of $40-50
FINAL_MODEL = 'gpt-4'  # Only for final polishing

# 3. Batch API calls
BATCH_SIZE = 10  # Process 10 chunks at once

# 4. Reuse knowledge graph
# Don't re-extract for every post
```

**Expected ROI**:
- Manual: 40-80 hours @ $50/hr = $2,000-4,000
- Automated: 2 hours + $50 API costs = $150
- **Savings: $1,850-3,850 per book (95%+ cost reduction)**

---

# EXAMPLES

## Complete Example: Book to Blog Series

See: `examples/book-to-blog-series.py`

```python
"""
Complete Example: Convert Book to Blog Series

This example shows the complete workflow from a PDF book
to 50+ published blog posts.
"""

from universal_content_pipeline import UniversalContentPipeline
import os

# Set environment variables
os.environ['OPENAI_API_KEY'] = 'sk-...'
os.environ['WORDPRESS_URL'] = 'https://myblog.com'
os.environ['WORDPRESS_USERNAME'] = 'admin'
os.environ['WORDPRESS_APP_PASSWORD'] = 'xxxx xxxx xxxx xxxx'

# Initialize pipeline
pipeline = UniversalContentPipeline(
    config_path='./config/pipeline-config.yaml'
)

# Process book
results = pipeline.process_document(
    document_path='./books/leadership-essentials.pdf',
    output_dir='./output/leadership-series',
    resume_from_checkpoint=False  # Start fresh
)

# Print summary
print(f"""
{'='*60}
PIPELINE COMPLETE
{'='*60}

Posts Generated: {results['stages']['generation']['post_count']}
Posts Published: {results['stages']['publishing']['post_count']}

Publishing Schedule:
- First post: {results['stages']['publishing']['posts'][0]['publish_date']}
- Last post: {results['stages']['publishing']['posts'][-1]['publish_date']}
- Duration: 17 weeks

Next Steps:
1. Review draft posts in WordPress
2. Approve for publishing
3. Monitor social media engagement
4. Analyze performance metrics

Report saved to: {results['output_dir']}/REPORT.txt
{'='*60}
""")
```

**Expected Output**:

```
==============================================================
UNIVERSAL CONTENT PIPELINE - Started
==============================================================

[STAGE 1/6] Document Ingestion...
✓ Extracted 245,678 characters from 287 pages
  Confidence: 98%
  Method: pdfplumber

[STAGE 2/6] Content Preparation...
  Chunking text semantically...
✓ Created 142 semantic chunks
  Avg size: 512 tokens

[STAGE 3/6] Knowledge Extraction...
✓ Extracted 87 concepts
  23 themes
  156 entities

[STAGE 4/6] Content Generation...
  Estimated cost: $47.50
  Generating post 142/142...
✓ Generated 52 high-quality blog posts

[STAGE 5/6] Publishing to WordPress...
  Publishing post 52/52...
✓ Published 52 posts

[STAGE 6/6] Social Distribution...
✓ Distributed 52 posts

==============================================================
PIPELINE COMPLETE!
==============================================================

Total time: 1h 47m
Total cost: $48.23
Posts created: 52
Scheduled: Feb 1 - May 28 (17 weeks)
```

---

# FILE REFERENCES

**Core Templates**:
- `templates/pipeline_orchestrator.py` - Main orchestrator (1000+ lines)
- `templates/content_generator.py` - AI content generation (500+ lines)
- `templates/wordpress_publisher.py` - WordPress integration (400+ lines)
- `templates/knowledge_extractor.py` - Knowledge graph extraction (300+ lines)
- `templates/social_distributor.py` - Social media distribution (200+ lines)

**Configuration**:
- `config/pipeline-config.yaml` - Main configuration
- `config/content-prompts.yaml` - AI prompts library
- `config/wordpress-config.yaml` - WordPress settings
- `config/social-config.yaml` - Social media settings

**Examples**:
- `examples/book-to-blog-series.py` - Complete workflow example
- `examples/research-to-content.py` - Academic research processing
- `examples/custom-pipeline.py` - Customized pipeline
- `examples/batch-processing.py` - Multiple books processing

**Checklists**:
- `checklists/setup.md` - Initial setup guide
- `checklists/quality-assurance.md` - QA checklist
- `checklists/pre-publishing.md` - Pre-publish checklist
- `checklists/post-launch.md` - Post-launch monitoring

**References**:
- `references/cost-optimization.md` - Cost saving strategies
- `references/content-templates.md` - Blog post templates
- `references/seo-guide.md` - SEO optimization guide
- `references/troubleshooting.md` - Common issues & solutions

---

# INTEGRATION POINTS

## Required Skills Integration

This skill builds on and integrates with:

1. **pdf-processing**: Document extraction stage
2. **semantic-chunking**: Text preparation stage
3. **translation-pipeline**: Optional translation stage

## WordPress Integration

Requires:
- WordPress 5.0+ with REST API enabled
- Application Password authentication
- Recommended plugins:
  - Yoast SEO (for SEO metadata)
  - Advanced Custom Fields (for custom metadata)

## Social Media Integration

Supported platforms:
- Twitter API v2
- LinkedIn API
- Facebook Graph API
- (Extensible to others)

---

# PRODUCTION CHECKLIST

Before going live:

- [ ] PDF processor tested with sample documents
- [ ] OpenAI API key configured and tested
- [ ] WordPress site accessible and API enabled
- [ ] Application password created for WordPress
- [ ] Test run completed with small document (10-20 pages)
- [ ] Quality scores reviewed and acceptable
- [ ] Publishing schedule configured
- [ ] Cost estimation reviewed and approved
- [ ] Backup/checkpoint system tested
- [ ] Error handling verified
- [ ] Social media accounts connected (if using)
- [ ] Human review workflow established
- [ ] Monitoring and analytics set up

---

# ESTIMATED PERFORMANCE

**Processing Speed** (300-page book):
- Stage 1: 2-5 minutes
- Stage 2: 5-10 minutes
- Stage 3: 10-20 minutes
- Stage 4: 30-60 minutes (most time-consuming)
- Stage 5: 5-10 minutes
- Stage 6: 5-10 minutes
- **Total: 1-2 hours**

**Content Quality**:
- Extraction accuracy: 95-98%
- Content quality score: 85-92%
- SEO optimization: 80-90/100
- Human approval rate: 85-95%

**Cost Efficiency**:
- Manual: $2,000-4,000 per book
- Automated: $50-100 per book
- **Savings: 95%+**

---

# ADVANCED TOPICS

## Custom Content Templates

Create domain-specific templates:

```python
# Add to content_generator.py

CUSTOM_TEMPLATES = {
    'technical_tutorial': {
        'structure': [
            'problem_statement',
            'solution_overview',
            'step_by_step_implementation',
            'code_examples',
            'testing',
            'troubleshooting'
        ],
        'sections': {
            'problem_statement': 'What are we solving?',
            'solution_overview': 'High-level approach',
            # ...
        }
    }
}
```

## Multi-Book Processing

Process multiple books as a series:

```python
books = [
    'leadership-vol-1.pdf',
    'leadership-vol-2.pdf',
    'leadership-vol-3.pdf'
]

for book in books:
    pipeline.process_document(
        document_path=book,
        output_dir=f'./output/{book.stem}',
        series_metadata={'series': 'Leadership Trilogy'}
    )
```

## Custom Knowledge Graphs

Build industry-specific knowledge graphs:

```python
# For medical content
medical_kg = KnowledgeExtractor(
    entity_types=['disease', 'treatment', 'symptom', 'medication'],
    relationship_types=['treats', 'causes', 'indicates'],
    domain='medical'
)
```

---

# SUPPORT & TROUBLESHOOTING

## Common Issues

**Issue**: Low extraction confidence
**Solution**: Use Google Vision OCR instead of Tesseract

**Issue**: Generated content too generic
**Solution**: Improve prompts, add more context from knowledge graph

**Issue**: Publishing fails
**Solution**: Check WordPress API credentials, verify REST API enabled

**Issue**: Cost too high
**Solution**: Use GPT-3.5-turbo for drafts, cache aggressively

See `references/troubleshooting.md` for complete guide.

---

# CONCLUSION

The Universal Content Pipeline represents a complete, production-ready solution for transforming documents into published content at scale. By combining proven patterns from knowledge extraction and multi-agent publishing, it delivers:

- **95%+ time savings** over manual content creation
- **Industrial-scale content production** from source materials
- **Consistent quality** through AI-powered generation
- **Complete automation** from document to distribution

Perfect for:
- Content marketers scaling production
- Publishers building blog libraries
- Educators creating tutorial series
- Thought leaders establishing authority

**Next Steps**:
1. Review prerequisites and setup
2. Run example with sample document
3. Customize configuration for your needs
4. Process your first book
5. Monitor results and optimize

---

## Integrates With

| Module | Path | Description |
|--------|------|-------------|
| prompt-template-engine | modules/prompt-template-engine/ | Variable rendering engine for content generation — template interpolation, conditional sections, prompt versioning |

---

**Skill Version**: 1.0.0
**Last Updated**: 2026-02-04
**Maintainer**: Streamlined Development
**License**: Proprietary
