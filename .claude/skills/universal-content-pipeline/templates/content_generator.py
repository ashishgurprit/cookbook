"""
Content Generator - AI-Powered Blog Post Creation

Transforms semantic chunks into complete, SEO-optimized blog posts using GPT-4.
Includes title generation, meta descriptions, internal linking, and image prompts.
"""

import os
import yaml
from typing import Dict, List, Optional
from openai import OpenAI
import tiktoken
from dataclasses import dataclass


@dataclass
class BlogPost:
    """Generated blog post with all metadata"""
    title: str
    slug: str
    content: str
    excerpt: str
    meta_description: str
    seo_title: str
    focus_keyword: str
    categories: List[str]
    tags: List[str]
    internal_links: List[Dict]
    featured_image_prompt: str
    word_count: int
    reading_time: int
    quality_score: float


class ContentGenerator:
    """AI-powered content generation from semantic chunks"""

    def __init__(
        self,
        model: str = 'gpt-4',
        api_key: str = None,
        style: str = 'educational',
        audience: str = 'professionals',
        prompts_config: str = 'config/content-prompts.yaml'
    ):
        self.client = OpenAI(api_key=api_key or os.getenv('OPENAI_API_KEY'))
        self.model = model
        self.style = style
        self.audience = audience
        self.encoding = tiktoken.encoding_for_model(model)

        # Load prompts
        with open(prompts_config, 'r') as f:
            self.prompts = yaml.safe_load(f)['prompts']

    def generate_post(
        self,
        chunk: Dict,
        knowledge_context: Dict,
        metadata: Dict = None
    ) -> BlogPost:
        """
        Generate complete blog post from chunk.

        Args:
            chunk: Semantic chunk with text and metadata
            knowledge_context: Knowledge graph (concepts, themes, etc.)
            metadata: Source document metadata

        Returns:
            BlogPost object with all content and metadata
        """

        # Extract relevant context
        context = self._extract_relevant_context(chunk, knowledge_context)

        # Generate main content
        content_response = self._generate_content(chunk, context, metadata)

        # Parse response
        parsed = self._parse_content_response(content_response)

        # Generate SEO elements
        seo_title = self._generate_seo_title(parsed['title'], parsed['focus_keyword'])
        meta_desc = self._generate_meta_description(parsed['title'], parsed['excerpt'], parsed['focus_keyword'])

        # Generate featured image prompt
        image_prompt = self._generate_image_prompt(parsed['title'], parsed['topic'])

        # Calculate metrics
        word_count = len(parsed['content'].split())
        reading_time = max(1, word_count // 200)  # ~200 words/minute

        # Quality assessment
        quality_score = self._assess_quality(parsed)

        # Create slug
        slug = self._create_slug(parsed['title'])

        return BlogPost(
            title=parsed['title'],
            slug=slug,
            content=parsed['content'],
            excerpt=parsed['excerpt'],
            meta_description=meta_desc,
            seo_title=seo_title,
            focus_keyword=parsed['focus_keyword'],
            categories=parsed['categories'],
            tags=parsed['tags'],
            internal_links=parsed['internal_links'],
            featured_image_prompt=image_prompt,
            word_count=word_count,
            reading_time=reading_time,
            quality_score=quality_score
        )

    def _generate_content(self, chunk: Dict, context: Dict, metadata: Dict) -> str:
        """Generate main blog post content"""

        # Build prompt
        system_prompt = self.prompts['blog_post_generation']['system'].format(
            style=self.style,
            audience=self.audience
        )

        user_prompt = self.prompts['blog_post_generation']['user'].format(
            chunk_text=chunk['text'],
            concepts=', '.join(c['name'] for c in context['concepts'][:5]),
            themes=', '.join(t['name'] for t in context['themes'][:3]),
            related_chunks=len(context.get('related_chunks', [])),
            book_title=metadata.get('title', 'Unknown'),
            author=metadata.get('author', 'Unknown'),
            chapter=chunk.get('metadata', {}).get('section', 'Unknown')
        )

        # Call OpenAI
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        )

        return response.choices[0].message.content

    def _generate_seo_title(self, title: str, keyword: str) -> str:
        """Generate SEO-optimized title"""

        system_prompt = "You are an SEO expert creating optimized page titles."
        user_prompt = f"""
Create an SEO-optimized page title (50-60 characters) for:
Title: {title}
Focus Keyword: {keyword}

Requirements:
- Include focus keyword
- 50-60 characters
- Compelling and clickable
- Format: Title | Brand/Context
"""

        response = self.client.chat.completions.create(
            model='gpt-3.5-turbo',  # Cheaper for simple tasks
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.5,
            max_tokens=100
        )

        return response.choices[0].message.content.strip()

    def _generate_meta_description(self, title: str, excerpt: str, keyword: str) -> str:
        """Generate meta description"""

        system_prompt = self.prompts['meta_description']['system']
        user_prompt = self.prompts['meta_description']['user'].format(
            title=title,
            summary=excerpt[:200],
            keyword=keyword
        )

        response = self.client.chat.completions.create(
            model='gpt-3.5-turbo',
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.5,
            max_tokens=100
        )

        desc = response.choices[0].message.content.strip()

        # Ensure length
        if len(desc) > 160:
            desc = desc[:157] + '...'

        return desc

    def _generate_image_prompt(self, title: str, topic: str) -> str:
        """Generate DALL-E prompt for featured image"""

        system_prompt = self.prompts['image_prompt_generation']['system']
        user_prompt = self.prompts['image_prompt_generation']['user'].format(
            title=title,
            topic=topic,
            style='professional, modern'
        )

        response = self.client.chat.completions.create(
            model='gpt-3.5-turbo',
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=200
        )

        return response.choices[0].message.content.strip()

    def _extract_relevant_context(self, chunk: Dict, knowledge_graph: Dict) -> Dict:
        """Extract relevant concepts/themes for this chunk"""

        chunk_id = chunk['chunk_id']

        # Find concepts that appear in this chunk
        relevant_concepts = [
            c for c in knowledge_graph.get('concepts', [])
            if chunk_id in c.get('chunks', [])
        ]

        # Find themes
        relevant_themes = [
            t for t in knowledge_graph.get('themes', [])
            if chunk_id in t.get('chunks', [])
        ]

        # Find related chunks (for internal linking)
        related_chunks = []
        for concept in relevant_concepts[:3]:
            for related_chunk_id in concept.get('chunks', []):
                if related_chunk_id != chunk_id and related_chunk_id not in related_chunks:
                    related_chunks.append(related_chunk_id)

        return {
            'concepts': relevant_concepts[:10],
            'themes': relevant_themes[:5],
            'related_chunks': related_chunks[:10]
        }

    def _parse_content_response(self, response: str) -> Dict:
        """Parse AI response into structured data"""

        # Simple parsing - in production, use structured output
        lines = response.split('\n')

        parsed = {
            'title': '',
            'excerpt': '',
            'content': '',
            'focus_keyword': '',
            'categories': [],
            'tags': [],
            'internal_links': [],
            'topic': ''
        }

        # Extract sections (this is simplified - use proper parsing)
        current_section = None

        for line in lines:
            if line.startswith('Title:'):
                parsed['title'] = line.replace('Title:', '').strip()
            elif line.startswith('Excerpt:'):
                parsed['excerpt'] = line.replace('Excerpt:', '').strip()
            elif line.startswith('Focus Keyword:'):
                parsed['focus_keyword'] = line.replace('Focus Keyword:', '').strip()
            elif line.startswith('Categories:'):
                cats = line.replace('Categories:', '').strip()
                parsed['categories'] = [c.strip() for c in cats.split(',')]
            elif line.startswith('Tags:'):
                tags = line.replace('Tags:', '').strip()
                parsed['tags'] = [t.strip() for t in tags.split(',')]
            elif 'Content:' in line or current_section == 'content':
                current_section = 'content'
                if 'Content:' not in line:
                    parsed['content'] += line + '\n'

        # Fallbacks
        if not parsed['title']:
            parsed['title'] = 'Untitled Post'
        if not parsed['focus_keyword']:
            parsed['focus_keyword'] = parsed['title'].split()[0]
        if not parsed['excerpt']:
            parsed['excerpt'] = parsed['content'][:200]
        if not parsed['categories']:
            parsed['categories'] = ['Uncategorized']
        if not parsed['tags']:
            parsed['tags'] = []

        parsed['topic'] = parsed['title']

        return parsed

    def _assess_quality(self, parsed: Dict) -> float:
        """Assess content quality (0-1)"""

        checks = {
            'has_title': len(parsed['title']) > 10,
            'has_content': len(parsed['content']) > 500,
            'has_excerpt': len(parsed['excerpt']) > 50,
            'has_keyword': bool(parsed['focus_keyword']),
            'has_categories': len(parsed['categories']) > 0,
            'has_tags': len(parsed['tags']) > 2,
            'word_count_ok': 800 <= len(parsed['content'].split()) <= 2500,
            'title_length_ok': 40 <= len(parsed['title']) <= 70
        }

        score = sum(checks.values()) / len(checks)

        return score

    def _create_slug(self, title: str) -> str:
        """Create URL slug from title"""

        import re

        slug = title.lower()
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[\s_]+', '-', slug)
        slug = slug.strip('-')

        return slug[:100]  # Limit length


# Example usage
if __name__ == '__main__':
    generator = ContentGenerator(
        model='gpt-4',
        style='educational',
        audience='professionals'
    )

    # Sample chunk
    chunk = {
        'text': 'Leadership is not about being in charge...',
        'chunk_id': 5,
        'tokens': 487,
        'metadata': {'section': 'Chapter 3: Leadership Fundamentals'}
    }

    # Sample knowledge context
    knowledge = {
        'concepts': [
            {'name': 'Leadership', 'chunks': [5, 12, 18]},
            {'name': 'Team Building', 'chunks': [5, 22]}
        ],
        'themes': [
            {'name': 'Personal Growth', 'chunks': [5, 7, 9]}
        ]
    }

    # Generate post
    post = generator.generate_post(
        chunk=chunk,
        knowledge_context=knowledge,
        metadata={'title': 'Leadership Essentials', 'author': 'John Maxwell'}
    )

    print(f"Title: {post.title}")
    print(f"Quality Score: {post.quality_score:.2%}")
    print(f"Word Count: {post.word_count}")
