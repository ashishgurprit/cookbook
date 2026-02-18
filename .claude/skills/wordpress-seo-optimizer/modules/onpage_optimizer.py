"""
On-Page SEO Optimizer Module

Analyzes and optimizes on-page SEO elements including title tags,
meta descriptions, headers, images, and content structure.
"""

import re
import html
from typing import Dict, List, Optional, Tuple
from bs4 import BeautifulSoup


class OnPageOptimizer:
    """Optimize on-page SEO elements."""

    # Optimal lengths
    TITLE_MIN = 50
    TITLE_MAX = 60
    META_MIN = 150
    META_MAX = 160
    URL_MAX = 75
    ALT_TEXT_MAX = 125

    def __init__(self):
        """Initialize on-page optimizer."""
        pass

    def analyze_onpage(self, post_data: Dict) -> Dict:
        """
        Analyze all on-page SEO elements.

        Args:
            post_data: Dictionary with:
                - title: Post title
                - content: HTML content
                - meta_description: Meta description
                - url_slug: URL slug
                - target_keyword: Primary keyword

        Returns:
            Analysis results with scores and recommendations
        """
        title = post_data.get('title', '')
        content = post_data.get('content', '')
        meta_description = post_data.get('meta_description', '')
        url_slug = post_data.get('url_slug', '')
        target_keyword = post_data.get('target_keyword', '')

        # Parse HTML content
        soup = BeautifulSoup(content, 'html.parser')

        # Analyze each component
        title_analysis = self._analyze_title(title, target_keyword)
        meta_analysis = self._analyze_meta_description(meta_description, target_keyword)
        headers_analysis = self._analyze_headers(soup, target_keyword)
        content_analysis = self._analyze_content(content)
        images_analysis = self._analyze_images(soup)
        url_analysis = self._analyze_url_slug(url_slug, target_keyword)

        # Calculate overall score
        total_score = (
            title_analysis['score'] +
            meta_analysis['score'] +
            headers_analysis['score'] +
            content_analysis['score'] +
            images_analysis['score'] +
            url_analysis['score']
        )

        # Collect all issues and recommendations
        issues = []
        recommendations = []

        for analysis in [title_analysis, meta_analysis, headers_analysis,
                        content_analysis, images_analysis, url_analysis]:
            issues.extend(analysis.get('issues', []))
            recommendations.extend(analysis.get('recommendations', []))

        return {
            'overall_score': total_score,
            'title': title_analysis,
            'meta_description': meta_analysis,
            'headers': headers_analysis,
            'content': content_analysis,
            'images': images_analysis,
            'url': url_analysis,
            'issues': issues,
            'recommendations': recommendations
        }

    def _analyze_title(self, title: str, keyword: str) -> Dict:
        """Analyze title tag (max 15 points)."""
        score = 0
        issues = []
        recommendations = []

        length = len(title)
        has_keyword = keyword.lower() in title.lower()
        keyword_position = title.lower().find(keyword.lower()) if has_keyword else -1

        # Length check (5 points)
        if self.TITLE_MIN <= length <= self.TITLE_MAX:
            score += 5
        else:
            if length < self.TITLE_MIN:
                issues.append(f"Title too short ({length} chars, target: {self.TITLE_MIN}-{self.TITLE_MAX})")
                recommendations.append(f"Expand title to {self.TITLE_MIN}-{self.TITLE_MAX} characters")
            elif length > self.TITLE_MAX:
                issues.append(f"Title too long ({length} chars, target: {self.TITLE_MIN}-{self.TITLE_MAX})")
                recommendations.append("Shorten title to improve display in search results")
            score += 2

        # Keyword presence (5 points)
        if has_keyword:
            score += 5
        else:
            issues.append("Target keyword not in title")
            recommendations.append(f"Include '{keyword}' in title tag")

        # Keyword position (5 points) - earlier is better
        if has_keyword and keyword_position <= 10:
            score += 5
        elif has_keyword:
            score += 3
            recommendations.append("Move target keyword earlier in title")

        return {
            'score': score,
            'max_score': 15,
            'length': length,
            'has_keyword': has_keyword,
            'keyword_position': keyword_position,
            'optimal': score >= 13,
            'issues': issues,
            'recommendations': recommendations
        }

    def _analyze_meta_description(self, meta_description: str, keyword: str) -> Dict:
        """Analyze meta description (max 10 points)."""
        score = 0
        issues = []
        recommendations = []

        length = len(meta_description)
        has_keyword = keyword.lower() in meta_description.lower()

        # Presence check (7 points)
        if not meta_description:
            issues.append("Meta description missing (critical)")
            recommendations.append("Add meta description (150-160 characters)")
            return {
                'score': 0,
                'max_score': 10,
                'length': 0,
                'has_keyword': False,
                'optimal': False,
                'issues': issues,
                'recommendations': recommendations
            }

        # Length check (7 points)
        if self.META_MIN <= length <= self.META_MAX:
            score += 7
        else:
            if length < self.META_MIN:
                issues.append(f"Meta description too short ({length} chars)")
                recommendations.append(f"Expand meta description to {self.META_MIN}-{self.META_MAX} characters")
            else:
                issues.append(f"Meta description too long ({length} chars, will be truncated)")
                recommendations.append(f"Shorten to {self.META_MAX} characters")
            score += 4

        # Keyword presence (3 points)
        if has_keyword:
            score += 3
        else:
            issues.append("Target keyword not in meta description")
            recommendations.append(f"Include '{keyword}' in meta description")

        return {
            'score': score,
            'max_score': 10,
            'length': length,
            'has_keyword': has_keyword,
            'optimal': score >= 9,
            'issues': issues,
            'recommendations': recommendations
        }

    def _analyze_headers(self, soup: BeautifulSoup, keyword: str) -> Dict:
        """Analyze header structure (max 10 points)."""
        score = 0
        issues = []
        recommendations = []

        # Extract all headers
        h1_tags = soup.find_all('h1')
        h2_tags = soup.find_all('h2')
        h3_tags = soup.find_all('h3')
        h4_tags = soup.find_all('h4')

        h1_count = len(h1_tags)
        h2_count = len(h2_tags)

        # H1 check (5 points)
        if h1_count == 1:
            score += 3
            h1_text = h1_tags[0].get_text()
            # Check if H1 has keyword
            if keyword.lower() in h1_text.lower():
                score += 2
            else:
                issues.append("H1 doesn't contain target keyword")
                recommendations.append(f"Include '{keyword}' in H1 heading")
        elif h1_count == 0:
            issues.append("No H1 heading found (critical)")
            recommendations.append(f"Add H1 heading with '{keyword}'")
        else:
            issues.append(f"Multiple H1 tags ({h1_count}) - should have only one")
            recommendations.append("Use only one H1 tag per page")
            score += 1

        # H2 structure (5 points)
        if h2_count >= 2:
            score += 3
            # Check if at least one H2 has keyword
            h2_texts = [h.get_text().lower() for h in h2_tags]
            if any(keyword.lower() in text for text in h2_texts):
                score += 2
            else:
                recommendations.append(f"Include '{keyword}' in at least one H2 heading")
                score += 1
        elif h2_count == 1:
            score += 2
            recommendations.append("Add more H2 headings for better content structure")
        else:
            issues.append("No H2 headings found")
            recommendations.append("Add H2 headings to structure content")

        # Check hierarchy (no scoring, just recommendations)
        if self._check_header_hierarchy(soup):
            pass  # Good hierarchy
        else:
            issues.append("Header hierarchy has gaps (e.g., H4 under H2)")
            recommendations.append("Fix header hierarchy - don't skip levels")

        return {
            'score': score,
            'max_score': 10,
            'h1_count': h1_count,
            'h2_count': h2_count,
            'h3_count': len(h3_tags),
            'h4_count': len(h4_tags),
            'optimal': score >= 8,
            'issues': issues,
            'recommendations': recommendations
        }

    def _check_header_hierarchy(self, soup: BeautifulSoup) -> bool:
        """Check if header hierarchy is logical (no skipped levels)."""
        # Simple check: ensure we don't have H3 before H2, etc.
        headers = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        if not headers:
            return True

        levels = [int(h.name[1]) for h in headers]

        for i in range(1, len(levels)):
            # If jump is more than 1 level, hierarchy is broken
            if levels[i] - levels[i-1] > 1:
                return False

        return True

    def _analyze_content(self, content: str) -> Dict:
        """Analyze content quality (max 20 points)."""
        score = 0
        issues = []
        recommendations = []

        # Strip HTML and count words
        text = self._strip_html(content)
        word_count = len(re.findall(r'\b\w+\b', text))

        # Word count check (10 points)
        if word_count >= 1500:
            score += 10
        elif word_count >= 1000:
            score += 8
            recommendations.append("Consider expanding content to 1500+ words for better rankings")
        elif word_count >= 500:
            score += 5
            recommendations.append("Expand content to at least 1000 words")
        else:
            issues.append(f"Content too short ({word_count} words)")
            recommendations.append("Add more comprehensive content (target: 1000+ words)")
            score += 2

        # Readability (10 points) - simplified for MVP
        # For MVP: Just check average sentence length
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]

        if sentences:
            avg_words_per_sentence = word_count / len(sentences)
            # Optimal: 15-20 words per sentence
            if 12 <= avg_words_per_sentence <= 22:
                score += 10
            elif 10 <= avg_words_per_sentence <= 25:
                score += 7
                recommendations.append("Consider varying sentence length for better readability")
            else:
                if avg_words_per_sentence > 25:
                    issues.append("Sentences too long (difficult to read)")
                    recommendations.append("Break up long sentences for better readability")
                else:
                    issues.append("Sentences too short (choppy reading)")
                    recommendations.append("Combine some short sentences")
                score += 4

        return {
            'score': score,
            'max_score': 20,
            'word_count': word_count,
            'sentence_count': len(sentences),
            'avg_words_per_sentence': round(word_count / len(sentences), 1) if sentences else 0,
            'optimal': score >= 16,
            'issues': issues,
            'recommendations': recommendations
        }

    def _analyze_images(self, soup: BeautifulSoup) -> Dict:
        """Analyze image optimization (max 10 points)."""
        score = 0
        issues = []
        recommendations = []

        images = soup.find_all('img')
        total_images = len(images)

        if total_images == 0:
            recommendations.append("Add images to improve engagement")
            return {
                'score': 5,  # Neutral score for no images
                'max_score': 10,
                'total_images': 0,
                'images_with_alt': 0,
                'alt_percentage': 0,
                'optimal': False,
                'issues': [],
                'recommendations': recommendations
            }

        # Check alt text
        images_with_alt = sum(1 for img in images if img.get('alt'))
        alt_percentage = (images_with_alt / total_images * 100) if total_images > 0 else 0

        # Alt text score (10 points)
        if alt_percentage == 100:
            score += 10
        elif alt_percentage >= 80:
            score += 7
            recommendations.append(f"Add alt text to {total_images - images_with_alt} more images")
        elif alt_percentage >= 50:
            score += 5
            issues.append(f"{total_images - images_with_alt} images missing alt text")
            recommendations.append("Add descriptive alt text to all images")
        else:
            issues.append(f"Most images ({total_images - images_with_alt}/{total_images}) missing alt text")
            recommendations.append("Add alt text to all images for accessibility and SEO")
            score += 2

        # Check alt text quality (not scored in MVP, just recommendations)
        for img in images:
            alt = img.get('alt', '')
            if alt and len(alt) > self.ALT_TEXT_MAX:
                recommendations.append(f"Shorten alt text to under {self.ALT_TEXT_MAX} characters")
                break

        return {
            'score': score,
            'max_score': 10,
            'total_images': total_images,
            'images_with_alt': images_with_alt,
            'alt_percentage': round(alt_percentage, 1),
            'optimal': alt_percentage == 100,
            'issues': issues,
            'recommendations': recommendations
        }

    def _analyze_url_slug(self, url_slug: str, keyword: str) -> Dict:
        """Analyze URL slug (max 5 points)."""
        score = 0
        issues = []
        recommendations = []

        if not url_slug:
            issues.append("URL slug is empty")
            return {
                'score': 0,
                'max_score': 5,
                'length': 0,
                'has_keyword': False,
                'optimal': False,
                'issues': issues,
                'recommendations': ["Generate clean URL slug"]
            }

        length = len(url_slug)
        has_keyword = keyword.lower().replace(' ', '-') in url_slug.lower()

        # Length check (2 points)
        if length <= self.URL_MAX:
            score += 2
        else:
            issues.append(f"URL slug too long ({length} chars, target: <{self.URL_MAX})")
            recommendations.append("Shorten URL slug")
            score += 1

        # Keyword presence (3 points)
        if has_keyword:
            score += 3
        else:
            issues.append("Target keyword not in URL")
            recommendations.append(f"Include '{keyword}' in URL slug")

        return {
            'score': score,
            'max_score': 5,
            'length': length,
            'has_keyword': has_keyword,
            'optimal': score >= 4,
            'issues': issues,
            'recommendations': recommendations
        }

    def generate_optimized_title(
        self,
        original_title: str,
        keyword: str,
        max_length: int = 60
    ) -> str:
        """
        Generate an optimized title tag.

        Args:
            original_title: Original title
            keyword: Target keyword to include
            max_length: Maximum length (default 60)

        Returns:
            Optimized title
        """
        # If keyword already in title and length is good, keep it
        if keyword.lower() in original_title.lower() and len(original_title) <= max_length:
            return original_title

        # Strategy: Put keyword at the beginning
        keyword_capitalized = keyword.title()

        # If title is too short, expand it
        if len(original_title) < self.TITLE_MIN:
            # Add keyword-based suffix
            optimized = f"{keyword_capitalized}: {original_title}"
        else:
            # Replace or prepend keyword
            optimized = f"{keyword_capitalized} | {original_title}"

        # Trim if too long
        if len(optimized) > max_length:
            # Try removing the pipe separator
            optimized = f"{keyword_capitalized} - {original_title}"

        if len(optimized) > max_length:
            # Truncate at word boundary
            optimized = optimized[:max_length].rsplit(' ', 1)[0] + "..."

        return optimized

    def generate_optimized_meta_description(
        self,
        content: str,
        keyword: str,
        max_length: int = 160
    ) -> str:
        """
        Generate an optimized meta description.

        Args:
            content: HTML content to extract description from
            keyword: Target keyword to include
            max_length: Maximum length (default 160)

        Returns:
            Optimized meta description
        """
        # Extract first paragraph
        text = self._strip_html(content)
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]

        if not sentences:
            return f"Learn about {keyword}. Discover expert tips and insights."

        # Start with keyword
        description = f"{keyword.capitalize()}. "

        # Add sentences until we reach optimal length
        for sentence in sentences:
            if len(description) + len(sentence) + 1 <= max_length - 20:  # Leave room for CTA
                description += sentence + ". "
            else:
                break

        # Add CTA
        if len(description) < max_length - 15:
            description += "Learn more today!"

        # Ensure it's within limits
        if len(description) > max_length:
            description = description[:max_length].rsplit(' ', 1)[0] + "..."

        # Ensure minimum length
        if len(description) < self.META_MIN:
            description += f" Discover everything you need to know about {keyword}."

        return description.strip()

    def _strip_html(self, html_content: str) -> str:
        """Strip HTML tags and decode entities."""
        text = re.sub(r'<[^>]+>', ' ', html_content)
        text = html.unescape(text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text


if __name__ == "__main__":
    # Test the module
    optimizer = OnPageOptimizer()

    test_post = {
        'title': "Dog Training",
        'content': """
            <h2>Introduction to Dog Training</h2>
            <p>Dog training is essential for all dog owners. Whether you have a puppy
            or an adult dog, training helps build a strong relationship.</p>

            <img src="dog1.jpg" alt="Golden retriever during training">

            <h2>Basic Commands</h2>
            <p>Start with basic commands like sit, stay, and come. These foundational
            commands are crucial for safety and obedience.</p>

            <img src="dog2.jpg">

            <h3>The Sit Command</h3>
            <p>Teaching your dog to sit is often the first command trainers recommend.
            It's simple and effective.</p>

            <h2>Positive Reinforcement</h2>
            <p>Always use positive reinforcement when training. Reward good behavior
            with treats and praise.</p>
        """,
        'meta_description': "",
        'url_slug': "dog-training",
        'target_keyword': "dog training tips"
    }

    result = optimizer.analyze_onpage(test_post)

    print("On-Page SEO Analysis:")
    print(f"Overall Score: {result['overall_score']}/70")
    print(f"\nTitle: {result['title']['score']}/{result['title']['max_score']}")
    print(f"Meta Description: {result['meta_description']['score']}/{result['meta_description']['max_score']}")
    print(f"Headers: {result['headers']['score']}/{result['headers']['max_score']}")
    print(f"Content: {result['content']['score']}/{result['content']['max_score']}")
    print(f"Images: {result['images']['score']}/{result['images']['max_score']}")
    print(f"URL: {result['url']['score']}/{result['url']['max_score']}")

    print(f"\nIssues ({len(result['issues'])}):")
    for issue in result['issues']:
        print(f"  ⚠️  {issue}")

    print(f"\nRecommendations ({len(result['recommendations'])}):")
    for i, rec in enumerate(result['recommendations'][:5], 1):
        print(f"  {i}. {rec}")

    # Test optimization generation
    print("\n--- OPTIMIZATION SUGGESTIONS ---")
    optimized_title = optimizer.generate_optimized_title(
        test_post['title'],
        test_post['target_keyword']
    )
    print(f"\nOptimized Title: {optimized_title}")

    optimized_meta = optimizer.generate_optimized_meta_description(
        test_post['content'],
        test_post['target_keyword']
    )
    print(f"Optimized Meta: {optimized_meta}")
