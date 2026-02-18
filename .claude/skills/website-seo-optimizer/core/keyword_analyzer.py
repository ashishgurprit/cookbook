"""
Keyword Analysis Module

Analyzes content for keyword optimization, density calculation,
and LSI keyword suggestions.
"""

import re
from typing import Dict, List, Optional
from collections import Counter
import html


class KeywordAnalyzer:
    """Analyze content for keyword optimization."""

    def __init__(self):
        """Initialize keyword analyzer."""
        self.stop_words = {
            'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from',
            'has', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'that', 'the',
            'to', 'was', 'will', 'with', 'you', 'your', 'this', 'but', 'not',
            'or', 'can', 'all', 'would', 'there', 'their', 'what', 'so', 'up',
            'out', 'if', 'about', 'which', 'when', 'make', 'just', 'know'
        }

    def analyze_content(
        self,
        content: str,
        target_keyword: str,
        title: str = "",
        meta_description: str = "",
        headings: List[str] = None
    ) -> Dict:
        """
        Analyze content for keyword optimization.

        Args:
            content: HTML content of the post
            target_keyword: Primary keyword to analyze
            title: Post title
            meta_description: Meta description
            headings: List of headings (H1, H2, H3, etc.)

        Returns:
            Dictionary with keyword analysis results
        """
        # Strip HTML tags
        text_content = self._strip_html(content)

        # Calculate word count
        word_count = self._count_words(text_content)

        # Calculate keyword density
        keyword_count = self._count_keyword_occurrences(text_content, target_keyword)
        density = (keyword_count / word_count * 100) if word_count > 0 else 0

        # Target density (1-2% is optimal)
        target_density = 1.5
        density_optimal = 1.0 <= density <= 2.0

        # Check keyword placement
        placement = self._check_keyword_placement(
            target_keyword,
            title,
            text_content,
            meta_description,
            headings or []
        )

        # Extract potential LSI keywords
        lsi_keywords = self._extract_lsi_keywords(text_content, target_keyword)

        # Generate recommendations
        recommendations = []

        if density < 1.0:
            additional_mentions = int((target_density * word_count / 100) - keyword_count)
            recommendations.append(
                f"Increase keyword density to {target_density}% (add {additional_mentions} more mentions)"
            )
        elif density > 2.5:
            recommendations.append(
                f"Decrease keyword density from {density:.1f}% to {target_density}% (keyword stuffing risk)"
            )

        if not placement['in_title']:
            recommendations.append("Add target keyword to title tag")

        if not placement['in_first_100']:
            recommendations.append("Include target keyword in first 100 words")

        if not placement['in_h1']:
            recommendations.append("Add target keyword to H1 heading")

        if len(lsi_keywords) < 3:
            recommendations.append("Include more LSI keywords for semantic relevance")

        return {
            'target_keyword': target_keyword,
            'keyword_count': keyword_count,
            'word_count': word_count,
            'density': round(density, 2),
            'target_density': target_density,
            'density_optimal': density_optimal,
            'placement': placement,
            'lsi_keywords': lsi_keywords,
            'recommendations': recommendations,
            'score': self._calculate_keyword_score(density, placement, lsi_keywords)
        }

    def _strip_html(self, html_content: str) -> str:
        """Strip HTML tags and decode entities."""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', html_content)
        # Decode HTML entities
        text = html.unescape(text)
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def _count_words(self, text: str) -> int:
        """Count words in text."""
        words = re.findall(r'\b\w+\b', text.lower())
        return len(words)

    def _count_keyword_occurrences(self, text: str, keyword: str) -> int:
        """Count keyword occurrences (case-insensitive, whole phrase)."""
        text_lower = text.lower()
        keyword_lower = keyword.lower()

        # Count exact phrase matches
        count = text_lower.count(keyword_lower)

        return count

    def _check_keyword_placement(
        self,
        keyword: str,
        title: str,
        content: str,
        meta_description: str,
        headings: List[str]
    ) -> Dict[str, bool]:
        """Check where the keyword appears."""
        keyword_lower = keyword.lower()

        # Check first 100 words
        words = content.split()[:100]
        first_100_words = ' '.join(words).lower()

        # Check H1 (first heading if provided)
        h1 = headings[0] if headings else ""

        return {
            'in_title': keyword_lower in title.lower(),
            'in_meta': keyword_lower in meta_description.lower(),
            'in_h1': keyword_lower in h1.lower(),
            'in_first_100': keyword_lower in first_100_words,
            'in_headings': any(keyword_lower in h.lower() for h in headings)
        }

    def _extract_lsi_keywords(self, text: str, target_keyword: str) -> List[str]:
        """
        Extract potential LSI (Latent Semantic Indexing) keywords.

        For MVP: Simple extraction of common 2-3 word phrases.
        Future: Use AI/ML for semantic keyword extraction.
        """
        # Extract 2-3 word phrases
        words = re.findall(r'\b\w+\b', text.lower())

        # Get bigrams and trigrams
        bigrams = [' '.join(words[i:i+2]) for i in range(len(words)-1)]
        trigrams = [' '.join(words[i:i+3]) for i in range(len(words)-2)]

        all_phrases = bigrams + trigrams

        # Count frequency
        phrase_counts = Counter(all_phrases)

        # Filter out stop-word-heavy phrases and target keyword
        target_lower = target_keyword.lower()
        lsi_candidates = []

        for phrase, count in phrase_counts.most_common(20):
            # Skip if it's the target keyword
            if phrase == target_lower:
                continue

            # Skip if too many stop words
            phrase_words = phrase.split()
            stop_word_count = sum(1 for w in phrase_words if w in self.stop_words)
            if stop_word_count >= len(phrase_words):
                continue

            # Only include if appears at least 2 times
            if count >= 2:
                lsi_candidates.append(phrase)

        return lsi_candidates[:5]  # Return top 5

    def _calculate_keyword_score(
        self,
        density: float,
        placement: Dict[str, bool],
        lsi_keywords: List[str]
    ) -> int:
        """Calculate keyword optimization score (0-100)."""
        score = 0

        # Density score (30 points)
        if 1.0 <= density <= 2.0:
            score += 30
        elif 0.5 <= density < 1.0 or 2.0 < density <= 2.5:
            score += 20
        elif density < 0.5:
            score += 5
        else:  # density > 2.5 (keyword stuffing risk)
            score += 0

        # Placement score (50 points)
        if placement['in_title']:
            score += 15
        if placement['in_h1']:
            score += 15
        if placement['in_first_100']:
            score += 10
        if placement['in_meta']:
            score += 5
        if placement['in_headings']:
            score += 5

        # LSI keywords score (20 points)
        lsi_count = len(lsi_keywords)
        if lsi_count >= 5:
            score += 20
        elif lsi_count >= 3:
            score += 15
        elif lsi_count >= 1:
            score += 10
        else:
            score += 0

        return min(score, 100)

    def suggest_keyword_placement(
        self,
        content: str,
        target_keyword: str,
        current_density: float,
        target_density: float = 1.5
    ) -> List[str]:
        """
        Suggest where to add more keyword mentions.

        Args:
            content: Post content
            target_keyword: Keyword to add
            current_density: Current keyword density
            target_density: Target density (default 1.5%)

        Returns:
            List of suggestions
        """
        suggestions = []

        # Calculate how many more mentions needed
        word_count = self._count_words(self._strip_html(content))
        current_count = self._count_keyword_occurrences(
            self._strip_html(content),
            target_keyword
        )
        target_count = int(target_density * word_count / 100)
        needed = target_count - current_count

        if needed <= 0:
            return ["Keyword density is optimal"]

        suggestions.append(f"Add {needed} more mentions of '{target_keyword}'")
        suggestions.append("Natural placements:")
        suggestions.append("  • In subheadings (H2/H3)")
        suggestions.append("  • In image alt text")
        suggestions.append("  • In the conclusion paragraph")
        suggestions.append("  • In internal link anchor text")

        return suggestions


def extract_keywords_from_title(title: str) -> List[str]:
    """Extract potential keywords from title."""
    # Remove common filler words
    stop_words = {
        'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from',
        'has', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'that', 'the',
        'to', 'was', 'will', 'with', 'how', 'what', 'when', 'where', 'why'
    }

    words = re.findall(r'\b\w+\b', title.lower())
    keywords = [w for w in words if w not in stop_words and len(w) > 3]

    # Return as both individual words and potential phrases
    keyword_list = keywords.copy()

    # Add 2-word combinations
    for i in range(len(keywords) - 1):
        keyword_list.append(f"{keywords[i]} {keywords[i+1]}")

    # Add 3-word combinations
    for i in range(len(keywords) - 2):
        keyword_list.append(f"{keywords[i]} {keywords[i+1]} {keywords[i+2]}")

    return keyword_list[:10]  # Return top 10


if __name__ == "__main__":
    # Test the module
    analyzer = KeywordAnalyzer()

    test_content = """
    <p>Dog training tips are essential for new dog owners. These dog training
    methods have been proven effective by professional trainers.</p>

    <h2>Puppy Training Basics</h2>
    <p>When training your puppy, consistency is key. Use positive reinforcement
    and reward good behavior.</p>

    <h2>Obedience Training</h2>
    <p>Dog obedience training helps establish boundaries. Training your dog
    improves the relationship between you and your pet.</p>
    """

    result = analyzer.analyze_content(
        content=test_content,
        target_keyword="dog training",
        title="Dog Training Tips for New Owners",
        meta_description="Learn effective dog training tips",
        headings=["Dog Training Tips for New Owners", "Puppy Training Basics", "Obedience Training"]
    )

    print("Keyword Analysis Results:")
    print(f"Target Keyword: {result['target_keyword']}")
    print(f"Keyword Count: {result['keyword_count']}")
    print(f"Word Count: {result['word_count']}")
    print(f"Density: {result['density']}%")
    print(f"Score: {result['score']}/100")
    print(f"\nPlacement:")
    for key, value in result['placement'].items():
        print(f"  {key}: {value}")
    print(f"\nLSI Keywords: {result['lsi_keywords']}")
    print(f"\nRecommendations:")
    for rec in result['recommendations']:
        print(f"  • {rec}")
