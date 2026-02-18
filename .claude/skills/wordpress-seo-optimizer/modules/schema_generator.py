"""
Schema Generator Module

Generates JSON-LD structured data for various content types.
Supports Article, FAQPage, HowTo, LocalBusiness, and more.
"""

import json
from typing import Dict, List, Optional
from datetime import datetime


class SchemaGenerator:
    """Generate schema.org structured data in JSON-LD format."""

    def __init__(self):
        """Initialize schema generator."""
        self.context = "https://schema.org"

    def generate_article_schema(
        self,
        headline: str,
        author_name: str,
        date_published: str,
        date_modified: Optional[str] = None,
        description: Optional[str] = None,
        image_url: Optional[str] = None,
        publisher_name: Optional[str] = None,
        publisher_logo: Optional[str] = None
    ) -> Dict:
        """
        Generate Article schema.

        Args:
            headline: Article headline
            author_name: Author name
            date_published: Publication date (ISO 8601 format)
            date_modified: Last modified date (optional)
            description: Article description (optional)
            image_url: Featured image URL (optional)
            publisher_name: Publisher name (optional)
            publisher_logo: Publisher logo URL (optional)

        Returns:
            Article schema as dictionary
        """
        schema = {
            "@context": self.context,
            "@type": "Article",
            "headline": headline,
            "author": {
                "@type": "Person",
                "name": author_name
            },
            "datePublished": date_published
        }

        if date_modified:
            schema["dateModified"] = date_modified
        else:
            schema["dateModified"] = date_published

        if description:
            schema["description"] = description

        if image_url:
            schema["image"] = image_url

        if publisher_name:
            publisher = {
                "@type": "Organization",
                "name": publisher_name
            }
            if publisher_logo:
                publisher["logo"] = {
                    "@type": "ImageObject",
                    "url": publisher_logo
                }
            schema["publisher"] = publisher

        return schema

    def generate_faq_schema(self, questions: List[Dict[str, str]]) -> Dict:
        """
        Generate FAQPage schema.

        Args:
            questions: List of dicts with 'question' and 'answer' keys

        Returns:
            FAQPage schema as dictionary
        """
        main_entity = []

        for q in questions:
            main_entity.append({
                "@type": "Question",
                "name": q.get('question', ''),
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": q.get('answer', '')
                }
            })

        return {
            "@context": self.context,
            "@type": "FAQPage",
            "mainEntity": main_entity
        }

    def generate_howto_schema(
        self,
        name: str,
        description: str,
        steps: List[Dict],
        total_time: Optional[str] = None,
        image_url: Optional[str] = None
    ) -> Dict:
        """
        Generate HowTo schema.

        Args:
            name: HowTo name/title
            description: HowTo description
            steps: List of step dicts with 'name' and 'text' keys
            total_time: Total time in ISO 8601 duration format (e.g., "PT30M")
            image_url: Image URL (optional)

        Returns:
            HowTo schema as dictionary
        """
        step_list = []

        for i, step in enumerate(steps, 1):
            step_schema = {
                "@type": "HowToStep",
                "name": step.get('name', f"Step {i}"),
                "text": step.get('text', ''),
                "url": step.get('url', ''),
                "position": i
            }

            if 'image' in step:
                step_schema["image"] = step['image']

            step_list.append(step_schema)

        schema = {
            "@context": self.context,
            "@type": "HowTo",
            "name": name,
            "description": description,
            "step": step_list
        }

        if total_time:
            schema["totalTime"] = total_time

        if image_url:
            schema["image"] = image_url

        return schema

    def generate_breadcrumb_schema(self, breadcrumbs: List[Dict[str, str]]) -> Dict:
        """
        Generate BreadcrumbList schema.

        Args:
            breadcrumbs: List of dicts with 'name' and 'url' keys

        Returns:
            BreadcrumbList schema as dictionary
        """
        item_list = []

        for i, crumb in enumerate(breadcrumbs, 1):
            item_list.append({
                "@type": "ListItem",
                "position": i,
                "name": crumb.get('name', ''),
                "item": crumb.get('url', '')
            })

        return {
            "@context": self.context,
            "@type": "BreadcrumbList",
            "itemListElement": item_list
        }

    def generate_local_business_schema(
        self,
        name: str,
        business_type: str,
        address: Dict[str, str],
        phone: str,
        url: Optional[str] = None,
        geo_coordinates: Optional[Dict[str, float]] = None,
        opening_hours: Optional[List[str]] = None,
        price_range: Optional[str] = None
    ) -> Dict:
        """
        Generate LocalBusiness schema.

        Args:
            name: Business name
            business_type: Type (e.g., "Restaurant", "Store", "ProfessionalService")
            address: Dict with street, city, state, zip, country
            phone: Phone number
            url: Website URL (optional)
            geo_coordinates: Dict with 'latitude' and 'longitude' (optional)
            opening_hours: List of opening hours strings (e.g., ["Mo-Fr 09:00-17:00"])
            price_range: Price range (e.g., "$$", "$$$")

        Returns:
            LocalBusiness schema as dictionary
        """
        schema = {
            "@context": self.context,
            "@type": business_type,
            "name": name,
            "address": {
                "@type": "PostalAddress",
                "streetAddress": address.get('street', ''),
                "addressLocality": address.get('city', ''),
                "addressRegion": address.get('state', ''),
                "postalCode": address.get('zip', ''),
                "addressCountry": address.get('country', '')
            },
            "telephone": phone
        }

        if url:
            schema["url"] = url

        if geo_coordinates:
            schema["geo"] = {
                "@type": "GeoCoordinates",
                "latitude": geo_coordinates.get('latitude'),
                "longitude": geo_coordinates.get('longitude')
            }

        if opening_hours:
            schema["openingHoursSpecification"] = []
            for hours in opening_hours:
                # Parse format like "Mo-Fr 09:00-17:00"
                parts = hours.split()
                if len(parts) >= 2:
                    days_part = parts[0]
                    time_part = parts[1]

                    schema["openingHoursSpecification"].append({
                        "@type": "OpeningHoursSpecification",
                        "dayOfWeek": days_part.split('-'),
                        "opens": time_part.split('-')[0],
                        "closes": time_part.split('-')[1] if '-' in time_part else time_part
                    })

        if price_range:
            schema["priceRange"] = price_range

        return schema

    def extract_faq_from_content(self, html_content: str) -> List[Dict[str, str]]:
        """
        Extract FAQ questions and answers from HTML content.

        Looks for patterns like:
        - <h3>Question?</h3><p>Answer...</p>
        - <dt>Question?</dt><dd>Answer...</dd>

        Args:
            html_content: HTML content

        Returns:
            List of question-answer pairs
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')
        faqs = []

        # Look for FAQ patterns
        # Pattern 1: h3 followed by p
        for h3 in soup.find_all(['h3', 'h4']):
            question_text = h3.get_text().strip()
            if '?' in question_text:  # Likely a question
                # Get next sibling paragraph
                next_p = h3.find_next_sibling('p')
                if next_p:
                    answer_text = next_p.get_text().strip()
                    faqs.append({
                        'question': question_text,
                        'answer': answer_text
                    })

        # Pattern 2: dl/dt/dd structure
        for dl in soup.find_all('dl'):
            dts = dl.find_all('dt')
            dds = dl.find_all('dd')

            for dt, dd in zip(dts, dds):
                faqs.append({
                    'question': dt.get_text().strip(),
                    'answer': dd.get_text().strip()
                })

        return faqs

    def auto_generate_from_post(
        self,
        post_data: Dict,
        site_name: Optional[str] = None,
        site_logo: Optional[str] = None
    ) -> List[Dict]:
        """
        Automatically generate appropriate schemas for a post.

        Args:
            post_data: Post data dictionary
            site_name: Site/publisher name
            site_logo: Site logo URL

        Returns:
            List of schema dictionaries
        """
        schemas = []

        # Always add Article schema
        article_schema = self.generate_article_schema(
            headline=post_data.get('title', ''),
            author_name=post_data.get('author', 'Anonymous'),
            date_published=post_data.get('date', datetime.now().isoformat()),
            date_modified=post_data.get('modified'),
            description=post_data.get('excerpt', ''),
            image_url=post_data.get('featured_image_url'),
            publisher_name=site_name,
            publisher_logo=site_logo
        )
        schemas.append(article_schema)

        # Check if content has FAQ
        content = post_data.get('content', '')
        faqs = self.extract_faq_from_content(content)

        if len(faqs) >= 2:  # At least 2 FAQs to make it worthwhile
            faq_schema = self.generate_faq_schema(faqs)
            schemas.append(faq_schema)

        return schemas

    def to_json_ld(self, schema: Dict, pretty: bool = True) -> str:
        """
        Convert schema dictionary to JSON-LD string.

        Args:
            schema: Schema dictionary
            pretty: Pretty-print JSON (default True)

        Returns:
            JSON-LD string
        """
        if pretty:
            return json.dumps(schema, indent=2, ensure_ascii=False)
        else:
            return json.dumps(schema, ensure_ascii=False)

    def to_html_script(self, schema: Dict) -> str:
        """
        Convert schema to HTML script tag.

        Args:
            schema: Schema dictionary

        Returns:
            HTML script tag with JSON-LD
        """
        json_ld = self.to_json_ld(schema, pretty=True)
        return f'<script type="application/ld+json">\n{json_ld}\n</script>'


if __name__ == "__main__":
    # Test schema generator
    generator = SchemaGenerator()

    print("="*60)
    print("SCHEMA GENERATOR TESTS")
    print("="*60)

    # Test 1: Article schema
    print("\n1. Article Schema:")
    print("-"*60)
    article = generator.generate_article_schema(
        headline="How to Train Your Dog: Complete Guide",
        author_name="John Smith",
        date_published="2026-02-11T10:00:00Z",
        date_modified="2026-02-11T15:30:00Z",
        description="Comprehensive guide to dog training for beginners",
        image_url="https://example.com/dog-training.jpg",
        publisher_name="Dog Training Pro",
        publisher_logo="https://example.com/logo.png"
    )
    print(generator.to_json_ld(article))

    # Test 2: FAQ schema
    print("\n2. FAQ Schema:")
    print("-"*60)
    faqs = generator.generate_faq_schema([
        {
            'question': 'What is the best age to start dog training?',
            'answer': 'You can start training puppies as early as 8 weeks old. Basic commands and socialization should begin immediately.'
        },
        {
            'question': 'How long does it take to train a dog?',
            'answer': 'Basic obedience training typically takes 6-12 weeks with consistent daily practice. Advanced training may take several months.'
        }
    ])
    print(generator.to_json_ld(faqs))

    # Test 3: HowTo schema
    print("\n3. HowTo Schema:")
    print("-"*60)
    howto = generator.generate_howto_schema(
        name="How to Teach Your Dog to Sit",
        description="Step-by-step guide to teaching the sit command",
        steps=[
            {
                'name': 'Get a treat',
                'text': 'Hold a small treat in your hand near your dog\'s nose'
            },
            {
                'name': 'Move treat up',
                'text': 'Slowly move the treat upward and backward over the dog\'s head'
            },
            {
                'name': 'Say "sit"',
                'text': 'As their bottom touches the ground, say "sit" and give the treat'
            }
        ],
        total_time="PT15M"
    )
    print(generator.to_json_ld(howto))

    # Test 4: HTML script tag
    print("\n4. HTML Script Tag:")
    print("-"*60)
    print(generator.to_html_script(article))
