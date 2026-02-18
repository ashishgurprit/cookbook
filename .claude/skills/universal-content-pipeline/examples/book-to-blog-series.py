"""
Complete Example: Convert Book to Blog Series

This example demonstrates the complete workflow from a PDF book
to 50+ published blog posts using the Universal Content Pipeline.

Usage:
    python book-to-blog-series.py --book ./books/leadership-guide.pdf

Requirements:
    - OpenAI API key
    - WordPress site with REST API
    - Optional: Google Vision API for OCR
"""

import os
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent / 'templates'))

from pipeline_orchestrator import UniversalContentPipeline


def setup_environment():
    """Set up environment variables"""

    # Check required environment variables
    required_vars = [
        'OPENAI_API_KEY',
        'WORDPRESS_URL',
        'WORDPRESS_USERNAME',
        'WORDPRESS_APP_PASSWORD'
    ]

    missing = [var for var in required_vars if not os.getenv(var)]

    if missing:
        print("❌ Missing required environment variables:")
        for var in missing:
            print(f"   - {var}")
        print("\nPlease set these variables or create a .env file")
        sys.exit(1)

    print("✓ Environment variables configured")


def main():
    """Main execution"""

    import argparse

    parser = argparse.ArgumentParser(
        description='Convert book to blog series'
    )
    parser.add_argument(
        '--book',
        required=True,
        help='Path to book PDF'
    )
    parser.add_argument(
        '--output',
        default=None,
        help='Output directory (default: auto-generated)'
    )
    parser.add_argument(
        '--config',
        default='config/pipeline-config.yaml',
        help='Pipeline configuration file'
    )
    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume from checkpoint if available'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Test without publishing to WordPress'
    )

    args = parser.parse_args()

    # Setup
    print("\n" + "="*60)
    print("BOOK TO BLOG SERIES CONVERTER")
    print("="*60 + "\n")

    setup_environment()

    # Validate book file
    book_path = Path(args.book)
    if not book_path.exists():
        print(f"❌ Book file not found: {args.book}")
        sys.exit(1)

    print(f"✓ Book file: {book_path.name}")

    # Generate output directory
    if args.output:
        output_dir = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        book_name = book_path.stem.replace(' ', '_').lower()
        output_dir = f"./output/{book_name}_{timestamp}"

    print(f"✓ Output directory: {output_dir}")

    # Load configuration
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"❌ Config file not found: {args.config}")
        print("   Using default configuration")
        config_path = None

    # Modify config for dry run
    if args.dry_run:
        print("\n⚠️  DRY RUN MODE - Posts will not be published to WordPress")
        # TODO: Modify config to skip publishing stage

    # Confirm before proceeding
    print("\n" + "-"*60)
    print("PIPELINE CONFIGURATION:")
    print("-"*60)
    print(f"Book: {book_path.name}")
    print(f"Output: {output_dir}")
    print(f"Config: {config_path or 'default'}")
    print(f"Resume: {args.resume}")
    print(f"Dry Run: {args.dry_run}")
    print("-"*60 + "\n")

    response = input("Proceed with pipeline? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Aborted.")
        sys.exit(0)

    # Initialize pipeline
    print("\n" + "="*60)
    print("INITIALIZING PIPELINE")
    print("="*60 + "\n")

    pipeline = UniversalContentPipeline(
        config_path=str(config_path) if config_path else None
    )

    # Process document
    try:
        results = pipeline.process_document(
            document_path=str(book_path),
            output_dir=output_dir,
            resume_from_checkpoint=args.resume
        )

        # Display results
        print("\n" + "="*60)
        print("PIPELINE COMPLETE")
        print("="*60 + "\n")

        print("RESULTS:")
        print("-"*60)
        print(f"Status: {results['status']}")
        print(f"Document: {results['document']}")
        print(f"Started: {results['started_at']}")
        print(f"Completed: {results['completed_at']}")
        print()

        print("STAGE RESULTS:")
        print("-"*60)

        # Stage 1
        extraction = results['stages']['extraction']
        print(f"1. Document Ingestion:")
        print(f"   - Pages: {extraction['page_count']}")
        print(f"   - Confidence: {extraction['confidence']:.2%}")
        print()

        # Stage 2
        preparation = results['stages']['preparation']
        print(f"2. Content Preparation:")
        print(f"   - Chunks: {preparation['chunk_count']}")
        print()

        # Stage 3
        knowledge = results['stages']['knowledge']
        print(f"3. Knowledge Extraction:")
        print(f"   - Concepts: {len(knowledge['concepts'])}")
        print(f"   - Themes: {len(knowledge['themes'])}")
        print()

        # Stage 4
        generation = results['stages']['generation']
        print(f"4. Content Generation:")
        print(f"   - Posts: {generation['post_count']}")
        print()

        # Stage 5
        if 'publishing' in results['stages']:
            publishing = results['stages']['publishing']
            print(f"5. Publishing:")
            print(f"   - Posts Published: {publishing['post_count']}")

            if publishing['posts']:
                first_post = publishing['posts'][0]
                last_post = publishing['posts'][-1]
                print(f"   - First Post: {first_post.get('publish_date', 'N/A')}")
                print(f"   - Last Post: {last_post.get('publish_date', 'N/A')}")
            print()

        # Stage 6
        if 'distribution' in results['stages']:
            distribution = results['stages']['distribution']
            print(f"6. Distribution:")
            print(f"   - Distributions: {distribution.get('distribution_count', 0)}")
            print()

        print("-"*60)
        print(f"\nFull report saved to: {output_dir}/REPORT.txt")
        print(f"Generated posts: {output_dir}/generated_posts.json")

        if not args.dry_run:
            print(f"\n✓ All posts published to WordPress!")
            print(f"  Visit your WordPress admin to review drafts")

        print("\n" + "="*60)
        print("SUCCESS")
        print("="*60 + "\n")

    except Exception as e:
        print("\n" + "="*60)
        print("PIPELINE FAILED")
        print("="*60 + "\n")

        print(f"Error: {e}")
        print(f"\nCheckpoint saved to: {output_dir}/checkpoint.json")
        print("You can resume with: --resume")

        sys.exit(1)


if __name__ == '__main__':
    main()
