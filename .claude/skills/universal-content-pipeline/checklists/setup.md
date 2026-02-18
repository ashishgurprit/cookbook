# Universal Content Pipeline - Setup Checklist

Complete this checklist before running the pipeline for the first time.

## Prerequisites

### Required Software

- [ ] Python 3.8+ installed
- [ ] pip package manager
- [ ] Git (for cloning skills)
- [ ] Text editor or IDE

### API Accounts

- [ ] OpenAI account with API access
- [ ] WordPress site with admin access
- [ ] Google Cloud account (optional, for Google Vision OCR)
- [ ] Social media API access (optional, for distribution)

## Installation

### 1. Install Python Dependencies

```bash
# Core dependencies
pip install openai tiktoken chromadb
pip install requests beautifulsoup4 markdownify
pip install python-dotenv pyyaml pillow

# PDF processing (from pdf-processing skill)
pip install PyPDF2 pdfplumber pdf2image camelot-py
pip install pytesseract  # For OCR fallback

# Optional: Google Vision OCR
pip install google-cloud-vision
```

- [ ] All core dependencies installed
- [ ] PDF processing libraries installed
- [ ] Optional dependencies installed (if needed)

### 2. Install Required Skills

```bash
# These skills must be installed first
cd ~/.claude/skills

# Install prerequisite skills
# (Assuming they're already in your Streamlined Development master)
```

- [ ] `pdf-processing` skill available
- [ ] `semantic-chunking` skill available
- [ ] `translation-pipeline` skill available (if using translation)

## Configuration

### 3. Set Up Environment Variables

Create a `.env` file in your project directory:

```bash
# Required
OPENAI_API_KEY=sk-...
WORDPRESS_URL=https://yourblog.com
WORDPRESS_USERNAME=admin
WORDPRESS_APP_PASSWORD=xxxx xxxx xxxx xxxx

# Optional
GOOGLE_VISION_API_KEY=...
TWITTER_API_KEY=...
LINKEDIN_API_KEY=...
```

- [ ] OpenAI API key configured
- [ ] WordPress credentials configured
- [ ] Optional API keys configured

### 4. Generate WordPress Application Password

1. Log into WordPress admin
2. Go to Users → Profile
3. Scroll to "Application Passwords"
4. Enter name: "Content Pipeline"
5. Click "Add New Application Password"
6. Copy the generated password (format: `xxxx xxxx xxxx xxxx`)

- [ ] WordPress application password created
- [ ] Password added to `.env` file

### 5. Verify WordPress REST API

Test API access:

```bash
curl https://yourblog.com/wp-json/wp/v2/posts \
  -u "username:xxxx xxxx xxxx xxxx"
```

Should return JSON with posts list.

- [ ] WordPress REST API accessible
- [ ] Authentication working

### 6. Configure Pipeline

Edit `config/pipeline-config.yaml`:

```yaml
# Update these settings
publishing:
  wordpress:
    url: 'https://yourblog.com'  # Your WordPress URL
    default_status: 'draft'       # Start with drafts
    default_author: 1              # Your user ID

content_generation:
  style: 'educational'    # Your preferred style
  audience: 'professionals'  # Your target audience
```

- [ ] WordPress URL updated
- [ ] Default settings configured
- [ ] Style and audience set

### 7. Test with Small Document

Create a test with a small PDF (5-10 pages):

```bash
python examples/book-to-blog-series.py \
  --book ./test.pdf \
  --dry-run
```

- [ ] Test run completes without errors
- [ ] Output directory created
- [ ] All stages execute successfully

## Verification

### 8. Verify Outputs

Check the output directory:

- [ ] `extracted_text.txt` exists and contains text
- [ ] `chunks.json` exists with semantic chunks
- [ ] `knowledge_graph.json` exists with concepts
- [ ] `generated_posts.json` exists with blog posts

### 9. Review Generated Content

Open `generated_posts.json` and check:

- [ ] Titles are compelling and SEO-optimized
- [ ] Content is coherent and well-structured
- [ ] Word count is appropriate (800-2000 words)
- [ ] SEO metadata is present
- [ ] Quality scores are acceptable (>0.85)

### 10. Test WordPress Publishing

Run a real test with 1-2 posts:

```bash
# Manually publish one post to verify
python -c "
from wordpress_publisher import WordPressPublisher

publisher = WordPressPublisher(
    site_url='https://yourblog.com',
    username='admin',
    app_password='xxxx xxxx xxxx xxxx'
)

result = publisher.publish_post(
    title='Test Post',
    content='<p>This is a test</p>',
    status='draft'
)

print(f'Published: {result}')
"
```

- [ ] Test post appears in WordPress drafts
- [ ] Categories and tags work
- [ ] Meta fields saved correctly

## Cost Estimation

### 11. Calculate Expected Costs

For a 300-page book:

```
Extraction (OCR):        $5-10 (if scanned)
Knowledge Extraction:    $0.50
Content Generation:      $40-50 (GPT-4)
---
Total:                   $45-60
```

- [ ] Budget approved for API costs
- [ ] Cost tracking set up (optional)

## Production Readiness

### 12. Final Checklist

Before processing your first real book:

- [ ] All dependencies installed and working
- [ ] Environment variables configured
- [ ] WordPress connection tested
- [ ] Test run completed successfully
- [ ] Generated content reviewed and acceptable
- [ ] Publishing to WordPress verified
- [ ] Budget for API costs approved
- [ ] Backup plan for failures
- [ ] Monitoring set up (optional)

## Post-Setup

### 13. First Production Run

Tips for your first book:

1. **Start with drafts**: Set `default_status: 'draft'` in config
2. **Review first 5 posts**: Check quality before continuing
3. **Use checkpoints**: Enable `save_checkpoints: true`
4. **Monitor costs**: Watch OpenAI API usage dashboard
5. **Have human review**: Don't auto-publish without review

### 14. Optimization (After First Run)

After your first successful run:

- [ ] Review quality scores and adjust prompts if needed
- [ ] Optimize chunk sizes based on output quality
- [ ] Fine-tune SEO settings
- [ ] Set up automated scheduling if desired
- [ ] Configure social media distribution

## Troubleshooting

### Common Issues

**PDF extraction fails**:
- Check PDF is not password-protected
- Try OCR if text extraction fails
- Verify PDF file is not corrupted

**WordPress publishing fails**:
- Verify application password (no quotes, spaces preserved)
- Check WordPress REST API is enabled
- Verify user has publish permissions

**High API costs**:
- Use `gpt-3.5-turbo` for drafts
- Enable aggressive caching
- Reduce chunk size to generate fewer posts

**Low quality posts**:
- Increase quality threshold
- Adjust content generation prompts
- Review knowledge extraction settings

## Support Resources

- Main documentation: `SKILL.md`
- Configuration reference: `config/pipeline-config.yaml`
- Troubleshooting: `references/troubleshooting.md`
- Cost optimization: `references/cost-optimization.md`

---

**Setup Complete!**

You're ready to start converting books to blog series. Start with a small test document and gradually scale up.
