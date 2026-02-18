# Cost Optimization Guide

Complete guide to minimizing API costs while maintaining quality in the Universal Content Pipeline.

## Cost Breakdown

### Typical Costs (300-page book → 50 posts)

| Component | API | Volume | Unit Cost | Total Cost |
|-----------|-----|--------|-----------|------------|
| **OCR** (if needed) | Google Vision | 300 pages | $1.50/1000 | $0.45 |
| **OCR** (alternative) | Tesseract | 300 pages | Free | $0 |
| **Embeddings** | OpenAI | 150 chunks | $0.02/1M tokens | $0.50 |
| **Content Generation** | GPT-4 | 50 posts | $30/1M in, $60/1M out | $45-50 |
| **Images** (optional) | DALL-E | 50 images | $0.04/image | $2.00 |
| **Total (with OCR)** | | | | **$48-53** |
| **Total (no OCR)** | | | | **$47.50** |

### Cost per Post

- **With GPT-4**: ~$1.00 per post
- **With GPT-3.5-turbo**: ~$0.10 per post
- **Savings potential**: 90% by using GPT-3.5 for drafts

---

## Optimization Strategies

### 1. Use Cheaper Models for Drafts

**Strategy**: Generate drafts with GPT-3.5-turbo, polish with GPT-4

```yaml
# config/pipeline-config.yaml
content_generation:
  cost_optimization:
    use_cheaper_model_for_drafts: true
    draft_model: 'gpt-3.5-turbo'  # $0.50-2/1M tokens
    polish_model: 'gpt-4'          # $30-60/1M tokens
    polish_threshold: 0.90         # Only polish if quality < 0.90
```

**Expected Savings**: 85-90%

**Implementation**:

```python
def generate_post_cost_optimized(chunk):
    # Generate with cheap model
    draft = generate_with_model(chunk, model='gpt-3.5-turbo')

    # Check quality
    quality = assess_quality(draft)

    if quality >= 0.90:
        # Draft is good enough
        return draft
    else:
        # Polish with expensive model
        return polish_with_model(draft, model='gpt-4')
```

**Results**:
- 70-80% of posts pass with cheap model
- Only 20-30% need expensive polishing
- Overall cost: ~$10-15 instead of $45-50

---

### 2. Aggressive Caching

**Strategy**: Cache everything that can be reused

```yaml
# config/pipeline-config.yaml
performance:
  use_cache: true
  cache_ttl: 2592000  # 30 days

content_preparation:
  translation:
    use_cache: true

content_generation:
  embeddings:
    use_cache: true
```

**What to Cache**:

1. **Translation**: Cache by MD5 hash of (text + source_lang + target_lang)
2. **Embeddings**: Cache by text hash
3. **Knowledge Extraction**: Cache by chunk hash
4. **Language Detection**: Cache by first 100 chars

**Expected Savings**: 40-50% on re-runs or similar content

**Cache Hit Rates**:
- First run: 0%
- Similar book (same topic): 20-30%
- Re-run after adjustments: 90%+

---

### 3. Optimize Chunk Sizes

**Strategy**: Fewer, larger chunks = fewer API calls

```yaml
# Expensive: Many small chunks
chunking:
  max_tokens: 300  # 150 chunks → 150 API calls

# Optimized: Fewer larger chunks
chunking:
  max_tokens: 600  # 75 chunks → 75 API calls
```

**Tradeoff Analysis**:

| Chunk Size | Chunks | API Calls | Cost | Quality |
|------------|--------|-----------|------|---------|
| 300 tokens | 200 | 200 | $80 | High precision |
| 500 tokens | 120 | 120 | $48 | Good balance |
| 800 tokens | 75 | 75 | $30 | Lower precision |

**Recommendation**: 500-600 tokens (sweet spot)

---

### 4. Batch API Calls

**Strategy**: Send multiple requests in parallel

```python
# Expensive: Sequential calls
for chunk in chunks:
    post = generate_post(chunk)  # 50 sequential API calls

# Optimized: Batch calls
batches = [chunks[i:i+5] for i in range(0, len(chunks), 5)]
for batch in batches:
    posts = generate_posts_batch(batch)  # 10 batched calls
```

**Benefits**:
- Reduced overhead
- Faster processing
- Potentially lower costs (batch discounts)

**Expected Savings**: 10-15%

---

### 5. Skip Unnecessary Stages

**Strategy**: Only run stages you need

```yaml
# Disable expensive optional features
knowledge_extraction:
  enabled: false  # Skip if not using internal linking

images:
  generate_featured: false  # Skip DALL-E ($2 saved)

distribution:
  enabled: false  # Skip social media distribution
```

**Cost by Stage**:
- Document ingestion: $0-10 (OCR dependent)
- Content preparation: $0.50 (embeddings)
- Knowledge extraction: $5 (optional)
- Content generation: $45-50 (required)
- Images: $2 (optional)
- Distribution: $0 (free APIs)

**Total savings if skipping optionals**: ~$7-17

---

### 6. Use Free OCR

**Strategy**: Use Tesseract instead of Google Vision

```yaml
document_ingestion:
  ocr_provider: 'tesseract'  # Free
  # vs
  ocr_provider: 'google_vision'  # $1.50/1000 pages
```

**Quality Comparison**:

| Provider | Cost | Quality | Speed |
|----------|------|---------|-------|
| Google Vision | $1.50/1000 pages | 95-98% | Fast |
| Tesseract | Free | 85-90% | Medium |
| Azure OCR | $1/1000 pages | 90-95% | Fast |

**Recommendation**:
- Use Tesseract for high-quality scans
- Use Google Vision for poor-quality scans
- Test extraction quality before full pipeline

**Potential Savings**: $0.45 per book

---

### 7. Reduce Post Count

**Strategy**: Generate fewer, higher-quality posts

```yaml
# More posts = higher cost
chunking:
  max_tokens: 400  # 150 chunks → 150 posts → $150

# Fewer posts = lower cost
chunking:
  max_tokens: 800  # 75 chunks → 75 posts → $75
```

**Alternative**: Selective generation

```python
# Generate posts only for high-value chunks
high_value_chunks = filter_by_quality(chunks, min_score=0.8)
posts = generate_posts(high_value_chunks)  # 50% fewer posts
```

**Expected Savings**: 50%+ (but fewer posts)

---

### 8. Optimize Prompts

**Strategy**: Shorter, more efficient prompts

```python
# Expensive: Verbose prompt (2000 tokens)
prompt = f"""
Transform the following content into a complete, engaging blog post...
[Long instructions with many examples]
Content: {chunk_text}
"""

# Optimized: Concise prompt (500 tokens)
prompt = f"""
Convert to blog post. Target: professionals.
Include: title, intro, body, conclusion.
Content: {chunk_text}
"""
```

**Token Savings**:
- Input tokens: 1500 saved per call
- 50 calls: 75,000 tokens saved
- Cost savings: ~$2-3 per book

---

### 9. Monitor and Set Budgets

**Strategy**: Set API spending limits

```python
class CostTracker:
    def __init__(self, budget=50):
        self.budget = budget
        self.spent = 0

    def check_budget(self, estimated_cost):
        if self.spent + estimated_cost > self.budget:
            raise BudgetExceededError()

    def record_cost(self, actual_cost):
        self.spent += actual_cost
```

**Implementation**:

```python
tracker = CostTracker(budget=50)

for chunk in chunks:
    estimated = estimate_cost(chunk)
    tracker.check_budget(estimated)

    post = generate_post(chunk)
    tracker.record_cost(actual_cost)
```

---

### 10. Use Provider Fallbacks

**Strategy**: Use free providers first, paid as fallback

```yaml
content_generation:
  provider_chain:
    - 'ollama'          # Free, local (quality: 70%)
    - 'gpt-3.5-turbo'   # Cheap (quality: 85%)
    - 'gpt-4'           # Expensive (quality: 95%)
```

**Cost Waterfall**:
1. Try free local model (Ollama)
2. If quality < 0.80, use GPT-3.5-turbo
3. If quality < 0.90, use GPT-4

**Expected Savings**: 50-70%

---

## Cost Optimization Checklist

### Before Processing

- [ ] Estimate total cost for the book
- [ ] Set budget limit
- [ ] Enable caching
- [ ] Configure cheaper models for drafts
- [ ] Disable optional expensive features
- [ ] Optimize chunk sizes
- [ ] Use free OCR if possible

### During Processing

- [ ] Monitor actual costs vs. estimates
- [ ] Check cache hit rates
- [ ] Pause if budget exceeded
- [ ] Save checkpoints to avoid re-running

### After Processing

- [ ] Review cost breakdown
- [ ] Analyze cost per post
- [ ] Identify optimization opportunities
- [ ] Update configuration for next run

---

## Cost Comparison: Strategies

### Baseline (No Optimization)

```
OCR: Google Vision      $0.45
Embeddings:             $0.50
Knowledge Extraction:   $5.00
Content (GPT-4):        $50.00
Images (DALL-E):        $2.00
---------------------------------
Total:                  $57.95
```

### Moderate Optimization

```
OCR: Tesseract          $0.00
Embeddings (cached):    $0.30
Knowledge: Disabled     $0.00
Content (GPT-3.5):      $5.00
Images: Disabled        $0.00
---------------------------------
Total:                  $5.30
Savings: 91%
```

### Aggressive Optimization

```
OCR: Tesseract          $0.00
Embeddings: Disabled    $0.00
Knowledge: Disabled     $0.00
Content (Ollama local): $0.00
Images: Disabled        $0.00
---------------------------------
Total:                  $0.00
Savings: 100%
Quality: Lower
```

---

## Recommended Configuration

**Best Balance** (cost vs. quality):

```yaml
# Optimized for $10-15 per book, good quality

document_ingestion:
  ocr_provider: 'tesseract'  # Free

content_preparation:
  chunking:
    max_tokens: 550  # Balanced

knowledge_extraction:
  enabled: false  # Save $5

content_generation:
  model: 'gpt-3.5-turbo'  # Cheap
  use_cheaper_model_for_drafts: true
  polish_threshold: 0.85

images:
  generate_featured: false  # Save $2

performance:
  use_cache: true
  batch_api_calls: true
```

**Expected Cost**: $8-12 per book
**Expected Quality**: 85-90%

---

## ROI Analysis

### Manual Content Creation

- Time: 40-80 hours
- Rate: $50/hour
- Total: $2,000-4,000 per book

### Automated Pipeline (Baseline)

- Time: 2 hours (mostly waiting)
- API Cost: $50-60
- Labor: $100 (setup + review)
- Total: $150-160
- **Savings: $1,850-3,850 (92-96%)**

### Automated Pipeline (Optimized)

- Time: 2 hours
- API Cost: $10-15
- Labor: $100
- Total: $110-115
- **Savings: $1,890-3,890 (94-97%)**

---

## Tips & Best Practices

1. **Start Expensive**: Run first book with GPT-4 to baseline quality
2. **Optimize Gradually**: Reduce to GPT-3.5 and compare
3. **Test Locally**: Try free models (Ollama) for non-critical content
4. **Cache Everything**: Re-running costs almost nothing with cache
5. **Monitor Quality**: Don't sacrifice too much quality for cost
6. **Batch Similar Books**: Process multiple books in same topic for cache benefits
7. **Use Checkpoints**: Failed runs don't waste money if you can resume
8. **Review Costs**: Check OpenAI dashboard after each run

---

## Common Mistakes

**Mistake 1**: Using GPT-4 for everything
- **Impact**: 10x cost increase
- **Fix**: Use GPT-3.5-turbo for drafts

**Mistake 2**: Not caching
- **Impact**: Re-running costs full price
- **Fix**: Enable aggressive caching

**Mistake 3**: Too many small chunks
- **Impact**: Excessive API calls
- **Fix**: Use 500-600 token chunks

**Mistake 4**: Generating too many posts
- **Impact**: 2x cost for 50% more posts
- **Fix**: Target 30-50 posts, not 100+

**Mistake 5**: Running without budget tracking
- **Impact**: Cost overruns
- **Fix**: Set budget limits, monitor spending

---

## Summary

**Recommended Approach**:

1. **First Book**: Use baseline config, measure costs
2. **Second Book**: Enable optimizations, compare quality
3. **Third Book**: Fine-tune based on learnings

**Target Costs**:
- **High Quality**: $40-50/book (GPT-4)
- **Balanced**: $10-15/book (GPT-3.5 + optimizations)
- **Budget**: $5-8/book (aggressive optimizations)

**Best Practice**: Aim for **$10-15/book** sweet spot
- Good enough quality for professional use
- 95%+ cost savings vs. manual
- Sustainable for regular use
