---
name: batch-processing
description: "Production-ready batch processing framework for bulk operations with progress tracking, error recovery, and resumability. Use when: (1) Processing large datasets or file collections, (2) Bulk API operations with rate limiting, (3) Data migration and transformation, (4) Scheduled batch jobs, (5) Operations requiring retry and recovery. Triggers on 'batch processing', 'bulk operations', 'process multiple', 'batch job', or data processing at scale."
license: Proprietary
---

# Batch Processing Framework

Generic, production-ready framework for bulk operations with progress tracking, error recovery, and resumability.

## Quick Reference: Common Batch Operations

| Operation Type | Typical Batch Size | Key Concerns |
|----------------|-------------------|--------------|
| API Calls | 10-100 | Rate limits, retries |
| File Processing | 50-500 | Memory, I/O performance |
| Database Operations | 100-1000 | Transactions, deadlocks |
| WordPress Posts | 10-50 | API throttling, content validation |
| Email Sending | 50-200 | Deliverability, spam limits |
| Image Processing | 10-100 | CPU/memory, parallel processing |
| Data Migration | 500-5000 | Consistency, rollback capability |

---

# WHEN TO USE BATCH PROCESSING

## Ideal Use Cases

```
Use batch processing when:

✓ Processing >100 items
✓ Operations take >30 seconds total
✓ Risk of failures mid-process
✓ Need progress visibility
✓ Memory constraints prevent loading all at once
✓ Rate limits require throttling
✓ Need ability to pause/resume
✓ Operations can be parallelized
```

## Don't Use For

```
❌ Real-time user interactions
❌ <10 items
❌ Operations must be atomic (all-or-nothing)
❌ No failure tolerance
❌ Instant completion required
```

---

# CORE ARCHITECTURE

## Components

```
┌─────────────────────────────────────────┐
│         Batch Processor                 │
│  - Chunking strategy                    │
│  - Concurrency control                  │
│  - Progress tracking                    │
│  - Error handling                       │
└───────────┬─────────────────────────────┘
            │
            ├──► Progress Tracker
            │    - Current/total items
            │    - ETA calculation
            │    - Visual progress bar
            │
            ├──► Error Handler
            │    - Retry logic
            │    - Failed items tracking
            │    - Error categorization
            │
            ├──► Checkpoint Manager
            │    - Save state periodically
            │    - Resume from last checkpoint
            │    - Rollback capability
            │
            └──► Result Aggregator
                 - Success count
                 - Failure count
                 - Summary statistics
```

## Processing Flow

```
1. INITIALIZATION
   └─► Load items to process
   └─► Check for existing checkpoint
   └─► Resume from checkpoint or start fresh

2. CHUNKING
   └─► Split items into batches
   └─► Determine batch size (config or auto-tune)

3. PROCESSING LOOP
   For each batch:
   ├─► Process items (serial or parallel)
   ├─► Track success/failures
   ├─► Update progress bar
   ├─► Save checkpoint (every N batches)
   └─► Respect rate limits (sleep if needed)

4. ERROR HANDLING
   ├─► Retry failed items (with exponential backoff)
   ├─► Skip after max retries
   └─► Log failed items for manual review

5. FINALIZATION
   ├─► Generate summary report
   ├─► Save failed items to file
   ├─► Clean up checkpoints
   └─► Send completion notification
```

---

# IMPLEMENTATION

## Base Batch Processor

See `templates/batch_processor.py` for complete implementation.

```python
from typing import List, Callable, Any, Optional
from dataclasses import dataclass
import time
import json
from pathlib import Path

@dataclass
class BatchResult:
    total_items: int
    successful: int
    failed: int
    skipped: int
    duration_seconds: float
    failed_items: List[Any]

class BatchProcessor:
    """Generic batch processor with error recovery"""

    def __init__(
        self,
        batch_size: int = 100,
        max_retries: int = 3,
        checkpoint_interval: int = 10,
        checkpoint_file: Optional[str] = None
    ):
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.checkpoint_interval = checkpoint_interval
        self.checkpoint_file = checkpoint_file or ".batch_checkpoint.json"

    def process(
        self,
        items: List[Any],
        process_fn: Callable[[Any], bool],
        resume: bool = True
    ) -> BatchResult:
        """
        Process items in batches with error recovery.

        Args:
            items: List of items to process
            process_fn: Function to process each item (returns True on success)
            resume: Resume from checkpoint if exists

        Returns:
            BatchResult with statistics
        """
        start_time = time.time()

        # Load checkpoint
        processed_indices, failed_items = self._load_checkpoint() if resume else (set(), [])

        # Filter already processed
        remaining = [
            (i, item) for i, item in enumerate(items)
            if i not in processed_indices
        ]

        print(f"Processing {len(remaining)} items (already processed: {len(processed_indices)})")

        successful = len(processed_indices)
        skipped = 0

        # Process in batches
        for batch_num, batch_start in enumerate(range(0, len(remaining), self.batch_size)):
            batch = remaining[batch_start:batch_start + self.batch_size]

            print(f"\nBatch {batch_num + 1}/{(len(remaining) + self.batch_size - 1) // self.batch_size}")

            for idx, item in batch:
                success, should_skip = self._process_with_retry(item, process_fn)

                if success:
                    successful += 1
                    processed_indices.add(idx)
                elif should_skip:
                    skipped += 1
                    processed_indices.add(idx)
                else:
                    failed_items.append({'index': idx, 'item': item})

                # Progress
                self._show_progress(successful + skipped, len(items), start_time)

            # Checkpoint
            if (batch_num + 1) % self.checkpoint_interval == 0:
                self._save_checkpoint(processed_indices, failed_items)

        # Final results
        duration = time.time() - start_time
        result = BatchResult(
            total_items=len(items),
            successful=successful,
            failed=len(failed_items),
            skipped=skipped,
            duration_seconds=duration,
            failed_items=failed_items
        )

        # Cleanup
        self._cleanup_checkpoint()

        return result

    def _process_with_retry(self, item, process_fn) -> tuple[bool, bool]:
        """Process with retry logic. Returns (success, should_skip)"""
        for attempt in range(self.max_retries):
            try:
                success = process_fn(item)
                if success:
                    return True, False
                # Explicit failure, don't retry
                return False, True
            except Exception as e:
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"Failed after {self.max_retries} attempts: {e}")
                    return False, False

    def _show_progress(self, current, total, start_time):
        """Show progress bar"""
        percent = (current / total) * 100
        elapsed = time.time() - start_time
        rate = current / elapsed if elapsed > 0 else 0
        eta = (total - current) / rate if rate > 0 else 0

        bar_length = 40
        filled = int(bar_length * current / total)
        bar = '█' * filled + '░' * (bar_length - filled)

        print(f"\r{bar} {percent:.1f}% ({current}/{total}) | "
              f"{rate:.1f} items/sec | ETA: {eta:.0f}s", end='')

    def _save_checkpoint(self, processed_indices, failed_items):
        """Save checkpoint to file"""
        with open(self.checkpoint_file, 'w') as f:
            json.dump({
                'processed': list(processed_indices),
                'failed': failed_items
            }, f)

    def _load_checkpoint(self):
        """Load checkpoint from file"""
        if Path(self.checkpoint_file).exists():
            with open(self.checkpoint_file, 'r') as f:
                data = json.load(f)
                return set(data['processed']), data['failed']
        return set(), []

    def _cleanup_checkpoint(self):
        """Remove checkpoint file"""
        Path(self.checkpoint_file).unlink(missing_ok=True)
```

---

# ADVANCED PATTERNS

## Pattern 1: Parallel Processing

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

class ParallelBatchProcessor(BatchProcessor):
    """Batch processor with parallel execution"""

    def __init__(self, max_workers: int = 5, **kwargs):
        super().__init__(**kwargs)
        self.max_workers = max_workers

    def process_parallel(self, items, process_fn):
        """Process items in parallel"""

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(process_fn, item): (i, item)
                for i, item in enumerate(items)
            }

            for future in as_completed(futures):
                i, item = futures[future]
                try:
                    result = future.result()
                    # Handle result
                except Exception as e:
                    # Handle error
                    pass
```

## Pattern 2: Rate-Limited Processing

```python
import time
from datetime import datetime, timedelta

class RateLimitedBatchProcessor(BatchProcessor):
    """Batch processor with rate limiting"""

    def __init__(self, requests_per_second: int = 10, **kwargs):
        super().__init__(**kwargs)
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = None

    def _process_with_rate_limit(self, item, process_fn):
        """Enforce rate limit before processing"""

        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)

        result = self._process_with_retry(item, process_fn)
        self.last_request_time = time.time()

        return result
```

## Pattern 3: Memory-Efficient Streaming

```python
class StreamingBatchProcessor(BatchProcessor):
    """Process large datasets without loading all into memory"""

    def process_from_generator(self, item_generator, process_fn):
        """Process items from generator/iterator"""

        batch = []
        for item in item_generator:
            batch.append(item)

            if len(batch) >= self.batch_size:
                self._process_batch(batch, process_fn)
                batch = []

        # Process remaining
        if batch:
            self._process_batch(batch, process_fn)
```

---

# REAL-WORLD EXAMPLES

## Example 1: WordPress Bulk Post Creation

```python
# See examples/wordpress-batch.py

from batch_processor import BatchProcessor

def create_post(post_data):
    """Create WordPress post via API"""
    response = requests.post(
        f"{WP_URL}/wp-json/wp/v2/posts",
        headers={'Authorization': f'Bearer {WP_TOKEN}'},
        json=post_data
    )
    return response.status_code == 201

# Process 500 posts
processor = BatchProcessor(batch_size=10, max_retries=3)
result = processor.process(posts_data, create_post)

print(f"Created {result.successful} posts")
print(f"Failed: {result.failed}")
```

## Example 2: Translation Batch

```python
# See examples/translation-batch.py

from batch_processor import RateLimitedBatchProcessor

def translate_text(item):
    source_text, target_lang = item
    result = translation_api.translate(source_text, target_lang)
    return result.success

# Rate-limited to 10 requests/sec
processor = RateLimitedBatchProcessor(
    requests_per_second=10,
    batch_size=50
)

items = [(text, 'es') for text in texts_to_translate]
result = processor.process(items, translate_text)
```

## Example 3: Image Processing Pipeline

```python
# See examples/image-batch.py

from batch_processor import ParallelBatchProcessor

def process_image(image_path):
    """Resize, optimize, upload image"""
    img = Image.open(image_path)
    img = img.resize((800, 600))
    img.save(f"processed/{Path(image_path).name}", optimize=True)
    return True

# Parallel processing with 8 workers
processor = ParallelBatchProcessor(
    max_workers=8,
    batch_size=100
)

image_paths = glob.glob("images/*.jpg")
result = processor.process(image_paths, process_image)
```

---

# BEST PRACTICES

## 1. Choosing Batch Size

```python
# Small batches (10-50):
- High memory per item
- Expensive operations
- Frequent failures expected
- Need granular progress

# Medium batches (100-500):
- Standard API calls
- Database operations
- Most common use case

# Large batches (1000+):
- Cheap operations
- Minimal failure risk
- Bulk database inserts
```

## 2. Checkpoint Strategy

```python
# Checkpoint every N batches (not every item!)
# Balance: Too frequent = slow, Too rare = lost work

Small jobs (< 1000 items): No checkpoint needed
Medium jobs (1000-10000): Checkpoint every 10-20 batches
Large jobs (> 10000): Checkpoint every 5-10 batches
```

## 3. Error Handling

```python
# Categorize errors
RETRY_ERRORS = [TimeoutError, ConnectionError, 503]
SKIP_ERRORS = [ValidationError, 400, 404]
FATAL_ERRORS = [AuthenticationError, 401, 403]

# Handle accordingly
if error in RETRY_ERRORS:
    retry_with_backoff()
elif error in SKIP_ERRORS:
    log_and_skip()
else:
    raise  # Fatal, stop processing
```

## 4. Monitoring

```python
# Track key metrics
- Items processed per second
- Success rate
- Average processing time per item
- Memory usage
- Failed items list

# Alert on
- Success rate < 90%
- Processing rate drops >50%
- Memory usage > 80%
```

---

# FILE REFERENCES

- `templates/batch_processor.py` - Complete batch processor class
- `templates/progress_tracker.py` - Advanced progress tracking
- `templates/error_recovery.py` - Error handling patterns
- `checklists/performance-tuning.md` - Performance optimization guide
- `examples/wordpress-batch.py` - WordPress bulk operations
- `examples/translation-batch.py` - Translation pipeline
- `examples/image-batch.py` - Image processing
- `examples/database-migration.py` - Database batch operations
- `references/batch-size-guide.md` - Choosing optimal batch sizes
