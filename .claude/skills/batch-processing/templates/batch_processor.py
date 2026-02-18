"""
Production-Ready Batch Processor

Complete implementation with progress tracking, checkpointing, and error recovery.
"""

from typing import List, Callable, Any, Optional, Dict
from dataclasses import dataclass, asdict
import time
import json
from pathlib import Path
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BatchResult:
    """Results from batch processing"""
    total_items: int
    successful: int
    failed: int
    skipped: int
    duration_seconds: float
    failed_items: List[Dict[str, Any]]
    start_time: str
    end_time: str
    items_per_second: float

    def to_dict(self):
        return asdict(self)

    def summary(self) -> str:
        """Generate summary report"""
        success_rate = (self.successful / self.total_items * 100) if self.total_items > 0 else 0

        return f"""
Batch Processing Summary
========================
Total Items:     {self.total_items}
Successful:      {self.successful} ({success_rate:.1f}%)
Failed:          {self.failed}
Skipped:         {self.skipped}
Duration:        {self.duration_seconds:.1f}s
Throughput:      {self.items_per_second:.1f} items/sec
Started:         {self.start_time}
Completed:       {self.end_time}
        """.strip()


class BatchProcessor:
    """
    Generic batch processor with error recovery and progress tracking.

    Features:
    - Configurable batch size
    - Automatic retry with exponential backoff
    - Checkpoint/resume capability
    - Progress bar with ETA
    - Summary statistics
    """

    def __init__(
        self,
        batch_size: int = 100,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        checkpoint_interval: int = 10,
        checkpoint_dir: str = ".batch_checkpoints",
        show_progress: bool = True
    ):
        """
        Initialize batch processor.

        Args:
            batch_size: Number of items per batch
            max_retries: Maximum retry attempts per item
            retry_delay: Initial retry delay (exponential backoff)
            checkpoint_interval: Save checkpoint every N batches
            checkpoint_dir: Directory to store checkpoints
            show_progress: Show progress bar
        """
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.checkpoint_interval = checkpoint_interval
        self.checkpoint_dir = Path(checkpoint_dir)
        self.show_progress = show_progress

        # Create checkpoint directory
        self.checkpoint_dir.mkdir(exist_ok=True)

    def process(
        self,
        items: List[Any],
        process_fn: Callable[[Any], bool],
        job_id: Optional[str] = None,
        resume: bool = True
    ) -> BatchResult:
        """
        Process items in batches with error recovery.

        Args:
            items: List of items to process
            process_fn: Function to process each item (returns True on success)
            job_id: Unique job identifier (for checkpointing)
            resume: Resume from checkpoint if exists

        Returns:
            BatchResult with statistics
        """

        job_id = job_id or f"batch_{int(time.time())}"
        checkpoint_file = self.checkpoint_dir / f"{job_id}.json"

        start_time = time.time()
        start_time_str = datetime.now().isoformat()

        # Load checkpoint
        if resume and checkpoint_file.exists():
            processed_indices, failed_items = self._load_checkpoint(checkpoint_file)
            logger.info(f"Resuming from checkpoint: {len(processed_indices)} items already processed")
        else:
            processed_indices = set()
            failed_items = []

        # Filter already processed
        remaining = [
            (i, item) for i, item in enumerate(items)
            if i not in processed_indices
        ]

        successful = len(processed_indices)
        skipped = 0

        logger.info(f"Processing {len(remaining)} items in batches of {self.batch_size}")

        # Process in batches
        num_batches = (len(remaining) + self.batch_size - 1) // self.batch_size

        for batch_num in range(num_batches):
            batch_start = batch_num * self.batch_size
            batch_end = min(batch_start + self.batch_size, len(remaining))
            batch = remaining[batch_start:batch_end]

            logger.info(f"Batch {batch_num + 1}/{num_batches}: Processing {len(batch)} items")

            for idx, item in batch:
                success, should_skip = self._process_with_retry(item, process_fn)

                if success:
                    successful += 1
                    processed_indices.add(idx)
                elif should_skip:
                    skipped += 1
                    processed_indices.add(idx)
                else:
                    failed_items.append({
                        'index': idx,
                        'item': str(item)[:200],  # Truncate for logging
                        'timestamp': datetime.now().isoformat()
                    })

                # Progress
                if self.show_progress:
                    self._show_progress(
                        successful + skipped + len(failed_items),
                        len(items),
                        start_time
                    )

            # Checkpoint
            if (batch_num + 1) % self.checkpoint_interval == 0:
                self._save_checkpoint(checkpoint_file, processed_indices, failed_items)
                logger.info(f"Checkpoint saved: {len(processed_indices)} items processed")

        # Final newline after progress bar
        if self.show_progress:
            print()

        # Calculate statistics
        end_time = time.time()
        duration = end_time - start_time
        items_per_second = len(items) / duration if duration > 0 else 0

        result = BatchResult(
            total_items=len(items),
            successful=successful,
            failed=len(failed_items),
            skipped=skipped,
            duration_seconds=duration,
            failed_items=failed_items,
            start_time=start_time_str,
            end_time=datetime.now().isoformat(),
            items_per_second=items_per_second
        )

        # Cleanup checkpoint
        if checkpoint_file.exists():
            checkpoint_file.unlink()

        # Save failed items
        if failed_items:
            failed_file = self.checkpoint_dir / f"{job_id}_failed.json"
            with open(failed_file, 'w') as f:
                json.dump(failed_items, f, indent=2)
            logger.warning(f"Failed items saved to: {failed_file}")

        return result

    def _process_with_retry(
        self,
        item: Any,
        process_fn: Callable[[Any], bool]
    ) -> tuple[bool, bool]:
        """
        Process item with retry logic.

        Returns:
            (success, should_skip) tuple
        """

        for attempt in range(self.max_retries):
            try:
                result = process_fn(item)

                if result:
                    return True, False

                # Explicit failure (don't retry)
                return False, True

            except KeyboardInterrupt:
                raise

            except Exception as e:
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.warning(
                        f"Attempt {attempt + 1}/{self.max_retries} failed: {e}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                    time.sleep(delay)
                else:
                    logger.error(f"Failed after {self.max_retries} attempts: {e}")
                    return False, False

        return False, False

    def _show_progress(self, current: int, total: int, start_time: float):
        """Display progress bar with ETA"""

        percent = (current / total) * 100
        elapsed = time.time() - start_time
        rate = current / elapsed if elapsed > 0 else 0
        eta = (total - current) / rate if rate > 0 else 0

        # Progress bar
        bar_length = 40
        filled = int(bar_length * current / total)
        bar = '█' * filled + '░' * (bar_length - filled)

        # Format
        print(
            f"\r{bar} {percent:5.1f}% | "
            f"{current}/{total} | "
            f"{rate:.1f} items/s | "
            f"ETA: {eta:.0f}s",
            end='',
            flush=True
        )

    def _save_checkpoint(
        self,
        checkpoint_file: Path,
        processed_indices: set,
        failed_items: List[Dict]
    ):
        """Save checkpoint to file"""

        checkpoint_data = {
            'processed_indices': list(processed_indices),
            'failed_items': failed_items,
            'timestamp': datetime.now().isoformat()
        }

        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint_data, f, indent=2)

    def _load_checkpoint(self, checkpoint_file: Path) -> tuple[set, List[Dict]]:
        """Load checkpoint from file"""

        with open(checkpoint_file, 'r') as f:
            data = json.load(f)

        return set(data['processed_indices']), data['failed_items']


# Example usage
if __name__ == "__main__":
    # Example: Process list of URLs
    urls = [f"https://example.com/page{i}" for i in range(100)]

    def download_page(url: str) -> bool:
        """Simulate downloading a page"""
        import random

        # Simulate processing time
        time.sleep(0.1)

        # Simulate random failures (10% failure rate)
        if random.random() < 0.1:
            raise Exception("Download failed")

        return True

    # Process with batch processor
    processor = BatchProcessor(
        batch_size=10,
        max_retries=3,
        checkpoint_interval=5
    )

    result = processor.process(
        urls,
        download_page,
        job_id="url_download"
    )

    print(result.summary())
