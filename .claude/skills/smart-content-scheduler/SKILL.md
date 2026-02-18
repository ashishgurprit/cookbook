# Smart Content Scheduler

> Intelligent category-based content scheduling with N-day interval publishing, randomized timing, multi-site coordination, and queue management. Designed for automated content pipelines that publish across many categories while maintaining natural distribution patterns.

## Module Dependencies

```
+---------------------------+
| smart-content-scheduler   |
+---------------------------+
            |
    +-------+-------+------------------+------------------+
    |               |                  |                  |
    v               v                  v                  v
+----------+  +-----------+  +------------------+  +-------------+
| scheduling|  | wordpress |  | content-pipeline |  | database-   |
| framework |  | publisher |  | orchestrator     |  | orm-patterns|
+----------+  +-----------+  +------------------+  +-------------+
    |               |                  |                  |
    v               v                  v                  v
 cron jobs     WP REST API      state machine       schedule/queue
 health checks post creation    CREATED->PUBLISHED  storage & queries
 notifications media upload     pipeline stages     row locking
               SEO/tags                              priority sorting
    |
    v
+------------------+
| social-media-    |
| client           |
+------------------+
    |
    v
 post to social
 after publish
```

**Required modules:**

| Module | Purpose |
|--------|---------|
| `scheduling-framework` | Cron job management, health checks, notification dispatch |
| `wordpress-publisher` | WordPress REST API publishing, media upload, category/tag management |
| `content-pipeline-orchestrator` | Pipeline state machine (CREATED -> QUEUED -> PUBLISHED) |
| `database-orm-patterns` | ORM models for Job, JobContent, queue storage, row locking |
| `social-media-client` | Social media posting after successful publish |

---

## Quick Start

### 1. Minimal Category-Based Scheduler

```python
import os
import random
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from threading import Thread, Event

logger = logging.getLogger(__name__)

# Configuration from environment
PUBLISH_INTERVAL_DAYS = int(os.getenv('SCHEDULER_PUBLISH_INTERVAL_DAYS', '3'))
MIN_GAP_HOURS = float(os.getenv('SCHEDULER_MIN_GAP_HOURS', '7'))
CHECK_INTERVAL_MINUTES = int(os.getenv('SCHEDULER_CHECK_INTERVAL', '10'))


class SmartScheduler:
    """
    Category-based scheduler with N-day intervals.

    Each category publishes once every N days at a random time,
    with minimum gap enforcement from its previous post.

    Example: 20 categories at 3-day intervals = ~6-7 posts per day.
    """

    def __init__(self):
        self._stop_event = Event()
        self._worker_thread: Optional[Thread] = None
        self._last_publish: Dict[str, datetime] = {}
        self._published_this_interval: Dict[str, str] = {}
        self._current_interval: Optional[str] = None

    def start(self):
        """Start scheduler in background thread."""
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self._stop_event.clear()
        self._worker_thread = Thread(target=self.run_continuous, daemon=True)
        self._worker_thread.start()

    def stop(self):
        """Stop scheduler gracefully."""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=10)

    def run_continuous(self):
        """Main scheduler loop."""
        self._last_publish = self.get_last_publish_time_per_category()
        while not self._stop_event.is_set():
            self.run_check()
            self._stop_event.wait(CHECK_INTERVAL_MINUTES * 60)
```

### 2. Wire It Up

```python
# In your main application entry point
scheduler = SmartScheduler()
scheduler.start()

# On shutdown
scheduler.stop()
```

### 3. Run from CLI

```bash
# Check scheduler status
python smart_scheduler.py status

# Run a single scheduling check
python smart_scheduler.py check

# Run continuously
python smart_scheduler.py run
```

---

## Category-Based Scheduling Engine

The core innovation of this scheduler is **per-category independent scheduling**. Instead of scheduling posts globally (e.g., "6 posts per day"), each category maintains its own N-day publishing cadence. This produces natural, evenly distributed content across all categories without manual coordination.

### Interval Windows

Categories are grouped into N-day interval windows. Each category publishes exactly once per window.

```python
def _get_interval_key(self, dt: datetime = None) -> str:
    """
    Create an interval key for grouping days into N-day windows.

    Uses day-of-year divided by interval length to create stable
    window boundaries. All datetimes within the same window
    produce the same key.

    Args:
        dt: Datetime to compute interval for. Defaults to UTC now.

    Returns:
        String key like "2026-15" (year-interval_number)
    """
    if dt is None:
        dt = datetime.utcnow()
    day_of_year = dt.timetuple().tm_yday
    interval_num = day_of_year // PUBLISH_INTERVAL_DAYS
    return f"{dt.year}-{interval_num}"


def _reset_interval_tracking(self):
    """
    Detect interval boundary crossings and reset tracking.

    Called at the start of each scheduling check. When a new
    interval begins, all categories become eligible to publish
    again.
    """
    current_interval = self._get_interval_key()
    if self._current_interval != current_interval:
        logger.info(f"New interval: {current_interval} (every {PUBLISH_INTERVAL_DAYS} days)")
        self._published_this_interval = {}
        self._current_interval = current_interval
```

### Eligibility Checks

A category can publish only when ALL of these conditions are met:

1. **Not already published this interval** -- prevents double-publishing within the same N-day window
2. **Minimum gap hours elapsed** -- safety buffer preventing posts too close together (e.g., 7 hours)
3. **Full interval days elapsed** -- at least N days since the category's last post
4. **No active delay** -- category is not temporarily deprioritized

```python
def can_publish_category(self, category: str) -> bool:
    """
    Check if a category is eligible to publish now.

    Enforces three constraints:
    1. Category delay (temporary deprioritization)
    2. Interval tracking (one post per N-day window)
    3. Minimum gap from last publish (hours-based safety buffer)

    Args:
        category: Category/brand identifier (e.g., "TECH", "LIFESTYLE")

    Returns:
        True if the category may publish in this check cycle
    """
    now = datetime.utcnow()

    # Check category-specific delay (deprioritization)
    delay_days = self.category_delays.get(category.upper(), 0)
    if delay_days > 0:
        delay_end = self._delay_start_time + timedelta(days=delay_days)
        if now < delay_end:
            return False

    # Already published in this interval window?
    if self._published_this_interval.get(category) == self._current_interval:
        return False

    # Check minimum gap from last publish
    last_time = self._last_publish.get(category)
    if last_time:
        hours_since = (now - last_time).total_seconds() / 3600
        if hours_since < MIN_GAP_HOURS:
            return False
        days_since = hours_since / 24
        if days_since < PUBLISH_INTERVAL_DAYS:
            return False

    return True
```

### Randomized Publish Timing

Rather than publishing at fixed times, the scheduler uses probability-based timing. Each check cycle rolls a random number against a probability that increases as the interval window approaches its end. This creates natural, unpredictable publish times while guaranteeing each category publishes within its window.

```python
def should_publish_now(self, category: str) -> bool:
    """
    Determine if category should publish NOW using randomized probability.

    The probability increases as the interval window closes:
    - Early in interval: low probability (natural randomness)
    - Late in interval: high probability (ensure publication)
    - Last hour: 100% (mandatory publish)

    This creates organic-looking publish patterns that are
    indistinguishable from manual scheduling.

    Args:
        category: Category identifier

    Returns:
        True if this category should publish in this check cycle
    """
    if not self.can_publish_category(category):
        return False

    now = datetime.utcnow()

    # Calculate hours remaining in current interval
    hours_left_today = 24 - now.hour - (now.minute / 60)
    day_in_interval = now.timetuple().tm_yday % PUBLISH_INTERVAL_DAYS
    days_left = PUBLISH_INTERVAL_DAYS - day_in_interval - 1
    hours_left = (days_left * 24) + hours_left_today

    if hours_left <= 1:
        return True  # Must publish -- last hour of interval

    # Increasing probability as deadline approaches
    # Scale factor of 3.0 ensures reasonable publish rates
    # with 10-minute check intervals
    base_probability = 1 / max(hours_left, 1)
    adjusted_probability = base_probability * 3.0

    return random.random() < adjusted_probability
```

**Probability table (3-day interval, 10-minute checks):**

| Hours Remaining | Probability per Check | Expected Checks to Publish |
|-----------------|----------------------|---------------------------|
| 72 (start) | ~4.2% | ~24 checks (~4 hours) |
| 36 (midpoint) | ~8.3% | ~12 checks (~2 hours) |
| 12 (day 3) | ~25% | ~4 checks (~40 min) |
| 1 (last hour) | 100% | 1 check (immediate) |

### Main Scheduling Loop

```python
def run_check(self):
    """
    Execute one scheduling check cycle.

    Steps:
    1. Detect interval boundary crossings
    2. Fetch all pending jobs grouped by category
    3. Shuffle categories for fairness
    4. Evaluate each category for publish eligibility
    5. Process at most ONE publish per check cycle
       (prevents burst publishing)
    """
    self._reset_interval_tracking()

    # Get all QUEUED jobs grouped by category
    pending = self.get_pending_jobs_by_category()
    if not pending:
        return

    # Shuffle for fairness -- no category gets systematic priority
    categories = list(pending.keys())
    random.shuffle(categories)

    for category in categories:
        if self._published_this_interval.get(category) == self._current_interval:
            continue

        if self.should_publish_now(category):
            jobs = pending.get(category, [])
            if jobs:
                self.process_category(category, jobs)
                break  # Only process one per check cycle
```

### Category Delay (Deprioritization)

Categories can be temporarily delayed to rebalance content distribution. This is useful when one category has been over-published relative to others.

```python
import json

# Environment variable: JSON string mapping category names to delay days
# Example: '{"TECH": 5, "NEWS": 3}'
CATEGORY_DELAYS_JSON = os.getenv('SCHEDULER_CATEGORY_DELAYS', '{}')
try:
    CATEGORY_DELAYS = json.loads(CATEGORY_DELAYS_JSON)
except json.JSONDecodeError:
    CATEGORY_DELAYS = {}
```

Usage:
```bash
# Delay the TECH category by 5 days from scheduler start
export SCHEDULER_CATEGORY_DELAYS='{"TECH": 5}'

# Delay multiple categories
export SCHEDULER_CATEGORY_DELAYS='{"TECH": 5, "NEWS": 3, "SPORTS": 2}'
```

---

## Multi-Site Publishing Coordination

When publishing to multiple WordPress sites or across multiple brands, the scheduler coordinates through configuration-driven rules and brand rotation.

### Brand Configuration

```python
from dataclasses import dataclass
from typing import Optional
import pytz


@dataclass
class ScheduleSlot:
    """A scheduled publishing slot for multi-site coordination."""
    slot_id: str
    scheduled_time: datetime
    category: Optional[str] = None
    item_id: Optional[str] = None
    status: str = "open"  # open, assigned, published, failed


class MultiSiteScheduler:
    """
    Manages cross-site content publishing schedule.

    Features:
    - Rule-based auto-scheduling with configurable posting times
    - Brand/category rotation and balancing
    - Timezone-aware scheduling per site
    - Blackout dates and allowed days filtering
    """

    def __init__(self, config_path: str = "scheduler/config"):
        self.rules = self._load_rules(config_path)
        self.brands = self._load_brands(config_path)
        self.timezone = pytz.timezone(
            self.rules.get("timezone", "America/New_York")
        )

    def _load_rules(self, config_path: str) -> dict:
        """
        Load scheduling rules. Falls back to sensible defaults.

        Rules include:
        - posts_per_day: Target number of posts per day
        - min_gap_hours: Minimum hours between any two posts
        - posting_times: Fixed daily time slots (e.g., ["06:00", "12:00", "18:00"])
        - timezone: IANA timezone for scheduling
        - brand_rotation: Strategy ("round_robin" or "weighted")
        - allowed_days: Days of week to publish (empty = all days)
        - blackout_dates: ISO dates to skip (holidays, maintenance)
        """
        rules_file = Path(config_path) / "rules.json"
        if rules_file.exists():
            with open(rules_file) as f:
                return json.load(f)
        return {
            "posts_per_day": 6,
            "min_gap_hours": 3,
            "posting_times": [
                "06:00", "09:00", "12:00",
                "15:00", "18:00", "21:00"
            ],
            "timezone": "America/New_York",
            "brand_rotation": "round_robin",
            "allowed_days": [],
            "blackout_dates": [],
            "max_queue_lookahead_days": 7
        }
```

### Slot Generation with Filtering

```python
def get_schedule(self, days: int = 7) -> List[ScheduleSlot]:
    """
    Generate available publishing slots for the next N days.

    Filters out:
    - Past time slots (for today)
    - Blackout dates
    - Non-allowed days of week

    Args:
        days: Number of days to generate slots for

    Returns:
        List of ScheduleSlot objects sorted chronologically
    """
    slots = []
    now = datetime.now(self.timezone)
    posting_times = self.rules.get("posting_times", [])
    allowed_days = [d.lower() for d in self.rules.get("allowed_days", [])]
    blackout_dates = self.rules.get("blackout_dates", [])

    for day_offset in range(days):
        date = now.date() + timedelta(days=day_offset)
        day_name = date.strftime("%A").lower()

        # Skip non-allowed days
        if allowed_days and day_name not in allowed_days:
            continue

        # Skip blackout dates
        if date.isoformat() in blackout_dates:
            continue

        for time_str in posting_times:
            hour, minute = map(int, time_str.split(":"))
            slot_time = self.timezone.localize(
                datetime.combine(
                    date,
                    datetime.min.time().replace(hour=hour, minute=minute)
                )
            )

            # Skip past times for today
            if slot_time <= now:
                continue

            slot_id = f"{date.isoformat()}_{time_str.replace(':', '')}"
            slots.append(ScheduleSlot(
                slot_id=slot_id,
                scheduled_time=slot_time
            ))

    return slots
```

### Round-Robin Brand Assignment

```python
def assign_items_to_slots(
    self,
    items: List[dict],
    slots: List[ScheduleSlot],
    balance_brands: bool = True
) -> List[ScheduleSlot]:
    """
    Assign queue items to available schedule slots.

    Two strategies:
    1. Round-robin (balance_brands=True): Distributes items evenly
       across categories/brands. Cycles through categories so no
       single category dominates consecutive slots.
    2. Sequential (balance_brands=False): Assigns items in priority
       order without category balancing.

    Args:
        items: Queue items sorted by priority (desc) then created_at (asc)
        slots: Available time slots
        balance_brands: Whether to balance across categories

    Returns:
        Slots with assigned items
    """
    if not items or not slots:
        return slots

    if balance_brands:
        # Group items by category
        by_category = {}
        for item in items:
            cat = item.get("category", "UNKNOWN")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(item)

        # Round-robin assignment across categories
        categories = list(by_category.keys())
        idx = 0

        for slot in slots:
            if not any(by_category.values()):
                break

            attempts = 0
            while attempts < len(categories):
                cat = categories[idx % len(categories)]
                if by_category.get(cat):
                    item = by_category[cat].pop(0)
                    slot.category = cat
                    slot.item_id = item.get("item_id")
                    slot.status = "assigned"
                    break
                idx += 1
                attempts += 1
            idx += 1
    else:
        for slot, item in zip(slots, items):
            slot.category = item.get("category")
            slot.item_id = item.get("item_id")
            slot.status = "assigned"

    return slots
```

### Publish Window Detection

```python
def get_next_publish_slot(self) -> Optional[ScheduleSlot]:
    """
    Find the next slot that is within its publish window.

    A slot is publishable when the current time falls within:
    - Up to 1 minute after the scheduled time (allow slight delay)
    - Up to 5 minutes before the scheduled time (early publish OK)

    This 6-minute window accommodates check interval timing
    without missing slots.

    Returns:
        The next publishable slot, or None
    """
    schedule = self.get_schedule(days=1)
    now = datetime.now(self.timezone)

    for slot in schedule:
        time_diff = (slot.scheduled_time - now).total_seconds()
        if -60 <= time_diff <= 300:
            return slot

    return None
```

---

## Timezone Handling Patterns

Timezone handling is critical when coordinating between UTC-based scheduling logic and WordPress sites configured for specific timezones.

### The WordPress Timezone Problem

WordPress returns post dates in the site's configured timezone but labels them as if they were UTC. This creates a systematic offset that must be corrected.

```python
# WordPress timezone offset from UTC
# Example: 11 for Australia/Sydney, -5 for America/New_York
WP_TIMEZONE_OFFSET_HOURS = int(os.getenv('WP_TIMEZONE_OFFSET_HOURS', '0'))


def get_last_publish_time_per_category(self) -> Dict[str, datetime]:
    """
    Fetch last publish time for each category from WordPress.

    CRITICAL: WordPress returns dates in site-local timezone but
    without timezone info. We must manually subtract the offset
    to convert to UTC for consistent scheduling comparisons.

    The conversion formula:
        utc_time = wordpress_local_time - timedelta(hours=WP_TIMEZONE_OFFSET_HOURS)

    Example:
        WordPress returns: 2026-02-16T14:00:00 (AEDT, UTC+11)
        Actual UTC time:   2026-02-16T03:00:00
        Offset applied:    14:00 - 11 hours = 03:00 UTC

    Returns:
        Dict mapping category name (uppercase) to last publish
        datetime in UTC
    """
    import requests

    wp_url = os.getenv('WP_SITE_URL', '').rstrip('/')
    wp_user = os.getenv('WP_USERNAME', '')
    wp_pass = os.getenv('WP_APP_PASSWORD', '')

    # Fetch recent posts
    response = requests.get(
        f'{wp_url}/wp-json/wp/v2/posts',
        auth=(wp_user, wp_pass),
        params={'per_page': 50, 'orderby': 'date', 'order': 'desc'},
        timeout=30
    )

    if response.status_code != 200:
        return {}

    posts = response.json()

    # Build category ID -> name mapping
    cat_response = requests.get(
        f'{wp_url}/wp-json/wp/v2/categories',
        auth=(wp_user, wp_pass),
        params={'per_page': 50},
        timeout=30
    )

    cat_map = {}
    if cat_response.status_code == 200:
        for cat in cat_response.json():
            cat_map[cat['id']] = cat['name'].upper()

    # Find most recent post per category with timezone correction
    last_publish = {}
    for post in posts:
        # Parse WordPress date (site's local timezone, no TZ info)
        date_str = post['date'].replace('Z', '').split('+')[0]
        post_date_local = datetime.fromisoformat(date_str)

        # Convert to UTC by subtracting the timezone offset
        post_date_utc = post_date_local - timedelta(
            hours=WP_TIMEZONE_OFFSET_HOURS
        )

        for cat_id in post.get('categories', []):
            cat_name = cat_map.get(cat_id, 'UNKNOWN')
            if cat_name not in last_publish:
                last_publish[cat_name] = post_date_utc

    return last_publish
```

### Timezone-Aware Slot Generation

For multi-site scheduling where each site has its own timezone, slots must be generated in the site's local timezone and compared against the current time in that timezone.

```python
import pytz

def generate_slots_for_site(
    site_timezone: str,
    posting_times: List[str],
    days: int = 7
) -> List[dict]:
    """
    Generate publishing slots in a specific site's timezone.

    Args:
        site_timezone: IANA timezone (e.g., "America/New_York")
        posting_times: List of "HH:MM" strings
        days: Number of days to generate

    Returns:
        List of slot dicts with UTC and local times
    """
    tz = pytz.timezone(site_timezone)
    now_local = datetime.now(tz)
    slots = []

    for day_offset in range(days):
        date = now_local.date() + timedelta(days=day_offset)
        for time_str in posting_times:
            hour, minute = map(int, time_str.split(":"))
            local_time = tz.localize(
                datetime.combine(
                    date,
                    datetime.min.time().replace(
                        hour=hour, minute=minute
                    )
                )
            )

            if local_time <= now_local:
                continue

            slots.append({
                "local_time": local_time.isoformat(),
                "utc_time": local_time.astimezone(pytz.utc).isoformat(),
                "timezone": site_timezone,
                "slot_id": f"{date.isoformat()}_{time_str.replace(':', '')}"
            })

    return slots
```

### Backdating Support

Some publishing workflows require setting custom publish dates (e.g., filling historical content gaps).

```python
def publish_with_custom_date(
    publisher,
    content: dict,
    category: str,
    publish_date: str,
    status: str = "publish"
) -> dict:
    """
    Publish content with a specific date (backdating).

    WordPress accepts ISO 8601 dates in the 'date' field.
    When backdating, the post appears in the archive at
    the specified date rather than the current date.

    Args:
        publisher: WordPress publisher instance
        content: Content data dict
        category: Category slug
        publish_date: ISO 8601 datetime string
                      (e.g., "2025-10-15T10:00:00")
        status: Post status ("publish", "draft", "pending")

    Returns:
        Publish result dict
    """
    post_data = {
        "title": content.get("title", "Untitled"),
        "content": content.get("html", ""),
        "status": status,
        "categories": [category],
        "date": publish_date  # WordPress accepts ISO 8601
    }

    return publisher.create_post(post_data)
```

---

## Queue Management

The queue system bridges the content pipeline (which produces content) and the scheduler (which publishes content). It uses database-backed storage with row-level locking for concurrent worker safety.

### Queue Retrieval with Category Grouping

```python
def get_pending_jobs_by_category(self) -> Dict[str, List[dict]]:
    """
    Fetch all QUEUED jobs grouped by category.

    Returns jobs in FIFO order within each category, enabling
    the scheduler to pick the oldest content first.

    Uses the database ORM pattern:
        SELECT * FROM jobs
        WHERE status = 'QUEUED'
        ORDER BY created_at ASC

    Returns:
        Dict mapping category name to list of job dicts,
        e.g., {"TECH": [{job1}, {job2}], "NEWS": [{job3}]}
    """
    from database.db import DatabaseSession
    from database.models import Job

    with DatabaseSession() as db:
        jobs = db.query(Job).filter(
            Job.status == 'QUEUED'
        ).order_by(Job.created_at.asc()).all()

        by_category = {}
        for job in jobs:
            cat = job.category or 'UNKNOWN'
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(job.to_dict())

        return by_category
```

### Priority-Based Queue with Database Locking

For concurrent workers (e.g., multiple Railway containers), use database-level row locking to prevent race conditions.

```python
def claim_jobs_for_processing(
    self,
    limit: int = 1,
    delayed_categories: List[str] = None
) -> List[dict]:
    """
    Atomically claim jobs for processing using FOR UPDATE SKIP LOCKED.

    This prevents race conditions when multiple workers compete:
    - Worker A locks row 1 -> Worker B skips row 1, takes row 2
    - If Worker A crashes, lock releases automatically

    Priority logic:
    1. Categories with < MIN_QUEUE_SIZE queued jobs get priority
    2. Delayed categories are excluded entirely
    3. Within priority group, oldest jobs first (FIFO)

    Args:
        limit: Maximum jobs to claim
        delayed_categories: Categories to skip (deprioritized)

    Returns:
        List of claimed job dicts (status already set to PROCESSING)
    """
    from database.db import DatabaseSession
    from database.models import Job
    from sqlalchemy import func

    delayed = [c.upper() for c in (delayed_categories or [])]
    MIN_QUEUE_SIZE = 2

    with DatabaseSession() as db:
        # Count QUEUED jobs per category
        queue_counts = db.query(
            Job.category,
            func.count(Job.job_id).label('count')
        ).filter(
            Job.status == 'QUEUED'
        ).group_by(Job.category).all()

        queued_by_cat = {row.category: row.count for row in queue_counts}

        # Find categories needing more queued jobs
        categories_needing = []
        created_cats = db.query(
            Job.category
        ).filter(
            Job.status == 'CREATED'
        ).distinct().all()

        for (cat,) in created_cats:
            if cat and cat.upper() not in delayed:
                if queued_by_cat.get(cat, 0) < MIN_QUEUE_SIZE:
                    categories_needing.append(cat)

        # Query with row locking
        query = db.query(Job).filter(Job.status == 'CREATED')

        if categories_needing:
            query = query.filter(Job.category.in_(categories_needing))
        elif delayed:
            query = query.filter(~Job.category.in_(delayed))

        jobs = query.order_by(
            Job.created_at.asc()
        ).limit(limit).with_for_update(skip_locked=True).all()

        # Mark as PROCESSING atomically
        claimed = []
        for job in jobs:
            job.status = 'PROCESSING'
            job.assigned_to = self.worker_id
            job.updated_at = datetime.utcnow()
            claimed.append(job.to_dict())

        db.commit()

    return claimed
```

### Content Validation Before Publish

Always validate content before publishing to prevent error posts, incomplete content, or quality issues from reaching production.

```python
def process_category(self, category: str, jobs: List[dict]) -> bool:
    """
    Publish one QUEUED job for a category.

    Critical flow:
    1. Load content from database
    2. VALIDATE content quality (reject if invalid)
    3. Load pre-uploaded media assets
    4. Publish to WordPress via publisher module
    5. Update job status to PUBLISHED on success
    6. Update interval tracking

    Args:
        category: Category being published
        jobs: List of available jobs (takes first/oldest)

    Returns:
        True if publish succeeded
    """
    if not jobs:
        return False

    job = jobs[0]  # FIFO -- oldest first
    job_id = job.get('job_id')

    from database.db import DatabaseSession
    from database.models import Job, JobContent

    with DatabaseSession() as db:
        # Load content
        content_row = db.query(JobContent).filter(
            JobContent.job_id == job_id,
            JobContent.content_type == 'article'
        ).first()

        if not content_row or not content_row.content:
            logger.error(f"No content found for {job_id}")
            return False

        content_data = content_row.content

        # VALIDATE before publishing
        from validators import ContentValidator
        is_valid, errors = ContentValidator.validate(content_data)
        if not is_valid:
            logger.error(f"Validation failed for {job_id}: {errors}")
            db_job = db.query(Job).filter(Job.job_id == job_id).first()
            if db_job:
                db_job.status = 'FAILED'
                db_job.error_message = f"Validation: {'; '.join(errors)}"
                db_job.updated_at = datetime.utcnow()
                db.commit()
            return False

        # Load pre-uploaded media if available
        media_row = db.query(JobContent).filter(
            JobContent.job_id == job_id,
            JobContent.content_type == 'media'
        ).first()
        uploaded_media = []
        if media_row and media_row.content:
            uploaded_media = media_row.content.get('uploaded_items', [])

        # Publish via wordpress-publisher module
        publisher = get_publisher()
        result = publisher.publish(
            content_data, category, uploaded_media
        )

        if result.get('success'):
            db_job = db.query(Job).filter(Job.job_id == job_id).first()
            if db_job:
                db_job.status = 'PUBLISHED'
                db_job.updated_at = datetime.utcnow()
                db.commit()

            # Update scheduler tracking
            self._published_this_interval[category] = self._current_interval
            self._last_publish[category] = datetime.utcnow()
            logger.info(f"Published {category}: {result.get('url')}")
            return True
        else:
            logger.error(f"Publish failed: {result.get('error')}")
            return False
```

### Duplicate Detection

Before processing content through the pipeline, check for duplicates against already-published posts to prevent redundant content.

```python
import re
import requests
from datetime import datetime, timedelta


class DuplicateChecker:
    """
    Check for duplicates against published posts on the target site.

    Uses normalized title comparison with periodic cache refresh.
    """

    def __init__(self, site_url: str, auth: tuple):
        self.site_url = site_url.rstrip('/')
        self.auth = auth
        self._published_titles: set = set()
        self._last_refresh = None
        self._refresh_interval = 300  # seconds

    def _normalize_title(self, title: str) -> str:
        """Strip all non-alphanumeric characters and lowercase."""
        return re.sub(r'[^a-z0-9]', '', title.lower())

    def refresh(self) -> int:
        """
        Fetch all published post titles from the site.

        Paginates through all posts to build a complete set
        of normalized titles for comparison.

        Returns:
            Number of known published titles
        """
        if (self._last_refresh and
            datetime.now() - self._last_refresh < timedelta(
                seconds=self._refresh_interval
            )):
            return len(self._published_titles)

        self._published_titles.clear()
        page = 1

        while True:
            response = requests.get(
                f'{self.site_url}/wp-json/wp/v2/posts',
                auth=self.auth,
                params={
                    'per_page': 100,
                    'page': page,
                    '_fields': 'title'
                },
                timeout=30
            )

            if response.status_code != 200:
                break

            posts = response.json()
            if not posts:
                break

            for post in posts:
                title = post.get('title', {}).get('rendered', '')
                normalized = self._normalize_title(title)
                if len(normalized) > 5:
                    self._published_titles.add(normalized)

            page += 1

        self._last_refresh = datetime.now()
        return len(self._published_titles)

    def is_duplicate(self, title: str) -> bool:
        """Check if a title matches any published post."""
        self.refresh()
        return self._normalize_title(title) in self._published_titles
```

### Auto-Replenishment

When the content queue runs low, automatically trigger ingestion to maintain a minimum buffer of content per category.

```python
# Configuration
MIN_CREATED_PER_CATEGORY = int(os.getenv('MIN_CREATED_PER_CATEGORY', '5'))
REPLENISH_CHECK_INTERVAL = int(os.getenv('REPLENISH_CHECK_INTERVAL', '3600'))
AUTO_REPLENISH_ENABLED = os.getenv('AUTO_REPLENISH_ENABLED', 'true').lower() == 'true'


def ensure_queue_filled(self) -> Dict[str, int]:
    """
    Auto-replenish: Ensure each category has minimum CREATED jobs.

    Runs periodically (default: every hour). For categories below
    the threshold, triggers content ingestion to refill the pipeline.

    Skips delayed/deprioritized categories.

    Returns:
        Dict of {category: jobs_ingested}
    """
    if not AUTO_REPLENISH_ENABLED:
        return {}

    created_counts = self._get_created_counts_by_category()
    all_categories = self._get_all_categories()
    results = {}

    # Sort by count ascending -- emptiest categories first
    needing = [
        (cat, created_counts.get(cat, 0))
        for cat in all_categories
        if cat.upper() not in self.delayed_categories
        and created_counts.get(cat, 0) < MIN_CREATED_PER_CATEGORY
    ]
    needing.sort(key=lambda x: x[1])

    for category, count in needing[:5]:  # Limit to 5 per cycle
        needed = MIN_CREATED_PER_CATEGORY - count
        ingested = self._trigger_ingest(category, needed)
        results[category] = ingested
        time.sleep(5)  # Rate limit between ingestion calls

    return results
```

---

## Notification Integration

The scheduler integrates with a multi-backend notification service for alerting on failures, quota exhaustion, and operational events.

### Notification Service Pattern

```python
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Alert data structure."""
    title: str
    message: str
    level: AlertLevel = AlertLevel.ERROR
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class NotificationService:
    """
    Multi-backend notification service.

    Supports: SMTP, SendGrid, Slack webhooks, Discord webhooks.
    Auto-discovers configured backends from environment variables.
    Sends alerts to ALL configured backends simultaneously.

    Usage:
        service = NotificationService()
        service.send_alert(Alert(
            title="Scheduler Error",
            message="Failed to publish TECH category",
            level=AlertLevel.ERROR,
            details={"category": "TECH", "error": "HTTP 500"}
        ))
    """

    def __init__(self):
        self.backends = []
        self._configure_backends()

    def _configure_backends(self):
        """Auto-discover configured notification backends."""
        # SMTP
        if os.getenv("SMTP_HOST"):
            self.backends.append(("smtp", {
                "host": os.getenv("SMTP_HOST"),
                "port": int(os.getenv("SMTP_PORT", "587")),
                "user": os.getenv("SMTP_USER"),
                "password": os.getenv("SMTP_PASSWORD"),
                "to_email": os.getenv("ALERT_EMAIL"),
                "from_email": os.getenv("SMTP_FROM", os.getenv("SMTP_USER"))
            }))

        # SendGrid
        if os.getenv("SENDGRID_API_KEY"):
            self.backends.append(("sendgrid", {
                "api_key": os.getenv("SENDGRID_API_KEY"),
                "to_email": os.getenv("ALERT_EMAIL"),
                "from_email": os.getenv("SENDGRID_FROM", "alerts@example.com")
            }))

        # Slack
        if os.getenv("SLACK_WEBHOOK_URL"):
            self.backends.append(("slack", {
                "webhook_url": os.getenv("SLACK_WEBHOOK_URL")
            }))

        # Discord
        if os.getenv("DISCORD_WEBHOOK_URL"):
            self.backends.append(("discord", {
                "webhook_url": os.getenv("DISCORD_WEBHOOK_URL")
            }))

    def send_alert(self, alert: Alert) -> Dict[str, Any]:
        """Send alert to all configured backends."""
        results = {}
        for backend_name, config in self.backends:
            try:
                getattr(self, f"_send_{backend_name}")(alert, config)
                results[backend_name] = {"success": True}
            except Exception as e:
                results[backend_name] = {"success": False, "error": str(e)}

        return {
            "success": any(r.get("success") for r in results.values()),
            "results": results
        }
```

### Pre-Defined Alert Functions

Create convenience functions for common scheduler alert scenarios:

```python
def alert_quota_exhausted(service_name: str, details: dict = None):
    """Alert when an API quota is exhausted (e.g., OpenAI, image gen)."""
    return send_alert(
        title=f"{service_name} Quota Exhausted",
        message=f"The {service_name} API quota has been exhausted. "
                f"Pipeline processing is paused until quota refills.",
        level=AlertLevel.CRITICAL,
        details=details
    )


def alert_job_failed(job_id: str, error: str, category: str = None):
    """Alert for individual job processing failure."""
    return send_alert(
        title="Job Processing Failed",
        message=f"Job {job_id} failed during processing.",
        level=AlertLevel.ERROR,
        details={"job_id": job_id, "category": category, "error": error}
    )


def alert_publish_failed(job_id: str, error: str):
    """Alert when WordPress publishing fails."""
    return send_alert(
        title="Publishing Failed",
        message=f"Failed to publish job {job_id} to WordPress.",
        level=AlertLevel.ERROR,
        details={"job_id": job_id, "error": error}
    )


def alert_scheduler_error(error: str, details: dict = None):
    """Alert for general scheduler operational errors."""
    return send_alert(
        title="Scheduler Error",
        message=f"The smart scheduler encountered an error: {error}",
        level=AlertLevel.WARNING,
        details=details
    )


def alert_high_failure_rate(failed: int, total: int, period: str = "last hour"):
    """Alert when failure rate exceeds threshold."""
    rate = (failed / total * 100) if total > 0 else 0
    return send_alert(
        title="High Failure Rate Detected",
        message=f"{failed}/{total} jobs ({rate:.1f}%) failed in {period}.",
        level=AlertLevel.WARNING if rate < 50 else AlertLevel.CRITICAL,
        details={
            "failed_count": failed,
            "total_count": total,
            "failure_rate": f"{rate:.1f}%",
            "period": period
        }
    )


def alert_database_error(error: str):
    """Alert for database connection failures."""
    return send_alert(
        title="Database Connection Error",
        message=f"Failed to connect to database: {error}",
        level=AlertLevel.CRITICAL,
        details={"error": error}
    )
```

### Integration in Pipeline Worker

```python
def _send_failure_alert(self, job_id: str, error: str, category: str = None):
    """
    Route job failures to appropriate alert handlers.

    Detects quota exhaustion errors and routes them to the
    quota-specific alert (which may trigger different
    escalation paths than generic failures).
    """
    error_lower = error.lower()

    # Detect quota/billing errors
    quota_keywords = [
        'quota', 'rate_limit', 'rate limit',
        'insufficient_quota', 'billing'
    ]
    if any(kw in error_lower for kw in quota_keywords):
        alert_quota_exhausted('OpenAI', {
            'job_id': job_id,
            'category': category,
            'error': error
        })
    else:
        alert_job_failed(job_id, error, category)
```

---

## Scheduler Status and Monitoring

### Comprehensive Status Report

```python
def get_status(self) -> dict:
    """
    Get complete scheduler status for monitoring dashboards.

    Returns:
        Dict with:
        - running: Whether scheduler thread is alive
        - current_interval: Current N-day window key
        - configuration: Interval days, gap hours, check interval
        - expected_posts_per_day: Calculated from categories and interval
        - total_pending: Total QUEUED jobs across all categories
        - categories: Per-category detail list with:
            - pending_jobs: Count of QUEUED jobs
            - last_publish: ISO datetime of last post
            - days_since: Days since last post
            - can_publish: Whether eligible now
            - published_this_interval: Already published in current window
    """
    pending = self.get_pending_jobs_by_category()
    self._last_publish = self.get_last_publish_time_per_category()
    self._reset_interval_tracking()
    now = datetime.utcnow()

    category_status = []
    all_cats = sorted(set(
        list(pending.keys()) + list(self._last_publish.keys())
    ))

    for cat in all_cats:
        last = self._last_publish.get(cat)
        hours_since = (now - last).total_seconds() / 3600 if last else None
        days_since = hours_since / 24 if hours_since else None

        can_publish = (
            (days_since is None or days_since >= PUBLISH_INTERVAL_DAYS) and
            self._published_this_interval.get(cat) != self._current_interval
        )

        category_status.append({
            'category': cat,
            'pending_jobs': len(pending.get(cat, [])),
            'last_publish': last.isoformat() if last else None,
            'days_since': round(days_since, 1) if days_since else None,
            'can_publish': can_publish,
            'published_this_interval': (
                self._published_this_interval.get(cat) == self._current_interval
            )
        })

    return {
        'running': self._worker_thread and self._worker_thread.is_alive(),
        'current_interval': self._current_interval,
        'publish_interval_days': PUBLISH_INTERVAL_DAYS,
        'min_gap_hours': MIN_GAP_HOURS,
        'check_interval_minutes': CHECK_INTERVAL_MINUTES,
        'expected_posts_per_day': len(all_cats) // PUBLISH_INTERVAL_DAYS + 1,
        'total_pending': sum(len(v) for v in pending.values()),
        'categories': category_status
    }
```

### CLI Status Display

```python
def display_status(status: dict):
    """Format scheduler status for terminal display."""
    print("=" * 70)
    print("SMART SCHEDULER STATUS")
    print("=" * 70)
    print(f"Running: {status['running']}")
    print(f"Interval: Every {status['publish_interval_days']} days/category")
    print(f"Min gap: {status['min_gap_hours']} hours")
    print(f"Check: Every {status['check_interval_minutes']} minutes")
    print(f"Expected: ~{status['expected_posts_per_day']} posts/day")
    print(f"Pending: {status['total_pending']} jobs")
    print()
    print(f"{'Category':<18} {'Pending':<8} {'Last Post':<12} "
          f"{'Days':<8} {'Eligible':<10}")
    print("-" * 70)

    for cat in status['categories']:
        last = cat['last_publish'][:10] if cat['last_publish'] else 'Never'
        days = f"{cat['days_since']:.1f}d" if cat['days_since'] else '-'
        eligible = 'YES' if cat['can_publish'] else 'no'
        print(f"{cat['category']:<18} {cat['pending_jobs']:<8} "
              f"{last:<12} {days:<8} {eligible:<10}")
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_PUBLISH_INTERVAL_DAYS` | `3` | Days between posts for same category |
| `SCHEDULER_MIN_GAP_HOURS` | `7` | Minimum hours between same-category posts |
| `SCHEDULER_CHECK_INTERVAL` | `10` | Minutes between scheduling checks |
| `SCHEDULER_CATEGORY_DELAYS` | `{}` | JSON: category delay overrides (e.g., `'{"TECH": 5}'`) |
| `WP_TIMEZONE_OFFSET_HOURS` | `0` | WordPress timezone offset from UTC (e.g., `11` for AEDT) |
| `WP_SITE_URL` | (required) | WordPress site URL |
| `WP_USERNAME` | (required) | WordPress username |
| `WP_APP_PASSWORD` | (required) | WordPress application password |
| `PIPELINE_BATCH_SIZE` | `1` | Jobs to process per batch cycle |
| `PIPELINE_INTERVAL_SECONDS` | `17280` | Seconds between pipeline processing cycles (~5 hours) |
| `MIN_CREATED_PER_CATEGORY` | `5` | Minimum CREATED jobs to maintain per category |
| `REPLENISH_CHECK_INTERVAL` | `3600` | Seconds between auto-replenish checks |
| `AUTO_REPLENISH_ENABLED` | `true` | Enable/disable auto-replenishment |
| `SCHEDULER_SECRET_KEY` | (required) | Secret for API token signing |
| `SCHEDULER_API_KEY` | (required) | Bearer token for internal API auth |
| **Notification backends** | | |
| `SMTP_HOST` | (optional) | SMTP server for email alerts |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | (optional) | SMTP username |
| `SMTP_PASSWORD` | (optional) | SMTP password |
| `ALERT_EMAIL` | (optional) | Recipient email for alerts |
| `SENDGRID_API_KEY` | (optional) | SendGrid API key |
| `SLACK_WEBHOOK_URL` | (optional) | Slack incoming webhook URL |
| `DISCORD_WEBHOOK_URL` | (optional) | Discord webhook URL |

---

## Integrates With

### `scheduling-framework` module
The smart content scheduler uses the scheduling framework for:
- **Cron job management**: The `run_continuous` loop pattern with `Event.wait()` for clean shutdown
- **Health checks**: `get_status()` endpoint pattern for monitoring dashboards
- **Notification dispatch**: Multi-backend alert routing on failures and quota exhaustion
- **Background threading**: Daemon thread pattern with `Thread(daemon=True)` for worker lifecycle

### `wordpress-publisher` module
Publishing is delegated entirely to the WordPress publisher:
- **Post creation**: `publish_story()`, `publish_story_with_uploaded_images()`, `publish_story_complete()`
- **Media upload**: `upload_story_images()`, `upload_media()`, `upload_audio()`
- **Category management**: `get_or_create_category()`, `get_category_for_tradition()` with ID mapping
- **Tag management**: `_get_or_create_tags()` for SEO tagging
- **Author rotation**: `get_author_for_tradition()` with dedicated author mapping and round-robin fallback
- **SEO integration**: Yoast meta fields, Schema.org JSON-LD injection, internal cross-linking
- **Content formatting**: HTML generation with images, audio players, quizzes, vocabulary sections
- **Multilingual publishing**: Polylang integration for translated content with hreflang links

### `content-pipeline-orchestrator` module
The scheduler is the final stage of the pipeline state machine:
- **State flow**: `CREATED -> RESEARCHING -> WRITING -> EDITING -> REVIEWING -> SEO_TAGGING -> GENERATING_IMAGES -> GENERATING_AUDIO -> QUEUED -> PUBLISHED`
- **Pipeline worker**: Processes jobs through all stages before handing to the scheduler at QUEUED
- **Status transitions**: `mark_job_status()` for atomic state changes with error tracking
- **Failure handling**: Jobs marked FAILED with error messages; alerts dispatched via notification service

### `database-orm-patterns` module
All scheduling state is persisted in the database:
- **Job model**: `Job` with fields for `status`, `category`, `created_at`, `updated_at`, `assigned_to`, `error_message`
- **JobContent model**: `JobContent` for storing article content, uploaded media references, SEO data
- **Row locking**: `with_for_update(skip_locked=True)` for concurrent worker safety
- **Queue queries**: Category-grouped queries with priority sorting and status filtering
- **Session management**: `DatabaseSession` context manager for automatic commit/rollback

### `social-media-client` module
After successful WordPress publishing:
- **Social posting**: Trigger social media posts with the published URL
- **Platform routing**: Determine which social platforms to post to based on category
- **Scheduling**: Optionally delay social posts relative to the WordPress publish time
- **Analytics tracking**: Track social engagement metrics back to the scheduler for optimization

---

## Design Decisions and Rationale

### Why per-category intervals instead of global post limits?

Global limits (e.g., "6 posts per day") create coordination problems: which category gets the next slot? Per-category intervals eliminate this by giving each category its own independent cadence. With 20 categories and 3-day intervals, you naturally get ~6-7 posts per day without any cross-category coordination logic.

### Why randomized probability instead of fixed schedules?

Fixed schedules produce predictable patterns that look automated. The probability-based approach creates natural-looking publish times that vary day to day while still guaranteeing publication within each interval window. The escalating probability ensures deadlines are met.

### Why one publish per check cycle?

Processing only one publish per check cycle prevents burst publishing. If three categories become eligible simultaneously, they publish in three consecutive check cycles (30 minutes apart with a 10-minute interval) rather than all at once. This creates a more natural distribution.

### Why FOR UPDATE SKIP LOCKED?

When running multiple worker instances (e.g., for horizontal scaling), standard queries create race conditions where two workers grab the same job. `FOR UPDATE SKIP LOCKED` provides optimistic concurrency: each worker atomically claims available work, and locked rows are simply skipped rather than blocking.
