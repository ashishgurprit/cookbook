---
name: google-analytics-search-console
description: "Production-ready Google Analytics 4 Data API and Google Search Console integration for SEO analytics pipelines. Use when: (1) Fetching GA4 page metrics, user engagement, or session data, (2) Pulling Search Console clicks, impressions, CTR, and position data, (3) Building combined SEO analytics dashboards, (4) Analyzing content performance across organic search, (5) Determining optimal content publishing times, (6) Monitoring indexing status and search visibility. Triggers on 'google analytics', 'GA4', 'search console', 'SEO metrics', 'organic search data', 'content performance analytics', 'search impressions', or 'indexing status'."
license: Proprietary
---

# Google Analytics & Search Console Integration

Production-ready integration with the GA4 Data API and Google Search Console API for comprehensive SEO analytics, content performance tracking, and organic search optimization.

## Module Dependency Diagram

```
                    +-------------------------------+
                    | google-analytics-search-console|
                    |         (this skill)           |
                    +------+------------+-----------+
                           |            |
              +------------+            +------------+
              |                                      |
    +---------v---------+               +------------v-----------+
    |   GA4 Data API    |               | Search Console API     |
    | - Page metrics    |               | - Clicks/Impressions   |
    | - User engagement |               | - CTR/Position         |
    | - Session data    |               | - Query performance    |
    | - Posting times   |               | - Indexing status      |
    +--------+----------+               +------------+-----------+
             |                                       |
             +------------------+--------------------+
                                |
                   +------------v-----------+
                   |  Combined SEO Pipeline |
                   |  - Unified reporting   |
                   |  - Cross-source joins  |
                   |  - Trend analysis      |
                   +------------+-----------+
                                |
          +---------------------+---------------------+
          |                     |                      |
+---------v--------+  +--------v---------+  +---------v--------+
| unified-api-client|  | batch-processing |  | database-orm-    |
| (HTTP + retry +  |  | (bulk data       |  |  patterns         |
|  auth management)|  |  collection)     |  | (store analytics) |
+------------------+  +------------------+  +------------------+
                                |
                      +---------v----------+
                      | scheduling-framework|
                      | (scheduled pulls)   |
                      +--------------------+
```

## Quick Reference

| Capability | GA4 Data API | Search Console API |
|---|---|---|
| **Primary Use** | On-site behavior | Search visibility |
| **Key Metrics** | Pageviews, sessions, bounce rate, engagement | Clicks, impressions, CTR, position |
| **Data Freshness** | Near real-time (4-8 hours) | 3-day delay |
| **Auth Method** | Service account (OAuth2) | Service account (OAuth2) |
| **Rate Limits** | 10 requests/second per property | 1,200 requests/minute |
| **Free Tier** | Unlimited (standard GA4) | Unlimited |
| **API Version** | v1beta (Data API) | v1 (Search Analytics) |
| **Python Package** | `google-analytics-data` | `google-api-python-client` |

---

# QUICK START

## Python Setup

```bash
# Install dependencies
pip install google-analytics-data google-api-python-client google-auth python-dotenv

# For TypeScript/Node.js
npm install googleapis @google-analytics/data dotenv
```

## Environment Configuration

```bash
# .env file
# --- Authentication (choose one method) ---
# Method 1: Service account file path
GOOGLE_CREDENTIALS_PATH=/path/to/service-account.json

# Method 2: Base64-encoded credentials (for cloud deployments)
GOOGLE_CREDENTIALS_BASE64=eyJ0eXBlIjoic2Vydi...

# Method 3: Application Default Credentials (GCP-hosted)
# No env var needed — uses metadata server automatically

# --- GA4 Configuration ---
GA4_PROPERTY_ID=properties/123456789

# --- Search Console Configuration ---
GSC_SITE_URL=https://example.com
# or for domain properties:
# GSC_SITE_URL=sc-domain:example.com

# --- Optional: Cache & Storage ---
ANALYTICS_CACHE_DIR=./cache/analytics
ANALYTICS_CACHE_TTL_HOURS=1
```

## Minimal Working Example (Python)

```python
from analytics_client import GA4Client, SearchConsoleClient

# Initialize clients
ga4 = GA4Client(
    property_id="properties/123456789",
    credentials_path="./service-account.json"
)

gsc = SearchConsoleClient(
    site_url="https://example.com",
    credentials_path="./service-account.json"
)

# Fetch GA4 site overview
overview = ga4.get_site_overview(days=30)
print(f"Pageviews: {overview['pageviews']}, Users: {overview['total_users']}")

# Fetch Search Console performance
performance = gsc.get_site_performance(days=30)
print(f"Clicks: {performance['clicks']}, Impressions: {performance['impressions']}")
```

## Minimal Working Example (TypeScript)

```typescript
import { GA4Client, SearchConsoleClient } from './analytics-client';

const ga4 = new GA4Client({
  propertyId: 'properties/123456789',
  credentialsPath: './service-account.json',
});

const gsc = new SearchConsoleClient({
  siteUrl: 'https://example.com',
  credentialsPath: './service-account.json',
});

// Fetch GA4 data
const overview = await ga4.getSiteOverview({ days: 30 });
console.log(`Pageviews: ${overview.pageviews}, Users: ${overview.totalUsers}`);

// Fetch Search Console data
const performance = await gsc.getSitePerformance({ days: 30 });
console.log(`Clicks: ${performance.clicks}, Impressions: ${performance.impressions}`);
```

---

# GA4 DATA API INTEGRATION

## Architecture

```
GA4 Data API Client
├── Authentication
│   ├── Service account file
│   ├── Base64-encoded credentials (cloud)
│   └── Application Default Credentials
│
├── Core Methods
│   ├── get_site_overview()      — aggregate site metrics
│   ├── get_top_pages()          — page-level performance
│   ├── get_category_performance() — metrics by content category
│   ├── get_content_recommendations() — data-driven suggestions
│   └── get_optimal_posting_times()  — audience activity analysis
│
├── Caching Layer
│   ├── File-based JSON cache
│   ├── Configurable TTL
│   └── Graceful fallback to cached data
│
└── Error Handling
    ├── Graceful degradation (mock data)
    ├── Library availability checks
    └── Structured logging
```

## Data Models

```python
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PageMetrics:
    """Metrics for a single page from GA4."""
    page_path: str
    page_title: str
    pageviews: int = 0
    unique_pageviews: int = 0
    avg_time_on_page: float = 0.0
    bounce_rate: float = 0.0
    entrances: int = 0
    exits: int = 0
    engagement_rate: float = 0.0

    @property
    def exit_rate(self) -> float:
        """Calculate exit rate as exits / pageviews."""
        return (self.exits / self.pageviews * 100) if self.pageviews > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "page_path": self.page_path,
            "page_title": self.page_title,
            "pageviews": self.pageviews,
            "unique_pageviews": self.unique_pageviews,
            "avg_time_on_page": self.avg_time_on_page,
            "bounce_rate": self.bounce_rate,
            "entrances": self.entrances,
            "exits": self.exits,
            "engagement_rate": self.engagement_rate,
            "exit_rate": self.exit_rate,
        }


@dataclass
class CategoryMetrics:
    """Aggregated metrics for a content category or section."""
    category: str
    total_pageviews: int = 0
    total_users: int = 0
    avg_session_duration: float = 0.0
    top_pages: List[PageMetrics] = field(default_factory=list)
    period_start: str = ""
    period_end: str = ""

    @property
    def pages_count(self) -> int:
        return len(self.top_pages)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "total_pageviews": self.total_pageviews,
            "total_users": self.total_users,
            "avg_session_duration": self.avg_session_duration,
            "top_pages": [p.to_dict() for p in self.top_pages],
            "pages_count": self.pages_count,
            "period_start": self.period_start,
            "period_end": self.period_end,
        }
```

## TypeScript Data Models

```typescript
interface PageMetrics {
  pagePath: string;
  pageTitle: string;
  pageviews: number;
  uniquePageviews: number;
  avgTimeOnPage: number;
  bounceRate: number;
  entrances: number;
  exits: number;
  engagementRate: number;
}

interface CategoryMetrics {
  category: string;
  totalPageviews: number;
  totalUsers: number;
  avgSessionDuration: number;
  topPages: PageMetrics[];
  periodStart: string;
  periodEnd: string;
}

interface SiteOverview {
  pageviews: number;
  totalUsers: number;
  newUsers: number;
  sessions: number;
  avgSessionDuration: number;
  bounceRate: number;
  engagementRate: number;
  periodDays: number;
  fetchedAt: string;
}
```

## Full GA4 Client Implementation

```python
import os
import json
import logging
import base64
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# Graceful import — allows the module to load even without the SDK
try:
    from google.analytics.data_v1beta import BetaAnalyticsDataClient
    from google.analytics.data_v1beta.types import (
        RunReportRequest,
        DateRange,
        Dimension,
        Metric,
        FilterExpression,
        Filter,
        OrderBy,
    )
    from google.oauth2 import service_account
    GA4_AVAILABLE = True
except ImportError:
    GA4_AVAILABLE = False
    logger.warning(
        "google-analytics-data not installed. "
        "Run: pip install google-analytics-data"
    )


class GA4Client:
    """
    Google Analytics 4 Data API client.

    Provides methods for fetching page-level metrics, site overviews,
    category performance breakdowns, and optimal posting time analysis.

    Supports three authentication methods:
      1. Service account JSON file path
      2. Base64-encoded service account JSON (for cloud/container deployments)
      3. Application Default Credentials (GCP environments)

    All methods gracefully degrade to cached or placeholder data when the
    API is unavailable, making the client safe for local development
    without credentials.
    """

    # Default GA4 metrics available in the Data API
    AVAILABLE_METRICS = [
        "screenPageViews",
        "totalUsers",
        "newUsers",
        "sessions",
        "averageSessionDuration",
        "bounceRate",
        "engagementRate",
        "eventCount",
        "conversions",
        "userEngagementDuration",
    ]

    def __init__(
        self,
        property_id: Optional[str] = None,
        credentials_path: Optional[str] = None,
        cache_dir: str = "cache/analytics/ga4",
        cache_ttl_hours: int = 1,
    ):
        """
        Initialize the GA4 client.

        Args:
            property_id: GA4 property identifier, e.g. "properties/123456789".
                         Falls back to GA4_PROPERTY_ID env var.
            credentials_path: Path to service account JSON file.
                              Falls back to GOOGLE_CREDENTIALS_PATH env var.
            cache_dir: Directory for file-based JSON cache.
            cache_ttl_hours: Cache time-to-live in hours.
        """
        self.property_id = property_id or os.getenv("GA4_PROPERTY_ID", "")
        self.credentials_path = (
            credentials_path or os.getenv("GOOGLE_CREDENTIALS_PATH")
        )
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._client: Optional[BetaAnalyticsDataClient] = None

        # Content category mappings — customize for your site structure.
        # Keys are logical names; values are URL path segments used for filtering.
        self.category_paths: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def configure_categories(self, mapping: Dict[str, str]) -> None:
        """
        Set the category-to-URL-path mapping for category-level reporting.

        Example:
            client.configure_categories({
                "tutorials": "tutorials",
                "blog": "blog",
                "docs": "documentation",
            })
        """
        self.category_paths = mapping

    def is_configured(self) -> bool:
        """Return True if minimum configuration is present."""
        has_property = bool(self.property_id)
        has_credentials = bool(
            self.credentials_path
            or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
            or os.getenv("GOOGLE_CREDENTIALS_BASE64")
        )
        return has_property and has_credentials

    # ------------------------------------------------------------------
    # Client lifecycle
    # ------------------------------------------------------------------

    def _get_client(self) -> Optional["BetaAnalyticsDataClient"]:
        """Lazily create and cache the API client."""
        if not GA4_AVAILABLE:
            return None

        if self._client is not None:
            return self._client

        try:
            # Priority 1: Base64-encoded credentials (cloud deployments)
            creds_b64 = os.getenv("GOOGLE_CREDENTIALS_BASE64")
            if creds_b64:
                creds_info = json.loads(base64.b64decode(creds_b64))
                credentials = service_account.Credentials.from_service_account_info(
                    creds_info,
                    scopes=["https://www.googleapis.com/auth/analytics.readonly"],
                )
                self._client = BetaAnalyticsDataClient(credentials=credentials)
                return self._client

            # Priority 2: File-based service account
            if self.credentials_path and os.path.exists(self.credentials_path):
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path,
                    scopes=["https://www.googleapis.com/auth/analytics.readonly"],
                )
                self._client = BetaAnalyticsDataClient(credentials=credentials)
                return self._client

            # Priority 3: Application Default Credentials
            self._client = BetaAnalyticsDataClient()
            return self._client

        except Exception as e:
            logger.error(f"Failed to create GA4 client: {e}")
            return None

    # ------------------------------------------------------------------
    # Core API methods
    # ------------------------------------------------------------------

    def get_site_overview(self, days: int = 30) -> Dict[str, Any]:
        """
        Fetch aggregate site-level metrics.

        Returns:
            Dict with keys: pageviews, total_users, new_users, sessions,
            avg_session_duration, bounce_rate, engagement_rate, period_days,
            fetched_at.
        """
        client = self._get_client()
        if not client:
            return self._read_cache_or_placeholder("site_overview", days)

        try:
            request = RunReportRequest(
                property=self.property_id,
                date_ranges=[
                    DateRange(start_date=f"{days}daysAgo", end_date="today")
                ],
                metrics=[
                    Metric(name="screenPageViews"),
                    Metric(name="totalUsers"),
                    Metric(name="newUsers"),
                    Metric(name="sessions"),
                    Metric(name="averageSessionDuration"),
                    Metric(name="bounceRate"),
                    Metric(name="engagementRate"),
                ],
            )

            response = client.run_report(request)

            if response.rows:
                row = response.rows[0]
                data = {
                    "pageviews": int(row.metric_values[0].value),
                    "total_users": int(row.metric_values[1].value),
                    "new_users": int(row.metric_values[2].value),
                    "sessions": int(row.metric_values[3].value),
                    "avg_session_duration": float(row.metric_values[4].value),
                    "bounce_rate": float(row.metric_values[5].value),
                    "engagement_rate": float(row.metric_values[6].value),
                    "period_days": days,
                    "fetched_at": datetime.now().isoformat(),
                }
                self._write_cache("site_overview", data)
                return data

        except Exception as e:
            logger.error(f"Failed to fetch site overview: {e}")

        return self._read_cache_or_placeholder("site_overview", days)

    def get_top_pages(
        self,
        days: int = 30,
        limit: int = 20,
        category: Optional[str] = None,
    ) -> List[PageMetrics]:
        """
        Fetch top-performing pages ordered by pageviews.

        Args:
            days: Lookback window in days.
            limit: Maximum number of pages to return.
            category: Optional category key (from category_paths) to filter by URL path.

        Returns:
            List of PageMetrics, sorted by pageviews descending.
        """
        client = self._get_client()
        if not client:
            return self._read_cached_pages(category, limit)

        try:
            # Build optional dimension filter for category
            dimension_filter = None
            if category and category in self.category_paths:
                path_segment = self.category_paths[category]
                dimension_filter = FilterExpression(
                    filter=Filter(
                        field_name="pagePath",
                        string_filter=Filter.StringFilter(
                            match_type=Filter.StringFilter.MatchType.CONTAINS,
                            value=f"/{path_segment}/",
                        ),
                    )
                )

            request = RunReportRequest(
                property=self.property_id,
                date_ranges=[
                    DateRange(start_date=f"{days}daysAgo", end_date="today")
                ],
                dimensions=[
                    Dimension(name="pagePath"),
                    Dimension(name="pageTitle"),
                ],
                metrics=[
                    Metric(name="screenPageViews"),
                    Metric(name="totalUsers"),
                    Metric(name="averageSessionDuration"),
                    Metric(name="bounceRate"),
                ],
                dimension_filter=dimension_filter,
                order_bys=[
                    OrderBy(
                        metric=OrderBy.MetricOrderBy(
                            metric_name="screenPageViews"
                        ),
                        desc=True,
                    )
                ],
                limit=limit,
            )

            response = client.run_report(request)

            pages = []
            for row in response.rows:
                pages.append(
                    PageMetrics(
                        page_path=row.dimension_values[0].value,
                        page_title=row.dimension_values[1].value,
                        pageviews=int(row.metric_values[0].value),
                        unique_pageviews=int(row.metric_values[1].value),
                        avg_time_on_page=float(row.metric_values[2].value),
                        bounce_rate=float(row.metric_values[3].value),
                    )
                )

            cache_key = f"top_pages_{category or 'all'}"
            self._write_cache(cache_key, [p.to_dict() for p in pages])
            return pages

        except Exception as e:
            logger.error(f"Failed to fetch top pages: {e}")

        return self._read_cached_pages(category, limit)

    def get_category_performance(
        self, days: int = 30
    ) -> Dict[str, CategoryMetrics]:
        """
        Get performance metrics broken down by configured content categories.

        Requires category_paths to be configured via configure_categories().

        Returns:
            Dict mapping category name -> CategoryMetrics.
        """
        if not self.category_paths:
            logger.warning(
                "No categories configured. Call configure_categories() first."
            )
            return {}

        results: Dict[str, CategoryMetrics] = {}
        period_start = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        period_end = datetime.now().strftime("%Y-%m-%d")

        for category_name in self.category_paths:
            top_pages = self.get_top_pages(
                days=days, limit=10, category=category_name
            )

            total_pageviews = sum(p.pageviews for p in top_pages)
            total_users = sum(p.unique_pageviews for p in top_pages)

            results[category_name] = CategoryMetrics(
                category=category_name,
                total_pageviews=total_pageviews,
                total_users=total_users,
                top_pages=top_pages[:5],
                period_start=period_start,
                period_end=period_end,
            )

        self._write_cache(
            "category_performance",
            {k: v.to_dict() for k, v in results.items()},
        )
        return results

    def get_content_recommendations(
        self, days: int = 30
    ) -> Dict[str, Any]:
        """
        Analyze category performance and produce data-driven content
        recommendations.

        Returns:
            Dict with per-category recommendations, top performer, and
            categories needing attention.
        """
        category_perf = self.get_category_performance(days)
        if not category_perf:
            return {"error": "No categories configured"}

        recommendations: Dict[str, Any] = {
            "generated_at": datetime.now().isoformat(),
            "period_days": days,
            "categories": {},
        }

        total_pageviews = sum(
            c.total_pageviews for c in category_perf.values()
        )
        avg_per_category = (
            total_pageviews / len(category_perf) if category_perf else 0
        )

        for name, metrics in category_perf.items():
            share = (
                round(metrics.total_pageviews / total_pageviews * 100, 1)
                if total_pageviews
                else 0
            )
            vs_avg = (
                round(
                    (metrics.total_pageviews - avg_per_category)
                    / avg_per_category
                    * 100,
                    1,
                )
                if avg_per_category
                else 0
            )

            rec: Dict[str, Any] = {
                "total_pageviews": metrics.total_pageviews,
                "share_of_total_pct": share,
                "vs_average_pct": vs_avg,
                "recommendations": [],
            }

            if metrics.total_pageviews < avg_per_category * 0.5:
                rec["recommendations"].append(
                    "Underperforming category — consider increasing content "
                    "frequency or improving SEO."
                )
            elif metrics.total_pageviews > avg_per_category * 1.5:
                rec["recommendations"].append(
                    "Top performer — maintain or expand content in this area."
                )

            if metrics.top_pages:
                rec["top_content_themes"] = [
                    p.page_title[:80] for p in metrics.top_pages[:3]
                ]

            recommendations["categories"][name] = rec

        sorted_cats = sorted(
            category_perf.items(),
            key=lambda x: x[1].total_pageviews,
            reverse=True,
        )
        recommendations["top_performing_category"] = (
            sorted_cats[0][0] if sorted_cats else None
        )
        recommendations["needs_attention"] = [
            name
            for name, m in sorted_cats
            if m.total_pageviews < avg_per_category * 0.5
        ]

        return recommendations

    def get_optimal_posting_times(self, days: int = 30) -> Dict[str, Any]:
        """
        Analyze user activity by hour and day-of-week to recommend
        optimal content publishing times.

        Returns:
            Dict with optimal_hours (list of ints), recommended_times
            (formatted strings), and day_of_week breakdown.
        """
        client = self._get_client()
        if not client:
            return self._default_posting_times()

        try:
            request = RunReportRequest(
                property=self.property_id,
                date_ranges=[
                    DateRange(start_date=f"{days}daysAgo", end_date="today")
                ],
                dimensions=[
                    Dimension(name="hour"),
                    Dimension(name="dayOfWeek"),
                ],
                metrics=[
                    Metric(name="sessions"),
                    Metric(name="engagementRate"),
                ],
                order_bys=[
                    OrderBy(
                        metric=OrderBy.MetricOrderBy(metric_name="sessions"),
                        desc=True,
                    )
                ],
            )

            response = client.run_report(request)

            # Aggregate sessions by hour
            hour_sessions: Dict[int, int] = {}
            day_sessions: Dict[int, int] = {}

            for row in response.rows:
                hour = int(row.dimension_values[0].value)
                day = int(row.dimension_values[1].value)
                sessions = int(row.metric_values[0].value)

                hour_sessions[hour] = hour_sessions.get(hour, 0) + sessions
                day_sessions[day] = day_sessions.get(day, 0) + sessions

            # Top 6 hours by session volume
            sorted_hours = sorted(
                hour_sessions.items(), key=lambda x: x[1], reverse=True
            )
            top_hours = sorted([h for h, _ in sorted_hours[:6]])

            # Day-of-week labels
            day_names = [
                "Sunday", "Monday", "Tuesday", "Wednesday",
                "Thursday", "Friday", "Saturday",
            ]
            sorted_days = sorted(
                day_sessions.items(), key=lambda x: x[1], reverse=True
            )
            best_days = [day_names[d] for d, _ in sorted_days[:3]]

            result = {
                "optimal_hours": top_hours,
                "recommended_times": [f"{h:02d}:00" for h in top_hours],
                "best_days": best_days,
                "hourly_breakdown": dict(sorted(hour_sessions.items())),
                "analysis_period_days": days,
                "generated_at": datetime.now().isoformat(),
            }

            self._write_cache("posting_times", result)
            return result

        except Exception as e:
            logger.error(f"Failed to analyze posting times: {e}")

        return self._default_posting_times()

    def get_realtime_overview(self) -> Dict[str, Any]:
        """
        Fetch real-time active user count.

        Note: Requires the GA4 Realtime API (different from the Data API).
        This method provides a pattern for real-time monitoring.
        """
        client = self._get_client()
        if not client:
            return {"active_users": 0, "source": "unavailable"}

        try:
            from google.analytics.data_v1beta.types import RunRealtimeReportRequest

            request = RunRealtimeReportRequest(
                property=self.property_id,
                metrics=[Metric(name="activeUsers")],
            )
            response = client.run_realtime_report(request)

            if response.rows:
                return {
                    "active_users": int(response.rows[0].metric_values[0].value),
                    "fetched_at": datetime.now().isoformat(),
                }
        except Exception as e:
            logger.error(f"Realtime report failed: {e}")

        return {"active_users": 0, "source": "error"}

    # ------------------------------------------------------------------
    # Caching layer
    # ------------------------------------------------------------------

    def _write_cache(self, key: str, data: Any) -> None:
        """Persist data to a JSON cache file."""
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(
                    {"data": data, "cached_at": datetime.now().isoformat()},
                    f,
                    indent=2,
                )
        except Exception as e:
            logger.error(f"Cache write failed for {key}: {e}")

    def _read_cache(self, key: str) -> Optional[Any]:
        """Read from cache if it exists and is within TTL."""
        cache_file = self.cache_dir / f"{key}.json"
        if not cache_file.exists():
            return None
        try:
            with open(cache_file) as f:
                cached = json.load(f)
            cached_at = datetime.fromisoformat(cached["cached_at"])
            if datetime.now() - cached_at < self.cache_ttl:
                return cached["data"]
        except Exception:
            pass
        return None

    def _read_cache_or_placeholder(
        self, key: str, days: int
    ) -> Dict[str, Any]:
        """Return cached data or a placeholder dict."""
        cached = self._read_cache(key)
        if cached is not None:
            return cached
        return {
            "pageviews": 0,
            "total_users": 0,
            "sessions": 0,
            "source": "placeholder",
            "period_days": days,
            "note": "GA4 not configured — using placeholder data",
        }

    def _read_cached_pages(
        self, category: Optional[str], limit: int
    ) -> List[PageMetrics]:
        """Return cached pages or an empty list."""
        cache_key = f"top_pages_{category or 'all'}"
        cached = self._read_cache(cache_key)
        if cached:
            return [PageMetrics(**p) for p in cached[:limit]]
        return []

    @staticmethod
    def _default_posting_times() -> Dict[str, Any]:
        """Sensible defaults when GA4 is not available."""
        return {
            "optimal_hours": [6, 9, 12, 15, 18, 21],
            "recommended_times": [
                "06:00", "09:00", "12:00", "15:00", "18:00", "21:00"
            ],
            "best_days": ["Tuesday", "Wednesday", "Thursday"],
            "source": "defaults",
            "generated_at": datetime.now().isoformat(),
        }
```

## TypeScript GA4 Client

```typescript
import { BetaAnalyticsDataClient } from '@google-analytics/data';
import { google } from 'googleapis';
import * as fs from 'fs';
import * as path from 'path';

interface GA4Config {
  propertyId: string;
  credentialsPath?: string;
  cacheDir?: string;
  cacheTtlHours?: number;
}

interface SiteOverview {
  pageviews: number;
  totalUsers: number;
  newUsers: number;
  sessions: number;
  avgSessionDuration: number;
  bounceRate: number;
  engagementRate: number;
  periodDays: number;
  fetchedAt: string;
}

class GA4Client {
  private client: BetaAnalyticsDataClient | null = null;
  private propertyId: string;
  private credentialsPath?: string;
  private cacheDir: string;
  private cacheTtlMs: number;

  constructor(config: GA4Config) {
    this.propertyId = config.propertyId;
    this.credentialsPath = config.credentialsPath;
    this.cacheDir = config.cacheDir || './cache/analytics/ga4';
    this.cacheTtlMs = (config.cacheTtlHours || 1) * 3600 * 1000;

    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  private getClient(): BetaAnalyticsDataClient {
    if (!this.client) {
      const options: Record<string, unknown> = {};

      if (this.credentialsPath) {
        options.keyFilename = this.credentialsPath;
      } else if (process.env.GOOGLE_CREDENTIALS_BASE64) {
        const decoded = Buffer.from(
          process.env.GOOGLE_CREDENTIALS_BASE64, 'base64'
        ).toString('utf-8');
        options.credentials = JSON.parse(decoded);
      }

      this.client = new BetaAnalyticsDataClient(options);
    }
    return this.client;
  }

  async getSiteOverview(opts: { days?: number } = {}): Promise<SiteOverview> {
    const days = opts.days || 30;
    const client = this.getClient();

    const [response] = await client.runReport({
      property: this.propertyId,
      dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
      metrics: [
        { name: 'screenPageViews' },
        { name: 'totalUsers' },
        { name: 'newUsers' },
        { name: 'sessions' },
        { name: 'averageSessionDuration' },
        { name: 'bounceRate' },
        { name: 'engagementRate' },
      ],
    });

    const row = response.rows?.[0];
    if (!row?.metricValues) {
      throw new Error('No data returned from GA4');
    }

    const val = (i: number): number =>
      parseFloat(row.metricValues![i].value || '0');

    return {
      pageviews: val(0),
      totalUsers: val(1),
      newUsers: val(2),
      sessions: val(3),
      avgSessionDuration: val(4),
      bounceRate: val(5),
      engagementRate: val(6),
      periodDays: days,
      fetchedAt: new Date().toISOString(),
    };
  }

  async getTopPages(opts: {
    days?: number;
    limit?: number;
    categoryPath?: string;
  } = {}): Promise<PageMetrics[]> {
    const { days = 30, limit = 20, categoryPath } = opts;
    const client = this.getClient();

    const request: Record<string, unknown> = {
      property: this.propertyId,
      dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
      dimensions: [{ name: 'pagePath' }, { name: 'pageTitle' }],
      metrics: [
        { name: 'screenPageViews' },
        { name: 'totalUsers' },
        { name: 'averageSessionDuration' },
        { name: 'bounceRate' },
      ],
      orderBys: [{
        metric: { metricName: 'screenPageViews' },
        desc: true,
      }],
      limit,
    };

    if (categoryPath) {
      request.dimensionFilter = {
        filter: {
          fieldName: 'pagePath',
          stringFilter: {
            matchType: 'CONTAINS',
            value: `/${categoryPath}/`,
          },
        },
      };
    }

    const [response] = await client.runReport(request);

    return (response.rows || []).map((row) => ({
      pagePath: row.dimensionValues![0].value || '',
      pageTitle: row.dimensionValues![1].value || '',
      pageviews: parseInt(row.metricValues![0].value || '0'),
      uniquePageviews: parseInt(row.metricValues![1].value || '0'),
      avgTimeOnPage: parseFloat(row.metricValues![2].value || '0'),
      bounceRate: parseFloat(row.metricValues![3].value || '0'),
      entrances: 0,
      exits: 0,
      engagementRate: 0,
    }));
  }
}

export { GA4Client, GA4Config, SiteOverview, PageMetrics };
```

---

# SEARCH CONSOLE API INTEGRATION

## Architecture

```
Search Console API Client
├── Authentication
│   ├── Service account file
│   ├── Base64-encoded credentials (cloud)
│   └── Shared credentials with GA4 client
│
├── Core Methods
│   ├── get_site_performance()   — aggregate search metrics
│   ├── get_page_metrics()       — per-page click/impression data
│   ├── get_top_queries()        — top search queries site-wide
│   ├── get_queries_for_page()   — queries driving traffic to a URL
│   ├── get_indexing_status()    — approximate index coverage
│   └── get_query_opportunities()— high-impression, low-CTR queries
│
├── Caching Layer
│   ├── File-based JSON cache
│   ├── 6-hour TTL (matches data delay)
│   └── Graceful fallback
│
└── Data Delay Handling
    └── Automatic 3-day offset (GSC data lag)
```

## Data Models

```python
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class PageSearchMetrics:
    """Search performance for a single URL."""
    page: str
    clicks: int = 0
    impressions: int = 0
    ctr: float = 0.0           # Percentage (0-100)
    position: float = 0.0      # Average search position
    top_queries: List[str] = field(default_factory=list)

    @property
    def click_through_rate(self) -> str:
        """Formatted CTR string."""
        return f"{self.ctr:.2f}%"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "page": self.page,
            "clicks": self.clicks,
            "impressions": self.impressions,
            "ctr": self.ctr,
            "position": self.position,
            "top_queries": self.top_queries,
        }


@dataclass
class QueryMetrics:
    """Search performance for a single query string."""
    query: str
    clicks: int = 0
    impressions: int = 0
    ctr: float = 0.0           # Percentage (0-100)
    position: float = 0.0      # Average search position
    pages: List[str] = field(default_factory=list)

    @property
    def is_opportunity(self) -> bool:
        """High impressions but low CTR suggests optimization potential."""
        return self.impressions > 100 and self.ctr < 3.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "clicks": self.clicks,
            "impressions": self.impressions,
            "ctr": self.ctr,
            "position": self.position,
            "pages": self.pages,
        }
```

## TypeScript Data Models

```typescript
interface PageSearchMetrics {
  page: string;
  clicks: number;
  impressions: number;
  ctr: number;        // percentage (0-100)
  position: number;   // average search position
  topQueries: string[];
}

interface QueryMetrics {
  query: string;
  clicks: number;
  impressions: number;
  ctr: number;
  position: number;
  pages: string[];
}

interface SiteSearchPerformance {
  clicks: number;
  impressions: number;
  ctr: number;
  position: number;
  periodDays: number;
  startDate: string;
  endDate: string;
  fetchedAt: string;
}

interface IndexingStatus {
  indexedPages: number;
  pagesWithClicks: number;
  pagesWithImpressions: number;
  fetchedAt: string;
}
```

## Full Search Console Client Implementation

```python
import os
import json
import logging
import base64
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    GSC_AVAILABLE = True
except ImportError:
    GSC_AVAILABLE = False
    logger.warning(
        "google-api-python-client not installed. "
        "Run: pip install google-api-python-client"
    )


class SearchConsoleClient:
    """
    Google Search Console API client.

    Provides methods for fetching search performance data, per-page
    metrics, query analysis, and indexing status.

    Important: Search Console data has a ~3-day delay. All date ranges
    are automatically adjusted to account for this.
    """

    SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly"]

    # GSC data is delayed by approximately 3 days
    DATA_DELAY_DAYS = 3

    def __init__(
        self,
        site_url: Optional[str] = None,
        credentials_path: Optional[str] = None,
        cache_dir: str = "cache/analytics/gsc",
        cache_ttl_hours: int = 6,
    ):
        """
        Initialize the Search Console client.

        Args:
            site_url: The site URL as registered in Search Console.
                      Examples: "https://example.com" or "sc-domain:example.com"
                      Falls back to GSC_SITE_URL env var.
            credentials_path: Path to service account JSON.
                              Falls back to GOOGLE_CREDENTIALS_PATH env var.
            cache_dir: Directory for file-based JSON cache.
            cache_ttl_hours: Cache TTL in hours (default 6, matching data delay).
        """
        self.site_url = site_url or os.getenv("GSC_SITE_URL", "")
        self.credentials_path = (
            credentials_path or os.getenv("GOOGLE_CREDENTIALS_PATH")
        )
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._service = None

    def is_configured(self) -> bool:
        """Return True if minimum configuration is present."""
        has_site = bool(self.site_url)
        has_credentials = bool(
            self.credentials_path
            or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
            or os.getenv("GOOGLE_CREDENTIALS_BASE64")
        )
        return has_site and has_credentials

    # ------------------------------------------------------------------
    # Service lifecycle
    # ------------------------------------------------------------------

    def _get_service(self):
        """Lazily create and cache the API service."""
        if not GSC_AVAILABLE:
            return None

        if self._service is not None:
            return self._service

        try:
            credentials = None

            # Priority 1: Base64-encoded credentials
            creds_b64 = os.getenv("GOOGLE_CREDENTIALS_BASE64")
            if creds_b64:
                creds_info = json.loads(base64.b64decode(creds_b64))
                credentials = service_account.Credentials.from_service_account_info(
                    creds_info, scopes=self.SCOPES
                )

            # Priority 2: File-based service account
            elif self.credentials_path and os.path.exists(self.credentials_path):
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path, scopes=self.SCOPES
                )

            if credentials:
                self._service = build(
                    "searchconsole", "v1", credentials=credentials
                )
                return self._service

            logger.warning("No credentials available for Search Console")
            return None

        except Exception as e:
            logger.error(f"Failed to create Search Console service: {e}")
            return None

    def _date_range(self, days: int) -> tuple:
        """
        Calculate start and end dates, accounting for GSC data delay.

        Returns:
            (start_date_str, end_date_str) in YYYY-MM-DD format.
        """
        end_date = datetime.now() - timedelta(days=self.DATA_DELAY_DAYS)
        start_date = end_date - timedelta(days=days)
        return start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d")

    # ------------------------------------------------------------------
    # Core API methods
    # ------------------------------------------------------------------

    def get_site_performance(self, days: int = 30) -> Dict[str, Any]:
        """
        Fetch aggregate site-level search performance.

        Returns:
            Dict with clicks, impressions, ctr (percentage), position,
            period metadata, and fetched_at timestamp.
        """
        service = self._get_service()
        if not service:
            return self._read_cache_or_placeholder("site_performance", days)

        try:
            start_date, end_date = self._date_range(days)

            response = (
                service.searchanalytics()
                .query(
                    siteUrl=self.site_url,
                    body={
                        "startDate": start_date,
                        "endDate": end_date,
                        "dimensions": [],
                        "rowLimit": 1,
                    },
                )
                .execute()
            )

            if response.get("rows"):
                row = response["rows"][0]
                data = {
                    "clicks": row.get("clicks", 0),
                    "impressions": row.get("impressions", 0),
                    "ctr": round(row.get("ctr", 0) * 100, 2),
                    "position": round(row.get("position", 0), 1),
                    "period_days": days,
                    "start_date": start_date,
                    "end_date": end_date,
                    "fetched_at": datetime.now().isoformat(),
                }
                self._write_cache("site_performance", data)
                return data

        except Exception as e:
            logger.error(f"Failed to fetch site performance: {e}")

        return self._read_cache_or_placeholder("site_performance", days)

    def get_page_metrics(
        self, days: int = 30, limit: int = 100
    ) -> List[PageSearchMetrics]:
        """
        Fetch search metrics per page, ordered by clicks descending.

        Args:
            days: Lookback window.
            limit: Maximum pages to return.

        Returns:
            List of PageSearchMetrics.
        """
        service = self._get_service()
        if not service:
            return self._read_cached_pages(limit)

        try:
            start_date, end_date = self._date_range(days)

            response = (
                service.searchanalytics()
                .query(
                    siteUrl=self.site_url,
                    body={
                        "startDate": start_date,
                        "endDate": end_date,
                        "dimensions": ["page"],
                        "rowLimit": limit,
                        "orderBy": [
                            {
                                "fieldName": "clicks",
                                "sortOrder": "DESCENDING",
                            }
                        ],
                    },
                )
                .execute()
            )

            pages = []
            for row in response.get("rows", []):
                pages.append(
                    PageSearchMetrics(
                        page=row["keys"][0],
                        clicks=row.get("clicks", 0),
                        impressions=row.get("impressions", 0),
                        ctr=round(row.get("ctr", 0) * 100, 2),
                        position=round(row.get("position", 0), 1),
                    )
                )

            self._write_cache(
                "page_metrics", [p.to_dict() for p in pages]
            )
            return pages

        except Exception as e:
            logger.error(f"Failed to fetch page metrics: {e}")

        return self._read_cached_pages(limit)

    def get_top_queries(
        self, days: int = 30, limit: int = 50
    ) -> List[QueryMetrics]:
        """
        Fetch top search queries for the entire site.

        Args:
            days: Lookback window.
            limit: Maximum queries to return.

        Returns:
            List of QueryMetrics, ordered by clicks descending.
        """
        service = self._get_service()
        if not service:
            return self._read_cached_queries(limit)

        try:
            start_date, end_date = self._date_range(days)

            response = (
                service.searchanalytics()
                .query(
                    siteUrl=self.site_url,
                    body={
                        "startDate": start_date,
                        "endDate": end_date,
                        "dimensions": ["query"],
                        "rowLimit": limit,
                        "orderBy": [
                            {
                                "fieldName": "clicks",
                                "sortOrder": "DESCENDING",
                            }
                        ],
                    },
                )
                .execute()
            )

            queries = []
            for row in response.get("rows", []):
                queries.append(
                    QueryMetrics(
                        query=row["keys"][0],
                        clicks=row.get("clicks", 0),
                        impressions=row.get("impressions", 0),
                        ctr=round(row.get("ctr", 0) * 100, 2),
                        position=round(row.get("position", 0), 1),
                    )
                )

            self._write_cache(
                "top_queries", [q.to_dict() for q in queries]
            )
            return queries

        except Exception as e:
            logger.error(f"Failed to fetch top queries: {e}")

        return self._read_cached_queries(limit)

    def get_queries_for_page(
        self, page_url: str, days: int = 30, limit: int = 20
    ) -> List[QueryMetrics]:
        """
        Fetch search queries that drive traffic to a specific page.

        Args:
            page_url: Full URL of the page.
            days: Lookback window.
            limit: Maximum queries to return.

        Returns:
            List of QueryMetrics for the given page.
        """
        service = self._get_service()
        if not service:
            return []

        try:
            start_date, end_date = self._date_range(days)

            response = (
                service.searchanalytics()
                .query(
                    siteUrl=self.site_url,
                    body={
                        "startDate": start_date,
                        "endDate": end_date,
                        "dimensions": ["query"],
                        "dimensionFilterGroups": [
                            {
                                "filters": [
                                    {
                                        "dimension": "page",
                                        "operator": "equals",
                                        "expression": page_url,
                                    }
                                ]
                            }
                        ],
                        "rowLimit": limit,
                        "orderBy": [
                            {
                                "fieldName": "impressions",
                                "sortOrder": "DESCENDING",
                            }
                        ],
                    },
                )
                .execute()
            )

            return [
                QueryMetrics(
                    query=row["keys"][0],
                    clicks=row.get("clicks", 0),
                    impressions=row.get("impressions", 0),
                    ctr=round(row.get("ctr", 0) * 100, 2),
                    position=round(row.get("position", 0), 1),
                )
                for row in response.get("rows", [])
            ]

        except Exception as e:
            logger.error(f"Failed to fetch queries for {page_url}: {e}")

        return []

    def get_query_opportunities(
        self, days: int = 30, limit: int = 30
    ) -> List[QueryMetrics]:
        """
        Find high-impression, low-CTR queries — SEO optimization targets.

        These are queries where your pages appear in search results
        frequently but users rarely click through, suggesting title/
        description improvements could yield significant traffic gains.

        Returns:
            List of QueryMetrics sorted by impressions, filtered to
            CTR < 3% and impressions > 100.
        """
        all_queries = self.get_top_queries(days=days, limit=500)
        opportunities = [
            q for q in all_queries
            if q.impressions > 100 and q.ctr < 3.0
        ]
        opportunities.sort(key=lambda q: q.impressions, reverse=True)
        return opportunities[:limit]

    def get_indexing_status(self) -> Dict[str, Any]:
        """
        Get approximate indexing status based on search analytics data.

        Returns:
            Dict with indexed_pages, pages_with_clicks,
            pages_with_impressions counts.
        """
        service = self._get_service()
        if not service:
            return {
                "status": "unavailable",
                "note": "Search Console not configured",
            }

        try:
            pages = self.get_page_metrics(days=30, limit=1000)
            return {
                "indexed_pages": len(pages),
                "pages_with_clicks": len(
                    [p for p in pages if p.clicks > 0]
                ),
                "pages_with_impressions": len(
                    [p for p in pages if p.impressions > 0]
                ),
                "fetched_at": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get indexing status: {e}")
            return {"status": "error", "error": str(e)}

    def get_performance_by_country(
        self, days: int = 30, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Fetch search performance broken down by country.

        Returns:
            List of dicts with country, clicks, impressions, ctr, position.
        """
        service = self._get_service()
        if not service:
            return []

        try:
            start_date, end_date = self._date_range(days)

            response = (
                service.searchanalytics()
                .query(
                    siteUrl=self.site_url,
                    body={
                        "startDate": start_date,
                        "endDate": end_date,
                        "dimensions": ["country"],
                        "rowLimit": limit,
                        "orderBy": [
                            {
                                "fieldName": "clicks",
                                "sortOrder": "DESCENDING",
                            }
                        ],
                    },
                )
                .execute()
            )

            return [
                {
                    "country": row["keys"][0],
                    "clicks": row.get("clicks", 0),
                    "impressions": row.get("impressions", 0),
                    "ctr": round(row.get("ctr", 0) * 100, 2),
                    "position": round(row.get("position", 0), 1),
                }
                for row in response.get("rows", [])
            ]

        except Exception as e:
            logger.error(f"Failed to fetch country data: {e}")
            return []

    def get_performance_by_device(
        self, days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Fetch search performance broken down by device type.

        Returns:
            List of dicts with device (MOBILE, DESKTOP, TABLET),
            clicks, impressions, ctr, position.
        """
        service = self._get_service()
        if not service:
            return []

        try:
            start_date, end_date = self._date_range(days)

            response = (
                service.searchanalytics()
                .query(
                    siteUrl=self.site_url,
                    body={
                        "startDate": start_date,
                        "endDate": end_date,
                        "dimensions": ["device"],
                        "rowLimit": 10,
                        "orderBy": [
                            {
                                "fieldName": "clicks",
                                "sortOrder": "DESCENDING",
                            }
                        ],
                    },
                )
                .execute()
            )

            return [
                {
                    "device": row["keys"][0],
                    "clicks": row.get("clicks", 0),
                    "impressions": row.get("impressions", 0),
                    "ctr": round(row.get("ctr", 0) * 100, 2),
                    "position": round(row.get("position", 0), 1),
                }
                for row in response.get("rows", [])
            ]

        except Exception as e:
            logger.error(f"Failed to fetch device data: {e}")
            return []

    # ------------------------------------------------------------------
    # Caching layer
    # ------------------------------------------------------------------

    def _write_cache(self, key: str, data: Any) -> None:
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(
                    {"data": data, "cached_at": datetime.now().isoformat()},
                    f,
                    indent=2,
                )
        except Exception as e:
            logger.error(f"Cache write failed for {key}: {e}")

    def _read_cache(self, key: str) -> Optional[Any]:
        cache_file = self.cache_dir / f"{key}.json"
        if not cache_file.exists():
            return None
        try:
            with open(cache_file) as f:
                cached = json.load(f)
            cached_at = datetime.fromisoformat(cached["cached_at"])
            if datetime.now() - cached_at < self.cache_ttl:
                return cached["data"]
        except Exception:
            pass
        return None

    def _read_cache_or_placeholder(
        self, key: str, days: int
    ) -> Dict[str, Any]:
        cached = self._read_cache(key)
        if cached is not None:
            return cached
        return {
            "clicks": 0,
            "impressions": 0,
            "ctr": 0.0,
            "position": 0.0,
            "source": "placeholder",
            "period_days": days,
            "note": "Search Console not configured — using placeholder data",
        }

    def _read_cached_pages(self, limit: int) -> List[PageSearchMetrics]:
        cached = self._read_cache("page_metrics")
        if cached:
            return [PageSearchMetrics(**p) for p in cached[:limit]]
        return []

    def _read_cached_queries(self, limit: int) -> List[QueryMetrics]:
        cached = self._read_cache("top_queries")
        if cached:
            return [QueryMetrics(**q) for q in cached[:limit]]
        return []
```

## TypeScript Search Console Client

```typescript
import { google, searchconsole_v1 } from 'googleapis';
import * as fs from 'fs';

interface GSCConfig {
  siteUrl: string;
  credentialsPath?: string;
  cacheDir?: string;
}

class SearchConsoleClient {
  private service: searchconsole_v1.Searchconsole | null = null;
  private siteUrl: string;
  private credentialsPath?: string;
  private cacheDir: string;

  private static readonly DATA_DELAY_DAYS = 3;

  constructor(config: GSCConfig) {
    this.siteUrl = config.siteUrl;
    this.credentialsPath = config.credentialsPath;
    this.cacheDir = config.cacheDir || './cache/analytics/gsc';

    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  private async getService(): Promise<searchconsole_v1.Searchconsole> {
    if (!this.service) {
      let auth;

      if (this.credentialsPath) {
        auth = new google.auth.GoogleAuth({
          keyFile: this.credentialsPath,
          scopes: ['https://www.googleapis.com/auth/webmasters.readonly'],
        });
      } else if (process.env.GOOGLE_CREDENTIALS_BASE64) {
        const decoded = Buffer.from(
          process.env.GOOGLE_CREDENTIALS_BASE64, 'base64'
        ).toString('utf-8');
        const credentials = JSON.parse(decoded);
        auth = new google.auth.GoogleAuth({
          credentials,
          scopes: ['https://www.googleapis.com/auth/webmasters.readonly'],
        });
      } else {
        auth = new google.auth.GoogleAuth({
          scopes: ['https://www.googleapis.com/auth/webmasters.readonly'],
        });
      }

      this.service = google.searchconsole({ version: 'v1', auth });
    }
    return this.service;
  }

  private dateRange(days: number): { startDate: string; endDate: string } {
    const end = new Date();
    end.setDate(end.getDate() - SearchConsoleClient.DATA_DELAY_DAYS);
    const start = new Date(end);
    start.setDate(start.getDate() - days);

    return {
      startDate: start.toISOString().split('T')[0],
      endDate: end.toISOString().split('T')[0],
    };
  }

  async getSitePerformance(opts: { days?: number } = {}):
    Promise<SiteSearchPerformance> {
    const days = opts.days || 30;
    const service = await this.getService();
    const { startDate, endDate } = this.dateRange(days);

    const response = await service.searchanalytics.query({
      siteUrl: this.siteUrl,
      requestBody: {
        startDate,
        endDate,
        dimensions: [],
        rowLimit: 1,
      },
    });

    const row = response.data.rows?.[0];
    if (!row) throw new Error('No data returned from Search Console');

    return {
      clicks: row.clicks || 0,
      impressions: row.impressions || 0,
      ctr: Math.round((row.ctr || 0) * 10000) / 100,
      position: Math.round((row.position || 0) * 10) / 10,
      periodDays: days,
      startDate,
      endDate,
      fetchedAt: new Date().toISOString(),
    };
  }

  async getTopQueries(opts: { days?: number; limit?: number } = {}):
    Promise<QueryMetrics[]> {
    const { days = 30, limit = 50 } = opts;
    const service = await this.getService();
    const { startDate, endDate } = this.dateRange(days);

    const response = await service.searchanalytics.query({
      siteUrl: this.siteUrl,
      requestBody: {
        startDate,
        endDate,
        dimensions: ['query'],
        rowLimit: limit,
        orderBy: [{ fieldName: 'clicks', sortOrder: 'DESCENDING' }],
      },
    });

    return (response.data.rows || []).map((row) => ({
      query: row.keys![0],
      clicks: row.clicks || 0,
      impressions: row.impressions || 0,
      ctr: Math.round((row.ctr || 0) * 10000) / 100,
      position: Math.round((row.position || 0) * 10) / 10,
      pages: [],
    }));
  }

  async getQueriesForPage(
    pageUrl: string,
    opts: { days?: number; limit?: number } = {}
  ): Promise<QueryMetrics[]> {
    const { days = 30, limit = 20 } = opts;
    const service = await this.getService();
    const { startDate, endDate } = this.dateRange(days);

    const response = await service.searchanalytics.query({
      siteUrl: this.siteUrl,
      requestBody: {
        startDate,
        endDate,
        dimensions: ['query'],
        dimensionFilterGroups: [{
          filters: [{
            dimension: 'page',
            operator: 'equals',
            expression: pageUrl,
          }],
        }],
        rowLimit: limit,
        orderBy: [{ fieldName: 'impressions', sortOrder: 'DESCENDING' }],
      },
    });

    return (response.data.rows || []).map((row) => ({
      query: row.keys![0],
      clicks: row.clicks || 0,
      impressions: row.impressions || 0,
      ctr: Math.round((row.ctr || 0) * 10000) / 100,
      position: Math.round((row.position || 0) * 10) / 10,
      pages: [pageUrl],
    }));
  }
}

export { SearchConsoleClient, GSCConfig };
```

---

# COMBINED SEO ANALYTICS PIPELINE

## Pipeline Architecture

```
Combined SEO Analytics Pipeline
================================

  Trigger: Scheduled (daily/weekly) or on-demand

  Step 1: Data Collection
  ┌───────────┐    ┌────────────────┐
  │ GA4 API   │    │ Search Console │
  │           │    │     API        │
  └─────┬─────┘    └───────┬────────┘
        │                  │
        └────────┬─────────┘
                 │
  Step 2: Data Normalization
  ┌──────────────v──────────────┐
  │  Normalize & Join on URL    │
  │  - GA4 pagePath -> full URL │
  │  - GSC page -> full URL     │
  └──────────────┬──────────────┘
                 │
  Step 3: Cross-Source Analysis
  ┌──────────────v──────────────┐
  │  Unified Page Report        │
  │  - Pageviews + Clicks       │
  │  - Engagement + CTR         │
  │  - Internal vs External     │
  └──────────────┬──────────────┘
                 │
  Step 4: Insights & Storage
  ┌──────────────v──────────────┐
  │  - Store in database        │
  │  - Generate recommendations │
  │  - Detect anomalies         │
  │  - Track trends             │
  └─────────────────────────────┘
```

## Full Pipeline Implementation

```python
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class UnifiedPageReport:
    """Combined GA4 + Search Console metrics for a single URL."""
    url: str
    page_path: str
    page_title: str = ""

    # GA4 metrics
    pageviews: int = 0
    unique_users: int = 0
    avg_time_on_page: float = 0.0
    bounce_rate: float = 0.0
    engagement_rate: float = 0.0

    # Search Console metrics
    search_clicks: int = 0
    search_impressions: int = 0
    search_ctr: float = 0.0
    avg_position: float = 0.0
    top_queries: List[str] = field(default_factory=list)

    # Derived metrics
    @property
    def organic_ratio(self) -> float:
        """Percentage of pageviews from organic search."""
        if self.pageviews == 0:
            return 0.0
        return min(round(self.search_clicks / self.pageviews * 100, 1), 100.0)

    @property
    def content_score(self) -> float:
        """
        Composite content quality score (0-100).

        Weighs engagement, search visibility, and user retention.
        """
        engagement_score = min(self.engagement_rate * 100, 30)
        visibility_score = min(self.search_impressions / 100, 30)
        retention_score = min(self.avg_time_on_page / 10, 20)
        ctr_score = min(self.search_ctr * 2, 20)

        return round(engagement_score + visibility_score + retention_score + ctr_score, 1)

    @property
    def status(self) -> str:
        """Classify page health."""
        score = self.content_score
        if score >= 70:
            return "strong"
        elif score >= 40:
            return "moderate"
        else:
            return "needs_attention"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "page_path": self.page_path,
            "page_title": self.page_title,
            "pageviews": self.pageviews,
            "unique_users": self.unique_users,
            "avg_time_on_page": self.avg_time_on_page,
            "bounce_rate": self.bounce_rate,
            "engagement_rate": self.engagement_rate,
            "search_clicks": self.search_clicks,
            "search_impressions": self.search_impressions,
            "search_ctr": self.search_ctr,
            "avg_position": self.avg_position,
            "top_queries": self.top_queries,
            "organic_ratio": self.organic_ratio,
            "content_score": self.content_score,
            "status": self.status,
        }


class SEOAnalyticsPipeline:
    """
    Combined GA4 + Search Console analytics pipeline.

    Joins data from both sources on URL, produces unified page reports,
    generates SEO recommendations, and detects anomalies.
    """

    def __init__(
        self,
        ga4_client: "GA4Client",
        gsc_client: "SearchConsoleClient",
        site_base_url: str = "",
    ):
        """
        Args:
            ga4_client: Initialized GA4Client instance.
            gsc_client: Initialized SearchConsoleClient instance.
            site_base_url: Base URL for joining GA4 paths with GSC URLs.
                           Example: "https://example.com"
        """
        self.ga4 = ga4_client
        self.gsc = gsc_client
        self.site_base_url = site_base_url.rstrip("/")

    def _normalize_url(self, page_path: str) -> str:
        """Convert a GA4 page path to a full URL for joining with GSC data."""
        if page_path.startswith("http"):
            return page_path
        return f"{self.site_base_url}{page_path}"

    def _extract_path(self, full_url: str) -> str:
        """Extract the path component from a full URL."""
        parsed = urlparse(full_url)
        return parsed.path or "/"

    def run(
        self,
        days: int = 30,
        page_limit: int = 100,
        enrich_queries: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute the full analytics pipeline.

        Args:
            days: Lookback window.
            page_limit: Maximum pages to analyze.
            enrich_queries: If True, fetch per-page queries from GSC
                            (slower but more detailed).

        Returns:
            Dict with unified_pages, summary, recommendations, and
            opportunities.
        """
        logger.info(f"Running SEO analytics pipeline ({days}-day window)")

        # ----------------------------------------------------------
        # Step 1: Collect data from both sources
        # ----------------------------------------------------------
        ga4_pages = self.ga4.get_top_pages(days=days, limit=page_limit)
        gsc_pages = self.gsc.get_page_metrics(days=days, limit=page_limit)
        ga4_overview = self.ga4.get_site_overview(days=days)
        gsc_overview = self.gsc.get_site_performance(days=days)

        # ----------------------------------------------------------
        # Step 2: Build lookup tables
        # ----------------------------------------------------------
        # GA4: keyed by page_path
        ga4_by_path: Dict[str, "PageMetrics"] = {
            p.page_path: p for p in ga4_pages
        }

        # GSC: keyed by normalized path
        gsc_by_path: Dict[str, "PageSearchMetrics"] = {
            self._extract_path(p.page): p for p in gsc_pages
        }

        # Union of all paths
        all_paths = set(ga4_by_path.keys()) | set(gsc_by_path.keys())

        # ----------------------------------------------------------
        # Step 3: Join and produce unified reports
        # ----------------------------------------------------------
        unified_pages: List[UnifiedPageReport] = []

        for path in all_paths:
            ga4_data = ga4_by_path.get(path)
            gsc_data = gsc_by_path.get(path)

            report = UnifiedPageReport(
                url=self._normalize_url(path),
                page_path=path,
            )

            if ga4_data:
                report.page_title = ga4_data.page_title
                report.pageviews = ga4_data.pageviews
                report.unique_users = ga4_data.unique_pageviews
                report.avg_time_on_page = ga4_data.avg_time_on_page
                report.bounce_rate = ga4_data.bounce_rate

            if gsc_data:
                report.search_clicks = gsc_data.clicks
                report.search_impressions = gsc_data.impressions
                report.search_ctr = gsc_data.ctr
                report.avg_position = gsc_data.position

                # Optionally enrich with per-page queries
                if enrich_queries and gsc_data.clicks > 0:
                    queries = self.gsc.get_queries_for_page(
                        gsc_data.page, days=days, limit=5
                    )
                    report.top_queries = [q.query for q in queries]

            unified_pages.append(report)

        # Sort by content score descending
        unified_pages.sort(key=lambda p: p.content_score, reverse=True)

        # ----------------------------------------------------------
        # Step 4: Generate insights
        # ----------------------------------------------------------
        summary = self._build_summary(
            unified_pages, ga4_overview, gsc_overview, days
        )
        recommendations = self._generate_recommendations(unified_pages)
        opportunities = self._find_opportunities(unified_pages)

        return {
            "unified_pages": [p.to_dict() for p in unified_pages],
            "summary": summary,
            "recommendations": recommendations,
            "opportunities": opportunities,
            "generated_at": datetime.now().isoformat(),
            "period_days": days,
        }

    def _build_summary(
        self,
        pages: List[UnifiedPageReport],
        ga4_overview: Dict[str, Any],
        gsc_overview: Dict[str, Any],
        days: int,
    ) -> Dict[str, Any]:
        """Build a high-level summary across both data sources."""
        total_pageviews = sum(p.pageviews for p in pages)
        total_clicks = sum(p.search_clicks for p in pages)
        total_impressions = sum(p.search_impressions for p in pages)

        status_counts = {"strong": 0, "moderate": 0, "needs_attention": 0}
        for p in pages:
            status_counts[p.status] = status_counts.get(p.status, 0) + 1

        avg_score = (
            round(sum(p.content_score for p in pages) / len(pages), 1)
            if pages
            else 0
        )

        return {
            "period_days": days,
            "total_pages_analyzed": len(pages),
            "ga4_total_pageviews": ga4_overview.get("pageviews", 0),
            "ga4_total_users": ga4_overview.get("total_users", 0),
            "gsc_total_clicks": gsc_overview.get("clicks", 0),
            "gsc_total_impressions": gsc_overview.get("impressions", 0),
            "gsc_avg_position": gsc_overview.get("position", 0),
            "gsc_avg_ctr": gsc_overview.get("ctr", 0),
            "avg_content_score": avg_score,
            "page_status_breakdown": status_counts,
        }

    def _generate_recommendations(
        self, pages: List[UnifiedPageReport]
    ) -> List[Dict[str, Any]]:
        """Produce actionable SEO recommendations from page data."""
        recommendations = []

        # High impressions, low CTR -> improve titles/descriptions
        low_ctr_pages = [
            p for p in pages
            if p.search_impressions > 100 and p.search_ctr < 2.0
        ]
        if low_ctr_pages:
            recommendations.append({
                "type": "ctr_optimization",
                "priority": "high",
                "message": (
                    f"{len(low_ctr_pages)} pages have high impressions but "
                    f"low CTR (<2%). Improve title tags and meta descriptions."
                ),
                "pages": [p.page_path for p in low_ctr_pages[:5]],
            })

        # High bounce rate pages
        high_bounce = [
            p for p in pages
            if p.bounce_rate > 0.7 and p.pageviews > 50
        ]
        if high_bounce:
            recommendations.append({
                "type": "engagement_improvement",
                "priority": "medium",
                "message": (
                    f"{len(high_bounce)} pages have bounce rates above 70%. "
                    f"Consider improving content, internal linking, or page speed."
                ),
                "pages": [p.page_path for p in high_bounce[:5]],
            })

        # Pages ranking on page 2 (positions 11-20) — close to page 1
        almost_page_one = [
            p for p in pages
            if 10 < p.avg_position <= 20 and p.search_impressions > 50
        ]
        if almost_page_one:
            recommendations.append({
                "type": "ranking_opportunity",
                "priority": "high",
                "message": (
                    f"{len(almost_page_one)} pages are on page 2 of search results. "
                    f"Targeted optimization could push them to page 1."
                ),
                "pages": [p.page_path for p in almost_page_one[:5]],
            })

        # Top performing content to replicate
        top_content = [p for p in pages if p.content_score >= 70]
        if top_content:
            recommendations.append({
                "type": "content_replication",
                "priority": "low",
                "message": (
                    f"{len(top_content)} pages are performing well. "
                    f"Analyze their patterns for new content ideas."
                ),
                "pages": [p.page_path for p in top_content[:5]],
            })

        return recommendations

    def _find_opportunities(
        self, pages: List[UnifiedPageReport]
    ) -> Dict[str, Any]:
        """
        Identify specific optimization opportunities.
        """
        # Pages with GA4 traffic but no search visibility
        no_search = [
            p for p in pages
            if p.pageviews > 20 and p.search_impressions == 0
        ]

        # Pages with search visibility but no GA4 tracking
        no_ga4 = [
            p for p in pages
            if p.search_clicks > 0 and p.pageviews == 0
        ]

        # Quick-win pages: good position but low CTR
        quick_wins = [
            p for p in pages
            if p.avg_position <= 10 and p.search_ctr < 5.0 and p.search_impressions > 50
        ]

        return {
            "pages_missing_search_visibility": [
                p.page_path for p in no_search[:10]
            ],
            "pages_missing_ga4_tracking": [
                p.page_path for p in no_ga4[:10]
            ],
            "quick_win_ctr_improvements": [
                {
                    "path": p.page_path,
                    "position": p.avg_position,
                    "ctr": p.search_ctr,
                    "impressions": p.search_impressions,
                }
                for p in quick_wins[:10]
            ],
        }
```

## Pipeline Usage Examples

```python
# --- Basic Usage ---

ga4 = GA4Client(property_id="properties/123456789")
gsc = SearchConsoleClient(site_url="https://example.com")

pipeline = SEOAnalyticsPipeline(
    ga4_client=ga4,
    gsc_client=gsc,
    site_base_url="https://example.com",
)

# Run the full pipeline
results = pipeline.run(days=30, page_limit=200, enrich_queries=True)

# Access unified page reports
for page in results["unified_pages"][:10]:
    print(
        f"{page['page_path']}: "
        f"score={page['content_score']}, "
        f"views={page['pageviews']}, "
        f"clicks={page['search_clicks']}, "
        f"position={page['avg_position']}"
    )

# View recommendations
for rec in results["recommendations"]:
    print(f"[{rec['priority'].upper()}] {rec['message']}")

# Quick wins
for qw in results["opportunities"]["quick_win_ctr_improvements"]:
    print(
        f"  {qw['path']}: position {qw['position']}, "
        f"CTR {qw['ctr']}%, impressions {qw['impressions']}"
    )
```

```python
# --- With Category Analysis ---

ga4 = GA4Client(property_id="properties/123456789")
ga4.configure_categories({
    "blog": "blog",
    "docs": "documentation",
    "tutorials": "tutorials",
    "api-reference": "api",
})

# Category-level recommendations
recommendations = ga4.get_content_recommendations(days=30)
print(f"Top category: {recommendations['top_performing_category']}")
print(f"Needs attention: {recommendations['needs_attention']}")
```

```python
# --- Scheduled Daily Report ---

import json
from datetime import datetime

def daily_seo_report():
    """Generate and save a daily SEO report."""
    pipeline = SEOAnalyticsPipeline(
        ga4_client=GA4Client(),
        gsc_client=SearchConsoleClient(),
        site_base_url=os.getenv("SITE_BASE_URL", ""),
    )

    results = pipeline.run(days=7, page_limit=500)

    # Save report
    report_path = f"reports/seo-{datetime.now().strftime('%Y-%m-%d')}.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)

    # Print summary
    summary = results["summary"]
    print(f"SEO Report — {summary['period_days']}-day window")
    print(f"  Pages analyzed: {summary['total_pages_analyzed']}")
    print(f"  GA4 pageviews: {summary['ga4_total_pageviews']}")
    print(f"  Search clicks: {summary['gsc_total_clicks']}")
    print(f"  Avg position: {summary['gsc_avg_position']}")
    print(f"  Content score: {summary['avg_content_score']}")
    print(f"  Recommendations: {len(results['recommendations'])}")

    return results
```

---

# STORING ANALYTICS DATA

## Database Schema (PostgreSQL)

Use this schema with the `database-orm-patterns` module for persistent storage.

```sql
-- Analytics snapshots table
CREATE TABLE analytics_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_date DATE NOT NULL,
    period_days INTEGER NOT NULL DEFAULT 30,
    source VARCHAR(20) NOT NULL,  -- 'ga4', 'gsc', 'combined'
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(snapshot_date, period_days, source)
);

-- Per-page metrics (normalized)
CREATE TABLE page_analytics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    page_path VARCHAR(500) NOT NULL,
    snapshot_date DATE NOT NULL,

    -- GA4 metrics
    pageviews INTEGER DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    avg_time_on_page REAL DEFAULT 0,
    bounce_rate REAL DEFAULT 0,

    -- GSC metrics
    search_clicks INTEGER DEFAULT 0,
    search_impressions INTEGER DEFAULT 0,
    search_ctr REAL DEFAULT 0,
    avg_position REAL DEFAULT 0,

    -- Derived
    content_score REAL DEFAULT 0,
    status VARCHAR(20) DEFAULT 'unknown',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(page_path, snapshot_date)
);

-- Query performance tracking
CREATE TABLE query_analytics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    query TEXT NOT NULL,
    snapshot_date DATE NOT NULL,
    clicks INTEGER DEFAULT 0,
    impressions INTEGER DEFAULT 0,
    ctr REAL DEFAULT 0,
    position REAL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(query, snapshot_date)
);

-- Indexes for common queries
CREATE INDEX idx_page_analytics_date ON page_analytics(snapshot_date);
CREATE INDEX idx_page_analytics_path ON page_analytics(page_path);
CREATE INDEX idx_page_analytics_score ON page_analytics(content_score DESC);
CREATE INDEX idx_query_analytics_date ON query_analytics(snapshot_date);
CREATE INDEX idx_query_analytics_impressions
    ON query_analytics(impressions DESC);
```

## SQLAlchemy ORM Models

```python
from sqlalchemy import (
    Column, String, Integer, Float, Date, DateTime, JSON,
    UniqueConstraint, Index, func
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()


class AnalyticsSnapshot(Base):
    __tablename__ = "analytics_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    snapshot_date = Column(Date, nullable=False)
    period_days = Column(Integer, nullable=False, default=30)
    source = Column(String(20), nullable=False)
    data = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("snapshot_date", "period_days", "source"),
    )


class PageAnalytics(Base):
    __tablename__ = "page_analytics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    page_path = Column(String(500), nullable=False)
    snapshot_date = Column(Date, nullable=False)

    pageviews = Column(Integer, default=0)
    unique_users = Column(Integer, default=0)
    avg_time_on_page = Column(Float, default=0)
    bounce_rate = Column(Float, default=0)

    search_clicks = Column(Integer, default=0)
    search_impressions = Column(Integer, default=0)
    search_ctr = Column(Float, default=0)
    avg_position = Column(Float, default=0)

    content_score = Column(Float, default=0)
    status = Column(String(20), default="unknown")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("page_path", "snapshot_date"),
        Index("idx_page_analytics_score", "content_score"),
    )


class QueryAnalytics(Base):
    __tablename__ = "query_analytics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    query = Column(String, nullable=False)
    snapshot_date = Column(Date, nullable=False)
    clicks = Column(Integer, default=0)
    impressions = Column(Integer, default=0)
    ctr = Column(Float, default=0)
    position = Column(Float, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("query", "snapshot_date"),
    )
```

## Pipeline-to-Database Integration

```python
from sqlalchemy.orm import Session
from datetime import date


def persist_pipeline_results(
    session: Session,
    results: Dict[str, Any],
) -> None:
    """
    Save pipeline results to the database.

    Integrates with the database-orm-patterns module for session management.
    """
    today = date.today()

    # Save raw snapshot
    snapshot = AnalyticsSnapshot(
        snapshot_date=today,
        period_days=results["period_days"],
        source="combined",
        data=results["summary"],
    )
    session.merge(snapshot)

    # Save per-page data
    for page_data in results["unified_pages"]:
        page = PageAnalytics(
            page_path=page_data["page_path"],
            snapshot_date=today,
            pageviews=page_data["pageviews"],
            unique_users=page_data["unique_users"],
            avg_time_on_page=page_data["avg_time_on_page"],
            bounce_rate=page_data["bounce_rate"],
            search_clicks=page_data["search_clicks"],
            search_impressions=page_data["search_impressions"],
            search_ctr=page_data["search_ctr"],
            avg_position=page_data["avg_position"],
            content_score=page_data["content_score"],
            status=page_data["status"],
        )
        session.merge(page)

    session.commit()
    logger.info(
        f"Persisted {len(results['unified_pages'])} page records "
        f"for {today}"
    )
```

---

# SCHEDULED DATA COLLECTION

## Integration with scheduling-framework

```python
from datetime import datetime, timedelta

# Daily collection schedule
ANALYTICS_SCHEDULES = {
    "daily_seo_pipeline": {
        "cron": "0 6 * * *",         # 6:00 AM daily
        "function": "run_daily_pipeline",
        "description": "Full GA4 + GSC pipeline with database persistence",
        "timeout_minutes": 15,
    },
    "weekly_deep_analysis": {
        "cron": "0 8 * * 1",         # 8:00 AM every Monday
        "function": "run_weekly_analysis",
        "description": "Deep content analysis with query enrichment",
        "timeout_minutes": 30,
    },
    "hourly_realtime_check": {
        "cron": "0 * * * *",         # Every hour
        "function": "check_realtime_traffic",
        "description": "Quick active user count check",
        "timeout_minutes": 2,
    },
}


def run_daily_pipeline():
    """Daily pipeline execution — integrate with scheduling-framework."""
    ga4 = GA4Client()
    gsc = SearchConsoleClient()

    pipeline = SEOAnalyticsPipeline(
        ga4_client=ga4,
        gsc_client=gsc,
        site_base_url=os.getenv("SITE_BASE_URL", ""),
    )

    # 7-day window for daily runs, skip expensive query enrichment
    results = pipeline.run(
        days=7,
        page_limit=200,
        enrich_queries=False,
    )

    # Persist to database (uses database-orm-patterns)
    from database import get_session

    with get_session() as session:
        persist_pipeline_results(session, results)

    return {
        "status": "success",
        "pages_analyzed": len(results["unified_pages"]),
        "recommendations": len(results["recommendations"]),
    }


def run_weekly_analysis():
    """
    Weekly deep analysis with full query enrichment.
    Uses batch-processing skill for rate-limited GSC calls.
    """
    ga4 = GA4Client()
    gsc = SearchConsoleClient()

    pipeline = SEOAnalyticsPipeline(
        ga4_client=ga4,
        gsc_client=gsc,
        site_base_url=os.getenv("SITE_BASE_URL", ""),
    )

    # 30-day window with full query enrichment
    results = pipeline.run(
        days=30,
        page_limit=500,
        enrich_queries=True,
    )

    # Store opportunities for follow-up
    opportunities = results.get("opportunities", {})
    quick_wins = opportunities.get("quick_win_ctr_improvements", [])

    logger.info(
        f"Weekly analysis complete: "
        f"{len(quick_wins)} quick-win opportunities found"
    )

    return results


def check_realtime_traffic():
    """Quick real-time check for monitoring dashboards."""
    ga4 = GA4Client()
    return ga4.get_realtime_overview()
```

## APScheduler Integration Example

```python
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

scheduler = BackgroundScheduler()

# Register analytics jobs
scheduler.add_job(
    run_daily_pipeline,
    CronTrigger.from_crontab("0 6 * * *"),
    id="daily_seo_pipeline",
    name="Daily SEO Pipeline",
    max_instances=1,
    misfire_grace_time=3600,
)

scheduler.add_job(
    run_weekly_analysis,
    CronTrigger.from_crontab("0 8 * * 1"),
    id="weekly_deep_analysis",
    name="Weekly Deep SEO Analysis",
    max_instances=1,
    misfire_grace_time=7200,
)

scheduler.start()
```

## Celery Integration Example

```python
from celery import Celery
from celery.schedules import crontab

app = Celery("analytics")

app.conf.beat_schedule = {
    "daily-seo-pipeline": {
        "task": "analytics.tasks.run_daily_pipeline",
        "schedule": crontab(hour=6, minute=0),
    },
    "weekly-deep-analysis": {
        "task": "analytics.tasks.run_weekly_analysis",
        "schedule": crontab(hour=8, minute=0, day_of_week=1),
    },
}


@app.task(bind=True, max_retries=3, default_retry_delay=300)
def run_daily_pipeline_task(self):
    try:
        return run_daily_pipeline()
    except Exception as exc:
        raise self.retry(exc=exc)
```

---

# BATCH DATA COLLECTION

## Integration with batch-processing Skill

When collecting data for many pages or queries, use the `batch-processing` skill to handle rate limits and error recovery.

```python
from batch_processor import RateLimitedBatchProcessor


def batch_collect_page_queries(
    gsc_client: SearchConsoleClient,
    page_urls: List[str],
    days: int = 30,
) -> Dict[str, List[QueryMetrics]]:
    """
    Collect search queries for a large number of pages.

    Uses the batch-processing skill for rate limiting and checkpointing.
    GSC rate limit: 1,200 requests/minute = 20 requests/second.
    """
    results: Dict[str, List[QueryMetrics]] = {}

    def fetch_queries(page_url: str) -> bool:
        queries = gsc_client.get_queries_for_page(
            page_url, days=days, limit=20
        )
        results[page_url] = queries
        return True

    processor = RateLimitedBatchProcessor(
        requests_per_second=15,   # Conservative to stay under limit
        batch_size=50,
        max_retries=3,
        checkpoint_file=".gsc_query_checkpoint.json",
    )

    batch_result = processor.process(page_urls, fetch_queries)

    logger.info(
        f"Batch query collection: "
        f"{batch_result.successful}/{batch_result.total_items} pages, "
        f"{batch_result.failed} failures, "
        f"{batch_result.duration_seconds:.1f}s"
    )

    return results
```

---

# ENVIRONMENT VARIABLES REFERENCE

| Variable | Required | Description | Example |
|---|---|---|---|
| `GA4_PROPERTY_ID` | Yes (for GA4) | GA4 property identifier | `properties/123456789` |
| `GSC_SITE_URL` | Yes (for GSC) | Site URL in Search Console | `https://example.com` |
| `GOOGLE_CREDENTIALS_PATH` | One of three | Path to service account JSON | `./service-account.json` |
| `GOOGLE_CREDENTIALS_BASE64` | One of three | Base64-encoded service account | `eyJ0eXBlIjoi...` |
| `GOOGLE_APPLICATION_CREDENTIALS` | One of three | GCP default credentials path | `/path/to/creds.json` |
| `ANALYTICS_CACHE_DIR` | No | Cache directory | `./cache/analytics` |
| `ANALYTICS_CACHE_TTL_HOURS` | No | Cache TTL (default: 1 for GA4, 6 for GSC) | `2` |
| `SITE_BASE_URL` | No | Base URL for path-to-URL joins | `https://example.com` |

### Service Account Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Enable the **Google Analytics Data API** and **Search Console API**
4. Create a service account under **IAM & Admin > Service Accounts**
5. Download the JSON key file
6. In GA4: Add the service account email as a **Viewer** under Admin > Property Access
7. In Search Console: Add the service account email as a **Full** user under Settings > Users and permissions

### Base64 Encoding for Cloud Deployments

```bash
# Encode credentials for environment variable storage
base64 -i service-account.json | tr -d '\n'

# In your .env or deployment config:
# GOOGLE_CREDENTIALS_BASE64=<paste the output>
```

---

# INTEGRATES WITH

## unified-api-client Module

The GA4 and Search Console clients follow the same authenticated HTTP client pattern as the `unified-api-client` module:

- **Lazy client initialization** with `_get_client()` / `_get_service()` pattern
- **Multi-strategy authentication** (file, base64, default credentials)
- **Retry logic** through Google SDK built-in retry or batch-processing wrapper
- **Connection reuse** via singleton client instances

When building custom API extensions on top of these clients, use the `unified-api-client` module's base class for consistency.

## batch-processing Skill

Use the `batch-processing` skill when:

- Collecting query data for more than 50 pages (rate-limited GSC calls)
- Running category-level performance analysis across many categories
- Performing bulk historical data backfills
- Processing pipeline results for large numbers of pages

The `RateLimitedBatchProcessor` from the batch-processing skill is the recommended wrapper for high-volume GSC query collection (see the Batch Data Collection section above).

## database-orm-patterns Module

Analytics data should be persisted using patterns from the `database-orm-patterns` module:

- **SQLAlchemy models** for `page_analytics`, `query_analytics`, and `analytics_snapshots` tables (schemas provided above)
- **Connection pooling** for scheduled pipeline runs
- **Cursor pagination** for querying historical analytics data
- **Bulk insert** for efficient storage of pipeline results

## scheduling-framework Module

Integrate with the `scheduling-framework` module for automated data collection:

- **Daily pipeline** (6 AM): 7-day window, 200 pages, no query enrichment
- **Weekly deep analysis** (Monday 8 AM): 30-day window, 500 pages, full queries
- **Hourly real-time check**: Active user count for dashboards

Use APScheduler, Celery, or cron-based scheduling depending on your infrastructure (examples provided in the Scheduled Data Collection section above).

---

# TROUBLESHOOTING

## Common Issues

| Issue | Cause | Solution |
|---|---|---|
| `google-analytics-data not installed` | Missing Python package | `pip install google-analytics-data` |
| `google-api-python-client not installed` | Missing Python package | `pip install google-api-python-client` |
| `Failed to create GA4 client` | Invalid credentials or property ID | Verify service account has Viewer access to the GA4 property |
| `Failed to create Search Console service` | Invalid credentials or site URL | Verify service account is added as a user in Search Console |
| `No data returned` | Property ID format wrong | Use `properties/XXXXXXXXX` format (not just the number) |
| GSC returns empty results | Data delay | GSC data has a 3-day delay; adjust date range accordingly |
| `403 Forbidden` | Insufficient permissions | Grant the service account the correct role in GA4/GSC |
| Rate limit errors | Too many requests | Use the batch-processing skill with `RateLimitedBatchProcessor` |

## Verifying Configuration

```python
# Quick configuration check
ga4 = GA4Client()
gsc = SearchConsoleClient()

print(f"GA4 configured: {ga4.is_configured()}")
print(f"GA4 property: {ga4.property_id}")
print(f"GSC configured: {gsc.is_configured()}")
print(f"GSC site URL: {gsc.site_url}")

# Test connectivity
if ga4.is_configured():
    overview = ga4.get_site_overview(days=1)
    if overview.get("source") != "placeholder":
        print("GA4 connection: OK")
    else:
        print("GA4 connection: FAILED (using placeholder data)")

if gsc.is_configured():
    perf = gsc.get_site_performance(days=1)
    if perf.get("source") != "placeholder":
        print("GSC connection: OK")
    else:
        print("GSC connection: FAILED (using placeholder data)")
```

---

# BEST PRACTICES

## 1. Data Freshness

- GA4 data is near real-time (4-8 hour lag).
- Search Console data has a **3-day delay** — never query the most recent 3 days.
- Cache GA4 data for 1 hour and GSC data for 6 hours to balance freshness vs. API usage.

## 2. Rate Limits

- GA4 Data API: 10 concurrent requests per property. Avoid parallel calls to the same property.
- Search Console API: 1,200 requests/minute. Use `RateLimitedBatchProcessor` at 15 req/sec for safety.

## 3. Credential Security

- Never commit service account JSON files to version control.
- Use base64-encoded credentials in CI/CD and cloud environments.
- Rotate service account keys every 90 days.
- Grant minimum required permissions (Viewer for GA4, Read-only for GSC).

## 4. Graceful Degradation

- All client methods fall back to cached data when the API is unreachable.
- Cached data falls back to placeholder data when no cache exists.
- This makes the entire pipeline safe to run in local development without credentials.

## 5. Content Score Tuning

The `UnifiedPageReport.content_score` weights can be adjusted for your use case:

```python
# Default weights (sum to 100):
# engagement_rate: 30 points
# search_impressions: 30 points
# avg_time_on_page: 20 points
# search_ctr: 20 points

# E-commerce sites might weight conversions higher
# Blog sites might weight time-on-page higher
# SaaS docs might weight search visibility higher
```

## 6. URL Normalization

When joining GA4 and GSC data, ensure consistent URL normalization:

- GA4 reports page paths (e.g., `/blog/my-post/`)
- GSC reports full URLs (e.g., `https://example.com/blog/my-post/`)
- The pipeline's `_normalize_url()` and `_extract_path()` handle this join
- Watch for trailing slash inconsistencies between the two sources
