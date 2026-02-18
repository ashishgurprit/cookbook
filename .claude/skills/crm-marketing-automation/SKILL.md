---
name: crm-marketing-automation
description: "Production CRM and marketing automation integration for Mautic (primary) and HubSpot (secondary). Use when: (1) Building contact management and lead capture, (2) Integrating marketing automation platforms, (3) Setting up campaign triggers and segment management, (4) Implementing lead scoring engines, (5) Embedding forms and tracking scripts, (6) Building webhook ingestion for CRM events, (7) Syncing contacts across channels. Triggers on 'CRM', 'Mautic', 'HubSpot', 'marketing automation', 'lead scoring', 'contact management', 'campaign', 'segment', 'lead pipeline', or 'form embed'."
license: Proprietary
---

# CRM & Marketing Automation - Production Integration Guide

**Version**: 1.0.0
**Last Updated**: 2026-02-16
**Primary CRM**: Mautic (open-source, self-hosted)
**Secondary CRM**: HubSpot (SaaS)
**Languages**: Python + TypeScript

> Complete production-ready CRM integration covering contact lifecycle management, marketing automation, lead scoring, campaign orchestration, and cross-platform sync. Extracted from production Mautic deployment at cloudgeeks.com.au.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Module Dependency Diagram](#module-dependency-diagram)
3. [Quick Start](#quick-start)
4. [Mautic API Integration](#mautic-api-integration)
5. [HubSpot API Integration](#hubspot-api-integration)
6. [Lead Scoring Engine](#lead-scoring-engine)
7. [Webhook Ingestion Patterns](#webhook-ingestion-patterns)
8. [Form Embeds & Tracking Scripts](#form-embeds--tracking-scripts)
9. [Pipeline Management](#pipeline-management)
10. [Bulk Operations](#bulk-operations)
11. [Environment Variables](#environment-variables)
12. [Testing Strategy](#testing-strategy)
13. [Integrates With](#integrates-with)

---

## Architecture Overview

### CRM Integration Strategy

**Why Mautic as Primary?**
- Self-hosted: full data ownership and GDPR compliance
- Open-source: no per-contact pricing, unlimited contacts
- REST API: complete programmatic control
- Plugin ecosystem: extensible with custom fields and segments
- Cost: $0 software license vs $800+/month for HubSpot Marketing Hub

**Why HubSpot as Secondary?**
- Industry-standard CRM for sales teams
- Superior deal/pipeline UI out of the box
- Ecosystem integrations (Salesforce, Zoom, etc.)
- Free tier covers basic CRM needs

**Architecture Diagram**:
```
┌──────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│   (Web App / Mobile App / Content Pipeline / API Gateway)    │
└──────────────┬──────────────────────────────┬────────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────┐  ┌──────────────────────────────┐
│   CRM Automation Service │  │   Webhook Ingestion Service  │
│   - Contact CRUD         │  │   - Mautic webhooks          │
│   - Segment management   │  │   - HubSpot webhooks         │
│   - Campaign triggers    │  │   - Form submissions         │
│   - Lead scoring         │  │   - Event tracking           │
└──────────┬───────────────┘  └──────────────┬───────────────┘
           │                                 │
    ┌──────┴──────┐                   ┌──────┴──────┐
    │             │                   │             │
    ▼             ▼                   ▼             ▼
┌─────────┐ ┌──────────┐      ┌──────────┐  ┌──────────┐
│ Mautic  │ │ HubSpot  │      │ Contact  │  │ Event    │
│  API    │ │  API     │      │   DB     │  │  Queue   │
│ (REST)  │ │ (REST)   │      │ (Local)  │  │ (Redis)  │
└─────────┘ └──────────┘      └──────────┘  └──────────┘
    │             │
    └──────┬──────┘
           ▼
┌──────────────────────────┐
│    Notification Router   │
│  (email/push/webhook)    │
└──────────────────────────┘
```

---

## Module Dependency Diagram

This skill integrates with five existing modules/skills in the Streamlined Development ecosystem:

```
                    ┌──────────────────────────────┐
                    │  crm-marketing-automation    │
                    │  (this skill)                │
                    └──────────┬───────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ unified-api-     │ │ omni-channel-    │ │ database-orm-    │
│ client (module)  │ │ core (module)    │ │ patterns (module)│
│                  │ │                  │ │                  │
│ - Base HTTP      │ │ - Cross-channel  │ │ - Contact/lead   │
│   client         │ │   marketing      │ │   storage        │
│ - Retry logic    │ │ - Has mautic.py  │ │ - Schema design  │
│ - Auth providers │ │   sync code      │ │ - Migrations     │
│ - Rate limiting  │ │ - Channel        │ │ - Query patterns │
│                  │ │   coordination   │ │                  │
└──────────────────┘ └──────────────────┘ └──────────────────┘
          │                    │
          ▼                    ▼
┌──────────────────┐ ┌──────────────────┐
│ notification-    │ │ batch-processing │
│ universal (skill)│ │ (skill)          │
│                  │ │                  │
│ - Email triggers │ │ - Bulk contact   │
│ - Push notifs    │ │   imports        │
│ - Webhook sends  │ │ - Mass segment   │
│ - Channel router │ │   updates        │
│ - Delivery       │ │ - Campaign batch │
│   tracking       │ │   operations     │
│                  │ │ - Progress/retry │
└──────────────────┘ └──────────────────┘
```

**Dependency Usage**:
| Dependency | Import Path | Used For |
|---|---|---|
| `unified-api-client` | `from modules.api_client import UnifiedClient` | Base HTTP with retry, auth headers, rate limit handling |
| `omni-channel-core` | `from modules.omni_channel import ChannelSync` | Cross-channel contact sync (Mautic <-> local DB) |
| `notification-universal` | `from skills.notifications import NotificationRouter` | Triggering emails, push, webhooks on CRM events |
| `batch-processing` | `from skills.batch import BatchProcessor` | Bulk contact imports, mass segment operations |
| `database-orm-patterns` | `from modules.database import ContactModel` | Local contact/lead storage, query optimization |

---

## Quick Start

### Python Quick Start

```python
"""
CRM Marketing Automation - Quick Start
Requires: pip install requests python-dotenv
"""
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime
import requests
from dotenv import load_dotenv

load_dotenv()


# --- Configuration ---

@dataclass
class CRMConfig:
    """Centralized CRM configuration."""
    # Mautic
    mautic_base_url: str = os.getenv("MAUTIC_BASE_URL", "")
    mautic_username: str = os.getenv("MAUTIC_USERNAME", "")
    mautic_password: str = os.getenv("MAUTIC_PASSWORD", "")

    # HubSpot
    hubspot_api_key: str = os.getenv("HUBSPOT_API_KEY", "")
    hubspot_base_url: str = "https://api.hubapi.com"

    # General
    project_source: str = os.getenv("PROJECT_SOURCE", "my-app")
    default_tags: List[str] = field(default_factory=lambda: ["app-signup"])

    def mautic_configured(self) -> bool:
        return bool(self.mautic_base_url and self.mautic_username and self.mautic_password)

    def hubspot_configured(self) -> bool:
        return bool(self.hubspot_api_key)


# --- Usage ---

config = CRMConfig()

# Initialize Mautic
from crm_client import MauticCRMClient  # see full implementation below
mautic = MauticCRMClient(config)

# Create a contact
contact = mautic.create_or_update_contact(
    email="user@example.com",
    firstname="Jane",
    lastname="Doe",
    custom_fields={"preferred_plan": "pro"},
    tags=["trial-user", "webinar-attendee"]
)

# Add to segment
mautic.add_to_segment(contact.id, segment_id=5)

# Trigger campaign
mautic.trigger_campaign(campaign_id=3, contact_id=contact.id)

# Record an event for lead scoring
mautic.record_event(contact.id, event_type="page_view", metadata={"page": "/pricing"})
```

### TypeScript Quick Start

```typescript
/**
 * CRM Marketing Automation - Quick Start
 * Requires: npm install axios dotenv
 */
import axios, { AxiosInstance } from 'axios';
import dotenv from 'dotenv';

dotenv.config();

// --- Configuration ---

interface CRMConfig {
  mautic: {
    baseUrl: string;
    username: string;
    password: string;
  };
  hubspot: {
    apiKey: string;
    baseUrl: string;
  };
  projectSource: string;
}

const config: CRMConfig = {
  mautic: {
    baseUrl: process.env.MAUTIC_BASE_URL || '',
    username: process.env.MAUTIC_USERNAME || '',
    password: process.env.MAUTIC_PASSWORD || '',
  },
  hubspot: {
    apiKey: process.env.HUBSPOT_API_KEY || '',
    baseUrl: 'https://api.hubapi.com',
  },
  projectSource: process.env.PROJECT_SOURCE || 'my-app',
};

// --- Mautic Client ---

class MauticClient {
  private client: AxiosInstance;

  constructor(private config: CRMConfig['mautic']) {
    this.client = axios.create({
      baseURL: `${config.baseUrl}/api`,
      auth: { username: config.username, password: config.password },
      headers: { 'Content-Type': 'application/json' },
      timeout: 30_000,
    });
  }

  async createContact(data: {
    email: string;
    firstname?: string;
    lastname?: string;
    tags?: string[];
    [key: string]: unknown;
  }) {
    const response = await this.client.post('/contacts/new', data);
    return response.data.contact;
  }

  async getContactByEmail(email: string) {
    const response = await this.client.get('/contacts', {
      params: { search: `email:${email}` },
    });
    const contacts = response.data.contacts;
    const firstKey = Object.keys(contacts)[0];
    return firstKey ? contacts[firstKey] : null;
  }

  async addToSegment(contactId: number, segmentId: number) {
    await this.client.post(`/segments/${segmentId}/contact/${contactId}/add`);
  }

  async triggerCampaign(campaignId: number, contactId: number) {
    await this.client.post(`/campaigns/${campaignId}/contact/${contactId}/add`);
  }
}

// --- Usage ---

const mautic = new MauticClient(config.mautic);

async function onUserSignup(email: string, name: string) {
  const contact = await mautic.createContact({
    email,
    firstname: name.split(' ')[0],
    lastname: name.split(' ').slice(1).join(' '),
    tags: ['signup', 'trial'],
  });

  await mautic.addToSegment(contact.id, 1); // Welcome segment
  await mautic.triggerCampaign(2, contact.id); // Onboarding campaign
}
```

---

## Mautic API Integration

### Contact Data Model

```python
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class ContactStage(Enum):
    """Contact lifecycle stages in the marketing funnel."""
    VISITOR = "visitor"
    SUBSCRIBER = "subscriber"
    LEAD = "lead"
    MQL = "marketing_qualified_lead"
    SQL = "sales_qualified_lead"
    OPPORTUNITY = "opportunity"
    CUSTOMER = "customer"
    EVANGELIST = "evangelist"


@dataclass
class CRMContact:
    """
    Generalized CRM contact model.
    Maps to both Mautic and HubSpot contact schemas.
    Use database-orm-patterns module for local storage of this model.
    """
    id: Optional[int] = None
    email: str = ""
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    company: Optional[str] = None
    phone: Optional[str] = None
    stage: ContactStage = ContactStage.VISITOR
    score: int = 0
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    project_source: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    # Engagement metrics
    total_events: int = 0
    last_active: Optional[datetime] = None

    def to_mautic_payload(self) -> Dict[str, Any]:
        """Convert to Mautic API payload format."""
        payload: Dict[str, Any] = {"email": self.email}
        if self.firstname:
            payload["firstname"] = self.firstname
        if self.lastname:
            payload["lastname"] = self.lastname
        if self.company:
            payload["company"] = self.company
        if self.phone:
            payload["phone"] = self.phone
        if self.tags:
            payload["tags"] = self.tags
        if self.project_source:
            payload["project_source"] = self.project_source
        payload["score"] = self.score
        # Flatten custom fields into payload
        payload.update(self.custom_fields)
        return payload

    def to_hubspot_payload(self) -> Dict[str, Any]:
        """Convert to HubSpot API properties format."""
        properties: Dict[str, str] = {
            "email": self.email,
            "lifecyclestage": self._stage_to_hubspot(),
            "hs_lead_status": "NEW",
        }
        if self.firstname:
            properties["firstname"] = self.firstname
        if self.lastname:
            properties["lastname"] = self.lastname
        if self.company:
            properties["company"] = self.company
        if self.phone:
            properties["phone"] = self.phone
        return {"properties": properties}

    def _stage_to_hubspot(self) -> str:
        stage_map = {
            ContactStage.VISITOR: "subscriber",
            ContactStage.SUBSCRIBER: "subscriber",
            ContactStage.LEAD: "lead",
            ContactStage.MQL: "marketingqualifiedlead",
            ContactStage.SQL: "salesqualifiedlead",
            ContactStage.OPPORTUNITY: "opportunity",
            ContactStage.CUSTOMER: "customer",
            ContactStage.EVANGELIST: "evangelist",
        }
        return stage_map.get(self.stage, "subscriber")

    @classmethod
    def from_mautic_response(cls, data: Dict[str, Any], project_source: str = "") -> "CRMContact":
        """Parse Mautic API contact response into CRMContact."""
        fields = data.get("fields", {}).get("all", {})
        return cls(
            id=data.get("id"),
            email=fields.get("email", ""),
            firstname=fields.get("firstname"),
            lastname=fields.get("lastname"),
            company=fields.get("company"),
            phone=fields.get("phone"),
            score=int(data.get("points", 0) or 0),
            tags=[t.get("tag", "") for t in data.get("tags", []) if isinstance(t, dict)],
            project_source=fields.get("project_source", project_source),
            custom_fields={
                k: v for k, v in fields.items()
                if k not in {"email", "firstname", "lastname", "company", "phone", "project_source"}
            },
            created_at=datetime.fromisoformat(data["dateAdded"]) if data.get("dateAdded") else None,
            updated_at=datetime.fromisoformat(data["dateModified"]) if data.get("dateModified") else None,
        )
```

### Full Mautic Client (Production)

```python
import logging
import time
from typing import Optional, Dict, Any, List, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("crm.mautic")


class MauticCRMClient:
    """
    Production Mautic CRM client with retry logic, rate limiting,
    and comprehensive contact/segment/campaign management.

    Leverages unified-api-client patterns for HTTP resilience.
    """

    def __init__(self, config: "CRMConfig"):
        self.base_url = config.mautic_base_url.rstrip("/")
        self.username = config.mautic_username
        self.password = config.mautic_password
        self.project_source = config.project_source

        # Configure session with retry (unified-api-client pattern)
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PATCH", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.auth = (self.username, self.password)
        self.session.headers.update({"Content-Type": "application/json"})

        # Rate limiting state
        self._last_request_time = 0.0
        self._min_request_interval = 0.1  # 100ms between requests

    def is_configured(self) -> bool:
        """Check if Mautic client has valid credentials."""
        return bool(self.base_url and self.username and self.password)

    # =========================================================================
    # Core HTTP Layer
    # =========================================================================

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """
        Make authenticated request to Mautic API with rate limiting and retry.

        Uses unified-api-client pattern: retry on 429/5xx, exponential backoff,
        structured error logging.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint path (e.g., /api/contacts/new)
            data: JSON request body
            params: URL query parameters

        Returns:
            Response JSON dict, or None on error
        """
        # Rate limiting
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.monotonic()

        url = f"{self.base_url}{endpoint}"

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=30,
            )

            if response.status_code in (200, 201):
                return response.json()

            logger.warning(
                "Mautic API error",
                extra={
                    "status": response.status_code,
                    "endpoint": endpoint,
                    "response": response.text[:500],
                },
            )
            return None

        except requests.exceptions.RequestException as e:
            logger.error(
                "Mautic request failed",
                extra={"endpoint": endpoint, "error": str(e)},
            )
            return None

    # =========================================================================
    # Contact Management
    # =========================================================================

    def create_contact(
        self,
        email: str,
        firstname: Optional[str] = None,
        lastname: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Optional[CRMContact]:
        """
        Create a new contact in Mautic.

        Args:
            email: Contact email address (required)
            firstname: First name
            lastname: Last name
            custom_fields: Dict of custom field name -> value
            tags: List of tag strings to apply

        Returns:
            CRMContact on success, None on failure
        """
        payload: Dict[str, Any] = {
            "email": email,
            "project_source": self.project_source,
        }

        if firstname:
            payload["firstname"] = firstname
        if lastname:
            payload["lastname"] = lastname
        if tags:
            payload["tags"] = tags
        if custom_fields:
            payload.update(custom_fields)

        result = self._request("POST", "/api/contacts/new", payload)

        if result and "contact" in result:
            return CRMContact.from_mautic_response(result["contact"], self.project_source)

        return None

    def get_contact_by_email(self, email: str) -> Optional[CRMContact]:
        """
        Look up a contact by email address.

        Uses Mautic search syntax: search=email:user@example.com

        Args:
            email: Email to search for

        Returns:
            CRMContact if found, None otherwise
        """
        result = self._request("GET", "/api/contacts", params={"search": f"email:{email}"})

        if result and "contacts" in result:
            contacts = result["contacts"]
            if contacts:
                contact_id = list(contacts.keys())[0]
                return CRMContact.from_mautic_response(
                    contacts[contact_id], self.project_source
                )

        return None

    def create_or_update_contact(
        self,
        email: str,
        firstname: Optional[str] = None,
        lastname: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Optional[CRMContact]:
        """
        Upsert pattern: find existing contact or create new one.

        This is the preferred method for most integrations. Prevents
        duplicate contacts and ensures field updates are applied.

        Args:
            email: Contact email (lookup key)
            firstname: First name (updated if provided)
            lastname: Last name (updated if provided)
            custom_fields: Custom fields to merge
            tags: Tags to add (additive, never removes existing tags)

        Returns:
            CRMContact with current state
        """
        existing = self.get_contact_by_email(email)

        if existing:
            update_data: Dict[str, Any] = {}
            if firstname:
                update_data["firstname"] = firstname
            if lastname:
                update_data["lastname"] = lastname
            if custom_fields:
                update_data.update(custom_fields)
            if tags:
                update_data["tags"] = list(set((existing.tags or []) + tags))

            if update_data:
                self.update_contact(existing.id, update_data)
                # Re-fetch to get merged state
                return self.get_contact_by_email(email)

            return existing

        return self.create_contact(
            email=email,
            firstname=firstname,
            lastname=lastname,
            custom_fields=custom_fields,
            tags=tags,
        )

    def update_contact(self, contact_id: int, data: Dict[str, Any]) -> bool:
        """
        Update specific fields on an existing contact.

        Args:
            contact_id: Mautic internal contact ID
            data: Dict of field_name -> new_value

        Returns:
            True if update succeeded
        """
        result = self._request("PATCH", f"/api/contacts/{contact_id}/edit", data)
        return result is not None

    def delete_contact(self, contact_id: int) -> bool:
        """
        Permanently delete a contact. Use with caution.

        For GDPR right-to-erasure compliance.

        Args:
            contact_id: Mautic internal contact ID

        Returns:
            True if deletion succeeded
        """
        result = self._request("DELETE", f"/api/contacts/{contact_id}/delete")
        return result is not None

    def search_contacts(
        self,
        search_query: str,
        start: int = 0,
        limit: int = 30,
        order_by: str = "date_added",
        order_dir: str = "DESC",
    ) -> Tuple[List[CRMContact], int]:
        """
        Search contacts using Mautic search syntax.

        Search syntax examples:
            - "email:*@company.com"       (email domain)
            - "tag:vip"                   (tagged contacts)
            - "segment:newsletter"        (segment members)
            - "!is:anonymous"             (known contacts only)
            - "owner:admin"               (owned by admin)

        Args:
            search_query: Mautic search string
            start: Pagination offset
            limit: Results per page (max 100)
            order_by: Sort field
            order_dir: Sort direction (ASC/DESC)

        Returns:
            Tuple of (contacts list, total count)
        """
        result = self._request(
            "GET",
            "/api/contacts",
            params={
                "search": search_query,
                "start": start,
                "limit": min(limit, 100),
                "orderBy": order_by,
                "orderByDir": order_dir,
            },
        )

        if result and "contacts" in result:
            contacts = [
                CRMContact.from_mautic_response(c, self.project_source)
                for c in result["contacts"].values()
            ]
            total = result.get("total", len(contacts))
            return contacts, total

        return [], 0

    # =========================================================================
    # Segment Management
    # =========================================================================

    def list_segments(self) -> List[Dict[str, Any]]:
        """
        List all available segments.

        Returns:
            List of segment dicts with id, name, description, alias
        """
        result = self._request("GET", "/api/segments")

        if result and "lists" in result:
            return [
                {
                    "id": seg.get("id"),
                    "name": seg.get("name"),
                    "alias": seg.get("alias"),
                    "description": seg.get("description"),
                    "publicName": seg.get("publicName"),
                }
                for seg in result["lists"].values()
            ]

        return []

    def create_segment(
        self,
        name: str,
        alias: Optional[str] = None,
        description: str = "",
        is_published: bool = True,
        filters: Optional[List[Dict]] = None,
    ) -> Optional[Dict]:
        """
        Create a new contact segment.

        Filter example (contacts with score > 50):
        [
            {
                "glue": "and",
                "field": "score",
                "object": "lead",
                "type": "number",
                "operator": "gt",
                "filter": "50"
            }
        ]

        Args:
            name: Segment display name
            alias: URL-safe alias (auto-generated if None)
            description: Segment description
            is_published: Whether segment is active
            filters: List of filter criteria dicts

        Returns:
            Segment data dict on success
        """
        payload: Dict[str, Any] = {
            "name": name,
            "description": description,
            "isPublished": is_published,
        }
        if alias:
            payload["alias"] = alias
        if filters:
            payload["filters"] = filters

        result = self._request("POST", "/api/segments/new", payload)
        return result.get("list") if result else None

    def add_to_segment(self, contact_id: int, segment_id: int) -> bool:
        """
        Add a contact to a segment.

        Args:
            contact_id: Mautic contact ID
            segment_id: Mautic segment ID

        Returns:
            True if successful
        """
        result = self._request(
            "POST",
            f"/api/segments/{segment_id}/contact/{contact_id}/add",
        )
        return result is not None

    def remove_from_segment(self, contact_id: int, segment_id: int) -> bool:
        """
        Remove a contact from a segment.

        Args:
            contact_id: Mautic contact ID
            segment_id: Mautic segment ID

        Returns:
            True if successful
        """
        result = self._request(
            "POST",
            f"/api/segments/{segment_id}/contact/{contact_id}/remove",
        )
        return result is not None

    # =========================================================================
    # Campaign Management
    # =========================================================================

    def list_campaigns(self, published_only: bool = True) -> List[Dict[str, Any]]:
        """
        List all campaigns.

        Args:
            published_only: Only return published campaigns

        Returns:
            List of campaign dicts
        """
        params = {}
        if published_only:
            params["search"] = "is:published"

        result = self._request("GET", "/api/campaigns", params=params)

        if result and "campaigns" in result:
            return [
                {
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "description": c.get("description"),
                    "isPublished": c.get("isPublished"),
                    "dateAdded": c.get("dateAdded"),
                    "events": list(c.get("events", {}).keys()),
                }
                for c in result["campaigns"].values()
            ]

        return []

    def trigger_campaign(self, campaign_id: int, contact_id: int) -> bool:
        """
        Add a contact to a campaign, triggering its automation flow.

        The contact will enter the campaign at its starting point and
        proceed through the defined events/actions/conditions.

        Args:
            campaign_id: Mautic campaign ID
            contact_id: Mautic contact ID

        Returns:
            True if contact was added to campaign
        """
        result = self._request(
            "POST",
            f"/api/campaigns/{campaign_id}/contact/{contact_id}/add",
        )
        return result is not None

    def remove_from_campaign(self, campaign_id: int, contact_id: int) -> bool:
        """
        Remove a contact from a campaign, stopping automation.

        Args:
            campaign_id: Mautic campaign ID
            contact_id: Mautic contact ID

        Returns:
            True if successful
        """
        result = self._request(
            "POST",
            f"/api/campaigns/{campaign_id}/contact/{contact_id}/remove",
        )
        return result is not None

    # =========================================================================
    # Email Management
    # =========================================================================

    def list_emails(self, email_type: str = "template") -> List[Dict[str, Any]]:
        """
        List available emails.

        Args:
            email_type: "template" (reusable) or "list" (segment email)

        Returns:
            List of email dicts
        """
        result = self._request(
            "GET",
            "/api/emails",
            params={"search": f"is:published emailType:{email_type}"},
        )

        if result and "emails" in result:
            return [
                {
                    "id": e.get("id"),
                    "name": e.get("name"),
                    "subject": e.get("subject"),
                    "emailType": e.get("emailType"),
                    "readCount": e.get("readCount"),
                    "sentCount": e.get("sentCount"),
                }
                for e in result["emails"].values()
            ]

        return []

    def send_email_to_contact(self, email_id: int, contact_id: int, tokens: Optional[Dict] = None) -> bool:
        """
        Send a template email to a specific contact.

        Tokens allow dynamic content replacement in the email template.
        Example: {"firstname": "Jane", "coupon_code": "SAVE20"}

        Args:
            email_id: Mautic email template ID
            contact_id: Recipient contact ID
            tokens: Dict of {token_name: value} for template personalization

        Returns:
            True if email was queued
        """
        payload: Dict[str, Any] = {}
        if tokens:
            payload["tokens"] = tokens

        result = self._request(
            "POST",
            f"/api/emails/{email_id}/contact/{contact_id}/send",
            payload,
        )
        return result is not None

    # =========================================================================
    # Event Recording (for lead scoring)
    # =========================================================================

    def record_event(
        self,
        contact_id: int,
        event_type: str,
        metadata: Optional[Dict] = None,
    ) -> bool:
        """
        Record a custom event on a contact for lead scoring/automation.

        Implemented via Mautic's point trigger system: updates custom fields
        and adjusts contact points based on event type.

        Typical event types:
            - page_view: Viewed a page (metadata: {page, duration})
            - form_submit: Submitted a form (metadata: {form_id, form_name})
            - email_open: Opened a marketing email
            - email_click: Clicked a link in email
            - purchase: Made a purchase (metadata: {amount, product})
            - quiz_complete: Completed a quiz (metadata: {score, topic})

        Args:
            contact_id: Mautic contact ID
            event_type: Event category string
            metadata: Additional event data

        Returns:
            True if event was recorded
        """
        # Update custom field with event data
        update: Dict[str, Any] = {
            f"last_{event_type}_at": datetime.utcnow().isoformat(),
        }
        if metadata:
            for key, value in metadata.items():
                update[f"{event_type}_{key}"] = str(value)

        # Adjust points based on event type (lead scoring)
        point_values = {
            "page_view": 1,
            "form_submit": 10,
            "email_open": 3,
            "email_click": 5,
            "purchase": 25,
            "quiz_complete": 8,
            "demo_request": 20,
            "pricing_view": 7,
            "case_study_download": 12,
        }

        points = point_values.get(event_type, 1)

        # Adjust contact points
        self._request(
            "POST",
            f"/api/contacts/{contact_id}/points/plus/{points}",
        )

        return self.update_contact(contact_id, update)
```

### Mautic API Endpoints Reference

| Operation | Method | Endpoint | Notes |
|---|---|---|---|
| Create contact | POST | `/api/contacts/new` | Returns contact with ID |
| Get contact | GET | `/api/contacts/{id}` | Full contact data |
| Update contact | PATCH | `/api/contacts/{id}/edit` | Partial update |
| Delete contact | DELETE | `/api/contacts/{id}/delete` | Permanent deletion |
| Search contacts | GET | `/api/contacts?search=...` | Mautic search syntax |
| List segments | GET | `/api/segments` | All segments |
| Add to segment | POST | `/api/segments/{id}/contact/{cid}/add` | Idempotent |
| Remove from segment | POST | `/api/segments/{id}/contact/{cid}/remove` | Safe if not member |
| List campaigns | GET | `/api/campaigns` | All campaigns |
| Add to campaign | POST | `/api/campaigns/{id}/contact/{cid}/add` | Triggers automation |
| Remove from campaign | POST | `/api/campaigns/{id}/contact/{cid}/remove` | Stops automation |
| Send email | POST | `/api/emails/{id}/contact/{cid}/send` | Template emails |
| Add points | POST | `/api/contacts/{id}/points/plus/{pts}` | Lead scoring |
| Subtract points | POST | `/api/contacts/{id}/points/minus/{pts}` | Score adjustment |
| List forms | GET | `/api/forms` | All forms |
| Get form | GET | `/api/forms/{id}` | Single form detail |

---

## HubSpot API Integration

### HubSpot Client (Production)

```python
import logging
from typing import Optional, Dict, Any, List, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("crm.hubspot")


class HubSpotCRMClient:
    """
    Production HubSpot CRM client.

    Covers contacts, deals, and workflow triggering.
    Uses HubSpot API v3 with Bearer token auth.
    """

    BASE_URL = "https://api.hubapi.com"

    def __init__(self, config: "CRMConfig"):
        self.api_key = config.hubspot_api_key

        # Session with retry (unified-api-client pattern)
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        })

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """Make authenticated request to HubSpot API v3."""
        url = f"{self.BASE_URL}{endpoint}"

        try:
            response = self.session.request(
                method=method, url=url, json=data, params=params, timeout=30
            )

            if response.status_code in (200, 201):
                return response.json()

            # HubSpot rate limit: 100 requests per 10 seconds
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 10))
                logger.warning(f"HubSpot rate limited, retry after {retry_after}s")
                import time
                time.sleep(retry_after)
                return self._request(method, endpoint, data, params)

            logger.warning(
                "HubSpot API error",
                extra={"status": response.status_code, "body": response.text[:500]},
            )
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"HubSpot request failed: {e}")
            return None

    # =========================================================================
    # Contact Management
    # =========================================================================

    def create_contact(
        self,
        email: str,
        firstname: Optional[str] = None,
        lastname: Optional[str] = None,
        properties: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict]:
        """
        Create a new HubSpot contact.

        Args:
            email: Contact email
            firstname: First name
            lastname: Last name
            properties: Additional HubSpot properties

        Returns:
            HubSpot contact dict on success
        """
        props: Dict[str, str] = {"email": email}
        if firstname:
            props["firstname"] = firstname
        if lastname:
            props["lastname"] = lastname
        if properties:
            props.update(properties)

        result = self._request(
            "POST",
            "/crm/v3/objects/contacts",
            {"properties": props},
        )
        return result

    def get_contact_by_email(self, email: str) -> Optional[Dict]:
        """
        Find a HubSpot contact by email.

        Uses the search API for reliable email lookup.

        Args:
            email: Email to search

        Returns:
            Contact dict or None
        """
        result = self._request(
            "POST",
            "/crm/v3/objects/contacts/search",
            {
                "filterGroups": [
                    {
                        "filters": [
                            {
                                "propertyName": "email",
                                "operator": "EQ",
                                "value": email,
                            }
                        ]
                    }
                ],
                "properties": [
                    "email", "firstname", "lastname", "company",
                    "lifecyclestage", "hs_lead_status",
                ],
                "limit": 1,
            },
        )

        if result and result.get("total", 0) > 0:
            return result["results"][0]
        return None

    def update_contact(self, contact_id: str, properties: Dict[str, str]) -> bool:
        """
        Update contact properties.

        Args:
            contact_id: HubSpot contact ID (string)
            properties: Properties to update

        Returns:
            True on success
        """
        result = self._request(
            "PATCH",
            f"/crm/v3/objects/contacts/{contact_id}",
            {"properties": properties},
        )
        return result is not None

    def create_or_update_contact(
        self,
        email: str,
        firstname: Optional[str] = None,
        lastname: Optional[str] = None,
        properties: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict]:
        """Upsert contact by email."""
        existing = self.get_contact_by_email(email)

        if existing:
            props: Dict[str, str] = {}
            if firstname:
                props["firstname"] = firstname
            if lastname:
                props["lastname"] = lastname
            if properties:
                props.update(properties)
            if props:
                self.update_contact(existing["id"], props)
            return self.get_contact_by_email(email)

        return self.create_contact(email, firstname, lastname, properties)

    # =========================================================================
    # Deal / Pipeline Management
    # =========================================================================

    def create_deal(
        self,
        deal_name: str,
        pipeline: str = "default",
        stage: str = "appointmentscheduled",
        amount: Optional[float] = None,
        contact_id: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Create a deal in HubSpot pipeline.

        Default pipeline stages:
            - appointmentscheduled
            - qualifiedtobuy
            - presentationscheduled
            - decisionmakerboughtin
            - contractsent
            - closedwon
            - closedlost

        Args:
            deal_name: Name for the deal
            pipeline: Pipeline ID or "default"
            stage: Deal stage within pipeline
            amount: Deal value in dollars
            contact_id: Associate with a contact

        Returns:
            Deal dict on success
        """
        properties: Dict[str, Any] = {
            "dealname": deal_name,
            "pipeline": pipeline,
            "dealstage": stage,
        }
        if amount is not None:
            properties["amount"] = str(amount)

        payload: Dict[str, Any] = {"properties": properties}

        if contact_id:
            payload["associations"] = [
                {
                    "to": {"id": contact_id},
                    "types": [
                        {
                            "associationCategory": "HUBSPOT_DEFINED",
                            "associationTypeId": 3,  # Deal to Contact
                        }
                    ],
                }
            ]

        return self._request("POST", "/crm/v3/objects/deals", payload)

    def update_deal_stage(self, deal_id: str, stage: str) -> bool:
        """
        Move a deal to a new pipeline stage.

        Args:
            deal_id: HubSpot deal ID
            stage: New stage name

        Returns:
            True on success
        """
        result = self._request(
            "PATCH",
            f"/crm/v3/objects/deals/{deal_id}",
            {"properties": {"dealstage": stage}},
        )
        return result is not None

    def list_deals(
        self,
        pipeline: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict]:
        """
        List deals, optionally filtered by pipeline.

        Args:
            pipeline: Pipeline ID filter
            limit: Max results

        Returns:
            List of deal dicts
        """
        params: Dict[str, Any] = {
            "limit": limit,
            "properties": "dealname,dealstage,amount,pipeline,closedate",
        }

        result = self._request("GET", "/crm/v3/objects/deals", params=params)

        if result and "results" in result:
            deals = result["results"]
            if pipeline:
                deals = [d for d in deals if d["properties"].get("pipeline") == pipeline]
            return deals

        return []

    # =========================================================================
    # Workflow Triggering
    # =========================================================================

    def enroll_in_workflow(self, workflow_id: int, email: str) -> bool:
        """
        Enroll a contact into a HubSpot workflow by email.

        Note: Requires Marketing Hub Professional or Enterprise.

        Args:
            workflow_id: HubSpot workflow ID
            email: Contact email to enroll

        Returns:
            True if enrollment succeeded
        """
        result = self._request(
            "POST",
            f"/automation/v2/workflows/{workflow_id}/enrollments/contacts/{email}",
        )
        return result is not None

    def unenroll_from_workflow(self, workflow_id: int, email: str) -> bool:
        """
        Remove a contact from a HubSpot workflow.

        Args:
            workflow_id: HubSpot workflow ID
            email: Contact email to remove

        Returns:
            True if removal succeeded
        """
        result = self._request(
            "DELETE",
            f"/automation/v2/workflows/{workflow_id}/enrollments/contacts/{email}",
        )
        return result is not None
```

### TypeScript HubSpot Client

```typescript
import axios, { AxiosInstance } from 'axios';

interface HubSpotContact {
  id: string;
  properties: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}

interface HubSpotDeal {
  id: string;
  properties: {
    dealname: string;
    dealstage: string;
    amount?: string;
    pipeline: string;
    closedate?: string;
  };
}

class HubSpotClient {
  private client: AxiosInstance;

  constructor(apiKey: string) {
    this.client = axios.create({
      baseURL: 'https://api.hubapi.com',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      timeout: 30_000,
    });

    // Rate limit interceptor (100 req / 10 sec)
    this.client.interceptors.response.use(undefined, async (error) => {
      if (error.response?.status === 429) {
        const retryAfter = parseInt(error.response.headers['retry-after'] || '10', 10);
        await new Promise((r) => setTimeout(r, retryAfter * 1000));
        return this.client.request(error.config);
      }
      throw error;
    });
  }

  // --- Contacts ---

  async createContact(properties: Record<string, string>): Promise<HubSpotContact> {
    const { data } = await this.client.post('/crm/v3/objects/contacts', { properties });
    return data;
  }

  async getContactByEmail(email: string): Promise<HubSpotContact | null> {
    const { data } = await this.client.post('/crm/v3/objects/contacts/search', {
      filterGroups: [
        { filters: [{ propertyName: 'email', operator: 'EQ', value: email }] },
      ],
      properties: ['email', 'firstname', 'lastname', 'lifecyclestage'],
      limit: 1,
    });
    return data.total > 0 ? data.results[0] : null;
  }

  async updateContact(contactId: string, properties: Record<string, string>): Promise<void> {
    await this.client.patch(`/crm/v3/objects/contacts/${contactId}`, { properties });
  }

  // --- Deals ---

  async createDeal(params: {
    dealname: string;
    pipeline?: string;
    dealstage?: string;
    amount?: number;
    contactId?: string;
  }): Promise<HubSpotDeal> {
    const properties: Record<string, string> = {
      dealname: params.dealname,
      pipeline: params.pipeline || 'default',
      dealstage: params.dealstage || 'appointmentscheduled',
    };
    if (params.amount !== undefined) {
      properties.amount = String(params.amount);
    }

    const payload: Record<string, unknown> = { properties };

    if (params.contactId) {
      payload.associations = [
        {
          to: { id: params.contactId },
          types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: 3 }],
        },
      ];
    }

    const { data } = await this.client.post('/crm/v3/objects/deals', payload);
    return data;
  }

  async updateDealStage(dealId: string, stage: string): Promise<void> {
    await this.client.patch(`/crm/v3/objects/deals/${dealId}`, {
      properties: { dealstage: stage },
    });
  }

  // --- Workflows ---

  async enrollInWorkflow(workflowId: number, email: string): Promise<void> {
    await this.client.post(
      `/automation/v2/workflows/${workflowId}/enrollments/contacts/${email}`
    );
  }
}
```

### HubSpot API Endpoints Reference

| Operation | Method | Endpoint | Notes |
|---|---|---|---|
| Create contact | POST | `/crm/v3/objects/contacts` | Properties in body |
| Search contacts | POST | `/crm/v3/objects/contacts/search` | Filter groups |
| Update contact | PATCH | `/crm/v3/objects/contacts/{id}` | Partial update |
| Delete contact | DELETE | `/crm/v3/objects/contacts/{id}` | Moves to recycle bin |
| Create deal | POST | `/crm/v3/objects/deals` | With associations |
| Update deal | PATCH | `/crm/v3/objects/deals/{id}` | Stage changes |
| List deals | GET | `/crm/v3/objects/deals` | With properties param |
| Enroll workflow | POST | `/automation/v2/workflows/{id}/enrollments/contacts/{email}` | Marketing Hub required |
| Unenroll workflow | DELETE | `/automation/v2/workflows/{id}/enrollments/contacts/{email}` | Same |

---

## Lead Scoring Engine

### Scoring Model

```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
import logging

logger = logging.getLogger("crm.scoring")


class ScoreCategory(Enum):
    """Categories contributing to lead score."""
    DEMOGRAPHIC = "demographic"   # Who they are
    BEHAVIORAL = "behavioral"     # What they do
    ENGAGEMENT = "engagement"     # How they interact
    FIRMOGRAPHIC = "firmographic" # Company attributes
    NEGATIVE = "negative"         # Score-reducing signals


@dataclass
class ScoringRule:
    """A single scoring rule definition."""
    name: str
    category: ScoreCategory
    points: int
    condition: str  # Human-readable description
    max_applications: int = 1  # How many times this rule can fire per contact
    decay_days: Optional[int] = None  # Points decay after N days


# Default scoring rules
DEFAULT_SCORING_RULES: List[ScoringRule] = [
    # --- Demographic (who they are) ---
    ScoringRule("has_email", ScoreCategory.DEMOGRAPHIC, 5, "Contact has valid email"),
    ScoringRule("has_full_name", ScoreCategory.DEMOGRAPHIC, 3, "Both first and last name provided"),
    ScoringRule("has_company", ScoreCategory.DEMOGRAPHIC, 5, "Company name provided"),
    ScoringRule("has_phone", ScoreCategory.DEMOGRAPHIC, 3, "Phone number provided"),

    # --- Behavioral (what they do) ---
    ScoringRule("page_view", ScoreCategory.BEHAVIORAL, 1, "Viewed a page", max_applications=50, decay_days=30),
    ScoringRule("pricing_page_view", ScoreCategory.BEHAVIORAL, 7, "Viewed pricing page", max_applications=5, decay_days=14),
    ScoringRule("case_study_download", ScoreCategory.BEHAVIORAL, 12, "Downloaded case study", max_applications=10),
    ScoringRule("demo_request", ScoreCategory.BEHAVIORAL, 20, "Requested a demo", max_applications=1),
    ScoringRule("free_trial_start", ScoreCategory.BEHAVIORAL, 15, "Started free trial", max_applications=1),
    ScoringRule("purchase", ScoreCategory.BEHAVIORAL, 25, "Made a purchase", max_applications=99),

    # --- Engagement (how they interact) ---
    ScoringRule("email_open", ScoreCategory.ENGAGEMENT, 3, "Opened marketing email", max_applications=50, decay_days=30),
    ScoringRule("email_click", ScoreCategory.ENGAGEMENT, 5, "Clicked link in email", max_applications=50, decay_days=30),
    ScoringRule("form_submit", ScoreCategory.ENGAGEMENT, 10, "Submitted a form", max_applications=20),
    ScoringRule("quiz_complete", ScoreCategory.ENGAGEMENT, 8, "Completed a quiz", max_applications=20),
    ScoringRule("webinar_attend", ScoreCategory.ENGAGEMENT, 15, "Attended webinar", max_applications=10),

    # --- Negative signals ---
    ScoringRule("email_bounce", ScoreCategory.NEGATIVE, -10, "Email bounced", max_applications=3),
    ScoringRule("email_unsubscribe", ScoreCategory.NEGATIVE, -15, "Unsubscribed from emails", max_applications=1),
    ScoringRule("inactive_30_days", ScoreCategory.NEGATIVE, -5, "No activity for 30 days", max_applications=10, decay_days=30),
    ScoringRule("spam_complaint", ScoreCategory.NEGATIVE, -25, "Marked as spam", max_applications=1),
]


class LeadScoringEngine:
    """
    Production lead scoring engine.

    Calculates composite scores from demographic, behavioral, engagement,
    and firmographic signals. Scores determine when a contact transitions
    between lifecycle stages (Visitor -> Subscriber -> Lead -> MQL -> SQL).

    Stage thresholds (configurable):
        - Subscriber:  score >= 10
        - Lead:        score >= 25
        - MQL:         score >= 50
        - SQL:         score >= 80

    Integrates with:
        - Mautic points system (syncs scores to Mautic contact points)
        - HubSpot lead scoring (maps to HubSpot lead status)
        - notification-universal skill (alerts sales on MQL/SQL threshold)
    """

    # Stage transition thresholds
    STAGE_THRESHOLDS = {
        ContactStage.SUBSCRIBER: 10,
        ContactStage.LEAD: 25,
        ContactStage.MQL: 50,
        ContactStage.SQL: 80,
    }

    def __init__(
        self,
        rules: Optional[List[ScoringRule]] = None,
        thresholds: Optional[Dict[ContactStage, int]] = None,
        on_stage_change: Optional[Callable] = None,
    ):
        """
        Initialize scoring engine.

        Args:
            rules: Custom scoring rules (uses defaults if None)
            thresholds: Custom stage thresholds
            on_stage_change: Callback when contact changes stage
                             Signature: (contact, old_stage, new_stage) -> None
        """
        self.rules = {r.name: r for r in (rules or DEFAULT_SCORING_RULES)}
        self.thresholds = thresholds or self.STAGE_THRESHOLDS
        self.on_stage_change = on_stage_change

    def calculate_score(self, contact: CRMContact, events: List[Dict]) -> int:
        """
        Calculate total lead score from contact data and event history.

        Args:
            contact: CRMContact with demographic data
            events: List of event dicts: {"type": str, "timestamp": str, "metadata": dict}

        Returns:
            Calculated total score
        """
        score = 0
        rule_counts: Dict[str, int] = {}

        # --- Demographic scoring ---
        if contact.email:
            score += self._apply_rule("has_email", rule_counts)
        if contact.firstname and contact.lastname:
            score += self._apply_rule("has_full_name", rule_counts)
        if contact.company:
            score += self._apply_rule("has_company", rule_counts)
        if contact.phone:
            score += self._apply_rule("has_phone", rule_counts)

        # --- Behavioral and engagement scoring ---
        now = datetime.utcnow()
        for event in events:
            event_type = event.get("type", "")
            event_time_str = event.get("timestamp")
            event_time = (
                datetime.fromisoformat(event_time_str)
                if event_time_str
                else now
            )

            rule = self.rules.get(event_type)
            if not rule:
                continue

            # Check decay
            if rule.decay_days:
                age = (now - event_time).days
                if age > rule.decay_days:
                    continue  # Expired event, skip

            score += self._apply_rule(event_type, rule_counts)

        # --- Negative: inactivity check ---
        if contact.last_active:
            days_inactive = (now - contact.last_active).days
            if days_inactive >= 30:
                inactive_periods = days_inactive // 30
                for _ in range(inactive_periods):
                    score += self._apply_rule("inactive_30_days", rule_counts)

        return max(score, 0)  # Score never goes below 0

    def _apply_rule(self, rule_name: str, counts: Dict[str, int]) -> int:
        """Apply a rule if under max applications."""
        rule = self.rules.get(rule_name)
        if not rule:
            return 0
        current = counts.get(rule_name, 0)
        if current >= rule.max_applications:
            return 0
        counts[rule_name] = current + 1
        return rule.points

    def determine_stage(self, score: int) -> ContactStage:
        """
        Determine lifecycle stage based on score.

        Args:
            score: Current lead score

        Returns:
            Appropriate ContactStage
        """
        if score >= self.thresholds.get(ContactStage.SQL, 80):
            return ContactStage.SQL
        if score >= self.thresholds.get(ContactStage.MQL, 50):
            return ContactStage.MQL
        if score >= self.thresholds.get(ContactStage.LEAD, 25):
            return ContactStage.LEAD
        if score >= self.thresholds.get(ContactStage.SUBSCRIBER, 10):
            return ContactStage.SUBSCRIBER
        return ContactStage.VISITOR

    def score_and_update(
        self,
        contact: CRMContact,
        events: List[Dict],
        mautic_client: Optional["MauticCRMClient"] = None,
        hubspot_client: Optional["HubSpotCRMClient"] = None,
    ) -> CRMContact:
        """
        Full scoring pipeline: calculate score, determine stage, sync to CRMs.

        This is the primary entry point for the scoring engine. Call this
        after recording new events to re-evaluate the contact.

        Args:
            contact: Contact to score
            events: Full event history for this contact
            mautic_client: Optional Mautic client for point sync
            hubspot_client: Optional HubSpot client for lifecycle sync

        Returns:
            Updated CRMContact with new score and stage
        """
        old_stage = contact.stage
        new_score = self.calculate_score(contact, events)
        new_stage = self.determine_stage(new_score)

        contact.score = new_score
        contact.stage = new_stage

        # Sync score to Mautic
        if mautic_client and contact.id:
            point_diff = new_score - (contact.score or 0)
            if point_diff > 0:
                mautic_client._request(
                    "POST",
                    f"/api/contacts/{contact.id}/points/plus/{point_diff}",
                )
            elif point_diff < 0:
                mautic_client._request(
                    "POST",
                    f"/api/contacts/{contact.id}/points/minus/{abs(point_diff)}",
                )

        # Sync lifecycle stage to HubSpot
        if hubspot_client and contact.id:
            hubspot_client.update_contact(
                str(contact.id),
                {"lifecyclestage": contact._stage_to_hubspot()},
            )

        # Fire stage change callback (e.g., notify sales via notification-universal)
        if new_stage != old_stage and self.on_stage_change:
            self.on_stage_change(contact, old_stage, new_stage)
            logger.info(
                f"Contact {contact.email} stage change: {old_stage.value} -> {new_stage.value} "
                f"(score: {new_score})"
            )

        return contact
```

### Stage Change Notification Integration

```python
# Integration with notification-universal skill
# Notify sales team when contact reaches MQL or SQL

def on_stage_change(contact: CRMContact, old_stage: ContactStage, new_stage: ContactStage):
    """
    Callback for lead scoring stage transitions.
    Uses notification-universal skill for multi-channel alerts.
    """
    # Only notify on high-value transitions
    notify_stages = {ContactStage.MQL, ContactStage.SQL, ContactStage.CUSTOMER}

    if new_stage not in notify_stages:
        return

    # Build notification payload (notification-universal format)
    notification = {
        "type": "lead_stage_change",
        "priority": "high" if new_stage == ContactStage.SQL else "medium",
        "channels": ["email", "slack"],
        "recipient": "sales-team",
        "data": {
            "contact_email": contact.email,
            "contact_name": f"{contact.firstname or ''} {contact.lastname or ''}".strip(),
            "old_stage": old_stage.value,
            "new_stage": new_stage.value,
            "score": contact.score,
            "company": contact.company,
        },
        "template": "lead_qualified",
    }

    # In production, send via notification-universal skill:
    # from skills.notifications import NotificationRouter
    # router = NotificationRouter()
    # router.send(notification)
    logger.info(f"Notification dispatched: {contact.email} reached {new_stage.value}")
```

---

## Webhook Ingestion Patterns

### FastAPI Webhook Receiver

```python
"""
Webhook ingestion for Mautic and HubSpot events.

Mount these routes in your FastAPI application to receive
real-time CRM events and trigger internal workflows.
"""
import hashlib
import hmac
import logging
from typing import Optional, Dict, Any

from fastapi import APIRouter, Request, HTTPException, Header
from pydantic import BaseModel

logger = logging.getLogger("crm.webhooks")

router = APIRouter(prefix="/webhooks/crm", tags=["CRM Webhooks"])


# --- Mautic Webhooks ---

class MauticWebhookPayload(BaseModel):
    """Mautic webhook payload structure."""
    # Mautic sends different shapes depending on the trigger
    # Common fields:
    mautic_event: Optional[str] = None  # e.g., "mautic.lead_post_save_new"

    class Config:
        extra = "allow"  # Mautic payloads vary by event type


@router.post("/mautic")
async def mautic_webhook(
    request: Request,
    x_mautic_webhook_signature: Optional[str] = Header(None, alias="Webhook-Signature"),
):
    """
    Receive Mautic webhook events.

    Supported Mautic webhook triggers:
        - mautic.lead_post_save_new      (new contact created)
        - mautic.lead_post_save_update   (contact updated)
        - mautic.lead_points_change      (score changed)
        - mautic.form_on_submit          (form submitted)
        - mautic.email_on_open           (email opened)
        - mautic.email_on_send           (email sent)
        - mautic.page_on_hit             (page viewed)

    Configure webhooks in Mautic:
        Settings -> Webhooks -> New
        URL: https://your-app.com/webhooks/crm/mautic
    """
    body = await request.body()
    payload = await request.json()

    # Validate webhook signature (if configured in Mautic)
    webhook_secret = request.app.state.config.get("MAUTIC_WEBHOOK_SECRET", "")
    if webhook_secret and x_mautic_webhook_signature:
        expected = hmac.new(
            webhook_secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, x_mautic_webhook_signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Route by event type
    event_triggers = payload.get("mautic.lead_post_save_new")
    if event_triggers:
        for event_data in event_triggers:
            contact = event_data.get("contact", {})
            await _handle_mautic_new_contact(contact)

    event_triggers = payload.get("mautic.lead_points_change")
    if event_triggers:
        for event_data in event_triggers:
            contact = event_data.get("contact", {})
            points = event_data.get("points", {})
            await _handle_mautic_score_change(contact, points)

    event_triggers = payload.get("mautic.form_on_submit")
    if event_triggers:
        for event_data in event_triggers:
            submission = event_data.get("submission", {})
            await _handle_mautic_form_submit(submission)

    event_triggers = payload.get("mautic.email_on_open")
    if event_triggers:
        for event_data in event_triggers:
            stat = event_data.get("stat", {})
            await _handle_mautic_email_open(stat)

    return {"status": "ok"}


async def _handle_mautic_new_contact(contact: Dict[str, Any]):
    """Process new Mautic contact creation event."""
    email = contact.get("fields", {}).get("all", {}).get("email")
    logger.info(f"Mautic new contact: {email}")
    # Sync to local database (database-orm-patterns module)
    # Trigger welcome sequence (notification-universal skill)


async def _handle_mautic_score_change(contact: Dict, points: Dict):
    """Process Mautic score/points change event."""
    email = contact.get("fields", {}).get("all", {}).get("email")
    new_points = points.get("new_points", 0)
    old_points = points.get("old_points", 0)
    logger.info(f"Mautic score change: {email} {old_points} -> {new_points}")
    # Re-evaluate lead stage via scoring engine
    # Notify sales on threshold crossings


async def _handle_mautic_form_submit(submission: Dict):
    """Process Mautic form submission event."""
    form_id = submission.get("form", {}).get("id")
    results = submission.get("results", {})
    email = results.get("email")
    logger.info(f"Mautic form {form_id} submitted by {email}")
    # Add contact to relevant segment
    # Trigger follow-up campaign


async def _handle_mautic_email_open(stat: Dict):
    """Process email open tracking event."""
    email_id = stat.get("email", {}).get("id")
    contact_email = stat.get("lead", {}).get("email")
    logger.info(f"Email {email_id} opened by {contact_email}")
    # Update engagement score


# --- HubSpot Webhooks ---

class HubSpotWebhookEvent(BaseModel):
    """Single HubSpot webhook event."""
    eventId: int
    subscriptionId: int
    portalId: int
    appId: int
    occurredAt: int  # Unix timestamp ms
    subscriptionType: str  # e.g., "contact.creation"
    attemptNumber: int
    objectId: int
    changeSource: Optional[str] = None
    propertyName: Optional[str] = None
    propertyValue: Optional[str] = None


@router.post("/hubspot")
async def hubspot_webhook(
    request: Request,
    x_hubspot_signature: Optional[str] = Header(None, alias="X-HubSpot-Signature"),
):
    """
    Receive HubSpot webhook events.

    Supported subscription types:
        - contact.creation
        - contact.deletion
        - contact.propertyChange
        - deal.creation
        - deal.propertyChange
        - deal.deletion

    Configure in HubSpot:
        Settings -> Integrations -> Private Apps -> Webhooks
    """
    body = await request.body()
    events = await request.json()  # HubSpot sends array of events

    # Validate signature
    client_secret = request.app.state.config.get("HUBSPOT_CLIENT_SECRET", "")
    if client_secret and x_hubspot_signature:
        source_string = client_secret + body.decode()
        expected = hashlib.sha256(source_string.encode()).hexdigest()
        if not hmac.compare_digest(expected, x_hubspot_signature):
            raise HTTPException(status_code=401, detail="Invalid HubSpot signature")

    for event in events:
        sub_type = event.get("subscriptionType", "")
        object_id = event.get("objectId")

        if sub_type == "contact.creation":
            logger.info(f"HubSpot new contact: {object_id}")
            # Sync to local DB and Mautic

        elif sub_type == "contact.propertyChange":
            prop = event.get("propertyName")
            value = event.get("propertyValue")
            logger.info(f"HubSpot contact {object_id} property change: {prop}={value}")

        elif sub_type == "deal.propertyChange":
            prop = event.get("propertyName")
            value = event.get("propertyValue")
            logger.info(f"HubSpot deal {object_id}: {prop}={value}")

            if prop == "dealstage" and value in ("closedwon", "closedlost"):
                # Deal closed - trigger notification
                logger.info(f"Deal {object_id} closed: {value}")

    return {"status": "ok"}
```

### Express.js Webhook Receiver (TypeScript)

```typescript
import express, { Request, Response } from 'express';
import crypto from 'crypto';

const router = express.Router();

// --- Mautic Webhook ---

router.post('/webhooks/crm/mautic', express.json(), (req: Request, res: Response) => {
  const payload = req.body;

  // Signature verification
  const secret = process.env.MAUTIC_WEBHOOK_SECRET;
  if (secret) {
    const signature = req.headers['webhook-signature'] as string;
    const expected = crypto.createHmac('sha256', secret)
      .update(JSON.stringify(payload))
      .digest('hex');
    if (signature !== expected) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
  }

  // Route events
  const newContacts = payload['mautic.lead_post_save_new'] || [];
  for (const event of newContacts) {
    const email = event.contact?.fields?.all?.email;
    console.log(`New Mautic contact: ${email}`);
  }

  const formSubmits = payload['mautic.form_on_submit'] || [];
  for (const event of formSubmits) {
    const formId = event.submission?.form?.id;
    const email = event.submission?.results?.email;
    console.log(`Form ${formId} submitted by ${email}`);
  }

  res.json({ status: 'ok' });
});

// --- HubSpot Webhook ---

router.post('/webhooks/crm/hubspot', express.json(), (req: Request, res: Response) => {
  const events: Array<{
    subscriptionType: string;
    objectId: number;
    propertyName?: string;
    propertyValue?: string;
  }> = req.body;

  // Signature verification
  const clientSecret = process.env.HUBSPOT_CLIENT_SECRET;
  if (clientSecret) {
    const signature = req.headers['x-hubspot-signature'] as string;
    const sourceString = clientSecret + JSON.stringify(req.body);
    const expected = crypto.createHash('sha256').update(sourceString).digest('hex');
    if (signature !== expected) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
  }

  for (const event of events) {
    switch (event.subscriptionType) {
      case 'contact.creation':
        console.log(`HubSpot new contact: ${event.objectId}`);
        break;
      case 'deal.propertyChange':
        if (event.propertyName === 'dealstage') {
          console.log(`Deal ${event.objectId} moved to ${event.propertyValue}`);
        }
        break;
    }
  }

  res.json({ status: 'ok' });
});

export default router;
```

---

## Form Embeds & Tracking Scripts

### Mautic Form Embed

```python
class MauticEmbedGenerator:
    """
    Generate Mautic form embeds and tracking scripts.

    Extracted from production mautic.py integration.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def form_embed_js(self, form_id: int) -> str:
        """
        Generate JavaScript embed for a Mautic form.

        Renders the form inline on the page with Mautic's default styling.
        Form submissions are tracked automatically in Mautic.

        Args:
            form_id: Mautic form ID (find in Mautic UI under Components -> Forms)

        Returns:
            HTML script tag for embedding
        """
        return (
            f'<script type="text/javascript" '
            f'src="{self.base_url}/form/generate.js?id={form_id}">'
            f'</script>'
        )

    def form_embed_iframe(self, form_id: int, width: str = "100%", height: str = "400px") -> str:
        """
        Generate iframe embed for isolated form rendering.

        Use when you need CSS isolation from the host page.

        Args:
            form_id: Mautic form ID
            width: iframe width
            height: iframe height

        Returns:
            HTML iframe tag
        """
        return (
            f'<iframe src="{self.base_url}/form/{form_id}" '
            f'width="{width}" height="{height}" '
            f'frameborder="0" scrolling="no" '
            f'style="border: none;">'
            f'</iframe>'
        )

    def tracking_script(self) -> str:
        """
        Generate Mautic page-view tracking script.

        Include this on every page to track visitor behavior.
        Mautic will correlate page views with known contacts
        once they submit a form or click a tracked link.

        Returns:
            Full HTML script block
        """
        return f"""<script>
    (function(w,d,t,u,n,a,m){{w['MauticTrackingObject']=n;
        w[n]=w[n]||function(){{(w[n].q=w[n].q||[]).push(arguments)}},a=d.createElement(t),
        m=d.getElementsByTagName(t)[0];a.async=1;a.src=u;m.parentNode.insertBefore(a,m)
    }})(window,document,'script','{self.base_url}/mtc.js','mt');

    mt('send', 'pageview');
</script>"""

    def tracking_script_with_contact(self, email: str, firstname: str = "", lastname: str = "") -> str:
        """
        Tracking script that identifies a known contact.

        Use after login or form submission to associate the
        browser session with a known Mautic contact.

        Args:
            email: Contact email (required for identification)
            firstname: Optional first name
            lastname: Optional last name

        Returns:
            HTML script block with contact identification
        """
        contact_data = f"'email': '{email}'"
        if firstname:
            contact_data += f", 'firstname': '{firstname}'"
        if lastname:
            contact_data += f", 'lastname': '{lastname}'"

        return f"""<script>
    (function(w,d,t,u,n,a,m){{w['MauticTrackingObject']=n;
        w[n]=w[n]||function(){{(w[n].q=w[n].q||[]).push(arguments)}},a=d.createElement(t),
        m=d.getElementsByTagName(t)[0];a.async=1;a.src=u;m.parentNode.insertBefore(a,m)
    }})(window,document,'script','{self.base_url}/mtc.js','mt');

    mt('send', 'pageview', {{{contact_data}}});
</script>"""

    def tracking_pixel(self, contact_email: Optional[str] = None) -> str:
        """
        Generate a tracking pixel for email or external page tracking.

        Use in HTML emails or third-party pages where JavaScript
        cannot be loaded.

        Args:
            contact_email: Optional email to associate the hit

        Returns:
            HTML img tag (1x1 transparent pixel)
        """
        url = f"{self.base_url}/mtracking.gif"
        if contact_email:
            url += f"?d=%7B%22email%22%3A%22{contact_email}%22%7D"
        return f'<img src="{url}" alt="" width="1" height="1" style="display:none;" />'
```

### React Form Component

```typescript
/**
 * React component for embedding Mautic forms.
 * Loads the form asynchronously and handles submission callbacks.
 */
import React, { useEffect, useRef } from 'react';

interface MauticFormProps {
  baseUrl: string;
  formId: number;
  onSubmit?: (formData: Record<string, string>) => void;
  className?: string;
}

export const MauticForm: React.FC<MauticFormProps> = ({
  baseUrl,
  formId,
  onSubmit,
  className,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Load form script
    const script = document.createElement('script');
    script.src = `${baseUrl}/form/generate.js?id=${formId}`;
    script.async = true;
    containerRef.current?.appendChild(script);

    // Listen for form submission events
    const handleMessage = (event: MessageEvent) => {
      if (event.origin === baseUrl && event.data?.type === 'mauticFormSubmit') {
        onSubmit?.(event.data.formData);
      }
    };
    window.addEventListener('message', handleMessage);

    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, [baseUrl, formId, onSubmit]);

  return <div ref={containerRef} className={className} />;
};

/**
 * Hook for Mautic page tracking.
 * Call in your app's root layout to track all page views.
 */
export function useMauticTracking(baseUrl: string) {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    // Avoid duplicate loading
    if ((window as any).MauticTrackingObject) return;

    const script = document.createElement('script');
    script.innerHTML = `
      (function(w,d,t,u,n,a,m){w['MauticTrackingObject']=n;
        w[n]=w[n]||function(){(w[n].q=w[n].q||[]).push(arguments)},a=d.createElement(t),
        m=d.getElementsByTagName(t)[0];a.async=1;a.src=u;m.parentNode.insertBefore(a,m)
      })(window,document,'script','${baseUrl}/mtc.js','mt');
      mt('send', 'pageview');
    `;
    document.head.appendChild(script);
  }, [baseUrl]);
}
```

---

## Pipeline Management

### Sales Pipeline Automation

```python
from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import Enum
from datetime import datetime


class PipelineStage(Enum):
    """Standard sales pipeline stages."""
    NEW = "new"
    CONTACTED = "contacted"
    QUALIFIED = "qualified"
    PROPOSAL = "proposal"
    NEGOTIATION = "negotiation"
    CLOSED_WON = "closed_won"
    CLOSED_LOST = "closed_lost"


@dataclass
class Deal:
    """Sales deal / opportunity."""
    id: Optional[str] = None
    name: str = ""
    contact_email: str = ""
    stage: PipelineStage = PipelineStage.NEW
    value: float = 0.0
    currency: str = "USD"
    probability: int = 0
    expected_close: Optional[datetime] = None
    notes: str = ""
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        # Auto-calculate probability from stage
        stage_probabilities = {
            PipelineStage.NEW: 10,
            PipelineStage.CONTACTED: 20,
            PipelineStage.QUALIFIED: 40,
            PipelineStage.PROPOSAL: 60,
            PipelineStage.NEGOTIATION: 80,
            PipelineStage.CLOSED_WON: 100,
            PipelineStage.CLOSED_LOST: 0,
        }
        if not self.probability:
            self.probability = stage_probabilities.get(self.stage, 0)


class PipelineManager:
    """
    Manage deals across Mautic and HubSpot pipelines.

    Provides a unified interface for deal creation, stage transitions,
    and pipeline analytics. Syncs state between CRM platforms.
    """

    # Stage mapping: Internal -> HubSpot
    HUBSPOT_STAGE_MAP = {
        PipelineStage.NEW: "appointmentscheduled",
        PipelineStage.CONTACTED: "qualifiedtobuy",
        PipelineStage.QUALIFIED: "qualifiedtobuy",
        PipelineStage.PROPOSAL: "presentationscheduled",
        PipelineStage.NEGOTIATION: "contractsent",
        PipelineStage.CLOSED_WON: "closedwon",
        PipelineStage.CLOSED_LOST: "closedlost",
    }

    def __init__(
        self,
        mautic: Optional["MauticCRMClient"] = None,
        hubspot: Optional["HubSpotCRMClient"] = None,
    ):
        self.mautic = mautic
        self.hubspot = hubspot

    def create_deal(
        self,
        name: str,
        contact_email: str,
        value: float = 0.0,
        stage: PipelineStage = PipelineStage.NEW,
    ) -> Deal:
        """
        Create a deal in all configured CRMs.

        Args:
            name: Deal name
            contact_email: Associated contact email
            value: Deal monetary value
            stage: Initial pipeline stage

        Returns:
            Deal object with CRM IDs
        """
        deal = Deal(name=name, contact_email=contact_email, value=value, stage=stage)

        # Create in HubSpot (primary deal tracking)
        if self.hubspot:
            contact = self.hubspot.get_contact_by_email(contact_email)
            hs_deal = self.hubspot.create_deal(
                deal_name=name,
                stage=self.HUBSPOT_STAGE_MAP.get(stage, "appointmentscheduled"),
                amount=value,
                contact_id=contact["id"] if contact else None,
            )
            if hs_deal:
                deal.id = hs_deal["id"]

        # Tag contact in Mautic for segment-based campaigns
        if self.mautic:
            mautic_contact = self.mautic.get_contact_by_email(contact_email)
            if mautic_contact:
                self.mautic.update_contact(
                    mautic_contact.id,
                    {"tags": [f"deal:{stage.value}"], "deal_value": str(value)},
                )

        return deal

    def advance_stage(self, deal: Deal, new_stage: PipelineStage) -> Deal:
        """
        Move deal to next pipeline stage.

        Automatically syncs to all configured CRMs and triggers
        stage-appropriate notifications.

        Args:
            deal: Current deal
            new_stage: Target stage

        Returns:
            Updated deal
        """
        old_stage = deal.stage
        deal.stage = new_stage

        # Sync to HubSpot
        if self.hubspot and deal.id:
            self.hubspot.update_deal_stage(
                deal.id,
                self.HUBSPOT_STAGE_MAP.get(new_stage, "appointmentscheduled"),
            )

        # Update Mautic contact tags
        if self.mautic:
            contact = self.mautic.get_contact_by_email(deal.contact_email)
            if contact:
                self.mautic.update_contact(contact.id, {
                    "tags": [f"deal:{new_stage.value}"],
                })

        logger.info(
            f"Deal '{deal.name}' advanced: {old_stage.value} -> {new_stage.value}"
        )
        return deal

    def get_pipeline_summary(self) -> Dict[str, Any]:
        """
        Get summary of all deals in pipeline.

        Returns:
            Dict with stage counts, total value, weighted value
        """
        if not self.hubspot:
            return {"error": "HubSpot not configured for pipeline reporting"}

        deals = self.hubspot.list_deals(limit=100)

        summary: Dict[str, Any] = {
            "total_deals": len(deals),
            "total_value": 0.0,
            "weighted_value": 0.0,
            "by_stage": {},
        }

        for deal in deals:
            props = deal.get("properties", {})
            stage = props.get("dealstage", "unknown")
            amount = float(props.get("amount", 0) or 0)

            if stage not in summary["by_stage"]:
                summary["by_stage"][stage] = {"count": 0, "value": 0.0}

            summary["by_stage"][stage]["count"] += 1
            summary["by_stage"][stage]["value"] += amount
            summary["total_value"] += amount

        return summary
```

---

## Bulk Operations

### Batch Contact Import

```python
"""
Bulk contact operations using the batch-processing skill.

Designed for importing large contact lists (CSV, API sync, etc.)
with progress tracking, rate limiting, and error recovery.
"""
from typing import List, Dict, Any, Optional
import csv
import logging
import time

logger = logging.getLogger("crm.bulk")


class BulkContactImporter:
    """
    Import contacts in batches with retry and progress tracking.

    Uses batch-processing skill patterns:
    - Chunked processing to respect rate limits
    - Progress tracking with ETA
    - Error collection and retry
    - Checkpoint/resume support
    """

    def __init__(
        self,
        mautic: "MauticCRMClient",
        batch_size: int = 50,
        delay_between_batches: float = 2.0,
    ):
        self.mautic = mautic
        self.batch_size = batch_size
        self.delay = delay_between_batches

    def import_from_csv(
        self,
        csv_path: str,
        email_column: str = "email",
        field_mapping: Optional[Dict[str, str]] = None,
        default_tags: Optional[List[str]] = None,
        segment_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Import contacts from CSV file into Mautic.

        Args:
            csv_path: Path to CSV file
            email_column: Name of email column in CSV
            field_mapping: Dict mapping CSV columns to Mautic fields
                           Example: {"First Name": "firstname", "Company": "company"}
            default_tags: Tags to apply to all imported contacts
            segment_id: Optional segment to add all contacts to

        Returns:
            Summary dict with counts and errors
        """
        field_mapping = field_mapping or {}
        default_tags = default_tags or []

        # Read CSV
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        total = len(rows)
        logger.info(f"Starting import of {total} contacts from {csv_path}")

        results = {
            "total": total,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "errors": [],
        }

        # Process in batches
        for batch_start in range(0, total, self.batch_size):
            batch = rows[batch_start : batch_start + self.batch_size]
            batch_num = (batch_start // self.batch_size) + 1
            total_batches = (total + self.batch_size - 1) // self.batch_size

            logger.info(f"Processing batch {batch_num}/{total_batches}")

            for row in batch:
                email = row.get(email_column, "").strip()
                if not email:
                    results["failed"] += 1
                    results["errors"].append({"row": row, "error": "Missing email"})
                    continue

                try:
                    # Map CSV fields to Mautic fields
                    custom_fields = {}
                    for csv_col, mautic_field in field_mapping.items():
                        if csv_col in row and row[csv_col]:
                            custom_fields[mautic_field] = row[csv_col]

                    contact = self.mautic.create_or_update_contact(
                        email=email,
                        firstname=custom_fields.pop("firstname", None),
                        lastname=custom_fields.pop("lastname", None),
                        custom_fields=custom_fields,
                        tags=default_tags,
                    )

                    if contact:
                        results["created"] += 1

                        # Add to segment if specified
                        if segment_id and contact.id:
                            self.mautic.add_to_segment(contact.id, segment_id)
                    else:
                        results["failed"] += 1
                        results["errors"].append({"email": email, "error": "API returned None"})

                except Exception as e:
                    results["failed"] += 1
                    results["errors"].append({"email": email, "error": str(e)})

            # Rate limit pause between batches
            if batch_start + self.batch_size < total:
                logger.info(f"Rate limit pause: {self.delay}s")
                time.sleep(self.delay)

        logger.info(
            f"Import complete: {results['created']} created, "
            f"{results['updated']} updated, {results['failed']} failed"
        )
        return results

    def bulk_add_to_segment(
        self,
        contact_ids: List[int],
        segment_id: int,
    ) -> Dict[str, int]:
        """
        Add multiple contacts to a segment in batches.

        Args:
            contact_ids: List of Mautic contact IDs
            segment_id: Target segment ID

        Returns:
            Dict with success/failure counts
        """
        results = {"success": 0, "failed": 0}

        for i in range(0, len(contact_ids), self.batch_size):
            batch = contact_ids[i : i + self.batch_size]
            for cid in batch:
                if self.mautic.add_to_segment(cid, segment_id):
                    results["success"] += 1
                else:
                    results["failed"] += 1

            if i + self.batch_size < len(contact_ids):
                time.sleep(self.delay)

        return results

    def bulk_trigger_campaign(
        self,
        contact_ids: List[int],
        campaign_id: int,
    ) -> Dict[str, int]:
        """
        Trigger a campaign for multiple contacts in batches.

        Args:
            contact_ids: List of Mautic contact IDs
            campaign_id: Campaign to trigger

        Returns:
            Dict with success/failure counts
        """
        results = {"success": 0, "failed": 0}

        for i in range(0, len(contact_ids), self.batch_size):
            batch = contact_ids[i : i + self.batch_size]
            for cid in batch:
                if self.mautic.trigger_campaign(campaign_id, cid):
                    results["success"] += 1
                else:
                    results["failed"] += 1

            if i + self.batch_size < len(contact_ids):
                time.sleep(self.delay)

        return results
```

---

## Environment Variables

```bash
# =============================================================================
# CRM & Marketing Automation Environment Variables
# =============================================================================

# --- Mautic (Primary CRM) ---
MAUTIC_BASE_URL=https://mautic.yourdomain.com    # No trailing slash
MAUTIC_USERNAME=api_user                          # Basic auth username
MAUTIC_PASSWORD=secure_password                   # Basic auth password
MAUTIC_WEBHOOK_SECRET=whsec_abc123                # Webhook signature secret

# --- HubSpot (Secondary CRM) ---
HUBSPOT_API_KEY=pat-na1-xxxxxxxx                  # Private app access token
HUBSPOT_CLIENT_SECRET=xxxxxxxx                    # For webhook validation
HUBSPOT_PORTAL_ID=12345678                        # Account portal ID

# --- General ---
PROJECT_SOURCE=my-app                             # Identifies contact source
CRM_DEFAULT_TAGS=app-signup                       # Comma-separated default tags

# --- Lead Scoring ---
LEAD_SCORE_MQL_THRESHOLD=50                       # Points for MQL
LEAD_SCORE_SQL_THRESHOLD=80                       # Points for SQL

# --- Batch Processing ---
CRM_BATCH_SIZE=50                                 # Contacts per batch
CRM_BATCH_DELAY=2.0                               # Seconds between batches

# --- Rate Limiting ---
MAUTIC_RATE_LIMIT_MS=100                          # Min ms between Mautic requests
HUBSPOT_RATE_LIMIT_PER_10S=100                    # HubSpot: 100 req per 10 seconds
```

### .env.example

```bash
# Copy to .env and fill in values
MAUTIC_BASE_URL=
MAUTIC_USERNAME=
MAUTIC_PASSWORD=
MAUTIC_WEBHOOK_SECRET=

HUBSPOT_API_KEY=
HUBSPOT_CLIENT_SECRET=

PROJECT_SOURCE=my-app
```

---

## Testing Strategy

### Unit Tests

```python
"""
Test patterns for CRM integrations.
Uses unittest.mock to avoid hitting real APIs.
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime


class TestMauticCRMClient:
    """Unit tests for Mautic CRM client."""

    @pytest.fixture
    def config(self):
        config = MagicMock()
        config.mautic_base_url = "https://mautic.test.com"
        config.mautic_username = "test_user"
        config.mautic_password = "test_pass"
        config.project_source = "test-app"
        return config

    @pytest.fixture
    def client(self, config):
        return MauticCRMClient(config)

    @patch("requests.Session.request")
    def test_create_contact(self, mock_request, client):
        """Test contact creation returns CRMContact."""
        mock_request.return_value = MagicMock(
            status_code=201,
            json=lambda: {
                "contact": {
                    "id": 42,
                    "fields": {
                        "all": {
                            "email": "test@example.com",
                            "firstname": "Test",
                            "lastname": "User",
                        }
                    },
                    "tags": [],
                    "points": 0,
                    "dateAdded": "2026-01-15T10:30:00+00:00",
                    "dateModified": None,
                }
            },
        )

        contact = client.create_contact(
            email="test@example.com",
            firstname="Test",
            lastname="User",
        )

        assert contact is not None
        assert contact.id == 42
        assert contact.email == "test@example.com"

    @patch("requests.Session.request")
    def test_create_or_update_existing(self, mock_request, client):
        """Test upsert finds existing contact and updates it."""
        # First call: search returns existing contact
        # Second call: patch updates it
        mock_request.side_effect = [
            MagicMock(
                status_code=200,
                json=lambda: {
                    "contacts": {
                        "42": {
                            "id": 42,
                            "fields": {"all": {"email": "existing@example.com"}},
                            "tags": [{"tag": "old-tag"}],
                            "points": 10,
                            "dateAdded": "2026-01-01T00:00:00+00:00",
                            "dateModified": None,
                        }
                    },
                    "total": 1,
                },
            ),
            MagicMock(status_code=200, json=lambda: {"contact": {"id": 42}}),
            MagicMock(
                status_code=200,
                json=lambda: {
                    "contacts": {
                        "42": {
                            "id": 42,
                            "fields": {
                                "all": {
                                    "email": "existing@example.com",
                                    "firstname": "Updated",
                                }
                            },
                            "tags": [{"tag": "old-tag"}, {"tag": "new-tag"}],
                            "points": 10,
                            "dateAdded": "2026-01-01T00:00:00+00:00",
                            "dateModified": None,
                        }
                    },
                    "total": 1,
                },
            ),
        ]

        contact = client.create_or_update_contact(
            email="existing@example.com",
            firstname="Updated",
            tags=["new-tag"],
        )

        assert contact is not None
        assert contact.firstname == "Updated"


class TestLeadScoringEngine:
    """Unit tests for lead scoring."""

    def test_demographic_scoring(self):
        engine = LeadScoringEngine()
        contact = CRMContact(
            email="test@example.com",
            firstname="Jane",
            lastname="Doe",
            company="Acme Corp",
        )

        score = engine.calculate_score(contact, [])
        # email(5) + full_name(3) + company(5) = 13
        assert score == 13

    def test_behavioral_scoring(self):
        engine = LeadScoringEngine()
        contact = CRMContact(email="test@example.com")
        events = [
            {"type": "page_view", "timestamp": datetime.utcnow().isoformat()},
            {"type": "pricing_page_view", "timestamp": datetime.utcnow().isoformat()},
            {"type": "demo_request", "timestamp": datetime.utcnow().isoformat()},
        ]

        score = engine.calculate_score(contact, events)
        # email(5) + page_view(1) + pricing(7) + demo(20) = 33
        assert score == 33

    def test_stage_determination(self):
        engine = LeadScoringEngine()
        assert engine.determine_stage(5) == ContactStage.VISITOR
        assert engine.determine_stage(10) == ContactStage.SUBSCRIBER
        assert engine.determine_stage(30) == ContactStage.LEAD
        assert engine.determine_stage(55) == ContactStage.MQL
        assert engine.determine_stage(85) == ContactStage.SQL

    def test_negative_scoring_floors_at_zero(self):
        engine = LeadScoringEngine()
        contact = CRMContact(email="test@example.com")
        events = [
            {"type": "email_bounce", "timestamp": datetime.utcnow().isoformat()},
            {"type": "email_unsubscribe", "timestamp": datetime.utcnow().isoformat()},
            {"type": "spam_complaint", "timestamp": datetime.utcnow().isoformat()},
        ]

        score = engine.calculate_score(contact, events)
        # email(5) + bounce(-10) + unsub(-15) + spam(-25) = -45 -> floors at 0
        assert score == 0
```

### Integration Test Pattern

```python
@pytest.mark.integration
class TestMauticIntegration:
    """
    Integration tests against a real Mautic instance.

    Requires MAUTIC_TEST_* environment variables.
    Run with: pytest -m integration
    """

    @pytest.fixture
    def live_client(self):
        import os
        config = CRMConfig()
        config.mautic_base_url = os.getenv("MAUTIC_TEST_BASE_URL", "")
        config.mautic_username = os.getenv("MAUTIC_TEST_USERNAME", "")
        config.mautic_password = os.getenv("MAUTIC_TEST_PASSWORD", "")

        if not config.mautic_configured():
            pytest.skip("Mautic test credentials not configured")

        return MauticCRMClient(config)

    def test_contact_lifecycle(self, live_client):
        """Test full contact create -> update -> segment -> delete cycle."""
        import uuid
        test_email = f"test-{uuid.uuid4().hex[:8]}@integration-test.dev"

        # Create
        contact = live_client.create_contact(
            email=test_email,
            firstname="Integration",
            lastname="Test",
            tags=["integration-test"],
        )
        assert contact is not None
        assert contact.email == test_email

        # Update
        success = live_client.update_contact(contact.id, {"company": "Test Corp"})
        assert success is True

        # Lookup
        found = live_client.get_contact_by_email(test_email)
        assert found is not None
        assert found.id == contact.id

        # Cleanup
        live_client.delete_contact(contact.id)
```

---

## Integrates With

This skill is designed to work seamlessly with the following modules and skills in the Streamlined Development ecosystem:

| Module / Skill | Integration Point | How It Connects |
|---|---|---|
| **`unified-api-client`** (module) | HTTP layer | Provides base `requests.Session` with retry, exponential backoff, auth header management. CRM clients inherit the retry strategy pattern (`Retry(total=3, backoff_factor=1, status_forcelist=[429,500,502,503,504])`). |
| **`omni-channel-core`** (module) | Contact sync | Contains `mautic.py` sync code for cross-channel marketing. This skill provides the full CRM client that `omni-channel-core` uses under the hood for contact creation, segment assignment, and campaign triggers across channels. |
| **`notification-universal`** (skill) | Event triggers | When lead scoring detects stage transitions (e.g., Lead -> MQL), the `on_stage_change` callback dispatches notifications through `NotificationRouter` (email to contact, Slack to sales team, push to account owner). CRM webhooks also feed into the notification pipeline. |
| **`batch-processing`** (skill) | Bulk operations | CSV imports, mass segment updates, and bulk campaign triggers use the batch-processing framework for chunked processing with progress tracking, error recovery, and rate-limit compliance. Pattern: `BulkContactImporter` wraps `BatchProcessor`. |
| **`database-orm-patterns`** (module) | Local storage | `CRMContact` model maps to a local database table for fast lookups, offline scoring, and analytics. Schema follows `database-orm-patterns` conventions (snake_case, UUID PKs, `created_at`/`updated_at` timestamps). Local DB acts as cache and single source of truth when CRM APIs are unavailable. |

### Cross-Skill Workflow Example

```python
"""
End-to-end workflow: User signs up -> CRM -> Scoring -> Notification -> Campaign

This demonstrates how all five dependencies work together.
"""

async def handle_user_signup(email: str, name: str, source: str = "website"):
    """
    Complete signup flow using all integrated modules/skills.
    """
    # 1. Create/update contact in Mautic (this skill)
    contact = mautic_client.create_or_update_contact(
        email=email,
        firstname=name.split()[0],
        lastname=" ".join(name.split()[1:]),
        custom_fields={"signup_source": source},
        tags=["signup", source],
    )

    # 2. Store locally (database-orm-patterns module)
    # db.contacts.upsert(contact.to_dict())

    # 3. Score the contact (this skill - lead scoring engine)
    events = [{"type": "form_submit", "timestamp": datetime.utcnow().isoformat()}]
    scored = scoring_engine.score_and_update(contact, events, mautic_client)

    # 4. Add to welcome segment (this skill)
    mautic_client.add_to_segment(contact.id, segment_id=WELCOME_SEGMENT_ID)

    # 5. Trigger onboarding campaign (this skill)
    mautic_client.trigger_campaign(campaign_id=ONBOARDING_CAMPAIGN_ID, contact_id=contact.id)

    # 6. Send immediate welcome notification (notification-universal skill)
    # notification_router.send({
    #     "type": "welcome",
    #     "channels": ["email"],
    #     "recipient": email,
    #     "template": "welcome_email",
    #     "data": {"name": name, "source": source},
    # })

    # 7. Sync to HubSpot if configured (this skill)
    if hubspot_client:
        hubspot_client.create_or_update_contact(
            email=email,
            firstname=name.split()[0],
            lastname=" ".join(name.split()[1:]),
            properties={"hs_lead_status": "NEW", "signup_source": source},
        )

    # 8. Cross-channel sync (omni-channel-core module)
    # channel_sync.sync_contact(contact, platforms=["mautic", "hubspot", "mailchimp"])

    return scored
```

---

## Appendix: Mautic Custom Field Setup

When deploying Mautic for the first time, create these custom fields to support the full integration:

| Field Alias | Label | Type | Group |
|---|---|---|---|
| `project_source` | Project Source | Text | Core |
| `signup_source` | Signup Source | Text | Core |
| `preferred_plan` | Preferred Plan | Select | Core |
| `deal_value` | Deal Value | Number | Professional |
| `last_page_view_at` | Last Page View | DateTime | Professional |
| `last_form_submit_at` | Last Form Submit | DateTime | Professional |
| `last_email_open_at` | Last Email Open | DateTime | Professional |
| `quiz_completions` | Quiz Completions | Number | Professional |
| `preferred_tradition` | Preferred Tradition | Text | Professional |

Create these via Mautic Admin -> Custom Fields, or via the API:

```bash
# Example: Create custom field via Mautic API
curl -X POST "https://mautic.yourdomain.com/api/fields/contact/new" \
  -u "username:password" \
  -H "Content-Type: application/json" \
  -d '{
    "label": "Project Source",
    "alias": "project_source",
    "type": "text",
    "group": "core",
    "isPublished": true
  }'
```
