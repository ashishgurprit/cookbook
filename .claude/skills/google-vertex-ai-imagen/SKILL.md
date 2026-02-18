---
name: google-vertex-ai-imagen
description: "Production-ready Google Cloud Vertex AI image generation pipeline with Imagen API, batch processing from CSV/spreadsheet prompts, Google Drive upload, and multi-session browser automation. Use when: (1) Generating images at scale via Vertex AI Imagen or Gemini, (2) Batch image generation from CSV or Google Sheets prompts, (3) Google Drive upload automation for generated images, (4) Image sizing for web, social media, and OG tags, (5) Prompt engineering for consistent AI image output, (6) Multi-model image generation comparison. Triggers on 'image generation', 'Vertex AI', 'Imagen', 'Gemini images', 'batch images', 'AI image pipeline', or 'generate images from prompts'."
license: Proprietary
---

# Google Vertex AI Imagen - Production Image Generation Pipeline

> End-to-end AI image generation: Vertex AI Imagen API + batch CSV/Sheets pipeline + Google Drive upload + post-generation optimization

**Version**: 1.0.0
**Last Updated**: 2026-02-16
**Source**: `gemini-image-automation` project
**Architecture**: Google Cloud (Vertex AI + Sheets API + Drive API) + Puppeteer browser automation
**Languages**: Python (API direct), TypeScript/Node.js (browser automation)

---

## Table of Contents

1. [Overview](#overview)
2. [Google Cloud Vertex AI Setup](#google-cloud-vertex-ai-setup)
3. [Imagen API Integration](#imagen-api-integration)
4. [Batch Image Generation Pipeline](#batch-image-generation-pipeline)
5. [Google Drive Upload Automation](#google-drive-upload-automation)
6. [Image Sizing Strategies](#image-sizing-strategies)
7. [Prompt Engineering for Consistent Output](#prompt-engineering-for-consistent-output)
8. [Quality Validation and Retry Logic](#quality-validation-and-retry-logic)
9. [Cost Optimization](#cost-optimization)
10. [Multi-Model Comparison](#multi-model-comparison)
11. [Integrates With](#integrates-with)

---

## Overview

### Architecture

```
Prompt Sources              Generation Engine              Output Pipeline
+------------------+       +---------------------+       +-------------------+
| CSV File         |       | Vertex AI Imagen API|       | Local Downloads   |
| Google Sheets    | ----> | Gemini Web UI       | ----> | Google Drive      |
| Markdown Prompts |       | (via Puppeteer)     |       | CDN / S3          |
+------------------+       +---------------------+       +-------------------+
        |                           |                            |
   MD Parser -----> CSV Generator ---> Queue Manager ---> Download Manager
        |                           |                            |
   Prompt Validation          Session Pool               Image Validation
                          (parallel browser tabs)        (size/dimension check)
```

### Two Approaches

| Approach | When to Use | Pros | Cons |
|----------|------------|------|------|
| **Vertex AI Imagen API** (Python) | Production, high volume, programmatic | Full control, no browser needed, reliable | Requires GCP billing, API costs |
| **Gemini Web UI Automation** (TypeScript) | Free tier usage, prototyping | No API cost, uses web interface | Browser automation fragile, rate limits |

### Quick Decision

```
Need > 50 images/day?           --> Vertex AI Imagen API (Python)
Budget-conscious / < 20 images? --> Gemini Web UI automation (TypeScript)
Need edit/inpaint/upscale?      --> Vertex AI Imagen API (Python)
One-off batch for blog posts?   --> CSV Mode with browser automation
```

---

## Google Cloud Vertex AI Setup

### Step 1: Create Project and Enable APIs

```bash
# Create or select a Google Cloud project
gcloud projects create my-image-gen --name="Image Generation"
gcloud config set project my-image-gen

# Enable required APIs
gcloud services enable aiplatform.googleapis.com    # Vertex AI (includes Imagen)
gcloud services enable sheets.googleapis.com         # Google Sheets API
gcloud services enable drive.googleapis.com          # Google Drive API
gcloud services enable storage.googleapis.com        # Cloud Storage (optional)
```

### Step 2: Create Service Account

```bash
# Create service account
gcloud iam service-accounts create image-gen-sa \
  --display-name="Image Generation Service Account" \
  --description="Service account for Imagen API and Drive automation"

# Grant roles
gcloud projects add-iam-policy-binding my-image-gen \
  --member="serviceAccount:image-gen-sa@my-image-gen.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding my-image-gen \
  --member="serviceAccount:image-gen-sa@my-image-gen.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

# Create and download key
gcloud iam service-accounts keys create credentials/service-account.json \
  --iam-account=image-gen-sa@my-image-gen.iam.gserviceaccount.com
```

### Step 3: Environment Configuration

```bash
# .env file
GOOGLE_APPLICATION_CREDENTIALS=./credentials/service-account.json
GOOGLE_CLOUD_PROJECT=my-image-gen
GOOGLE_CLOUD_REGION=us-central1

# Google Sheets (optional - for Sheets-backed queue)
SPREADSHEET_ID=your-spreadsheet-id-here

# Browser Profiles (for Gemini Web UI automation)
ACCOUNT_1_PROFILE_PATH=./profiles/account1
ACCOUNT_2_PROFILE_PATH=./profiles/account2

# Download Settings
DOWNLOAD_BASE_DIR=./downloads

# Rate Limiting
PROMPT_DELAY_MS=90000

# Logging
LOG_LEVEL=info
LOG_DIR=./logs
```

### Step 4: Authentication Patterns

```python
# Python: Vertex AI authentication
from google.cloud import aiplatform
from google.auth import credentials
import os

def initialize_vertex_ai():
    """Initialize Vertex AI with project credentials."""
    aiplatform.init(
        project=os.getenv("GOOGLE_CLOUD_PROJECT"),
        location=os.getenv("GOOGLE_CLOUD_REGION", "us-central1"),
    )

# Alternative: explicit credentials
from google.oauth2 import service_account

def get_credentials():
    """Load service account credentials."""
    creds = service_account.Credentials.from_service_account_file(
        os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
        scopes=[
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive.file",
        ]
    )
    return creds
```

```typescript
// TypeScript: Google Auth for Sheets/Drive
import { GoogleAuth } from 'google-auth-library';
import { google } from 'googleapis';

async function initializeGoogleApis() {
  const auth = new GoogleAuth({
    keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    scopes: [
      'https://www.googleapis.com/auth/spreadsheets',
      'https://www.googleapis.com/auth/drive.file',
    ],
  });

  const sheets = google.sheets({ version: 'v4', auth });
  const drive = google.drive({ version: 'v3', auth });

  return { sheets, drive, auth };
}
```

### Service Account Limitations

```
IMPORTANT: Service accounts have NO Google Drive storage quota.
They cannot CREATE new files in their own Drive.

Solution: Create spreadsheets/folders with your personal account,
then SHARE with the service account email for read/write access.

Service accounts CAN:
  - Read/write files shared with them
  - Upload to shared Drive folders
  - Modify spreadsheets shared with them

Service accounts CANNOT:
  - Create files in their own Drive (0 GB quota)
  - Own files or folders
```

---

## Imagen API Integration

### Generate Images (Vertex AI Imagen 3)

```python
import vertexai
from vertexai.preview.vision_models import ImageGenerationModel
import base64
from pathlib import Path

def generate_image(
    prompt: str,
    output_path: str,
    width: int = 1920,
    height: int = 1080,
    number_of_images: int = 1,
    aspect_ratio: str = "16:9",
    negative_prompt: str = "",
    seed: int | None = None,
    guidance_scale: float = 7.5,
    model_name: str = "imagen-3.0-generate-002",
) -> list[str]:
    """
    Generate images using Vertex AI Imagen 3.

    Args:
        prompt: Text description of the desired image
        output_path: Directory to save generated images
        width: Image width in pixels
        height: Image height in pixels
        number_of_images: How many variations to generate (1-4)
        aspect_ratio: "1:1", "16:9", "9:16", "4:3", "3:4"
        negative_prompt: What to avoid in the image
        seed: Reproducibility seed (optional)
        guidance_scale: How closely to follow prompt (1-30, default 7.5)
        model_name: Imagen model version

    Returns:
        List of paths to generated images
    """
    vertexai.init(
        project="my-image-gen",
        location="us-central1",
    )

    model = ImageGenerationModel.from_pretrained(model_name)

    # Generate
    response = model.generate_images(
        prompt=prompt,
        number_of_images=number_of_images,
        aspect_ratio=aspect_ratio,
        negative_prompt=negative_prompt,
        seed=seed,
        guidance_scale=guidance_scale,
        safety_filter_level="block_few",      # "block_none" | "block_few" | "block_some" | "block_most"
        person_generation="allow_all",         # "allow_all" | "allow_adult" | "dont_allow"
        language="en",
    )

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    saved_paths = []
    for idx, image in enumerate(response.images):
        filename = f"generated_{idx}.png"
        filepath = output_dir / filename
        image.save(str(filepath))
        saved_paths.append(str(filepath))

    return saved_paths
```

### Edit Images (Inpainting / Outpainting)

```python
from vertexai.preview.vision_models import ImageGenerationModel, Image

def edit_image(
    input_image_path: str,
    mask_image_path: str,
    edit_prompt: str,
    output_path: str,
    edit_mode: str = "inpainting-insert",
) -> str:
    """
    Edit an existing image using Imagen's editing capabilities.

    Edit modes:
        - inpainting-insert: Add content inside masked area
        - inpainting-remove: Remove content in masked area
        - outpainting: Extend image beyond original boundaries
        - product-image: Place product on new background

    Args:
        input_image_path: Path to the source image
        mask_image_path: Path to the mask (white = edit area)
        edit_prompt: Description of what to add/change
        output_path: Where to save the result
        edit_mode: Type of edit operation

    Returns:
        Path to edited image
    """
    model = ImageGenerationModel.from_pretrained("imagen-3.0-capability-001")

    base_image = Image.load_from_file(input_image_path)
    mask_image = Image.load_from_file(mask_image_path)

    response = model.edit_image(
        prompt=edit_prompt,
        base_image=base_image,
        mask=mask_image,
        edit_mode=edit_mode,
        number_of_images=1,
    )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    response.images[0].save(str(output_file))

    return str(output_file)
```

### Upscale Images

```python
def upscale_image(
    input_image_path: str,
    output_path: str,
    upscale_factor: str = "x2",
) -> str:
    """
    Upscale an image using Imagen's super-resolution.

    Args:
        input_image_path: Path to the image to upscale
        output_path: Where to save the upscaled image
        upscale_factor: "x2" or "x4"

    Returns:
        Path to upscaled image
    """
    model = ImageGenerationModel.from_pretrained("imagen-3.0-capability-001")

    base_image = Image.load_from_file(input_image_path)

    response = model.upscale_image(
        image=base_image,
        upscale_factor=upscale_factor,
    )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    response.images[0].save(str(output_file))

    return str(output_file)
```

### Gemini Web UI Automation (Alternative)

When using the free Gemini web interface via Puppeteer instead of the API:

```typescript
// Prompt construction with ||| delimiter prevents Gemini from splitting
function constructPrompt(data: PromptItem): string {
  let prompt = `/imagine `;
  prompt += `Size: ${data.size} ||| `;
  prompt += `Colors: ${data.colors} ||| `;
  prompt += `Typography: ${data.typography} ||| `;
  prompt += `Description: ${data.description}`;

  // Add title/author for Hero images (not Hero-OG)
  if (data.imageType.toLowerCase() === 'hero' && data.title) {
    prompt += ` ||| Title: ${data.title}`;
    prompt += ` ||| Published by: ${data.author || 'Author Name'}`;
  }

  return prompt;
}

// Image detection: track URLs before/after generation
async function waitForGenerationComplete(page: Page): Promise<void> {
  const imageUrlsBefore = await page.$$eval(
    'img[src*="googleusercontent.com"]',
    imgs => imgs.map(img => img.src)
  );

  const maxWaitTime = 300000; // 5 minutes
  const checkInterval = 5000; // 5 seconds

  const startTime = Date.now();
  while (Date.now() - startTime < maxWaitTime) {
    const imageUrlsNow = await page.$$eval(
      'img[src*="googleusercontent.com"]',
      imgs => imgs.map(img => img.src)
    );

    const newImages = imageUrlsNow.filter(
      url => !imageUrlsBefore.includes(url)
    );

    if (newImages.length > 0) {
      // New image detected -- wait for full load
      await page.waitForTimeout(10000);
      return;
    }

    // Check for error states
    const hasError = await page.evaluate(() =>
      document.body.textContent?.includes('You stopped this response') || false
    );
    if (hasError) {
      throw new Error('Prompt was split - "You stopped this response" detected');
    }

    await page.waitForTimeout(checkInterval);
  }

  throw new Error('No new image appeared after 5 minutes');
}
```

---

## Batch Image Generation Pipeline

### CSV Prompt Format

The batch pipeline reads prompts from a structured CSV file:

```csv
Prompt ID,Image Type,Image Filename,Size,Colors,Typography/Brand,Description,Title (Hero),Author (Hero),Status,Generated Image Path,Session ID,Generated At
1,Hero,hero-ai-healthcare.png,1920x1080px,"#2563eb, #1e40af, #ffffff","Modern sans-serif, professional tech blog","Healthcare professional analyzing patient data on advanced displays with AI-powered medical insights. Modern hospital setting with connected IoT devices. High quality, 4K, professional photography",AI in Healthcare Diagnostics,Ash Ganda,PENDING,,,
2,Regular,diagram-architecture.png,1600x900px,"#3B82F6, #1E3A8A, #FFFFFF","Clean sans-serif","Technical architecture diagram showing microservices with API gateway, load balancer, and database clusters. Professional technical illustration style.",,,,,,
3,Hero-OG,hero-ai-healthcare-og.jpg,1200x630px,"#2563eb, #1e40af, #ffffff","Modern sans-serif","Same scene as hero but composed for 1.91:1 social media aspect ratio. No title text overlay.",,,,,,
```

### Prompt Data Types

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class ImageType(Enum):
    HERO = "Hero"           # Website hero/featured image with title overlay
    HERO_OG = "Hero-OG"     # Social media version (no text overlay)
    REGULAR = "Regular"     # In-content images (diagrams, infographics)

class PromptStatus(Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RATE_LIMITED = "RATE_LIMITED"

@dataclass
class PromptItem:
    id: str
    row_index: int
    image_type: ImageType
    filename: str
    size: str                    # e.g., "1920x1080px"
    colors: str                  # e.g., "#2563eb, #1e40af, #ffffff"
    typography: str              # e.g., "Modern sans-serif, professional"
    description: str             # The actual AI prompt
    title: Optional[str] = None  # For hero images
    author: Optional[str] = None # For hero images
    status: PromptStatus = PromptStatus.PENDING
    image_path: Optional[str] = None
    session_id: Optional[str] = None
    generated_at: Optional[str] = None
```

### Markdown-to-CSV Conversion

Parse prompts from structured Markdown files into CSV for batch processing:

```python
import re
import csv
from pathlib import Path

def parse_markdown_prompts(md_path: str) -> list[dict]:
    """
    Parse prompts from a structured Markdown file.

    Supported formats:
      - GEMINI_IMAGE_PROMPTS.md (### header + **Field:** value)
      - IMAGE_PROMPTS.md (### header + **Slug:** + **Header/Infographic/Context Prompt:**)

    Returns list of prompt dicts ready for CSV generation.
    """
    content = Path(md_path).read_text()
    prompts = []

    # Split by ### headers
    blocks = re.split(r'^###\s+', content, flags=re.MULTILINE)

    for block in blocks:
        if not block.strip():
            continue

        lines = block.strip().split('\n')
        header = lines[0].strip()

        prompt = {}

        # Determine image type from header
        prompt['image_type'] = 'Hero' if 'hero' in header.lower() else 'Regular'

        # Extract structured fields
        for line in lines:
            line = line.strip()
            if line.startswith('**File:**'):
                prompt['filename'] = line.replace('**File:**', '').strip().strip('`')
            elif line.startswith('**Size:**'):
                prompt['size'] = line.replace('**Size:**', '').strip()
            elif line.startswith('**Colors:**'):
                prompt['colors'] = line.replace('**Colors:**', '').strip()
            elif line.startswith('**Typography:**'):
                prompt['typography'] = line.replace('**Typography:**', '').strip()
            elif line.startswith('**Prompt:**') or line.startswith('**Description:**'):
                key = '**Prompt:**' if '**Prompt:**' in line else '**Description:**'
                prompt['description'] = line.replace(key, '').strip()
            elif line.startswith('**Title:**'):
                prompt['title'] = line.replace('**Title:**', '').strip()
            elif line.startswith('**Author:**'):
                prompt['author'] = line.replace('**Author:**', '').strip()

        if prompt.get('filename') and prompt.get('description'):
            prompts.append(prompt)

    return prompts


def generate_csv(prompts: list[dict], output_path: str) -> None:
    """Generate batch processing CSV from parsed prompts."""
    headers = [
        'Prompt ID', 'Image Type', 'Image Filename', 'Size',
        'Colors', 'Typography/Brand', 'Description',
        'Title (Hero)', 'Author (Hero)', 'Status',
        'Generated Image Path', 'Session ID', 'Generated At',
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for idx, prompt in enumerate(prompts, 1):
            writer.writerow([
                idx,
                prompt.get('image_type', 'Regular'),
                prompt.get('filename', ''),
                prompt.get('size', '1920x1080px'),
                prompt.get('colors', ''),
                prompt.get('typography', ''),
                prompt.get('description', ''),
                prompt.get('title', ''),
                prompt.get('author', ''),
                'PENDING', '', '', '',
            ])
```

### Queue Manager with Mutex Lock

```python
import asyncio
import csv
from datetime import datetime
from pathlib import Path

class CSVQueueManager:
    """
    Thread-safe queue manager backed by CSV file.
    Supports concurrent access from multiple processing sessions.
    """

    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.data: list[PromptItem] = []
        self.assigned_prompts: set[str] = set()
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Load prompts from CSV file."""
        with open(self.csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                self.data.append(PromptItem(
                    id=row.get('Prompt ID', str(idx + 1)),
                    row_index=idx + 1,
                    image_type=ImageType(row.get('Image Type', 'Regular')),
                    filename=row.get('Image Filename', ''),
                    size=row.get('Size', '1920x1080px'),
                    colors=row.get('Colors', ''),
                    typography=row.get('Typography/Brand', ''),
                    description=row.get('Description', ''),
                    title=row.get('Title (Hero)') or None,
                    author=row.get('Author (Hero)') or None,
                    status=PromptStatus(row.get('Status', 'PENDING')),
                ))

    async def get_next_batch(self, count: int) -> list[PromptItem]:
        """Get next N pending prompts (thread-safe with mutex lock)."""
        async with self._lock:
            pending = []
            for item in self.data:
                if len(pending) >= count:
                    break
                if (item.status == PromptStatus.PENDING
                        and item.id not in self.assigned_prompts
                        and item.filename and item.description):
                    self.assigned_prompts.add(item.id)
                    pending.append(item)
            return pending

    async def update_status(
        self, prompt_id: str, status: PromptStatus,
        image_path: str = None, session_id: str = None,
    ) -> None:
        """Update status of a specific prompt."""
        for item in self.data:
            if item.id == prompt_id:
                item.status = status
                item.image_path = image_path
                item.session_id = session_id
                item.generated_at = datetime.utcnow().isoformat()
                break

    async def get_stats(self) -> dict:
        """Get queue statistics."""
        stats = {'total': 0, 'pending': 0, 'in_progress': 0, 'completed': 0, 'failed': 0}
        for item in self.data:
            stats['total'] += 1
            stats[item.status.value.lower()] = stats.get(item.status.value.lower(), 0) + 1
        return stats

    async def reset_in_progress(self) -> int:
        """Reset all IN_PROGRESS/FAILED back to PENDING for recovery."""
        count = 0
        for item in self.data:
            if item.status in (PromptStatus.IN_PROGRESS, PromptStatus.FAILED):
                item.status = PromptStatus.PENDING
                count += 1
        return count

    async def save_to_csv(self) -> None:
        """Persist current state to CSV (output file)."""
        output_path = self.csv_path.replace('.csv', '-completed.csv')
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Prompt ID', 'Image Type', 'Image Filename', 'Size',
                'Colors', 'Typography/Brand', 'Description',
                'Title (Hero)', 'Author (Hero)', 'Status',
                'Generated Image Path', 'Session ID', 'Generated At',
            ])
            for item in self.data:
                writer.writerow([
                    item.id, item.image_type.value, item.filename,
                    item.size, item.colors, item.typography,
                    item.description, item.title or '', item.author or '',
                    item.status.value, item.image_path or '',
                    item.session_id or '', item.generated_at or '',
                ])
```

### Parallel Session Pool

```python
import asyncio
from datetime import datetime

class SessionPool:
    """
    Coordinate parallel image generation across multiple sessions.
    Each session processes prompts independently with configurable delays.
    """

    def __init__(self, generators: list, delay_seconds: float = 90.0):
        self.generators = generators
        self.delay_seconds = delay_seconds
        self.active_prompts: dict[str, str] = {}  # session_id -> prompt_id

    async def process_queue(self, queue_manager: CSVQueueManager) -> dict:
        """Process entire queue using all sessions in parallel."""
        results = {'completed': 0, 'failed': 0}

        # Start independent processing loop for each session
        tasks = [
            self._session_loop(gen, queue_manager, results)
            for gen in self.generators
        ]

        await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _session_loop(
        self, generator, queue_manager: CSVQueueManager, results: dict,
    ) -> None:
        """Processing loop for a single session."""
        session_id = generator.session_id

        while True:
            # Get ONE prompt (atomic, thread-safe)
            batch = await queue_manager.get_next_batch(1)
            if not batch:
                break  # Queue empty

            prompt = batch[0]
            self.active_prompts[session_id] = prompt.id

            try:
                await queue_manager.update_status(
                    prompt.id, PromptStatus.IN_PROGRESS, session_id=session_id
                )

                # Generate image
                image_path = await generator.generate(prompt)

                # Validate
                if await self._validate_image(image_path):
                    await queue_manager.update_status(
                        prompt.id, PromptStatus.COMPLETED,
                        image_path=image_path, session_id=session_id,
                    )
                    results['completed'] += 1
                else:
                    await queue_manager.update_status(
                        prompt.id, PromptStatus.FAILED, session_id=session_id,
                    )
                    results['failed'] += 1

            except Exception as e:
                await queue_manager.update_status(
                    prompt.id, PromptStatus.FAILED, session_id=session_id,
                )
                results['failed'] += 1

            finally:
                self.active_prompts.pop(session_id, None)

            # Rate limiting delay between prompts per session
            await asyncio.sleep(self.delay_seconds)

    async def _validate_image(self, image_path: str) -> bool:
        """Validate generated image meets quality thresholds."""
        from pathlib import Path
        from PIL import Image

        path = Path(image_path)
        if not path.exists():
            return False

        # File size check (> 50KB to filter out logos/icons)
        file_size = path.stat().st_size
        if file_size < 50_000:
            return False

        # Dimension check (at least 500px in one dimension)
        try:
            with Image.open(path) as img:
                width, height = img.size
                if width < 500 and height < 500:
                    return False
        except Exception:
            return False

        return True
```

### Batch Processing with Vertex AI API

```python
import asyncio
from pathlib import Path
from datetime import datetime

async def batch_generate_from_csv(
    csv_path: str,
    output_dir: str,
    concurrency: int = 4,
    delay_between: float = 2.0,
) -> dict:
    """
    Process an entire CSV of prompts through Vertex AI Imagen.

    Args:
        csv_path: Path to the prompts CSV file
        output_dir: Directory to save generated images
        concurrency: Number of parallel generation tasks
        delay_between: Seconds between API calls per worker

    Returns:
        Statistics dict with completed/failed counts
    """
    queue = CSVQueueManager(csv_path)
    await queue.initialize()
    await queue.reset_in_progress()

    stats = await queue.get_stats()
    print(f"Queue: {stats['total']} total, {stats['pending']} pending")

    # Create output directory organized by date
    today = datetime.now().strftime('%Y-%m-%d')
    output_path = Path(output_dir) / today
    output_path.mkdir(parents=True, exist_ok=True)

    semaphore = asyncio.Semaphore(concurrency)

    async def process_one(prompt: PromptItem) -> bool:
        async with semaphore:
            try:
                await queue.update_status(prompt.id, PromptStatus.IN_PROGRESS)

                # Parse dimensions from size string
                width, height = parse_size(prompt.size)

                # Determine aspect ratio
                aspect_ratio = get_closest_aspect_ratio(width, height)

                # Build the full prompt
                full_prompt = build_imagen_prompt(prompt)

                # Generate via Vertex AI
                paths = generate_image(
                    prompt=full_prompt,
                    output_path=str(output_path),
                    aspect_ratio=aspect_ratio,
                    number_of_images=1,
                )

                if paths:
                    # Rename to expected filename
                    final_path = output_path / prompt.filename
                    Path(paths[0]).rename(final_path)

                    await queue.update_status(
                        prompt.id, PromptStatus.COMPLETED,
                        image_path=str(final_path),
                    )
                    return True

            except Exception as e:
                print(f"Failed {prompt.filename}: {e}")
                await queue.update_status(prompt.id, PromptStatus.FAILED)

            await asyncio.sleep(delay_between)
            return False

    # Process all pending prompts
    while True:
        batch = await queue.get_next_batch(concurrency)
        if not batch:
            break

        tasks = [process_one(p) for p in batch]
        await asyncio.gather(*tasks)

    await queue.save_to_csv()
    return await queue.get_stats()


def parse_size(size_str: str) -> tuple[int, int]:
    """Parse '1920x1080px' into (1920, 1080)."""
    clean = size_str.lower().replace('px', '').strip()
    parts = clean.split('x')
    return int(parts[0]), int(parts[1])


def get_closest_aspect_ratio(width: int, height: int) -> str:
    """Map dimensions to Imagen's supported aspect ratios."""
    ratio = width / height
    ratios = {
        "1:1": 1.0,
        "4:3": 4/3,
        "3:4": 3/4,
        "16:9": 16/9,
        "9:16": 9/16,
    }
    closest = min(ratios.items(), key=lambda x: abs(x[1] - ratio))
    return closest[0]


def build_imagen_prompt(prompt: PromptItem) -> str:
    """Construct the full prompt string for Imagen API."""
    parts = [prompt.description]

    if prompt.colors:
        parts.append(f"Use color palette: {prompt.colors}")

    if prompt.image_type == ImageType.HERO and prompt.title:
        parts.append(
            f'Include text overlay with title "{prompt.title}" '
            f'and author credit "{prompt.author or "Author"}"'
        )

    if prompt.typography:
        parts.append(f"Typography style: {prompt.typography}")

    parts.append("High quality, 4K, professional photography")

    return ". ".join(parts)
```

---

## Google Drive Upload Automation

### Upload Generated Images to Google Drive

```python
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from pathlib import Path

class GoogleDriveUploader:
    """Upload generated images to organized Google Drive folders."""

    def __init__(self, credentials_path: str):
        creds = service_account.Credentials.from_service_account_file(
            credentials_path,
            scopes=['https://www.googleapis.com/auth/drive.file'],
        )
        self.service = build('drive', 'v3', credentials=creds)

    def get_or_create_folder(
        self, folder_name: str, parent_id: str = None
    ) -> str:
        """Get existing folder or create new one."""
        query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"
        if parent_id:
            query += f" and '{parent_id}' in parents"

        results = self.service.files().list(
            q=query, spaces='drive', fields='files(id, name)'
        ).execute()

        files = results.get('files', [])
        if files:
            return files[0]['id']

        # Create folder
        file_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder',
        }
        if parent_id:
            file_metadata['parents'] = [parent_id]

        folder = self.service.files().create(
            body=file_metadata, fields='id'
        ).execute()

        return folder['id']

    def upload_image(
        self,
        local_path: str,
        folder_id: str,
        filename: str = None,
    ) -> dict:
        """
        Upload a single image to Google Drive.

        Returns:
            Dict with 'id', 'name', 'webViewLink'
        """
        path = Path(local_path)
        upload_name = filename or path.name

        # Determine MIME type
        mime_types = {
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.webp': 'image/webp',
            '.gif': 'image/gif',
        }
        mime_type = mime_types.get(path.suffix.lower(), 'image/png')

        file_metadata = {
            'name': upload_name,
            'parents': [folder_id],
        }

        media = MediaFileUpload(
            str(path),
            mimetype=mime_type,
            resumable=True,
        )

        file = self.service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, webViewLink, webContentLink',
        ).execute()

        return file

    def upload_batch(
        self,
        image_dir: str,
        drive_folder_id: str,
        pattern: str = "*.{png,jpg,jpeg,webp}",
    ) -> list[dict]:
        """Upload all images from a directory to Google Drive."""
        image_dir = Path(image_dir)
        results = []

        for ext in ['*.png', '*.jpg', '*.jpeg', '*.webp']:
            for image_path in sorted(image_dir.glob(ext)):
                try:
                    result = self.upload_image(
                        str(image_path), drive_folder_id
                    )
                    results.append(result)
                    print(f"Uploaded: {image_path.name} -> {result.get('webViewLink', 'N/A')}")
                except Exception as e:
                    print(f"Failed: {image_path.name} - {e}")
                    results.append({'name': image_path.name, 'error': str(e)})

        return results
```

### Organized Upload Pipeline

```python
from datetime import datetime

async def upload_generated_images(
    downloads_dir: str,
    root_folder_id: str,
    credentials_path: str,
    site_name: str = "blog",
) -> dict:
    """
    Upload all generated images to organized Google Drive structure.

    Drive Structure:
      Generated Images/
        blog/
          2026-02-16/
            hero-ai-healthcare.png
            hero-ai-healthcare-og.jpg
            diagram-architecture.png
    """
    uploader = GoogleDriveUploader(credentials_path)

    # Create folder hierarchy
    root_id = uploader.get_or_create_folder("Generated Images", root_folder_id)
    site_id = uploader.get_or_create_folder(site_name, root_id)

    today = datetime.now().strftime('%Y-%m-%d')
    date_id = uploader.get_or_create_folder(today, site_id)

    # Upload all images from today's downloads
    today_dir = Path(downloads_dir) / today
    if not today_dir.exists():
        print(f"No images found in {today_dir}")
        return {'uploaded': 0}

    results = uploader.upload_batch(str(today_dir), date_id)

    uploaded = sum(1 for r in results if 'error' not in r)
    failed = sum(1 for r in results if 'error' in r)

    return {
        'uploaded': uploaded,
        'failed': failed,
        'folder_url': f"https://drive.google.com/drive/folders/{date_id}",
        'details': results,
    }
```

---

## Image Sizing Strategies

### The Dual Image Problem

Hero/featured images must display correctly in two contexts with incompatible aspect ratios:

| Context | Aspect Ratio | Recommended Size | Purpose |
|---------|-------------|-----------------|---------|
| **Website Display** | 16:9 or 2.34:1 | 1920x1080px or 1800x768px | Responsive container |
| **Social Media (OG)** | 1.91:1 | 1200x630px | Facebook, LinkedIn, Twitter |

Using one image for both causes cropping. The solution is to generate TWO versions per hero image.

### Size Reference Table

| Image Type | Dimensions | Aspect Ratio | Use Case |
|------------|-----------|--------------|----------|
| **Hero (16:9 site)** | 1920x1080px | 16:9 | Standard website hero |
| **Hero (ultrawide site)** | 1800x768px | 2.34:1 | Wide-container sites |
| **OG / Social Media** | 1200x630px | 1.91:1 | Facebook, LinkedIn, Twitter |
| **Diagram** | 1600x900px | 16:9 | Technical diagrams, flowcharts |
| **Infographic** | 1200x1600px | 3:4 | Portrait detailed content |
| **Inline Screenshot** | 800x450px | 16:9 | In-content screenshots |
| **Square Social** | 1080x1080px | 1:1 | Instagram posts |
| **Thumbnail** | 400x225px | 16:9 | Grid/list previews |
| **Pinterest** | 1000x1500px | 2:3 | Pinterest pins |

### Dual Image Generation Strategy

```python
def generate_dual_hero_images(
    prompt: PromptItem,
    site_size: tuple[int, int],
    output_dir: str,
) -> dict[str, str]:
    """
    Generate both site display and OG versions of a hero image.

    Args:
        prompt: The prompt item with description, title, etc.
        site_size: (width, height) for the website version
        output_dir: Directory to save both images

    Returns:
        Dict with 'site' and 'og' paths
    """
    results = {}

    # 1. Site display version (with title/author overlay)
    site_prompt = build_imagen_prompt(prompt)  # Includes title text
    site_paths = generate_image(
        prompt=site_prompt,
        output_path=output_dir,
        aspect_ratio=get_closest_aspect_ratio(*site_size),
    )
    if site_paths:
        results['site'] = site_paths[0]

    # 2. OG/social media version (NO title/author overlay)
    og_prompt_item = PromptItem(
        id=prompt.id + '-og',
        row_index=prompt.row_index,
        image_type=ImageType.HERO_OG,
        filename=prompt.filename.replace('.png', '-og.jpg'),
        size='1200x630px',
        colors=prompt.colors,
        typography=prompt.typography,
        description=prompt.description,
        # Intentionally omit title and author
    )
    og_prompt = build_imagen_prompt(og_prompt_item)
    og_paths = generate_image(
        prompt=og_prompt,
        output_path=output_dir,
        aspect_ratio="16:9",  # Closest supported ratio
    )
    if og_paths:
        results['og'] = og_paths[0]

    return results
```

### Post-Generation Resize Script

```bash
#!/bin/bash
# resize-images.sh -- Resize generated images to exact target dimensions
# Uses macOS 'sips' or ImageMagick 'convert'

DOWNLOAD_DIR="downloads/$(date +%Y-%m-%d)"

echo "Resizing images to exact dimensions..."

# Hero images (1920x1080px)
for f in "$DOWNLOAD_DIR"/*-hero.{png,jpg}; do
  [ -f "$f" ] && sips -z 1080 1920 "$f" 2>/dev/null
done

# OG images (1200x630px)
for f in "$DOWNLOAD_DIR"/*-og.{png,jpg}; do
  [ -f "$f" ] && sips -z 630 1200 "$f" 2>/dev/null
done

# Infographics (1024x1400px)
for f in "$DOWNLOAD_DIR"/*-infographic.{png,jpg}; do
  [ -f "$f" ] && sips -z 1400 1024 "$f" 2>/dev/null
done

# Inline images (800x450px)
for f in "$DOWNLOAD_DIR"/*-inline.{png,jpg} "$DOWNLOAD_DIR"/*-mobile.{png,jpg}; do
  [ -f "$f" ] && sips -z 450 800 "$f" 2>/dev/null
done

echo "Resize complete. Verifying dimensions..."
file "$DOWNLOAD_DIR"/*.{png,jpg} 2>/dev/null | grep -o "[0-9]*x[0-9]*" | sort | uniq -c
```

### HTML OG Meta Tags

```html
<!-- In your blog post template -->
<meta property="og:image" content="https://yoursite.com/images/hero-topic-og.jpg" />
<meta property="og:image:width" content="1200" />
<meta property="og:image:height" content="630" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:image" content="https://yoursite.com/images/hero-topic-og.jpg" />
```

---

## Prompt Engineering for Consistent Output

### Prompt Structure (Proven Pattern)

```
/imagine Size: {width}x{height}px ||| Colors: {hex_codes} ||| Typography: {style} ||| Description: {detailed_visual_description} [||| Title: {title}] [||| Published by: {author}]
```

**Key insight**: Use `|||` as a delimiter to prevent Gemini from splitting the prompt into multiple messages ("You stopped this response" error).

### High-Quality Prompt Template

```
{subject_description}.
{environment_and_setting}.
{style_and_aesthetic}: {adjectives}.
{technical_quality}: High quality, 4K, professional photography.
{color_directive}: Use color palette {hex_codes}.
{composition_notes}.
```

### Example Prompts by Category

**Hero Image (Tech Blog)**:
```
Professional tech workspace with AI visualization on screens showing neural
networks and data flows. Modern minimalist office with developer working on
advanced AI systems. Soft ambient lighting, depth of field with blurred
background elements. Clean, modern aesthetic with blue (#2563eb) and white
(#ffffff) color scheme. High quality, 4K, professional photography.
```

**Infographic**:
```
Vertical infographic titled 'Local SEO Checklist for Businesses'. Organized
in 4 sections: (1) Google Business Profile Optimization (with checkboxes for
photos, reviews, posts), (2) Website & Local Pages (suburb-specific pages),
(3) Citations & Directories (NAP consistency), (4) Reviews & Reputation
(5-star icons). Include icons for each item. Use navy #1e3a5f and blue
#3b82f6 color scheme. Clean white background, professional design with
progress tracker at bottom.
```

**Medical/Healthcare**:
```
Split-screen image: Left side shows a professional medical receptionist at a
modern clinic desk with computer displaying a medical practice website. Right
side shows close-up of patient using tablet to book appointment online, clean
medical website interface visible with 'Book Online' button. Diverse patients
in background. Professional healthcare photography, bright and welcoming.
```

### Description Quality Checklist

```
Good prompts include:
  [x] Specific visual elements (objects, people, layout)
  [x] Environment/setting description
  [x] Color palette with hex codes
  [x] Aesthetic terms (clean, modern, professional, futuristic)
  [x] Technical quality directive (4K, professional photography)
  [x] Composition notes (depth of field, lighting)
  [x] 50-100+ words minimum

Bad prompts:
  [ ] "AI in healthcare" (too vague, 3 words)
  [ ] "Make a cool image" (no specifics)
  [ ] No color guidance (random palette)
  [ ] No style/aesthetic direction
```

### Consistency Strategies

```python
# 1. Brand-specific prompt suffixes
BRAND_SUFFIXES = {
    "techblog": "Clean, modern tech aesthetic. Professional photography. "
                "Blue (#2563eb) and white (#ffffff) color scheme.",
    "medical": "Professional healthcare aesthetic. Bright, welcoming, "
               "trustworthy. Blue (#4a90e2) and white (#ffffff).",
    "finance": "Corporate professional aesthetic. Dark navy (#1e3a5f) "
               "and gold (#d4af37) accents. Authority and trust.",
}

# 2. Negative prompts for quality control
NEGATIVE_PROMPTS = {
    "general": "blurry, low quality, distorted, watermark, text artifacts, "
               "clipart, cartoon, anime, sketch",
    "professional": "unprofessional, casual, messy, cluttered, dark, "
                    "gloomy, low resolution",
    "photo": "illustration, painting, drawing, 3D render, CGI, "
             "artificial looking",
}

# 3. Seed-based reproducibility
# Use the same seed to get similar compositions across a series
SERIES_SEED = 42  # Same seed = similar style across batch
```

### Filename Conventions

```
hero-{topic-keywords}.png         # Hero image for website
hero-{topic-keywords}-og.jpg      # Hero OG version for social media
diagram-{topic}.png               # Technical diagrams
infographic-{topic}.png           # Infographic (portrait)
screenshot-{app-name}.png         # Screenshot captures
inline-{context-description}.png  # In-content images

Rules:
  - Lowercase only
  - Hyphens (not underscores or spaces)
  - Descriptive and SEO-friendly
  - Include image type prefix
```

---

## Quality Validation and Retry Logic

### Image Validation Pipeline

```python
from pathlib import Path
from PIL import Image
import hashlib

class ImageValidator:
    """Validate generated images meet quality and dimension requirements."""

    MIN_FILE_SIZE_KB = 50       # Reject images under 50KB (likely logos)
    MIN_DIMENSION_PX = 500      # At least 500px in one dimension
    MAX_FILE_SIZE_MB = 20       # Reject images over 20MB (likely errors)

    def validate(self, image_path: str, expected_size: str = None) -> dict:
        """
        Run full validation suite on a generated image.

        Returns:
            {
                'valid': bool,
                'file_size_kb': float,
                'dimensions': (width, height),
                'hash': str,
                'errors': list[str],
            }
        """
        path = Path(image_path)
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
        }

        # 1. File exists
        if not path.exists():
            result['valid'] = False
            result['errors'].append(f"File does not exist: {image_path}")
            return result

        # 2. File size
        file_size = path.stat().st_size
        result['file_size_kb'] = round(file_size / 1024, 2)

        if file_size < self.MIN_FILE_SIZE_KB * 1024:
            result['valid'] = False
            result['errors'].append(
                f"File too small ({result['file_size_kb']}KB < {self.MIN_FILE_SIZE_KB}KB)"
            )

        if file_size > self.MAX_FILE_SIZE_MB * 1024 * 1024:
            result['valid'] = False
            result['errors'].append(
                f"File too large ({file_size / (1024*1024):.1f}MB > {self.MAX_FILE_SIZE_MB}MB)"
            )

        # 3. Image dimensions
        try:
            with Image.open(path) as img:
                width, height = img.size
                result['dimensions'] = (width, height)
                result['format'] = img.format

                if width < self.MIN_DIMENSION_PX and height < self.MIN_DIMENSION_PX:
                    result['valid'] = False
                    result['errors'].append(
                        f"Image too small ({width}x{height} < {self.MIN_DIMENSION_PX}px)"
                    )

                # Check against expected size
                if expected_size:
                    exp_w, exp_h = parse_size(expected_size)
                    tolerance = 0.1  # 10% tolerance
                    if (abs(width - exp_w) / exp_w > tolerance or
                            abs(height - exp_h) / exp_h > tolerance):
                        result['warnings'].append(
                            f"Size mismatch: got {width}x{height}, "
                            f"expected ~{exp_w}x{exp_h}"
                        )
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"Cannot read image: {e}")

        # 4. Content hash (for deduplication)
        if path.exists():
            result['hash'] = hashlib.md5(path.read_bytes()).hexdigest()

        return result
```

### Retry Logic with Exponential Backoff

```python
import asyncio
import random

class RetryableImageGenerator:
    """Image generator with configurable retry and backoff strategy."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 30.0,
        max_delay: float = 300.0,
        backoff_factor: float = 2.0,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.validator = ImageValidator()

    async def generate_with_retry(
        self, prompt: PromptItem, output_dir: str,
    ) -> str:
        """
        Generate image with automatic retry on failure.

        Retry triggers:
          - API error (network, rate limit, server error)
          - Validation failure (image too small, corrupted)
          - Content safety rejection (modify prompt and retry)
        """
        last_error = None

        for attempt in range(1, self.max_retries + 1):
            try:
                # Generate the image
                image_path = await self._generate(prompt, output_dir)

                # Validate
                validation = self.validator.validate(
                    image_path, expected_size=prompt.size
                )

                if validation['valid']:
                    if validation.get('warnings'):
                        for w in validation['warnings']:
                            print(f"  Warning: {w}")
                    return image_path

                # Validation failed -- retry
                print(
                    f"  Validation failed (attempt {attempt}/{self.max_retries}): "
                    f"{validation['errors']}"
                )
                last_error = Exception(f"Validation: {validation['errors']}")

            except RateLimitError:
                print(f"  Rate limited (attempt {attempt}/{self.max_retries})")
                last_error = RateLimitError("Rate limit exceeded")

            except ContentSafetyError as e:
                print(f"  Content safety rejection: {e}")
                # Modify prompt to be less restrictive
                prompt = self._soften_prompt(prompt)
                last_error = e

            except Exception as e:
                print(f"  Error (attempt {attempt}/{self.max_retries}): {e}")
                last_error = e

            # Exponential backoff with jitter
            if attempt < self.max_retries:
                delay = min(
                    self.base_delay * (self.backoff_factor ** (attempt - 1)),
                    self.max_delay,
                )
                jitter = random.uniform(0, delay * 0.1)
                total_delay = delay + jitter
                print(f"  Retrying in {total_delay:.1f}s...")
                await asyncio.sleep(total_delay)

        raise last_error or Exception(
            f"Failed after {self.max_retries} attempts"
        )

    def _soften_prompt(self, prompt: PromptItem) -> PromptItem:
        """
        Modify prompt to avoid content safety filters.
        Remove potentially flagged terms while preserving intent.
        """
        # Common substitutions
        replacements = {
            'weapon': 'tool',
            'fight': 'compete',
            'attack': 'challenge',
            'blood': 'red accent',
            'dark': 'dramatic',
        }
        description = prompt.description
        for old, new in replacements.items():
            description = description.replace(old, new)

        return PromptItem(
            **{**prompt.__dict__, 'description': description}
        )


class RateLimitError(Exception):
    pass

class ContentSafetyError(Exception):
    pass
```

### Generation Log (JSONL Audit Trail)

```python
import json
from pathlib import Path
from datetime import datetime

class GenerationLogger:
    """Append-only JSONL log for complete audit trail of all generations."""

    def __init__(self, log_dir: str = "./logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "generation-log.jsonl"

    def log_generation(
        self,
        prompt: PromptItem,
        image_path: str,
        session_id: str,
        duration_seconds: float = None,
        model: str = "imagen-3.0-generate-002",
    ) -> None:
        """Append a generation record to the log."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "sessionId": session_id,
            "promptId": prompt.id,
            "filename": prompt.filename,
            "imageType": prompt.image_type.value,
            "size": prompt.size,
            "colors": prompt.colors,
            "title": prompt.title,
            "author": prompt.author,
            "description": prompt.description,
            "imagePath": image_path,
            "model": model,
            "durationSeconds": duration_seconds,
        }

        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def get_stats(self) -> dict:
        """Read log and compute aggregate statistics."""
        if not self.log_file.exists():
            return {'total': 0}

        entries = []
        with open(self.log_file, 'r') as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

        return {
            'total': len(entries),
            'by_type': {
                t: sum(1 for e in entries if e.get('imageType') == t)
                for t in set(e.get('imageType', 'Unknown') for e in entries)
            },
            'by_session': {
                s: sum(1 for e in entries if e.get('sessionId') == s)
                for s in set(e.get('sessionId', 'unknown') for e in entries)
            },
            'avg_duration': (
                sum(e.get('durationSeconds', 0) for e in entries) / len(entries)
                if entries else 0
            ),
        }
```

---

## Cost Optimization

### Vertex AI Imagen Pricing (as of 2026)

| Model | Resolution | Per Image | Notes |
|-------|-----------|-----------|-------|
| **Imagen 3 (Standard)** | Up to 1024x1024 | ~$0.04 | Best quality/price |
| **Imagen 3 (HD)** | Up to 2048x2048 | ~$0.08 | Higher resolution |
| **Imagen 3 Edit** | Based on input | ~$0.04 | Inpainting/outpainting |
| **Imagen 3 Upscale** | 2x or 4x | ~$0.02 | Super-resolution |
| **Gemini Web UI** | Variable | Free | Rate limited, browser automation |

### Cost Optimization Strategies

```python
# Strategy 1: Generate at standard resolution, upscale after
# Cost: $0.04 + $0.02 = $0.06 vs $0.08 for HD direct
# Savings: 25% on high-res images

async def generate_and_upscale(prompt, target_size):
    """Generate at standard size, then upscale. Cheaper than HD generation."""
    # Generate at 1024x1024
    standard_path = generate_image(prompt, aspect_ratio="1:1")

    # Upscale to target
    if target_size[0] > 1024 or target_size[1] > 1024:
        upscaled_path = upscale_image(standard_path, upscale_factor="x2")
        # Then resize to exact target
        resize_to_exact(upscaled_path, target_size)
        return upscaled_path

    return standard_path


# Strategy 2: Batch during off-peak hours
# Lower latency, potentially lower costs with committed use discounts

BATCH_SCHEDULE = {
    'off_peak': {'hours': range(0, 8), 'max_concurrent': 8},
    'peak': {'hours': range(8, 22), 'max_concurrent': 2},
    'evening': {'hours': range(22, 24), 'max_concurrent': 4},
}


# Strategy 3: Cache generated images by prompt hash
import hashlib

def get_prompt_hash(prompt: PromptItem) -> str:
    """Generate deterministic hash for a prompt to enable caching."""
    key = f"{prompt.description}|{prompt.size}|{prompt.colors}|{prompt.image_type.value}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]

async def generate_with_cache(prompt: PromptItem, cache_dir: str) -> str:
    """Check cache before generating. Saves API costs for repeated prompts."""
    prompt_hash = get_prompt_hash(prompt)
    cache_path = Path(cache_dir) / f"{prompt_hash}.png"

    if cache_path.exists():
        print(f"  Cache hit: {prompt_hash}")
        return str(cache_path)

    # Generate new image
    result_path = await generate_image(prompt)

    # Cache it
    import shutil
    shutil.copy2(result_path, cache_path)

    return result_path


# Strategy 4: Model selection by image type
MODEL_SELECTION = {
    ImageType.HERO: "imagen-3.0-generate-002",      # Highest quality for heroes
    ImageType.HERO_OG: "imagen-3.0-generate-002",   # Same quality for social
    ImageType.REGULAR: "imagen-3.0-generate-001",   # Standard for diagrams
}


# Strategy 5: Budget tracking
class BudgetTracker:
    """Track API costs and enforce spending limits."""

    COST_PER_IMAGE = {
        "imagen-3.0-generate-002": 0.04,
        "imagen-3.0-generate-001": 0.03,
        "imagen-3.0-capability-001": 0.04,
        "upscale": 0.02,
    }

    def __init__(self, daily_limit: float = 10.0):
        self.daily_limit = daily_limit
        self.daily_spend = 0.0

    def can_generate(self, model: str = "imagen-3.0-generate-002") -> bool:
        cost = self.COST_PER_IMAGE.get(model, 0.04)
        return (self.daily_spend + cost) <= self.daily_limit

    def record_generation(self, model: str = "imagen-3.0-generate-002"):
        cost = self.COST_PER_IMAGE.get(model, 0.04)
        self.daily_spend += cost

    def get_remaining_budget(self) -> float:
        return self.daily_limit - self.daily_spend

    def get_remaining_images(self, model: str = "imagen-3.0-generate-002") -> int:
        cost = self.COST_PER_IMAGE.get(model, 0.04)
        return int(self.get_remaining_budget() / cost)
```

### Cost Comparison: 100 Hero Images

```
Vertex AI Imagen 3 (Standard):
  100 x $0.04 = $4.00

Vertex AI Imagen 3 (HD):
  100 x $0.08 = $8.00

Generate Standard + Upscale:
  100 x ($0.04 + $0.02) = $6.00

Gemini Web UI (Browser Automation):
  100 x $0.00 = $0.00 (but 2-4 hours of automation time + fragile)

DALL-E 3 (OpenAI):
  100 x $0.04-$0.08 = $4.00-$8.00

Stable Diffusion (Self-hosted):
  GPU time only: ~$0.50-$2.00 total (A100 at $1.50/hr)
```

---

## Multi-Model Comparison

### Feature Matrix

| Feature | Vertex AI Imagen 3 | OpenAI DALL-E 3 | Stable Diffusion XL | Midjourney |
|---------|-------------------|-----------------|---------------------|------------|
| **API Access** | Yes | Yes | Yes (self-host) | No (Discord only) |
| **Max Resolution** | 2048x2048 | 1024x1024 | Unlimited (self-host) | 1024x1024 |
| **Aspect Ratios** | 5 presets | 3 presets | Any | 4 presets |
| **Inpainting** | Yes | No | Yes | No |
| **Outpainting** | Yes | No | Yes | No |
| **Upscaling** | Built-in (x2, x4) | No | Real-ESRGAN | Built-in |
| **Text in Images** | Good | Better | Poor | Good |
| **Photorealism** | Excellent | Excellent | Good | Excellent |
| **Batch API** | Yes | Yes | Yes | No |
| **Cost (per image)** | $0.04-$0.08 | $0.04-$0.08 | ~$0.01-$0.02 | $0.01-$0.02 |
| **Safety Filters** | Configurable | Strict | None (self-host) | Moderate |
| **Seed Control** | Yes | No | Yes | Yes |
| **Self-Hosting** | No | No | Yes | No |
| **Google Integration** | Native | Manual | Manual | Manual |

### When to Use Each

```
Vertex AI Imagen 3:
  - Already in Google Cloud ecosystem
  - Need inpainting/outpainting/upscaling
  - Want configurable safety filters
  - Need Google Sheets/Drive integration
  - Enterprise compliance requirements

OpenAI DALL-E 3:
  - Best text rendering in images
  - ChatGPT integration needed
  - Simple API, quick prototyping
  - Already using OpenAI for other tasks

Stable Diffusion XL (Self-hosted):
  - Maximum control over output
  - Custom fine-tuned models needed
  - Cost-sensitive at high volume
  - No content restrictions needed
  - Custom image dimensions required

Midjourney:
  - Highest aesthetic quality
  - Artistic/creative images
  - Manual workflow acceptable
  - Community/inspiration browsing
```

### Multi-Provider Implementation

```python
from abc import ABC, abstractmethod

class ImageGenerator(ABC):
    """Abstract base for swappable image generation providers."""

    @abstractmethod
    async def generate(
        self, prompt: str, width: int, height: int, **kwargs
    ) -> str:
        """Generate an image and return the file path."""
        pass

    @abstractmethod
    def get_cost_per_image(self) -> float:
        pass


class VertexAIGenerator(ImageGenerator):
    """Google Vertex AI Imagen 3 generator."""

    async def generate(self, prompt, width, height, **kwargs):
        aspect_ratio = get_closest_aspect_ratio(width, height)
        paths = generate_image(
            prompt=prompt,
            output_path=kwargs.get('output_dir', './output'),
            aspect_ratio=aspect_ratio,
            model_name=kwargs.get('model', 'imagen-3.0-generate-002'),
        )
        return paths[0] if paths else None

    def get_cost_per_image(self):
        return 0.04


class DallEGenerator(ImageGenerator):
    """OpenAI DALL-E 3 generator."""

    async def generate(self, prompt, width, height, **kwargs):
        import openai
        client = openai.OpenAI()

        # DALL-E 3 supports: 1024x1024, 1024x1792, 1792x1024
        dall_e_size = "1024x1024"
        if width > height:
            dall_e_size = "1792x1024"
        elif height > width:
            dall_e_size = "1024x1792"

        response = client.images.generate(
            model="dall-e-3",
            prompt=prompt,
            size=dall_e_size,
            quality=kwargs.get('quality', 'standard'),
            n=1,
        )

        # Download the image
        import urllib.request
        output_path = Path(kwargs.get('output_dir', './output'))
        output_path.mkdir(parents=True, exist_ok=True)
        filepath = output_path / f"dalle_{hash(prompt)[:8]}.png"
        urllib.request.urlretrieve(response.data[0].url, str(filepath))
        return str(filepath)

    def get_cost_per_image(self):
        return 0.04


class StableDiffusionGenerator(ImageGenerator):
    """Stable Diffusion XL via local or hosted API."""

    async def generate(self, prompt, width, height, **kwargs):
        import requests

        # Call local Stable Diffusion API (e.g., AUTOMATIC1111, ComfyUI)
        api_url = kwargs.get('api_url', 'http://localhost:7860')

        payload = {
            "prompt": prompt,
            "negative_prompt": kwargs.get('negative_prompt', ''),
            "width": width,
            "height": height,
            "steps": kwargs.get('steps', 30),
            "cfg_scale": kwargs.get('cfg_scale', 7.5),
            "seed": kwargs.get('seed', -1),
        }

        response = requests.post(f"{api_url}/sdapi/v1/txt2img", json=payload)
        response.raise_for_status()

        data = response.json()
        import base64
        output_path = Path(kwargs.get('output_dir', './output'))
        output_path.mkdir(parents=True, exist_ok=True)
        filepath = output_path / f"sd_{hash(prompt)[:8]}.png"
        filepath.write_bytes(base64.b64decode(data['images'][0]))
        return str(filepath)

    def get_cost_per_image(self):
        return 0.01  # GPU time only


# Factory pattern for provider selection
def get_generator(provider: str = "vertex-ai") -> ImageGenerator:
    """Factory to create the appropriate image generator."""
    generators = {
        "vertex-ai": VertexAIGenerator,
        "dall-e": DallEGenerator,
        "stable-diffusion": StableDiffusionGenerator,
    }

    generator_class = generators.get(provider)
    if not generator_class:
        raise ValueError(f"Unknown provider: {provider}. Options: {list(generators.keys())}")

    return generator_class()
```

---

## Integrates With

### Direct Dependencies

| Module/Skill | Purpose | Integration Point |
|-------------|---------|-------------------|
| **`image-optimizer`** module | Post-generation optimization (WebP conversion, resize, compress) | Run after generation to optimize file size and format |
| **`image-generation-validator`** module | Hash/timestamp validation for generated images | Validate each generated image before marking as COMPLETED |
| **`media-processing-universal`** skill | Media pipeline patterns (multi-provider, CDN, storage) | Upload pipeline and CDN delivery patterns |
| **`batch-processing`** skill | Bulk generation operations (queue, retry, progress) | Queue management and parallel processing framework |
| **`unified-api-client`** module | Google API client patterns (auth, rate limiting) | Google Sheets, Drive, and Vertex AI authentication |

### Integration Examples

```python
# Post-generation: optimize with image-optimizer
from image_optimizer import optimize_for_web

async def generate_and_optimize(prompt, output_dir):
    # 1. Generate via Vertex AI
    raw_path = await generate_image(prompt, output_dir)

    # 2. Optimize with image-optimizer module
    optimized_path = optimize_for_web(
        raw_path,
        format='webp',
        quality=85,
        max_width=1920,
    )

    # 3. Validate with image-generation-validator
    validation = ImageValidator().validate(optimized_path, expected_size=prompt.size)
    if not validation['valid']:
        raise ValueError(f"Post-optimization validation failed: {validation['errors']}")

    return optimized_path
```

```python
# Full pipeline: generate -> validate -> optimize -> upload
async def full_pipeline(csv_path, drive_folder_id, credentials_path):
    # 1. Batch generate (uses batch-processing patterns)
    stats = await batch_generate_from_csv(csv_path, "./downloads")

    # 2. Optimize all generated images
    today = datetime.now().strftime('%Y-%m-%d')
    downloads_dir = f"./downloads/{today}"
    for image_file in Path(downloads_dir).glob("*.*"):
        optimize_for_web(str(image_file))

    # 3. Upload to Google Drive
    upload_result = await upload_generated_images(
        downloads_dir, drive_folder_id, credentials_path
    )

    return {**stats, **upload_result}
```

### Pipeline Architecture

```
CSV/Sheets Prompts
       |
       v
+------------------+
| Queue Manager    |  <-- batch-processing skill
| (CSV or Sheets)  |
+------------------+
       |
       v
+------------------+
| Session Pool     |  Parallel generation across N workers
| (Parallel)       |
+------------------+
       |
       v
+------------------+
| Image Generator  |  <-- unified-api-client module (auth)
| (Vertex AI /     |
|  Gemini / DALL-E)|
+------------------+
       |
       v
+------------------+
| Validator        |  <-- image-generation-validator module
| (Size, Dims,     |
|  Hash, Content)  |
+------------------+
       |
       v
+------------------+
| Optimizer        |  <-- image-optimizer module
| (WebP, Resize,   |
|  Compress)       |
+------------------+
       |
       v
+------------------+
| Upload           |  <-- media-processing-universal skill
| (Drive, S3, CDN) |
+------------------+
       |
       v
+------------------+
| Log & Report     |
| (JSONL audit,    |
|  CSV status)     |
+------------------+
```
