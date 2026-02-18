---
name: wordpress-patterns
description: "Production-ready WordPress development patterns covering REST API integration, block theme customization, security hardening, and CMS integration. Use when: (1) Building headless WordPress architectures, (2) Custom WordPress API integrations, (3) Block theme development, (4) WordPress security hardening, (5) Deployment troubleshooting. Triggers on 'WordPress', 'WP REST API', 'block theme', 'WP-CLI', 'WordPress security', or 'headless CMS'."
license: Proprietary
---

# WordPress Patterns Skill

**Production-ready patterns for WordPress development, REST API integration, and deployment**

Comprehensive knowledge base covering 13 critical WordPress patterns learned from production implementations including headless WordPress, REST API integration, block theme customization, and security hardening.

## Value Proposition

**Time Saved**: 10-20 hours troubleshooting common WordPress issues
**Coverage**: REST API, Block Themes, Security, Deployment, CMS Integration
**Battle-Tested**: All patterns from production implementations
**Error Prevention**: Avoid common pitfalls in WordPress development

---

## Quick Reference: WordPress Operations

| Operation | Method | Key Concerns |
|-----------|--------|--------------|
| **Post by URL** | Slug-based lookup | Extract slug from URL |
| **Image Upload** | `/wp-json/wp/v2/media` | Content-Disposition header required |
| **Content Update** | HTML cleanup | Remove old images with regex |
| **Static Pages** | Explicit slug + status | Must set status='publish' |
| **Navigation** | Template editing | Preserve `ref` parameter |
| **Theme CSS** | Database (wp_global_styles) | Not in files, use WP-CLI |
| **Security** | Multiple plugins | MFA + Custom Login + Firewall |
| **API Blocks** | Use WP-CLI via SSH | Security plugins block REST writes |
| **Timezone** | Local time returned | Convert to UTC with offset |

---

# TABLE OF CONTENTS

1. [REST API Integration](#rest-api-integration)
2. [Block Theme Customization](#block-theme-customization)
3. [Security & Deployment](#security--deployment)
4. [CMS Integration](#cms-integration)
5. [Content Management Patterns](#content-management-patterns)

---

# REST API INTEGRATION

## Pattern 1: Slug-Based Lookup for URL-to-Post-ID Conversion

**Problem**: Need to query WordPress post by URL but REST API only accepts IDs.

**Solution**: Extract slug from URL and query using `slug` parameter.

```python
def extract_slug_from_url(url):
    """Extract post slug from WordPress URL."""
    url = url.rstrip('/')  # Remove trailing slash
    slug = url.split('/')[-1]  # Get last part
    return slug

def get_post_by_slug(slug):
    """Fetch post by slug from WordPress REST API."""
    response = requests.get(
        f'{WP_URL}/wp-json/wp/v2/posts',
        params={'slug': slug},  # Query parameter for slug search
        headers=headers,
        timeout=10
    )

    if response.status_code == 200:
        posts = response.json()
        if posts:
            post = posts[0]  # Slug is unique, returns array with 1 item
            return {
                'success': True,
                'id': post['id'],
                'title': post['title']['rendered'],
                'url': post['link'],
                'content': post['content']['rendered']
            }

    return {'success': False, 'error': 'Post not found'}
```

**Usage**:
```python
url = 'https://site.com/2026/01/12/story-title/'
slug = extract_slug_from_url(url)  # 'story-title'
post = get_post_by_slug(slug)
print(post['id'])  # 3154
```

**API Response Format**:
```json
// GET /wp-json/wp/v2/posts?slug=story-title
[
    {
        "id": 3154,
        "slug": "story-title",
        "link": "https://site.com/2026/01/12/story-title/",
        "title": {"rendered": "Story Title"},
        "content": {"rendered": "<p>...</p>"}
    }
]
```

**Prevention Checklist**:
- [ ] Always use `slug` parameter for URL-based lookups
- [ ] Handle both http:// and https:// URLs uniformly
- [ ] Remove trailing slashes before parsing
- [ ] Check if posts array is empty (slug not found)
- [ ] Add proper error handling for 404 responses

---

## Pattern 2: Image Upload with Content-Disposition Header

**Problem**: Image uploads to WordPress may fail or have incorrect filenames without proper headers.

**Solution**: Use `Content-Disposition` header with binary data upload.

```python
def upload_image_to_wordpress(image_path, title):
    """Upload an image to WordPress media library."""
    with open(image_path, 'rb') as img:
        filename = os.path.basename(image_path)

        media_headers = {
            'Authorization': f'Basic {token}',
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Type': 'image/png'  # Match actual image type
        }

        response = requests.post(
            f'{WP_URL}/wp-json/wp/v2/media',
            headers=media_headers,
            data=img,  # Raw binary data (not files={'file': img})
            timeout=60  # Long timeout for large images
        )

        if response.status_code == 201:  # Created (not 200)
            media = response.json()
            return {
                'success': True,
                'id': media['id'],  # Media ID for wp-image-{id}
                'url': media['source_url'],  # Full image URL
                'filename': filename
            }

        return {
            'success': False,
            'error': response.json()
        }
```

**Key Points**:
- Status code is **201 Created**, not 200 OK
- Use `data=img` for binary, not `files={'file': img}` multipart
- `Content-Disposition: attachment; filename="..."` is required
- Response includes `id` (for featured_media and CSS classes) and `source_url`

**Updating Post with Uploaded Images**:
```python
def update_post_with_images(post_id, uploaded_images):
    """Insert images into post content."""
    image_html = ""
    for i, img in enumerate(uploaded_images, 1):
        scene_name = "Opening" if i == 1 else "Middle" if i == 2 else "Conclusion"
        image_html += f'''<figure class="wp-block-image size-full">
<img loading="lazy" decoding="async" width="2048" height="2048"
     src="{img["url"]}"
     alt="{post_title} - Scene {i}"
     class="wp-image-{img['id']}" />
<figcaption>Scene {i}: {scene_name}</figcaption>
</figure>

'''

    # Update post with images + set featured media
    update_data = {
        'content': image_html + existing_content,
        'featured_media': uploaded_images[0]['id']  # First image as hero
    }

    requests.post(
        f'{WP_URL}/wp-json/wp/v2/posts/{post_id}',
        headers=headers,
        json=update_data
    )
```

**Prevention Checklist**:
- [ ] Always set Content-Disposition with filename
- [ ] Use appropriate Content-Type (image/png, image/jpeg, image/webp)
- [ ] Check for 201 Created status, not 200
- [ ] Set timeout ≥ 60s for large image uploads
- [ ] Store media ID for later featured_media assignment

---

## Pattern 3: Content Update with HTML Cleanup

**Problem**: Replacing images in WordPress posts leaves old images in content, creating duplicates.

**Solution**: Strip existing images before adding new ones using regex patterns.

```python
import re

def update_post_with_images(post_id, uploaded_images):
    """Update post content with new images, removing old ones."""
    # 1. Get current content
    current_content = get_post_content(post_id)

    # 2. Remove old images using regex patterns
    clean_content = current_content

    # Remove block editor image markup
    clean_content = re.sub(
        r'<!-- wp:image.*?-->.*?<!-- /wp:image -->',
        '',
        clean_content,
        flags=re.DOTALL  # Match across newlines
    )

    # Remove figure tags
    clean_content = re.sub(
        r'<figure class="wp-block-image.*?</figure>',
        '',
        clean_content,
        flags=re.DOTALL
    )

    # Remove standalone img tags
    clean_content = re.sub(r'<img[^>]*>', '', clean_content)

    # Remove empty paragraphs
    clean_content = re.sub(r'<p>\s*</p>', '', clean_content)

    # 3. Build new image HTML
    image_html = ""
    for i, img in enumerate(uploaded_images, 1):
        scene_name = "Opening" if i == 1 else "Middle" if i == 2 else "Conclusion"
        image_html += f'''<figure class="wp-block-image size-full story-illustration">
<img loading="lazy" decoding="async" width="2048" height="2048" src="{img["url"]}"
     alt="Story - Scene {i}" class="wp-image-{img['id']}" />
<figcaption class="wp-element-caption">Scene {i}: {scene_name}</figcaption>
</figure>

'''

    # 4. Prepend new images to cleaned content
    new_content = image_html + clean_content

    # 5. Update post
    update_data = {
        'content': new_content,
        'featured_media': uploaded_images[0]['id']
    }

    response = requests.post(
        f'{WP_URL}/wp-json/wp/v2/posts/{post_id}',
        headers=headers,
        json=update_data,
        timeout=30
    )

    return response.status_code == 200
```

**Regex Patterns Explained**:
| Pattern | Purpose | Flags |
|---------|---------|-------|
| `<!-- wp:image.*?-->.*?<!-- /wp:image -->` | Remove Gutenberg block comments | `DOTALL` |
| `<figure class="wp-block-image.*?</figure>` | Remove figure wrappers | `DOTALL` |
| `<img[^>]*>` | Remove standalone images | None |
| `<p>\s*</p>` | Remove empty paragraphs | None |

**Prevention Checklist**:
- [ ] Always clean old images before adding new ones
- [ ] Use `re.DOTALL` flag for multi-line patterns
- [ ] Test regex on sample content before applying to all posts
- [ ] Keep backup of original content before modification
- [ ] Validate HTML structure after cleanup

---

## Pattern 4: Static Pages with Slug and Status

**Problem**: Pages created via REST API not appearing correctly or with wrong URLs.

**Solution**: Explicitly set `slug` and `status` fields during page creation.

```python
def create_wordpress_page(title, slug, content):
    """Create a static page in WordPress."""
    page_data = {
        "title": title,
        "slug": slug,              # Explicit slug required
        "status": "publish",        # Must be 'publish' not 'draft'
        "content": content,
        "author": 1
    }

    response = requests.post(
        f"{WP_URL}/wp-json/wp/v2/pages",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json=page_data,
        timeout=30
    )

    if response.status_code == 201:
        page = response.json()
        return {
            'success': True,
            'id': page['id'],
            'url': page['link'],
            'slug': page['slug']
        }

    return {'success': False, 'error': response.json()}
```

**Batch Page Creation**:
```python
pages = [
    {"title": "Privacy Policy", "slug": "privacy-policy"},
    {"title": "About Us", "slug": "about"},
    {"title": "Contact", "slug": "contact"},
    {"title": "Terms of Use", "slug": "terms"}
]

for page in pages:
    result = create_wordpress_page(
        title=page['title'],
        slug=page['slug'],
        content=generate_page_content(page['slug'])
    )
    print(f"Created: {result['url']}")
```

**Prevention Checklist**:
- [ ] Always specify slug explicitly (don't rely on auto-generation)
- [ ] Set status to 'publish' for immediate visibility
- [ ] Verify page creation with GET request after POST
- [ ] Handle slug conflicts (WordPress adds -2, -3 suffixes)
- [ ] Set appropriate page template if needed

---

## Pattern 5: WordPress REST API Returns Local Timezone, Not UTC

**Problem**: Dates from WordPress REST API cause timezone bugs when compared with UTC timestamps.

**Solution**: Convert WordPress local time to UTC using timezone offset.

```python
from datetime import datetime, timedelta
import os

# Add timezone offset env var
WP_TIMEZONE_OFFSET_HOURS = int(os.getenv('WP_TIMEZONE_OFFSET_HOURS', '0'))

def get_post_age_in_days(post):
    """Calculate post age correctly handling WordPress timezone."""
    # WordPress returns local time (e.g., Australia/Sydney = UTC+11)
    date_str = post['date'].replace('Z', '').split('+')[0]
    post_date_local = datetime.fromisoformat(date_str)

    # Convert to UTC
    post_date_utc = post_date_local - timedelta(hours=WP_TIMEZONE_OFFSET_HOURS)

    # Compare with current UTC time
    now_utc = datetime.utcnow()
    age = now_utc - post_date_utc

    return age.days
```

**Example Issue**:
```python
# WordPress returns: 2026-01-06T13:33:42 (local time, actually UTC 02:33:42)
# Scheduler UTC time: 2026-01-06T03:24:58
# Naive comparison: 03:24 - 13:33 = -10 hours = -0.4 days (WRONG!)

# Correct comparison:
# Convert local to UTC: 13:33 - 11h = 02:33 UTC
# Compare: 03:24 - 02:33 = 0.85 hours = 0.03 days (CORRECT!)
```

**Environment Configuration**:
```bash
# .env file
WP_TIMEZONE_OFFSET_HOURS=11  # Australia/Sydney
# or
WP_TIMEZONE_OFFSET_HOURS=-5  # US Eastern
# or
WP_TIMEZONE_OFFSET_HOURS=0   # UTC
```

**Alternative: Use date_gmt Field**:
```python
# WordPress also provides date_gmt field (always UTC)
def get_post_age_simple(post):
    """Use date_gmt field if available (always UTC)."""
    if 'date_gmt' in post:
        date_str = post['date_gmt'].replace('Z', '')
        post_date_utc = datetime.fromisoformat(date_str)
        now_utc = datetime.utcnow()
        return (now_utc - post_date_utc).days

    # Fallback to date with offset
    return get_post_age_in_days(post)
```

**Prevention Checklist**:
- [ ] Always check timezone of external API datetime fields
- [ ] Use configurable timezone offset rather than hardcoding
- [ ] Validate calculated values are reasonable (negative days = timezone bug)
- [ ] Prefer `date_gmt` field when available (returns UTC)
- [ ] Document WordPress timezone setting in project notes

---

# BLOCK THEME CUSTOMIZATION

## Pattern 6: Navigation Block Requires ref Parameter

**Problem**: Hamburger menu displays but has no menu items after updating header template.

**Solution**: Always preserve `ref` parameter when modifying navigation blocks.

```html
<!-- WRONG - loses menu items -->
<!-- wp:navigation {"overlayMenu":"always","icon":"menu"} /-->

<!-- CORRECT - includes ref to menu ID -->
<!-- wp:navigation {"ref":5,"overlayMenu":"always","icon":"menu"} /-->
```

**Finding Menu ID**:
```bash
# Query WordPress navigation entities
curl "https://site.com/wp-json/wp/v2/navigation" \
     -u username:password \
     | jq '.[] | {id, title}'

# Response:
# {"id": 5, "title": {"rendered": "Primary Navigation"}}
```

**Via WP-CLI**:
```bash
sudo /opt/bitnami/wp-cli/bin/wp post list \
     --post_type=wp_navigation \
     --fields=ID,post_title \
     --path=/home/bitnami/stack/wordpress
```

**Updating Navigation Template**:
```python
import json

def update_navigation_template(template_id, menu_id):
    """Update header template with correct navigation ref."""

    # Get current template
    response = requests.get(f'{WP_URL}/wp-json/wp/v2/templates/{template_id}')
    template = response.json()

    # Parse content
    content = template['content']['raw']

    # Update navigation block (preserve ref parameter)
    content = content.replace(
        '<!-- wp:navigation {',
        f'<!-- wp:navigation {{"ref":{menu_id},'
    )

    # Update template
    update_response = requests.post(
        f'{WP_URL}/wp-json/wp/v2/templates/{template_id}',
        headers=headers,
        json={'content': content}
    )

    return update_response.status_code == 200
```

**Prevention Checklist**:
- [ ] Always preserve `ref` parameter when modifying navigation blocks
- [ ] Query `/wp-json/wp/v2/navigation` to find menu IDs before editing
- [ ] Test navigation immediately after template changes
- [ ] Keep backup of working header template
- [ ] Document menu ID in project configuration

---

## Pattern 7: Twenty Twenty-Five Theme CSS Stored in Database

**Problem**: Cannot find CSS files to edit - customizations don't persist.

**Solution**: WordPress Block Themes store CSS in database as `wp_global_styles` post type.

```bash
# 1. Find global styles post ID
sudo /opt/bitnami/wp-cli/bin/wp post list \
     --post_type=wp_global_styles \
     --format=csv \
     --fields=ID,post_name \
     --path=/home/bitnami/stack/wordpress 2>/dev/null

# Output: ID,post_name
#         89,wp-global-styles-twentytwentyfive

# 2. Export CSS content
sudo /opt/bitnami/wp-cli/bin/wp post get 89 \
     --field=post_content \
     --path=/home/bitnami/stack/wordpress 2>/dev/null > /tmp/styles.json

# 3. Modify with sed (CSS is embedded in JSON)
sed -i 's/"overlay-opacity":"0.5"/"overlay-opacity":"0.3"/g' /tmp/styles.json

# 4. Update database
sudo /opt/bitnami/wp-cli/bin/wp post update 89 /tmp/styles.json \
     --post_content \
     --path=/home/bitnami/stack/wordpress
```

**Key Post Types**:
| Post Type | Purpose | Example ID |
|-----------|---------|------------|
| `wp_global_styles` | All custom CSS | 89 |
| `wp_template` | Page templates | 1105 (home) |
| `wp_template_part` | Reusable parts | 1000 (footer), 1002 (header) |
| `wp_navigation` | Menu structure | 5 |

**Python Implementation**:
```python
def update_theme_css(property_path, new_value):
    """Update theme CSS via WP-CLI."""
    import subprocess
    import json

    # Export current styles
    cmd = [
        'sudo', '/opt/bitnami/wp-cli/bin/wp', 'post', 'get', '89',
        '--field=post_content',
        '--path=/home/bitnami/stack/wordpress'
    ]
    styles_json = subprocess.check_output(cmd, text=True)
    styles = json.loads(styles_json)

    # Update nested property (e.g., "styles.blocks.core/cover.overlay.opacity")
    keys = property_path.split('.')
    obj = styles
    for key in keys[:-1]:
        obj = obj[key]
    obj[keys[-1]] = new_value

    # Save to temp file
    with open('/tmp/styles.json', 'w') as f:
        json.dump(styles, f)

    # Update database
    cmd = [
        'sudo', '/opt/bitnami/wp-cli/bin/wp', 'post', 'update', '89',
        '/tmp/styles.json', '--post_content',
        '--path=/home/bitnami/stack/wordpress'
    ]
    subprocess.check_call(cmd)
```

**Prevention Checklist**:
- [ ] Always backup before modifying: `cp /tmp/styles.json /tmp/styles_backup.json`
- [ ] Query post types first to find correct IDs
- [ ] Test changes on staging if possible
- [ ] Document post IDs in project notes
- [ ] Use WP-CLI for database modifications, not manual SQL

---

## Pattern 8: Block Theme Flex Layouts Override text-align CSS

**Problem**: Custom CSS `text-align: left` doesn't work on flex-based block layouts.

**Root Cause**: WordPress block themes use `is-layout-flex` class with `align-items: center` default. In flex containers, `text-align` property is ignored - alignment is controlled by `justify-content` (main axis) and `align-items` (cross axis).

**What Doesn't Work**:
```css
/* These don't work on flex items */
.wp-block-post-title { text-align: left !important; }
.wp-block-post-title a { text-align: left !important; display: block !important; }

/* These also insufficient */
.wp-block-group.is-vertical.is-layout-flex { align-items: flex-start !important; }
```

**Template Changes (Also Insufficient)**:
```json
// Changed group layout from flex to default
{"layout":{"type":"default"}}  // instead of {"type":"flex"}

// Added textAlign to block attributes
{"isLink":true,"fontSize":"xx-large","textAlign":"left"}
```

**Lesson Learned**: Some alignment issues in WordPress block themes are difficult to fix via CSS alone. The theme's compiled CSS is more specific than custom CSS, and WordPress core applies inline styles via `is-layout-flex` class.

**Options**:
1. **Accept the limitation** - If alignment is minor issue
2. **Use Visual Site Editor** - Fine-tuned control via GUI
3. **Create child theme** - Override with higher-specificity CSS
4. **Switch themes** - Choose theme with more flexible layouts
5. **Use Flow Layout** - Change template to use `{"layout":{"type":"flow"}}` instead of flex

**Prevention Checklist**:
- [ ] Test alignment early when choosing block themes
- [ ] Check if theme uses flex or flow layouts for query loops
- [ ] Consider using Visual Editor for complex layout changes
- [ ] Document known limitations for the theme
- [ ] Prefer themes with CSS customization documentation

---

# SECURITY & DEPLOYMENT

## Pattern 9: WP-CLI Required When REST API Blocked by Security Plugins

**Problem**: WordPress REST API returning 403 Forbidden for template/settings modifications.

**Solution**: Use WP-CLI via SSH for administrative operations when security plugins block API.

```bash
# Connect via SSH (PuTTY or terminal)
ssh bitnami@your-server-ip

# Navigate to WordPress directory
cd ~/stack/wordpress

# Use WP-CLI with sudo (Bitnami requires this)
WP_CLI="/opt/bitnami/wp-cli/bin/wp"
WP_PATH="/home/bitnami/stack/wordpress"

# Common WP-CLI commands:

# List posts by type
sudo $WP_CLI post list --post_type=wp_global_styles --format=csv --path=$WP_PATH

# Get post content
sudo $WP_CLI post get 89 --field=post_content --path=$WP_PATH > /tmp/file.json

# Update post content
sudo $WP_CLI post update 89 /tmp/file.json --post_content --path=$WP_PATH

# List active plugins
sudo $WP_CLI plugin list --status=active --path=$WP_PATH

# Create user
sudo $WP_CLI user create johndoe john@example.com --role=author --path=$WP_PATH

# Update option
sudo $WP_CLI option update blogdescription "New site description" --path=$WP_PATH
```

**Python Wrapper for WP-CLI**:
```python
import subprocess

class WPCLIManager:
    """Wrapper for WP-CLI commands via SSH."""

    def __init__(self, ssh_host, ssh_user, wp_path='/home/bitnami/stack/wordpress'):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.wp_path = wp_path
        self.wp_cli = '/opt/bitnami/wp-cli/bin/wp'

    def run_command(self, cmd_parts):
        """Execute WP-CLI command via SSH."""
        full_cmd = [
            'ssh', f'{self.ssh_user}@{self.ssh_host}',
            f'sudo {self.wp_cli} {" ".join(cmd_parts)} --path={self.wp_path}'
        ]

        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True
        )

        return result.stdout.strip()

    def get_post(self, post_id, field=None):
        """Get post data."""
        cmd = ['post', 'get', str(post_id)]
        if field:
            cmd.extend(['--field', field])
        return self.run_command(cmd)

    def update_post(self, post_id, data_file, field='post_content'):
        """Update post from file."""
        # First, upload file via scp
        subprocess.run(['scp', data_file, f'{self.ssh_user}@{self.ssh_host}:/tmp/'])

        # Then update via WP-CLI
        cmd = ['post', 'update', str(post_id), f'/tmp/{os.path.basename(data_file)}', f'--{field}']
        return self.run_command(cmd)
```

**When to Use WP-CLI vs REST API**:

| Operation | Use WP-CLI | Use REST API |
|-----------|------------|--------------|
| Read posts/pages | Either | REST API (easier) |
| Create posts/pages | Either | REST API (easier) |
| Update templates | WP-CLI | Blocked by security |
| Modify global styles | WP-CLI | Blocked by security |
| Plugin management | WP-CLI | Not available |
| User management | WP-CLI | REST API (if enabled) |
| Database operations | WP-CLI | Not available |

**Prevention Checklist**:
- [ ] Set up SSH access to WordPress server early in project
- [ ] Document WP-CLI commands for common operations
- [ ] Keep security plugins active but know WP-CLI workaround
- [ ] Whitelist specific IPs in security plugins if needed
- [ ] Test both REST API and WP-CLI paths during development

---

## Pattern 10: MalCare Firewall Blocks WordPress REST API

**Problem**: REST API calls returning 403 Forbidden with "MalCare Firewall - Blocked because of Malicious Activities".

**Root Cause**: MalCare security plugin treats automated REST API requests (especially settings updates) as potential attacks.

**Solution Options**:

**Option 1: Use WP-CLI (Recommended)**
```bash
# See Pattern 9 above
ssh user@server
sudo /opt/bitnami/wp-cli/bin/wp post update 123 --path=/path/to/wordpress
```

**Option 2: Whitelist IP in MalCare**
```
1. WordPress Admin → MalCare → Firewall Settings
2. Add your deployment server IP to whitelist
3. Test REST API calls
```

**Option 3: Temporarily Disable Firewall**
```python
def wordpress_operation_with_firewall_handling():
    """Handle MalCare firewall for critical operations."""

    # Try REST API first
    response = requests.post(
        f"{WP_URL}/wp-json/wp/v2/posts",
        headers=headers,
        json=post_data
    )

    if response.status_code == 403 and 'MalCare' in response.text:
        print("Blocked by MalCare - falling back to WP-CLI")
        # Fall back to WP-CLI
        return use_wp_cli_alternative()

    return response.json()
```

**REST API Operations Status**:
```python
# Read operations: ✓ Work fine
response = requests.get(f"{WP_URL}/wp-json/wp/v2/posts", headers=headers)

# Write operations: ⚠ May be blocked
# - Post creation: Usually works
# - Post updates: Usually works
# - Settings updates: Often blocked
# - Template updates: Often blocked
# - Plugin management: Blocked
```

**Prevention Checklist**:
- [ ] Check for security plugins before planning REST API automation
- [ ] Document which operations require manual WordPress admin access
- [ ] Consider whitelisting deployment IPs in MalCare
- [ ] Have WP-CLI fallback for all critical operations
- [ ] Test API access from deployment environment before launch

---

## Pattern 11: WordPress Security Hardening Requires Multiple Plugins

**Problem**: WordPress core doesn't include MFA, custom login URLs, or firewall protection.

**Solution**: Implement layered security with multiple specialized plugins.

**Recommended Security Stack**:

```
┌─────────────────────────────────────────────────────────┐
│              WordPress Security Stack                    │
├─────────────────────────────────────────────────────────┤
│ 1. MFA                → Two-Factor plugin               │
│ 2. Custom Login URL   → WPS Hide Login                 │
│ 3. Firewall           → MalCare or Wordfence           │
│ 4. Auto-Updates       → Core WordPress feature         │
│ 5. SSL/HTTPS          → Let's Encrypt + Really Simple SSL│
│ 6. File Permissions   → 644 for files, 755 for dirs   │
│ 7. Database Backup    → UpdraftPlus or BackupBuddy     │
└─────────────────────────────────────────────────────────┘
```

**1. Multi-Factor Authentication**:
```
Plugin: Two-Factor
Settings:
  - Require MFA for administrators
  - Support TOTP apps (Google Authenticator, Authy)
  - Backup codes enabled
```

**2. Custom Login URL**:
```
Plugin: WPS Hide Login
Settings:
  - Change /wp-admin to custom URL (e.g., /login-secure-2024)
  - Store custom URL securely (losing it = locked out)
  - Document in password manager
```

**3. Firewall Protection**:
```
Plugin: MalCare
Settings:
  - Enable firewall
  - Auto-block suspicious IPs
  - Whitelist known admin IPs
  - Enable malware scanner
```

**4. Configuration Checklist**:
```bash
# wp-config.php security additions
define('DISALLOW_FILE_EDIT', true);  # Disable plugin/theme editor
define('WP_AUTO_UPDATE_CORE', 'minor');  # Auto-update WordPress
define('FORCE_SSL_ADMIN', true);  # Require HTTPS for admin

# .htaccess protection
<Files wp-config.php>
    order allow,deny
    deny from all
</Files>

# Disable directory browsing
Options -Indexes

# Protect .htaccess itself
<Files .htaccess>
    order allow,deny
    deny from all
</Files>
```

**Security Hardening Script**:
```python
def harden_wordpress_security():
    """Automated WordPress security hardening."""

    checks = {
        'ssl_enabled': check_https(),
        'custom_login_url': check_custom_login(),
        'mfa_enabled': check_mfa_plugin(),
        'firewall_active': check_firewall_plugin(),
        'auto_updates': check_auto_updates(),
        'file_permissions': check_file_permissions(),
        'admin_username': check_admin_not_default(),
        'db_prefix': check_db_prefix_changed()
    }

    failed = [k for k, v in checks.items() if not v]

    if failed:
        print(f"⚠ Security issues found: {', '.join(failed)}")
        return False

    print("✓ WordPress security hardened")
    return True
```

**Prevention Checklist**:
- [ ] Document security plugin stack in project README
- [ ] Store custom login URL securely (losing it = locked out)
- [ ] Test login flow after security changes in incognito window
- [ ] Enable auto-updates for plugins and themes
- [ ] Regular security audits (monthly)
- [ ] Keep backup of working security configuration

---

## Pattern 12: Decap CMS with YAML Frontmatter

**Problem**: Need Git-based CMS workflow for WordPress content with version control.

**Solution**: Use Decap CMS (formerly Netlify CMS) with YAML frontmatter format.

```yaml
# config.yml for Decap CMS
backend:
  name: github
  repo: username/wordpress-content
  branch: main

media_folder: "static/images"
public_folder: "/images"

collections:
  - name: "posts"
    label: "Blog Posts"
    folder: "content/posts"
    create: true
    slug: "{{year}}-{{month}}-{{day}}-{{slug}}"
    fields:
      - {label: "Title", name: "title", widget: "string"}
      - {label: "Publish Date", name: "date", widget: "datetime"}
      - {label: "Categories", name: "categories", widget: "list"}
      - {label: "Tags", name: "tags", widget: "list"}
      - {label: "Featured Image", name: "featured_image", widget: "image"}
      - {label: "Body", name: "body", widget: "markdown"}
```

**YAML Frontmatter Format**:
```yaml
---
title: "How to Build WordPress Headless CMS"
date: 2026-01-06T10:00:00Z
categories:
  - WordPress
  - Headless CMS
tags:
  - REST API
  - React
  - JAMstack
featured_image: /images/wordpress-headless.png
author: johndoe
status: publish
---

Content goes here in Markdown format...
```

**Workflow**:
```
1. Content Team writes in Decap CMS (Git-backed)
   ↓
2. Git commit triggers GitHub Actions
   ↓
3. Parse YAML frontmatter + Markdown body
   ↓
4. Convert Markdown to WordPress HTML
   ↓
5. Publish via WordPress REST API
   ↓
6. WordPress serves content (or headless frontend)
```

**Python Integration**:
```python
import yaml
import markdown
from pathlib import Path

def sync_decap_to_wordpress(file_path):
    """Sync Decap CMS content to WordPress."""

    # Read file
    content = Path(file_path).read_text()

    # Split frontmatter and body
    parts = content.split('---', 2)
    frontmatter = yaml.safe_load(parts[1])
    body_markdown = parts[2].strip()

    # Convert Markdown to HTML
    html_content = markdown.markdown(
        body_markdown,
        extensions=['extra', 'codehilite']
    )

    # Prepare WordPress data
    post_data = {
        'title': frontmatter['title'],
        'content': html_content,
        'status': frontmatter.get('status', 'draft'),
        'date': frontmatter['date'],
        'categories': get_category_ids(frontmatter.get('categories', [])),
        'tags': get_tag_ids(frontmatter.get('tags', [])),
        'featured_media': upload_featured_image(frontmatter.get('featured_image'))
    }

    # Publish to WordPress
    response = requests.post(
        f'{WP_URL}/wp-json/wp/v2/posts',
        headers=headers,
        json=post_data
    )

    return response.status_code == 201
```

**Benefits**:
- Version control for content (Git history)
- Editorial workflow (branch/PR/merge)
- Content preview before publish
- Team collaboration
- Backup/rollback capability

**Prevention Checklist**:
- [ ] Validate YAML frontmatter structure before parsing
- [ ] Handle missing fields gracefully (use defaults)
- [ ] Convert Markdown extensions properly (tables, code blocks)
- [ ] Test image upload path resolution
- [ ] Set up CI/CD for automatic sync on Git push

---

# CONTENT MANAGEMENT PATTERNS

## Pattern 13: WordPress Duplicate Detection with Graph-Based Resolution

**Problem**: Multi-way duplicates create conflicts (Post A = Post B, Post B = Post C, Post C = Post A).

**Solution**: Two-pass algorithm - build "keep" set first, "delete" set second.

```python
def identify_posts_to_delete(duplicates_data):
    """Create smart deletion list using graph-based conflict resolution."""
    keep_posts = set()
    delete_candidates = {}

    # First pass: identify all posts marked as "keep"
    for dup in duplicates_data:
        keep_id = dup['keep_id']
        delete_id = dup['delete_id']
        keep_posts.add(keep_id)

        # Only add to delete_candidates if not already marked "keep"
        if delete_id not in keep_posts:
            delete_candidates[delete_id] = {
                'title': dup['post2']['title'] if delete_id == dup['post2']['id'] else dup['post1']['title'],
                'reason': dup['reason'],
                'duplicate_of': keep_id
            }

    # Second pass: remove any conflicts
    final_delete_list = {
        post_id: info for post_id, info in delete_candidates.items()
        if post_id not in keep_posts
    }

    return final_delete_list

# Usage
duplicates = detect_duplicates(all_posts)
to_delete = identify_posts_to_delete(duplicates)

print(f"Found {len(duplicates)} duplicate pairs")
print(f"Will delete {len(to_delete)} posts")
print(f"Conflicts resolved: {len(duplicates) - len(to_delete)}")
```

**Algorithm**:
1. Build `keep_posts` set first (posts with most images + longest content)
2. Only add posts to `delete_candidates` if they're not in `keep_posts`
3. Final pass removes any remaining conflicts
4. Validate no post appears in both keep and delete sets

**Prevention Checklist**:
- [ ] Always use two-pass algorithm for duplicate resolution
- [ ] Build "keep" set first, "delete" set second
- [ ] Log conflicts found and how they were resolved
- [ ] Validate no post appears in both keep and delete sets
- [ ] Dry-run before actual deletion

---

# COMPLETE IMPLEMENTATION EXAMPLE

## Headless WordPress Blog Publisher

See `examples/wordpress-publisher.py` for complete implementation combining:
- Slug-based post lookup
- Image upload with proper headers
- Content cleanup and replacement
- Error handling and retries
- Rate limiting
- Logging and monitoring

**Quick Start**:
```python
from wordpress_publisher import WordPressPublisher

publisher = WordPressPublisher(
    url='https://yourblog.com',
    username='admin',
    app_password='your-app-password'
)

# Create post with images
result = publisher.publish_post(
    title='My Post Title',
    content='<p>Post content here</p>',
    images=['image1.png', 'image2.png'],
    categories=['Technology', 'WordPress'],
    tags=['REST API', 'Headless CMS']
)

print(f"Published: {result['url']}")
```

---

# TROUBLESHOOTING GUIDE

## Common Issues and Solutions

### Issue 1: 403 Forbidden on REST API
```
Symptom: API returns 403, "MalCare Firewall" in response
Solution: Use WP-CLI via SSH (Pattern 9) or whitelist IP
```

### Issue 2: Images Not Appearing
```
Symptom: Image uploaded but not showing in post
Solution: Check Content-Disposition header (Pattern 2)
```

### Issue 3: Negative Time Values
```
Symptom: Post age shows negative days
Solution: Add timezone offset conversion (Pattern 5)
```

### Issue 4: Navigation Menu Empty
```
Symptom: Hamburger icon shows but no menu items
Solution: Add ref parameter to navigation block (Pattern 6)
```

### Issue 5: CSS Changes Not Persisting
```
Symptom: Theme CSS edits don't save
Solution: Use WP-CLI to edit wp_global_styles (Pattern 7)
```

### Issue 6: Text Alignment Broken
```
Symptom: text-align CSS doesn't work
Solution: Flex layout issue, use Visual Editor (Pattern 8)
```

---

# BEST PRACTICES

## 1. Error Handling
```python
def safe_wordpress_operation(operation_fn, *args, **kwargs):
    """Wrapper for WordPress operations with retry logic."""
    max_retries = 3

    for attempt in range(max_retries):
        try:
            result = operation_fn(*args, **kwargs)
            return result
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                raise
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                # Try WP-CLI fallback
                return wp_cli_fallback(operation_fn.__name__, *args, **kwargs)
            raise
```

## 2. Rate Limiting
```python
class WordPressClient:
    """Rate-limited WordPress API client."""

    def __init__(self, requests_per_minute=60):
        self.min_interval = 60.0 / requests_per_minute
        self.last_request_time = None

    def _enforce_rate_limit(self):
        """Sleep if needed to respect rate limit."""
        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)

        self.last_request_time = time.time()
```

## 3. Logging
```python
import logging

logger = logging.getLogger('wordpress')
logger.setLevel(logging.INFO)

# Log all API calls
def log_api_call(method, endpoint, status_code):
    logger.info(f"{method} {endpoint} - {status_code}")

# Log errors with context
def log_error(operation, error, context):
    logger.error(f"Failed: {operation}", extra={
        'error': str(error),
        'context': context
    })
```

---

# PERFORMANCE OPTIMIZATION

## 1. Batch Operations
```python
# Instead of: 1000 individual requests
for post in posts:
    update_post(post['id'], post['data'])

# Use: Batch update
batch_size = 50
for i in range(0, len(posts), batch_size):
    batch = posts[i:i+batch_size]
    update_posts_batch(batch)
```

## 2. Caching
```python
from functools import lru_cache
from datetime import datetime, timedelta

class CachedWordPressClient:
    """WordPress client with response caching."""

    def __init__(self):
        self.cache = {}
        self.cache_ttl = timedelta(minutes=5)

    @lru_cache(maxsize=128)
    def get_category_id(self, category_name):
        """Get category ID with caching."""
        response = requests.get(
            f'{WP_URL}/wp-json/wp/v2/categories',
            params={'search': category_name}
        )
        categories = response.json()
        return categories[0]['id'] if categories else None
```

## 3. Parallel Processing
```python
from concurrent.futures import ThreadPoolExecutor

def publish_posts_parallel(posts, max_workers=5):
    """Publish multiple posts in parallel."""
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(publish_post, post): post
            for post in posts
        }

        for future in as_completed(futures):
            post = futures[future]
            try:
                result = future.result()
                print(f"Published: {post['title']}")
            except Exception as e:
                print(f"Failed: {post['title']} - {e}")
```

---

# SECURITY CHECKLIST

Before deploying WordPress integration:

- [ ] Enable HTTPS/SSL for WordPress site
- [ ] Use Application Passwords (not admin password)
- [ ] Restrict REST API access by IP (if possible)
- [ ] Enable MFA for admin accounts
- [ ] Use custom login URL
- [ ] Install and configure firewall plugin
- [ ] Enable auto-updates for core/plugins/themes
- [ ] Regular backups (daily for database)
- [ ] File permissions: 644 for files, 755 for directories
- [ ] Disable file editing: `define('DISALLOW_FILE_EDIT', true)`
- [ ] Hide WordPress version
- [ ] Use strong database prefix (not wp_)
- [ ] Monitor failed login attempts
- [ ] Regular security audits

---

# FILE REFERENCES

- `examples/wordpress-publisher.py` - Complete WordPress publisher class
- `examples/rest-api.md` - REST API pattern examples
- `examples/block-themes.md` - Block theme customization guide
- `examples/deployment.md` - Deployment and security patterns
- `checklists/security-audit.md` - WordPress security audit checklist
- `checklists/pre-deployment.md` - Pre-deployment checklist

---

# ADDITIONAL RESOURCES

## Official Documentation
- [WordPress REST API Handbook](https://developer.wordpress.org/rest-api/)
- [Block Editor Handbook](https://developer.wordpress.org/block-editor/)
- [WP-CLI Documentation](https://wp-cli.org/)
- [WordPress Security](https://wordpress.org/support/article/hardening-wordpress/)

## Related Skills
- `batch-processing` - For bulk WordPress operations
- `api-patterns` - Generic API integration patterns
- `security-owasp` - General security best practices
- `deployment-lifecycle` - Deployment workflows

---

**End of WordPress Patterns Skill**

*Last Updated: 2026-01-06*
*Source: 13 production lessons from multi-agent-flow-content-pipeline*
