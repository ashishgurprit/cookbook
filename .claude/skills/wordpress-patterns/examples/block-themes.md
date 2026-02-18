# WordPress Block Theme Customization Examples

Complete examples for customizing WordPress block themes (Twenty Twenty-Five and similar) including templates, global styles, and navigation.

---

## Table of Contents

1. [Understanding Block Themes](#understanding-block-themes)
2. [Global Styles Management](#global-styles-management)
3. [Template Customization](#template-customization)
4. [Navigation Management](#navigation-management)
5. [CSS Customization](#css-customization)
6. [Common Issues](#common-issues)

---

## Understanding Block Themes

WordPress block themes store configuration in the **database**, not in theme files. This is fundamentally different from classic themes.

**Key Post Types**:
| Post Type | Purpose | Common IDs | Access Method |
|-----------|---------|------------|---------------|
| `wp_global_styles` | All custom CSS and theme settings | 89 | WP-CLI required |
| `wp_template` | Page templates (home, single, archive) | 1105, 1106 | REST API or WP-CLI |
| `wp_template_part` | Reusable parts (header, footer) | 1000, 1002 | REST API or WP-CLI |
| `wp_navigation` | Menu structure | 5 | REST API |

**Storage Architecture**:
```
WordPress Database
├── wp_posts (all content types)
│   ├── post_type='wp_global_styles'  ← CSS rules
│   ├── post_type='wp_template'       ← Page templates
│   ├── post_type='wp_template_part'  ← Header/Footer
│   └── post_type='wp_navigation'     ← Menus
└── wp_options (site settings)
```

---

## Global Styles Management

### Exporting Global Styles

```bash
#!/bin/bash
# Export Twenty Twenty-Five global styles

WP_CLI="/opt/bitnami/wp-cli/bin/wp"
WP_PATH="/home/bitnami/stack/wordpress"

# Find global styles post ID
STYLE_ID=$(sudo $WP_CLI post list \
    --post_type=wp_global_styles \
    --post_name=wp-global-styles-twentytwentyfive \
    --field=ID \
    --path=$WP_PATH 2>/dev/null)

echo "Global Styles Post ID: $STYLE_ID"

# Export to JSON
sudo $WP_CLI post get $STYLE_ID \
    --field=post_content \
    --path=$WP_PATH 2>/dev/null > global-styles.json

echo "Exported to global-styles.json"
```

### Global Styles JSON Structure

```json
{
  "version": 2,
  "settings": {
    "color": {
      "palette": [
        {
          "slug": "base",
          "color": "#ffffff",
          "name": "Base"
        },
        {
          "slug": "contrast",
          "color": "#000000",
          "name": "Contrast"
        },
        {
          "slug": "accent-1",
          "color": "#ff6b6b",
          "name": "Accent 1"
        }
      ]
    },
    "typography": {
      "fontFamilies": [
        {
          "fontFamily": "\"Poppins\", sans-serif",
          "slug": "heading",
          "name": "Heading Font"
        },
        {
          "fontFamily": "\"Open Sans\", sans-serif",
          "slug": "body",
          "name": "Body Font"
        }
      ],
      "fontSizes": [
        {
          "size": "0.875rem",
          "slug": "small",
          "name": "Small"
        },
        {
          "size": "1rem",
          "slug": "medium",
          "name": "Medium"
        },
        {
          "size": "2.5rem",
          "slug": "x-large",
          "name": "Extra Large"
        }
      ]
    },
    "spacing": {
      "units": ["px", "em", "rem", "vh", "vw", "%"],
      "padding": true,
      "margin": true
    }
  },
  "styles": {
    "color": {
      "background": "var(--wp--preset--color--base)",
      "text": "var(--wp--preset--color--contrast)"
    },
    "typography": {
      "fontFamily": "var(--wp--preset--font-family--body)",
      "fontSize": "var(--wp--preset--font-size--medium)",
      "lineHeight": "1.6"
    },
    "spacing": {
      "padding": {
        "top": "0px",
        "right": "0px",
        "bottom": "0px",
        "left": "0px"
      }
    },
    "blocks": {
      "core/cover": {
        "spacing": {
          "padding": {
            "top": "var(--wp--preset--spacing--50)",
            "bottom": "var(--wp--preset--spacing--50)"
          }
        },
        "color": {
          "overlay": {
            "opacity": "0.3"
          }
        }
      },
      "core/post-title": {
        "typography": {
          "fontFamily": "var(--wp--preset--font-family--heading)",
          "fontSize": "var(--wp--preset--font-size--x-large)",
          "fontWeight": "700"
        }
      }
    },
    "elements": {
      "button": {
        "color": {
          "background": "var(--wp--preset--color--contrast)",
          "text": "var(--wp--preset--color--base)"
        },
        "border": {
          "radius": "30px"
        },
        "typography": {
          "fontSize": "1rem",
          "fontWeight": "600"
        }
      },
      "link": {
        "color": {
          "text": "var(--wp--preset--color--accent-1)"
        },
        ":hover": {
          "color": {
            "text": "var(--wp--preset--color--accent-2)"
          }
        }
      }
    }
  }
}
```

### Modifying Global Styles with Python

```python
import json
import subprocess
from pathlib import Path

class GlobalStylesManager:
    """Manage WordPress global styles via WP-CLI."""

    def __init__(self, wp_cli_path='/opt/bitnami/wp-cli/bin/wp', wp_path='/home/bitnami/stack/wordpress'):
        self.wp_cli = wp_cli_path
        self.wp_path = wp_path
        self.style_id = None

    def _run_wp_cli(self, command):
        """Execute WP-CLI command."""
        full_cmd = ['sudo', self.wp_cli] + command + ['--path=' + self.wp_path]
        result = subprocess.run(full_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        return result.stdout.strip()

    def find_global_styles_id(self):
        """Find global styles post ID."""
        if not self.style_id:
            self.style_id = self._run_wp_cli([
                'post', 'list',
                '--post_type=wp_global_styles',
                '--post_name=wp-global-styles-twentytwentyfive',
                '--field=ID'
            ])
        return int(self.style_id)

    def export_styles(self, output_file='global-styles.json'):
        """Export global styles to JSON file."""
        style_id = self.find_global_styles_id()
        content = self._run_wp_cli(['post', 'get', str(style_id), '--field=post_content'])

        with open(output_file, 'w') as f:
            json.dump(json.loads(content), f, indent=2)

        return output_file

    def import_styles(self, input_file='global-styles.json'):
        """Import global styles from JSON file."""
        style_id = self.find_global_styles_id()

        # Upload file via scp first
        # Then update post
        self._run_wp_cli(['post', 'update', str(style_id), input_file, '--post_content'])

    def update_color_palette(self, colors):
        """
        Update color palette.

        Args:
            colors: List of dicts with 'slug', 'color', 'name'

        Example:
            >>> manager.update_color_palette([
                {'slug': 'primary', 'color': '#FF6B6B', 'name': 'Primary'},
                {'slug': 'secondary', 'color': '#4ECDC4', 'name': 'Secondary'}
            ])
        """
        # Export current styles
        self.export_styles('/tmp/styles.json')

        # Load and modify
        with open('/tmp/styles.json', 'r') as f:
            styles = json.load(f)

        styles['settings']['color']['palette'] = colors

        # Save modified
        with open('/tmp/styles.json', 'w') as f:
            json.dump(styles, f, indent=2)

        # Import back
        self.import_styles('/tmp/styles.json')

    def update_block_style(self, block_name, style_updates):
        """
        Update specific block styles.

        Args:
            block_name: Block name (e.g., 'core/cover', 'core/post-title')
            style_updates: Dict with style updates

        Example:
            >>> manager.update_block_style('core/cover', {
                'color': {'overlay': {'opacity': '0.3'}}
            })
        """
        self.export_styles('/tmp/styles.json')

        with open('/tmp/styles.json', 'r') as f:
            styles = json.load(f)

        # Navigate to block styles
        if 'blocks' not in styles['styles']:
            styles['styles']['blocks'] = {}

        if block_name not in styles['styles']['blocks']:
            styles['styles']['blocks'][block_name] = {}

        # Deep merge style updates
        def deep_merge(base, updates):
            for key, value in updates.items():
                if isinstance(value, dict) and key in base:
                    deep_merge(base[key], value)
                else:
                    base[key] = value

        deep_merge(styles['styles']['blocks'][block_name], style_updates)

        with open('/tmp/styles.json', 'w') as f:
            json.dump(styles, f, indent=2)

        self.import_styles('/tmp/styles.json')


# Usage Example
if __name__ == '__main__':
    manager = GlobalStylesManager()

    # Export for backup
    manager.export_styles('backup-styles.json')

    # Update color palette
    manager.update_color_palette([
        {'slug': 'base', 'color': '#ffffff', 'name': 'White'},
        {'slug': 'contrast', 'color': '#111111', 'name': 'Almost Black'},
        {'slug': 'accent-1', 'color': '#FF6B6B', 'name': 'Red'},
        {'slug': 'accent-2', 'color': '#4ECDC4', 'name': 'Teal'},
        {'slug': 'accent-3', 'color': '#FFD93D', 'name': 'Yellow'}
    ])

    # Update cover block overlay opacity
    manager.update_block_style('core/cover', {
        'color': {
            'overlay': {
                'opacity': '0.3'
            }
        }
    })

    print("Global styles updated!")
```

### Common Style Modifications

```bash
#!/bin/bash
# Common global style modifications

# 1. Change overlay opacity (cover blocks)
jq '.styles.blocks."core/cover".color.overlay.opacity = "0.3"' global-styles.json > temp.json && mv temp.json global-styles.json

# 2. Change button border radius
jq '.styles.elements.button.border.radius = "30px"' global-styles.json > temp.json && mv temp.json global-styles.json

# 3. Update primary color
jq '(.settings.color.palette[] | select(.slug == "accent-1") | .color) = "#FF6B6B"' global-styles.json > temp.json && mv temp.json global-styles.json

# 4. Change heading font
jq '(.settings.typography.fontFamilies[] | select(.slug == "heading") | .fontFamily) = "\"Poppins\", sans-serif"' global-styles.json > temp.json && mv temp.json global-styles.json
```

---

## Template Customization

### Listing Templates

```bash
#!/bin/bash
# List all templates

WP_CLI="/opt/bitnami/wp-cli/bin/wp"
WP_PATH="/home/bitnami/stack/wordpress"

sudo $WP_CLI post list \
    --post_type=wp_template \
    --format=table \
    --fields=ID,post_name,post_title \
    --path=$WP_PATH 2>/dev/null
```

**Output**:
```
+------+------------------+---------------+
| ID   | post_name        | post_title    |
+------+------------------+---------------+
| 1105 | home             | Home          |
| 1106 | single           | Single Post   |
| 1107 | archive          | Archive       |
| 1108 | 404              | 404 Not Found |
+------+------------------+---------------+
```

### Exporting Template

```bash
#!/bin/bash
# Export home template

TEMPLATE_ID=1105

sudo $WP_CLI post get $TEMPLATE_ID \
    --field=post_content \
    --path=$WP_PATH 2>/dev/null > home-template.html
```

### Template Structure

```html
<!-- wp:template-part {"slug":"header","theme":"twentytwentyfive","tagName":"header"} /-->

<!-- wp:group {"tagName":"main","layout":{"type":"constrained"}} -->
<main class="wp-block-group">
    <!-- wp:query {"queryId":0,"query":{"perPage":10,"pages":0,"offset":0,"postType":"post","order":"desc","orderBy":"date"}} -->
    <div class="wp-block-query">
        <!-- wp:post-template {"layout":{"type":"grid","columnCount":3}} -->
            <!-- wp:group {"layout":{"type":"flex","orientation":"vertical"}} -->
            <div class="wp-block-group">
                <!-- wp:post-featured-image {"isLink":true} /-->

                <!-- wp:post-title {"isLink":true,"fontSize":"x-large"} /-->

                <!-- wp:post-excerpt {"moreText":"Read more"} /-->

                <!-- wp:post-date /-->
            </div>
            <!-- /wp:group -->
        <!-- /wp:post-template -->

        <!-- wp:query-pagination {"layout":{"type":"flex","justifyContent":"center"}} -->
            <!-- wp:query-pagination-previous /-->
            <!-- wp:query-pagination-numbers /-->
            <!-- wp:query-pagination-next /-->
        <!-- /wp:query-pagination -->
    </div>
    <!-- /wp:query -->
</main>
<!-- /wp:group -->

<!-- wp:template-part {"slug":"footer","theme":"twentytwentyfive","tagName":"footer"} /-->
```

### Modifying Templates with Python

```python
import re
import subprocess

class TemplateManager:
    """Manage WordPress templates via WP-CLI."""

    def __init__(self, wp_cli_path='/opt/bitnami/wp-cli/bin/wp', wp_path='/home/bitnami/stack/wordpress'):
        self.wp_cli = wp_cli_path
        self.wp_path = wp_path

    def _run_wp_cli(self, command):
        """Execute WP-CLI command."""
        full_cmd = ['sudo', self.wp_cli] + command + ['--path=' + self.wp_path]
        result = subprocess.run(full_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        return result.stdout.strip()

    def list_templates(self):
        """List all templates."""
        output = self._run_wp_cli([
            'post', 'list',
            '--post_type=wp_template',
            '--format=csv',
            '--fields=ID,post_name,post_title'
        ])

        templates = []
        for line in output.split('\n')[1:]:  # Skip header
            parts = line.split(',')
            if len(parts) >= 3:
                templates.append({
                    'id': int(parts[0]),
                    'slug': parts[1],
                    'title': parts[2]
                })

        return templates

    def get_template_content(self, template_id):
        """Get template content."""
        return self._run_wp_cli(['post', 'get', str(template_id), '--field=post_content'])

    def update_template(self, template_id, content):
        """Update template content."""
        # Save to temp file
        with open('/tmp/template.html', 'w') as f:
            f.write(content)

        self._run_wp_cli(['post', 'update', str(template_id), '/tmp/template.html', '--post_content'])

    def remove_spacers(self, template_id):
        """Remove spacer blocks from template."""
        content = self.get_template_content(template_id)

        # Remove spacer blocks (multi-line pattern)
        content = re.sub(
            r'<!-- wp:spacer \{.*?\} -->.*?<!-- /wp:spacer -->',
            '',
            content,
            flags=re.DOTALL
        )

        # Remove extra empty lines
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)

        self.update_template(template_id, content)

    def change_post_grid_columns(self, template_id, column_count=3):
        """Change post grid column count."""
        content = self.get_template_content(template_id)

        # Update columnCount in post-template block
        content = re.sub(
            r'"columnCount":\d+',
            f'"columnCount":{column_count}',
            content
        )

        self.update_template(template_id, content)

    def add_featured_image_to_posts(self, template_id):
        """Add featured image to post template if not present."""
        content = self.get_template_content(template_id)

        if 'wp:post-featured-image' not in content:
            # Find post-template block and add featured image
            insertion_point = content.find('<!-- wp:post-title')

            if insertion_point != -1:
                featured_image_block = '<!-- wp:post-featured-image {"isLink":true,"aspectRatio":"16/9"} /-->\n\n'
                content = content[:insertion_point] + featured_image_block + content[insertion_point:]
                self.update_template(template_id, content)


# Usage Example
if __name__ == '__main__':
    manager = TemplateManager()

    # List templates
    templates = manager.list_templates()
    for tmpl in templates:
        print(f"{tmpl['id']}: {tmpl['title']} ({tmpl['slug']})")

    # Get home template ID
    home_template = next((t for t in templates if t['slug'] == 'home'), None)

    if home_template:
        # Remove spacers
        manager.remove_spacers(home_template['id'])

        # Change grid to 4 columns
        manager.change_post_grid_columns(home_template['id'], 4)

        # Add featured images
        manager.add_featured_image_to_posts(home_template['id'])

        print("Home template updated!")
```

---

## Navigation Management

### Finding Navigation Menu

```bash
#!/bin/bash
# Find navigation menu ID

sudo $WP_CLI post list \
    --post_type=wp_navigation \
    --format=csv \
    --fields=ID,post_title \
    --path=$WP_PATH 2>/dev/null
```

**Output**:
```
ID,post_title
5,Primary Navigation
```

### Updating Header with Navigation Reference

```python
def update_header_navigation(manager, navigation_id=5):
    """Update header template with correct navigation reference."""

    # Find header template part
    templates = manager._run_wp_cli([
        'post', 'list',
        '--post_type=wp_template_part',
        '--post_name=header',
        '--field=ID'
    ])

    header_id = int(templates)

    # Get header content
    content = manager.get_template_content(header_id)

    # Ensure navigation block has ref parameter
    # Pattern: <!-- wp:navigation {...} /-->
    # We need: <!-- wp:navigation {"ref":5,...} /-->

    if f'"ref":{navigation_id}' not in content:
        # Add ref parameter to navigation block
        content = re.sub(
            r'(<!-- wp:navigation \{)',
            f r'\1"ref":{navigation_id},',
            content
        )

        manager.update_template(header_id, content)
        print(f"Updated header navigation reference to menu ID {navigation_id}")


# Usage
if __name__ == '__main__':
    manager = TemplateManager()
    update_header_navigation(manager, navigation_id=5)
```

### Navigation Block with Overlay Menu

```html
<!-- Correct navigation block with all parameters -->
<!-- wp:navigation {"ref":5,"overlayMenu":"always","icon":"menu","layout":{"type":"flex","justifyContent":"space-between"}} /-->

<!-- Broken navigation (missing ref) -->
<!-- wp:navigation {"overlayMenu":"always","icon":"menu"} /-->
```

---

## CSS Customization

### Adding Custom CSS

```python
def add_custom_css_to_theme(manager):
    """Add custom CSS rules to global styles."""

    manager.export_styles('/tmp/styles.json')

    with open('/tmp/styles.json', 'r') as f:
        styles = json.load(f)

    # Add custom CSS in blocks section
    if 'blocks' not in styles['styles']:
        styles['styles']['blocks'] = {}

    # Example: Style query loop post cards
    styles['styles']['blocks']['core/post-template'] = {
        'spacing': {
            'blockGap': '2rem'
        }
    }

    # Example: Style post titles in loops
    styles['styles']['blocks']['core/post-title'] = {
        'typography': {
            'fontFamily': 'var(--wp--preset--font-family--heading)',
            'fontSize': 'var(--wp--preset--font-size--x-large)',
            'fontWeight': '700',
            'lineHeight': '1.2'
        },
        'spacing': {
            'margin': {
                'top': '0',
                'bottom': '1rem'
            }
        }
    }

    # Example: Style buttons
    styles['styles']['elements']['button'] = {
        'color': {
            'background': 'var(--wp--preset--color--contrast)',
            'text': 'var(--wp--preset--color--base)'
        },
        'border': {
            'radius': '30px',
            'width': '0'
        },
        'typography': {
            'fontSize': '1rem',
            'fontWeight': '600'
        },
        'spacing': {
            'padding': {
                'top': '12px',
                'right': '24px',
                'bottom': '12px',
                'left': '24px'
            }
        },
        ':hover': {
            'color': {
                'background': 'var(--wp--preset--color--accent-1)'
            }
        }
    }

    with open('/tmp/styles.json', 'w') as f:
        json.dump(styles, f, indent=2)

    manager.import_styles('/tmp/styles.json')
    print("Custom CSS added!")


# Usage
if __name__ == '__main__':
    manager = GlobalStylesManager()
    add_custom_css_to_theme(manager)
```

---

## Common Issues

### Issue 1: Flex Layout Overrides text-align

**Problem**: `text-align: left` doesn't work on post titles in query loops.

**Root Cause**: WordPress uses `is-layout-flex` class with `align-items: center`. In flex containers, `text-align` is ignored.

**Solutions**:

**Option 1: Change Layout Type (Template)**
```json
// Change from flex to flow layout
{"layout":{"type":"flow"}}  // instead of {"type":"flex"}
```

**Option 2: Use Flex Properties (CSS)**
```css
/* This won't work */
.wp-block-post-title { text-align: left !important; }

/* Use flex properties instead */
.wp-block-group.is-layout-flex {
    align-items: flex-start !important;
}
```

**Option 3: Visual Editor**
Use WordPress Visual Site Editor for precise alignment control.

### Issue 2: Changes Not Appearing

**Checklist**:
1. Clear WordPress cache (if caching plugin installed)
2. Clear browser cache (Ctrl+Shift+R)
3. Check if changes were saved to database:
   ```bash
   sudo $WP_CLI post get 89 --field=post_content --path=$WP_PATH | grep "overlay"
   ```
4. Verify correct post ID
5. Check file permissions

### Issue 3: Navigation Menu Empty

**Problem**: Hamburger icon shows but menu has no items.

**Solution**: Add `ref` parameter with correct menu ID:
```python
# Find menu ID
menu_id = manager._run_wp_cli([
    'post', 'list',
    '--post_type=wp_navigation',
    '--field=ID'
])

# Update header template to include ref
update_header_navigation(manager, navigation_id=int(menu_id))
```

---

**End of Block Theme Examples**

See `SKILL.md` for complete WordPress patterns documentation.
