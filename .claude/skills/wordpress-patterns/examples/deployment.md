# WordPress Deployment and Security Patterns

Complete examples for WordPress security hardening, deployment workflows, and production best practices.

---

## Table of Contents

1. [Security Hardening](#security-hardening)
2. [WP-CLI Operations](#wp-cli-operations)
3. [Deployment Workflows](#deployment-workflows)
4. [Monitoring and Maintenance](#monitoring-and-maintenance)
5. [Troubleshooting](#troubleshooting)

---

## Security Hardening

### Security Stack Setup

```bash
#!/bin/bash
# Complete WordPress security hardening script

WP_CLI="/opt/bitnami/wp-cli/bin/wp"
WP_PATH="/home/bitnami/stack/wordpress"

echo "=== WordPress Security Hardening ==="

# 1. Install security plugins
echo "Installing security plugins..."
sudo $WP_CLI plugin install two-factor --activate --path=$WP_PATH
sudo $WP_CLI plugin install wps-hide-login --activate --path=$WP_PATH
# MalCare usually pre-installed on managed hosting

# 2. Create admin user with MFA
echo "Creating admin user..."
sudo $WP_CLI user create secureadmin admin@yourdomain.com \
    --role=administrator \
    --user_pass="$(openssl rand -base64 32)" \
    --path=$WP_PATH

# 3. Configure custom login URL
echo "Setting custom login URL..."
sudo $WP_CLI option update whl_page "login-secure-$(date +%Y)" --path=$WP_PATH

# 4. Enable auto-updates
echo "Enabling auto-updates..."
sudo $WP_CLI config set WP_AUTO_UPDATE_CORE true --raw --path=$WP_PATH
sudo $WP_CLI plugin auto-updates enable --all --path=$WP_PATH
sudo $WP_CLI theme auto-updates enable --all --path=$WP_PATH

# 5. Set secure file permissions
echo "Setting file permissions..."
sudo find $WP_PATH -type f -exec chmod 644 {} \;
sudo find $WP_PATH -type d -exec chmod 755 {} \;
sudo chmod 600 $WP_PATH/wp-config.php

# 6. Disable file editing
echo "Disabling file editing..."
if ! grep -q "DISALLOW_FILE_EDIT" $WP_PATH/wp-config.php; then
    sudo sed -i "/\/\* That's all/i define('DISALLOW_FILE_EDIT', true);" $WP_PATH/wp-config.php
fi

# 7. Force SSL for admin
if ! grep -q "FORCE_SSL_ADMIN" $WP_PATH/wp-config.php; then
    sudo sed -i "/\/\* That's all/i define('FORCE_SSL_ADMIN', true);" $WP_PATH/wp-config.php
fi

echo "Security hardening complete!"
echo "Custom login URL: https://yourdomain.com/login-secure-$(date +%Y)"
```

### wp-config.php Security Additions

```php
<?php
/**
 * Security-hardened wp-config.php additions
 * Add these lines before "That's all, stop editing!"
 */

// Disable file editing from WordPress admin
define('DISALLOW_FILE_EDIT', true);

// Disable file updates from WordPress admin
define('DISALLOW_FILE_MODS', true);

// Force SSL for admin pages
define('FORCE_SSL_ADMIN', true);

// Enable auto-updates for minor versions
define('WP_AUTO_UPDATE_CORE', 'minor');

// Increase memory limit
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');

// Security keys and salts (generate from https://api.wordpress.org/secret-key/1.1/salt/)
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');

// Limit post revisions
define('WP_POST_REVISIONS', 5);

// Set autosave interval (seconds)
define('AUTOSAVE_INTERVAL', 300);

// Disable debug display in production
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('WP_DEBUG_LOG', true);  // Log to wp-content/debug.log

// Custom database table prefix (not wp_)
$table_prefix = 'wp_secure_';
```

### .htaccess Security Hardening

```apache
# Security-hardened .htaccess for WordPress

# Protect wp-config.php
<files wp-config.php>
order allow,deny
deny from all
</files>

# Protect .htaccess itself
<files .htaccess>
order allow,deny
deny from all
</files>

# Disable directory browsing
Options -Indexes

# Protect sensitive files
<FilesMatch "^.*(error_log|wp-config\.php|php.ini|\.[hH][tT][aApP].*)$">
Order deny,allow
Deny from all
</FilesMatch>

# Protect wp-includes
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^wp-admin/includes/ - [F,L]
RewriteRule !^wp-includes/ - [S=3]
RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>

# Disable XML-RPC (prevents brute force attacks)
<files xmlrpc.php>
order allow,deny
deny from all
</files>

# Limit file upload size
LimitRequestBody 10485760

# Set security headers
<IfModule mod_headers.c>
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>

# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
```

### Security Audit Script

```python
#!/usr/bin/env python3
"""
WordPress Security Audit Script
Checks security configuration and reports issues
"""

import subprocess
import re
import sys
from pathlib import Path

class WordPressSecurityAuditor:
    """Audit WordPress security configuration."""

    def __init__(self, wp_path='/home/bitnami/stack/wordpress'):
        self.wp_path = Path(wp_path)
        self.wp_cli = '/opt/bitnami/wp-cli/bin/wp'
        self.issues = []
        self.warnings = []
        self.successes = []

    def run_wp_cli(self, command):
        """Execute WP-CLI command."""
        full_cmd = ['sudo', self.wp_cli] + command.split() + [f'--path={self.wp_path}']
        result = subprocess.run(full_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        return result.stdout.strip()

    def check_ssl(self):
        """Check if SSL is enforced."""
        config_content = (self.wp_path / 'wp-config.php').read_text()

        if "define('FORCE_SSL_ADMIN', true)" in config_content:
            self.successes.append("✓ SSL enforced for admin")
            return True
        else:
            self.issues.append("✗ SSL not enforced for admin - Add FORCE_SSL_ADMIN")
            return False

    def check_file_editing(self):
        """Check if file editing is disabled."""
        config_content = (self.wp_path / 'wp-config.php').read_text()

        if "define('DISALLOW_FILE_EDIT', true)" in config_content:
            self.successes.append("✓ File editing disabled")
            return True
        else:
            self.issues.append("✗ File editing enabled - Add DISALLOW_FILE_EDIT")
            return False

    def check_admin_username(self):
        """Check if default admin username is used."""
        users = self.run_wp_cli('user list --role=administrator --field=user_login')

        if 'admin' in users.lower():
            self.warnings.append("⚠ Default 'admin' username detected")
            return False
        else:
            self.successes.append("✓ No default admin username")
            return True

    def check_db_prefix(self):
        """Check if default database prefix is used."""
        config_content = (self.wp_path / 'wp-config.php').read_text()
        match = re.search(r"\$table_prefix\s*=\s*'([^']+)'", config_content)

        if match:
            prefix = match.group(1)
            if prefix == 'wp_':
                self.warnings.append("⚠ Default database prefix 'wp_' in use")
                return False
            else:
                self.successes.append(f"✓ Custom database prefix: {prefix}")
                return True

        return False

    def check_security_plugins(self):
        """Check if security plugins are installed."""
        plugins = self.run_wp_cli('plugin list --status=active --field=name')

        required_plugins = {
            'malcare': False,
            'wordfence': False,
            'two-factor': False,
            'wps-hide-login': False
        }

        for plugin_name in required_plugins.keys():
            if plugin_name in plugins.lower():
                required_plugins[plugin_name] = True

        if required_plugins['two-factor']:
            self.successes.append("✓ MFA plugin installed")
        else:
            self.issues.append("✗ No MFA plugin installed")

        if required_plugins['wps-hide-login']:
            self.successes.append("✓ Custom login URL plugin installed")
        else:
            self.warnings.append("⚠ No custom login URL plugin")

        if required_plugins['malcare'] or required_plugins['wordfence']:
            self.successes.append("✓ Firewall plugin installed")
        else:
            self.issues.append("✗ No firewall plugin installed")

    def check_file_permissions(self):
        """Check file permissions."""
        config_perms = oct((self.wp_path / 'wp-config.php').stat().st_mode)[-3:]

        if config_perms == '600':
            self.successes.append("✓ wp-config.php permissions correct (600)")
        else:
            self.issues.append(f"✗ wp-config.php permissions insecure ({config_perms})")

    def check_auto_updates(self):
        """Check if auto-updates are enabled."""
        config_content = (self.wp_path / 'wp-config.php').read_text()

        if "WP_AUTO_UPDATE_CORE" in config_content:
            self.successes.append("✓ Auto-updates configured")
            return True
        else:
            self.warnings.append("⚠ Auto-updates not configured")
            return False

    def check_debug_mode(self):
        """Check if debug mode is disabled in production."""
        config_content = (self.wp_path / 'wp-config.php').read_text()

        if "define('WP_DEBUG', false)" in config_content or 'WP_DEBUG' not in config_content:
            self.successes.append("✓ Debug mode disabled")
            return True
        else:
            self.issues.append("✗ Debug mode enabled in production")
            return False

    def run_audit(self):
        """Run all security checks."""
        print("=== WordPress Security Audit ===\n")

        self.check_ssl()
        self.check_file_editing()
        self.check_admin_username()
        self.check_db_prefix()
        self.check_security_plugins()
        self.check_file_permissions()
        self.check_auto_updates()
        self.check_debug_mode()

        print("\n=== Audit Results ===\n")

        if self.successes:
            print("Successes:")
            for success in self.successes:
                print(f"  {success}")

        if self.warnings:
            print("\nWarnings:")
            for warning in self.warnings:
                print(f"  {warning}")

        if self.issues:
            print("\nCritical Issues:")
            for issue in self.issues:
                print(f"  {issue}")
            print("\n⚠ Please fix critical issues before going to production!")
            return 1
        else:
            print("\n✓ No critical issues found!")
            return 0


if __name__ == '__main__':
    auditor = WordPressSecurityAuditor()
    sys.exit(auditor.run_audit())
```

---

## WP-CLI Operations

### Complete WP-CLI Wrapper

```python
#!/usr/bin/env python3
"""
Complete WP-CLI wrapper for WordPress operations
Handles security plugins blocking REST API
"""

import subprocess
import json
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class WPCLIManager:
    """Comprehensive WP-CLI manager for WordPress operations."""

    def __init__(
        self,
        ssh_host: str = None,
        ssh_user: str = 'bitnami',
        wp_path: str = '/home/bitnami/stack/wordpress',
        wp_cli_path: str = '/opt/bitnami/wp-cli/bin/wp',
        use_ssh: bool = False
    ):
        """
        Initialize WP-CLI manager.

        Args:
            ssh_host: SSH hostname (if using remote)
            ssh_user: SSH username
            wp_path: Path to WordPress installation
            wp_cli_path: Path to WP-CLI binary
            use_ssh: If True, run commands via SSH
        """
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.wp_path = wp_path
        self.wp_cli = wp_cli_path
        self.use_ssh = use_ssh

    def run_command(self, command: List[str], as_json: bool = False) -> str:
        """
        Execute WP-CLI command.

        Args:
            command: Command parts (e.g., ['post', 'list', '--format=csv'])
            as_json: If True, parse JSON output

        Returns:
            Command output as string or parsed JSON

        Example:
            >>> manager.run_command(['post', 'list', '--format=json'], as_json=True)
            [{'ID': 1, 'post_title': 'Hello World'}, ...]
        """
        # Build command
        cmd_parts = ['sudo', self.wp_cli] + command + [f'--path={self.wp_path}']

        if self.use_ssh:
            # Run via SSH
            ssh_cmd = ' '.join(cmd_parts)
            full_cmd = ['ssh', f'{self.ssh_user}@{self.ssh_host}', ssh_cmd]
        else:
            full_cmd = cmd_parts

        logger.debug(f"Running: {' '.join(full_cmd)}")

        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            stderr=subprocess.DEVNULL
        )

        output = result.stdout.strip()

        if as_json:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON: {output[:200]}")
                return []

        return output

    # Post operations
    def list_posts(
        self,
        post_type: str = 'post',
        status: str = 'any',
        per_page: int = 100
    ) -> List[Dict]:
        """List posts."""
        return self.run_command([
            'post', 'list',
            f'--post_type={post_type}',
            f'--post_status={status}',
            f'--posts_per_page={per_page}',
            '--format=json'
        ], as_json=True)

    def get_post(self, post_id: int, field: Optional[str] = None) -> Dict:
        """Get post by ID."""
        cmd = ['post', 'get', str(post_id)]
        if field:
            cmd.extend(['--field', field])
            return self.run_command(cmd)
        else:
            cmd.append('--format=json')
            return self.run_command(cmd, as_json=True)

    def create_post(self, post_data: Dict) -> int:
        """Create new post."""
        cmd = ['post', 'create']

        for key, value in post_data.items():
            if key == 'content':
                # Save content to temp file
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html') as f:
                    f.write(value)
                    temp_file = f.name
                cmd.extend([f'--{key}', temp_file])
            else:
                cmd.extend([f'--{key}', str(value)])

        cmd.append('--porcelain')  # Return only post ID
        return int(self.run_command(cmd))

    def update_post(self, post_id: int, updates: Dict) -> bool:
        """Update existing post."""
        cmd = ['post', 'update', str(post_id)]

        for key, value in updates.items():
            cmd.extend([f'--{key}', str(value)])

        output = self.run_command(cmd)
        return 'Success' in output

    def delete_post(self, post_id: int, force: bool = True) -> bool:
        """Delete post."""
        cmd = ['post', 'delete', str(post_id)]
        if force:
            cmd.append('--force')

        output = self.run_command(cmd)
        return 'Success' in output

    # Template operations
    def list_templates(self) -> List[Dict]:
        """List all templates."""
        return self.run_command([
            'post', 'list',
            '--post_type=wp_template',
            '--format=json'
        ], as_json=True)

    def get_template(self, template_id: int) -> str:
        """Get template content."""
        return self.run_command([
            'post', 'get', str(template_id),
            '--field=post_content'
        ])

    def update_template(self, template_id: int, content: str) -> bool:
        """Update template content."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html') as f:
            f.write(content)
            temp_file = f.name

        output = self.run_command([
            'post', 'update', str(template_id),
            temp_file,
            '--post_content'
        ])

        return 'Success' in output

    # Global styles operations
    def get_global_styles_id(self) -> int:
        """Get global styles post ID."""
        styles = self.run_command([
            'post', 'list',
            '--post_type=wp_global_styles',
            '--format=json'
        ], as_json=True)

        if styles:
            return styles[0]['ID']

        raise Exception("Global styles not found")

    def export_global_styles(self, output_file: str):
        """Export global styles to JSON file."""
        style_id = self.get_global_styles_id()
        content = self.get_post(style_id, field='post_content')

        with open(output_file, 'w') as f:
            json.dump(json.loads(content), f, indent=2)

        logger.info(f"Exported global styles to {output_file}")

    def import_global_styles(self, input_file: str):
        """Import global styles from JSON file."""
        style_id = self.get_global_styles_id()

        output = self.run_command([
            'post', 'update', str(style_id),
            input_file,
            '--post_content'
        ])

        return 'Success' in output

    # Plugin operations
    def list_plugins(self, status: str = 'active') -> List[str]:
        """List plugins."""
        return self.run_command([
            'plugin', 'list',
            f'--status={status}',
            '--field=name'
        ]).split('\n')

    def install_plugin(self, plugin_name: str, activate: bool = True) -> bool:
        """Install plugin."""
        cmd = ['plugin', 'install', plugin_name]
        if activate:
            cmd.append('--activate')

        output = self.run_command(cmd)
        return 'Success' in output

    def activate_plugin(self, plugin_name: str) -> bool:
        """Activate plugin."""
        output = self.run_command(['plugin', 'activate', plugin_name])
        return 'Success' in output

    def deactivate_plugin(self, plugin_name: str) -> bool:
        """Deactivate plugin."""
        output = self.run_command(['plugin', 'deactivate', plugin_name])
        return 'Success' in output

    # User operations
    def create_user(
        self,
        username: str,
        email: str,
        role: str = 'author',
        password: Optional[str] = None
    ) -> int:
        """Create WordPress user."""
        cmd = ['user', 'create', username, email, f'--role={role}']

        if password:
            cmd.extend([f'--user_pass={password}'])

        cmd.append('--porcelain')
        return int(self.run_command(cmd))

    # Database operations
    def db_export(self, output_file: str):
        """Export database."""
        self.run_command(['db', 'export', output_file])
        logger.info(f"Database exported to {output_file}")

    def db_query(self, query: str) -> str:
        """Execute database query."""
        return self.run_command(['db', 'query', query])


# Usage Example
if __name__ == '__main__':
    # Local usage
    manager = WPCLIManager()

    # List posts
    posts = manager.list_posts(status='publish', per_page=10)
    print(f"Found {len(posts)} posts")

    # Export global styles
    manager.export_global_styles('global-styles-backup.json')

    # Create user
    user_id = manager.create_user('johndoe', 'john@example.com', role='author')
    print(f"Created user: {user_id}")

    # Remote usage via SSH
    remote_manager = WPCLIManager(
        ssh_host='your-server.com',
        ssh_user='bitnami',
        use_ssh=True
    )

    remote_posts = remote_manager.list_posts()
    print(f"Remote server has {len(remote_posts)} posts")
```

---

## Deployment Workflows

### Complete Deployment Script

```bash
#!/bin/bash
# WordPress deployment script with security checks

set -e  # Exit on error

# Configuration
WP_URL="https://yourdomain.com"
WP_PATH="/home/bitnami/stack/wordpress"
WP_CLI="/opt/bitnami/wp-cli/bin/wp"
BACKUP_DIR="/home/bitnami/backups"
DEPLOY_DATE=$(date +%Y%m%d_%H%M%S)

echo "=== WordPress Deployment Started ==="
echo "Date: $DEPLOY_DATE"

# 1. Backup database
echo "Creating database backup..."
mkdir -p $BACKUP_DIR
sudo $WP_CLI db export "$BACKUP_DIR/db_backup_$DEPLOY_DATE.sql" --path=$WP_PATH
echo "✓ Database backed up"

# 2. Backup files (if needed)
echo "Creating files backup..."
sudo tar -czf "$BACKUP_DIR/files_backup_$DEPLOY_DATE.tar.gz" \
    --exclude="$WP_PATH/wp-content/cache" \
    --exclude="$WP_PATH/wp-content/uploads" \
    $WP_PATH
echo "✓ Files backed up"

# 3. Enable maintenance mode
echo "Enabling maintenance mode..."
sudo $WP_CLI maintenance-mode activate --path=$WP_PATH
echo "✓ Maintenance mode enabled"

# 4. Update WordPress core
echo "Updating WordPress core..."
sudo $WP_CLI core update --path=$WP_PATH
echo "✓ WordPress core updated"

# 5. Update plugins
echo "Updating plugins..."
sudo $WP_CLI plugin update --all --path=$WP_PATH
echo "✓ Plugins updated"

# 6. Update themes
echo "Updating themes..."
sudo $WP_CLI theme update --all --path=$WP_PATH
echo "✓ Themes updated"

# 7. Flush caches
echo "Flushing caches..."
sudo $WP_CLI cache flush --path=$WP_PATH
sudo $WP_CLI rewrite flush --path=$WP_PATH
echo "✓ Caches flushed"

# 8. Run security audit
echo "Running security audit..."
python3 security_audit.py
AUDIT_RESULT=$?

if [ $AUDIT_RESULT -ne 0 ]; then
    echo "⚠ Security audit found issues!"
    echo "Review issues before proceeding."
fi

# 9. Test site health
echo "Testing site health..."
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" $WP_URL)

if [ "$HEALTH" != "200" ]; then
    echo "✗ Site health check failed (HTTP $HEALTH)"
    echo "Rolling back..."

    # Rollback database
    sudo $WP_CLI db import "$BACKUP_DIR/db_backup_$DEPLOY_DATE.sql" --path=$WP_PATH

    # Disable maintenance mode
    sudo $WP_CLI maintenance-mode deactivate --path=$WP_PATH

    echo "Rollback complete. Please investigate."
    exit 1
fi

echo "✓ Site health check passed"

# 10. Disable maintenance mode
echo "Disabling maintenance mode..."
sudo $WP_CLI maintenance-mode deactivate --path=$WP_PATH
echo "✓ Maintenance mode disabled"

# 11. Clean old backups (keep last 7 days)
echo "Cleaning old backups..."
find $BACKUP_DIR -name "db_backup_*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "files_backup_*.tar.gz" -mtime +7 -delete
echo "✓ Old backups cleaned"

echo "=== Deployment Complete ==="
echo "Deployment Date: $DEPLOY_DATE"
echo "Backup Location: $BACKUP_DIR"
echo "Site URL: $WP_URL"
```

### Python Deployment Manager

```python
#!/usr/bin/env python3
"""
WordPress deployment manager
Handles deployment, rollback, and health checks
"""

import subprocess
import requests
import datetime
import json
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WordPressDeploymentManager:
    """Manage WordPress deployments."""

    def __init__(
        self,
        wp_url: str,
        wp_path: str = '/home/bitnami/stack/wordpress',
        wp_cli_path: str = '/opt/bitnami/wp-cli/bin/wp',
        backup_dir: str = '/home/bitnami/backups'
    ):
        self.wp_url = wp_url.rstrip('/')
        self.wp_path = Path(wp_path)
        self.wp_cli = wp_cli_path
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)

    def run_wp_cli(self, command):
        """Execute WP-CLI command."""
        full_cmd = ['sudo', self.wp_cli] + command.split() + [f'--path={self.wp_path}']
        result = subprocess.run(full_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        return result.returncode == 0, result.stdout.strip()

    def backup_database(self):
        """Backup WordPress database."""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = self.backup_dir / f'db_backup_{timestamp}.sql'

        logger.info("Creating database backup...")
        success, _ = self.run_wp_cli(f'db export {backup_file}')

        if success:
            logger.info(f"✓ Database backed up to {backup_file}")
            return backup_file
        else:
            logger.error("✗ Database backup failed")
            return None

    def enable_maintenance_mode(self):
        """Enable WordPress maintenance mode."""
        logger.info("Enabling maintenance mode...")
        success, _ = self.run_wp_cli('maintenance-mode activate')
        return success

    def disable_maintenance_mode(self):
        """Disable WordPress maintenance mode."""
        logger.info("Disabling maintenance mode...")
        success, _ = self.run_wp_cli('maintenance-mode deactivate')
        return success

    def update_core(self):
        """Update WordPress core."""
        logger.info("Updating WordPress core...")
        success, output = self.run_wp_cli('core update')
        if 'Success' in output or 'already' in output.lower():
            logger.info("✓ WordPress core updated")
            return True
        else:
            logger.error("✗ WordPress core update failed")
            return False

    def update_plugins(self):
        """Update all plugins."""
        logger.info("Updating plugins...")
        success, output = self.run_wp_cli('plugin update --all')
        if success:
            logger.info("✓ Plugins updated")
            return True
        else:
            logger.error("✗ Plugin update failed")
            return False

    def update_themes(self):
        """Update all themes."""
        logger.info("Updating themes...")
        success, output = self.run_wp_cli('theme update --all')
        if success:
            logger.info("✓ Themes updated")
            return True
        else:
            logger.error("✗ Theme update failed")
            return False

    def flush_caches(self):
        """Flush WordPress caches."""
        logger.info("Flushing caches...")
        self.run_wp_cli('cache flush')
        self.run_wp_cli('rewrite flush')
        logger.info("✓ Caches flushed")

    def check_site_health(self):
        """Check if site is accessible."""
        logger.info("Checking site health...")

        try:
            response = requests.get(self.wp_url, timeout=10)

            if response.status_code == 200:
                logger.info("✓ Site health check passed")
                return True
            else:
                logger.error(f"✗ Site health check failed (HTTP {response.status_code})")
                return False

        except Exception as e:
            logger.error(f"✗ Site health check failed: {e}")
            return False

    def rollback_database(self, backup_file):
        """Rollback database from backup."""
        logger.info(f"Rolling back database from {backup_file}...")
        success, _ = self.run_wp_cli(f'db import {backup_file}')

        if success:
            logger.info("✓ Database rolled back")
            return True
        else:
            logger.error("✗ Database rollback failed")
            return False

    def deploy(self):
        """Execute complete deployment workflow."""
        logger.info("=== WordPress Deployment Started ===")

        # 1. Backup
        backup_file = self.backup_database()
        if not backup_file:
            logger.error("Deployment aborted: backup failed")
            return False

        # 2. Maintenance mode
        if not self.enable_maintenance_mode():
            logger.warning("Failed to enable maintenance mode")

        # 3. Updates
        updates_success = True
        if not self.update_core():
            updates_success = False
        if not self.update_plugins():
            updates_success = False
        if not self.update_themes():
            updates_success = False

        # 4. Flush caches
        self.flush_caches()

        # 5. Health check
        if not self.check_site_health():
            logger.error("Health check failed! Rolling back...")
            self.rollback_database(backup_file)
            self.disable_maintenance_mode()
            return False

        # 6. Disable maintenance mode
        self.disable_maintenance_mode()

        logger.info("=== Deployment Complete ===")
        return updates_success


if __name__ == '__main__':
    manager = WordPressDeploymentManager(
        wp_url='https://yourdomain.com'
    )

    success = manager.deploy()
    exit(0 if success else 1)
```

---

**End of Deployment Examples**

See `SKILL.md` for complete WordPress patterns documentation.
