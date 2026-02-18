# pnpm Migration Skill

**Purpose**: Migrate JavaScript/TypeScript projects from npm/yarn to pnpm to reduce disk space, improve install speed, and eliminate dependency bloat.

**When to use**: Any project with `node_modules` that wants to reduce disk usage by 50-70% and speed up installations by 2-3x.

---

## Why pnpm?

### Space Savings
- **npm/yarn**: Each project has full copy of dependencies → 500MB-2GB per project
- **pnpm**: Hard links to global store → 100MB-500MB per project
- **Result**: 10 projects with React = 5GB (npm) vs 800MB (pnpm)

### Speed Improvements
- Installs are 2-3x faster due to content-addressable store
- No redundant downloads of same packages
- Better monorepo support

### Strict Dependency Resolution
- Prevents phantom dependencies (using packages not in package.json)
- Forces proper dependency declarations
- Better security (no access to unlisted deps)

---

## Quick Migration Guide

### 1. Install pnpm Globally

```bash
# macOS/Linux
curl -fsSL https://get.pnpm.io/install.sh | sh -

# Or via npm (ironic but works)
npm install -g pnpm

# Verify
pnpm --version
```

### 2. Migrate Single Project

```bash
cd /path/to/project

# Remove old package manager files
rm -rf node_modules
rm package-lock.json  # npm
rm yarn.lock          # yarn

# Install with pnpm
pnpm install

# Test that project works
pnpm run dev
pnpm run build
pnpm test

# Commit the new lockfile
git add pnpm-lock.yaml
git commit -m "chore: Migrate to pnpm for reduced disk usage"
```

### 3. Update package.json Scripts

No changes needed! pnpm is compatible with npm scripts:

```json
{
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "test": "jest"
  }
}
```

Just run:
```bash
pnpm dev    # instead of npm run dev
pnpm build  # instead of npm run build
pnpm test   # instead of npm test
```

---

## Common Commands Mapping

| npm | yarn | pnpm |
|-----|------|------|
| `npm install` | `yarn` | `pnpm install` |
| `npm install <pkg>` | `yarn add <pkg>` | `pnpm add <pkg>` |
| `npm install -D <pkg>` | `yarn add -D <pkg>` | `pnpm add -D <pkg>` |
| `npm uninstall <pkg>` | `yarn remove <pkg>` | `pnpm remove <pkg>` |
| `npm run <script>` | `yarn <script>` | `pnpm <script>` |
| `npm update` | `yarn upgrade` | `pnpm update` |
| `npx <cmd>` | `yarn dlx <cmd>` | `pnpm dlx <cmd>` |

---

## Project Types & Migration Notes

### Next.js Projects

```bash
cd project
rm -rf node_modules .next package-lock.json
pnpm install
pnpm dev  # Verify it works
```

**Gotcha**: `.npmrc` files may need updating:
```
# .npmrc
shamefully-hoist=false  # Default, strict mode
# shamefully-hoist=true   # If you have phantom dep issues
```

### React Projects (CRA, Vite)

```bash
cd project
rm -rf node_modules build package-lock.json
pnpm install
pnpm start  # or pnpm dev
```

### Node.js Backend (Express, Fastify)

```bash
cd project
rm -rf node_modules package-lock.json
pnpm install
pnpm start
```

### Monorepos (Turborepo, Nx, Lerna)

pnpm has **native monorepo support** (better than npm/yarn):

```yaml
# pnpm-workspace.yaml
packages:
  - 'apps/*'
  - 'packages/*'
```

```bash
# Install all workspace dependencies
pnpm install

# Run command in specific package
pnpm --filter my-app dev

# Run command in all packages
pnpm -r build
```

---

## Migration Script for Multiple Projects

Save as `~/scripts/migrate-to-pnpm.sh`:

```bash
#!/bin/bash
#
# Migrate JavaScript/TypeScript project to pnpm
# Usage: ./migrate-to-pnpm.sh /path/to/project

set -e

PROJECT_PATH="${1:-.}"
PROJECT_PATH=$(cd "$PROJECT_PATH" && pwd)
PROJECT_NAME=$(basename "$PROJECT_PATH")

echo "Migrating $PROJECT_NAME to pnpm..."

cd "$PROJECT_PATH"

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo "Error: No package.json found"
    exit 1
fi

# Check if pnpm is installed
if ! command -v pnpm &> /dev/null; then
    echo "Error: pnpm not installed"
    echo "Install with: curl -fsSL https://get.pnpm.io/install.sh | sh -"
    exit 1
fi

# Backup old lockfiles
if [ -f "package-lock.json" ]; then
    echo "Backing up package-lock.json..."
    mv package-lock.json package-lock.json.bak
fi

if [ -f "yarn.lock" ]; then
    echo "Backing up yarn.lock..."
    mv yarn.lock yarn.lock.bak
fi

# Remove node_modules
if [ -d "node_modules" ]; then
    echo "Removing node_modules..."
    rm -rf node_modules
fi

# Install with pnpm
echo "Installing with pnpm..."
pnpm install

echo ""
echo "✓ Migration complete!"
echo ""
echo "Next steps:"
echo "  1. Test the project: pnpm dev (or pnpm start)"
echo "  2. Run tests: pnpm test"
echo "  3. If everything works, commit pnpm-lock.yaml"
echo "  4. Delete backups: rm *.lock.bak"
echo ""
echo "Disk space saved: Check with 'du -sh node_modules'"
```

Make it executable:
```bash
chmod +x ~/scripts/migrate-to-pnpm.sh
```

Use it:
```bash
~/scripts/migrate-to-pnpm.sh /path/to/project
```

---

## Batch Migration for All Projects

Migrate all projects in Development folder:

```bash
#!/bin/bash
# batch-migrate-to-pnpm.sh

for dir in ~/Development/*/; do
    if [ -f "$dir/package.json" ]; then
        echo "Processing: $(basename "$dir")"
        ~/scripts/migrate-to-pnpm.sh "$dir"
        echo "---"
    fi
done

echo "All projects migrated!"
echo "Total disk space saved:"
du -sh ~/Development/*/node_modules 2>/dev/null | awk '{sum+=$1} END {print sum " → Projected: " sum*0.3}'
```

---

## Troubleshooting

### Issue: "Cannot find module 'X'"

**Cause**: Phantom dependency - you were using a package not listed in package.json

**Fix**: Add the missing package
```bash
pnpm add <missing-package>
```

### Issue: Peer dependency warnings

**Normal behavior** - pnpm is stricter about peer deps

**Fix options**:
1. Install the peer dependency: `pnpm add <peer-dep>`
2. Use `--shamefully-hoist` flag: `pnpm install --shamefully-hoist`
3. Add to `.npmrc`:
   ```
   auto-install-peers=true
   ```

### Issue: Build fails with "Module not found"

**Fix**: Enable hoisting for problematic packages
```
# .npmrc
public-hoist-pattern[]=*eslint*
public-hoist-pattern[]=*prettier*
```

### Issue: Docker builds fail

**Fix**: Copy pnpm-lock.yaml and use pnpm in Dockerfile

```dockerfile
FROM node:18-alpine

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Install dependencies
RUN pnpm install --frozen-lockfile

COPY . .

RUN pnpm build

CMD ["pnpm", "start"]
```

---

## CI/CD Configuration

### GitHub Actions

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v2
        with:
          version: 8

      - uses: actions/setup-node@v4
        with:
          node-version: 18
          cache: 'pnpm'

      - run: pnpm install --frozen-lockfile
      - run: pnpm test
      - run: pnpm build
```

### GitLab CI

```yaml
image: node:18

cache:
  key: ${CI_COMMIT_REF_SLUG}
  paths:
    - .pnpm-store

before_script:
  - corepack enable
  - corepack prepare pnpm@latest --activate
  - pnpm config set store-dir .pnpm-store
  - pnpm install --frozen-lockfile

test:
  script:
    - pnpm test
    - pnpm build
```

### Railway/Heroku

Add to `package.json`:
```json
{
  "engines": {
    "node": "18.x",
    "pnpm": "8.x"
  },
  "scripts": {
    "build": "pnpm install && pnpm run build:app"
  }
}
```

Railway: Enable pnpm in settings or add `railway.json`:
```json
{
  "build": {
    "builder": "NIXPACKS",
    "nixpacksConfigPath": "nixpacks.toml"
  }
}
```

---

## Best Practices

### 1. Commit pnpm-lock.yaml

Always commit the lockfile for reproducible builds:
```bash
git add pnpm-lock.yaml
git commit -m "chore: Add pnpm lockfile"
```

### 2. Add .npmrc for Team Consistency

```
# .npmrc
shamefully-hoist=false
strict-peer-dependencies=false
auto-install-peers=true
```

Commit this file so team uses same settings.

### 3. Update Documentation

Update README.md:
```markdown
## Installation

This project uses [pnpm](https://pnpm.io) for dependency management.

\`\`\`bash
# Install pnpm globally
npm install -g pnpm

# Install dependencies
pnpm install

# Run development server
pnpm dev
\`\`\`
```

### 4. Clean Global Store Occasionally

```bash
# Remove unused packages from global store
pnpm store prune
```

---

## Disk Space Analysis

### Before Migration (npm)

```bash
$ du -sh ~/Development/*/node_modules
512M    blog-automation/node_modules
728M    claude-essay-agent/node_modules
1.2G    enterprise-translation/node_modules
450M    nextjs-app/node_modules
...
Total: ~15GB for 20 projects
```

### After Migration (pnpm)

```bash
$ du -sh ~/Development/*/node_modules
120M    blog-automation/node_modules
180M    claude-essay-agent/node_modules
250M    enterprise-translation/node_modules
90M     nextjs-app/node_modules
...
Total: ~3GB for 20 projects + 2GB global store = 5GB
```

**Savings: 10GB (67% reduction)**

---

## Migration Checklist

- [ ] Install pnpm globally
- [ ] Test migration on one non-critical project first
- [ ] Verify project builds and runs correctly
- [ ] Check Docker/CI configurations
- [ ] Update team documentation
- [ ] Migrate remaining projects
- [ ] Remove old lockfiles after verification
- [ ] Update deployment pipelines
- [ ] Educate team on pnpm commands
- [ ] Set up `.npmrc` for consistency

---

## When NOT to Use pnpm

- **Legacy projects**: Very old projects with complex build processes may have issues
- **Team resistance**: If team refuses to learn new tool
- **CI/CD limitations**: Some old CI systems don't support pnpm well
- **Specific npm features**: If using npm-specific features like `npm audit fix`

For 95% of projects, pnpm is superior.

---

## Resources

- [pnpm.io](https://pnpm.io) - Official documentation
- [Benchmarks](https://pnpm.io/benchmarks) - Speed comparisons
- [Migration Guide](https://pnpm.io/installation) - Official migration docs
- [Troubleshooting](https://pnpm.io/faq) - Common issues

---

## Quick Reference Card

```bash
# Installation
curl -fsSL https://get.pnpm.io/install.sh | sh -

# Migration
rm -rf node_modules package-lock.json yarn.lock
pnpm install

# Daily usage
pnpm add <package>          # Add dependency
pnpm add -D <package>       # Add dev dependency
pnpm remove <package>       # Remove dependency
pnpm install                # Install all deps
pnpm update                 # Update deps
pnpm <script>               # Run script

# Troubleshooting
pnpm install --shamefully-hoist  # If phantom deps issue
pnpm store prune                 # Clean global store
```

---

**Impact**: Migrating 20-30 projects can save 10-15GB disk space and significantly speed up CI/CD pipelines.
