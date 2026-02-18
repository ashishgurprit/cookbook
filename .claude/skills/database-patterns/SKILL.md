# Database Patterns

> Best practices for database design and operations.
> Auto-discovered when database work detected.

## Schema Design

### 1. Naming Conventions

```sql
-- Tables: plural, snake_case
CREATE TABLE users (...);
CREATE TABLE order_items (...);

-- Columns: singular, snake_case
user_id, created_at, is_active

-- Primary keys: id or table_id
users.id or users.user_id

-- Foreign keys: referenced_table_id
orders.user_id REFERENCES users(id)

-- Indexes: idx_table_column
CREATE INDEX idx_users_email ON users(email);

-- Constraints: table_column_type
CONSTRAINT users_email_unique UNIQUE (email)
```

### 2. Data Types

```sql
-- Use appropriate types
-- BAD
CREATE TABLE users (
    id VARCHAR(255),           -- Use UUID or BIGINT
    age VARCHAR(10),           -- Use INTEGER
    price VARCHAR(20),         -- Use DECIMAL
    is_active VARCHAR(5),      -- Use BOOLEAN
    created_at VARCHAR(50)     -- Use TIMESTAMP
);

-- GOOD
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    age INTEGER CHECK (age > 0),
    price DECIMAL(10, 2),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Use ENUM for fixed options
CREATE TYPE user_status AS ENUM ('active', 'inactive', 'suspended');
```

### 3. Relationships

```sql
-- One-to-Many (user has many orders)
CREATE TABLE orders (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- ...
);

-- Many-to-Many (users <-> roles)
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- One-to-One (user has one profile)
CREATE TABLE profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- ...
);
```

## Indexing Strategies

### When to Add Indexes

```sql
-- 1. Primary keys (automatic)
-- 2. Foreign keys (not automatic in PostgreSQL!)
CREATE INDEX idx_orders_user_id ON orders(user_id);

-- 3. Frequently queried columns
CREATE INDEX idx_users_email ON users(email);

-- 4. Columns used in WHERE clauses
CREATE INDEX idx_orders_status ON orders(status);

-- 5. Columns used in ORDER BY
CREATE INDEX idx_orders_created_at ON orders(created_at DESC);

-- 6. Composite indexes for common query patterns
-- Order matters! (leftmost prefix)
CREATE INDEX idx_orders_user_status_date
    ON orders(user_id, status, created_at);

-- Works for:
-- WHERE user_id = ?
-- WHERE user_id = ? AND status = ?
-- WHERE user_id = ? AND status = ? AND created_at > ?

-- Does NOT work for:
-- WHERE status = ?  (missing leftmost)
```

### Index Types

```sql
-- B-tree (default) - equality, range queries
CREATE INDEX idx_users_age ON users(age);

-- Hash - equality only, faster for exact matches
CREATE INDEX idx_users_email ON users USING hash(email);

-- GIN - arrays, full-text search, JSONB
CREATE INDEX idx_users_tags ON users USING gin(tags);
CREATE INDEX idx_docs_content ON documents USING gin(to_tsvector('english', content));

-- Partial index - subset of rows
CREATE INDEX idx_active_users ON users(email) WHERE is_active = true;

-- Expression index
CREATE INDEX idx_users_lower_email ON users(LOWER(email));
```

## Query Optimization

### 1. EXPLAIN ANALYZE

```sql
-- Always check query plans
EXPLAIN ANALYZE
SELECT * FROM orders
WHERE user_id = '123' AND status = 'pending';

-- Look for:
-- Seq Scan (bad on large tables) → Add index
-- Nested Loop (can be slow) → Check join conditions
-- High actual time → Optimize
```

### 2. N+1 Query Problem

```python
# BAD - N+1 queries
users = User.query.all()
for user in users:
    orders = Order.query.filter_by(user_id=user.id).all()  # N queries!

# GOOD - Single query with JOIN
users = db.session.query(User).options(
    joinedload(User.orders)
).all()

# Or with subquery for large datasets
users = db.session.query(User).options(
    subqueryload(User.orders)
).all()
```

### 3. Pagination

```python
# Offset pagination (simple but slow on large offsets)
def get_users_offset(page: int, per_page: int = 20):
    offset = (page - 1) * per_page
    return User.query.offset(offset).limit(per_page).all()

# Cursor pagination (better for large datasets)
def get_users_cursor(cursor: str = None, limit: int = 20):
    query = User.query.order_by(User.created_at.desc())

    if cursor:
        cursor_date = decode_cursor(cursor)
        query = query.filter(User.created_at < cursor_date)

    users = query.limit(limit + 1).all()

    has_more = len(users) > limit
    users = users[:limit]

    next_cursor = encode_cursor(users[-1].created_at) if has_more else None

    return {"data": users, "next_cursor": next_cursor}
```

### 4. Batch Operations

```python
# BAD - Individual inserts
for item in items:
    db.session.add(Item(**item))
    db.session.commit()  # Commit per item!

# GOOD - Bulk insert
db.session.bulk_insert_mappings(Item, items)
db.session.commit()

# Or with executemany
db.session.execute(
    Item.__table__.insert(),
    items
)
```

## Migrations

### Best Practices

```python
# 1. Always make migrations reversible
def upgrade():
    op.add_column('users', sa.Column('phone', sa.String(20)))

def downgrade():
    op.drop_column('users', 'phone')

# 2. Add columns as nullable first
def upgrade():
    # Step 1: Add nullable column
    op.add_column('users', sa.Column('status', sa.String(20), nullable=True))

def upgrade_data():
    # Step 2: Backfill data (separate migration)
    op.execute("UPDATE users SET status = 'active' WHERE status IS NULL")

def upgrade_constraint():
    # Step 3: Add NOT NULL constraint (separate migration)
    op.alter_column('users', 'status', nullable=False)

# 3. Create indexes concurrently (PostgreSQL)
def upgrade():
    op.execute('CREATE INDEX CONCURRENTLY idx_users_email ON users(email)')

# 4. Never modify old migrations - create new ones
```

### Safe Schema Changes

| Operation | Safe? | Notes |
|-----------|-------|-------|
| Add column (nullable) | ✅ | Always safe |
| Add column (NOT NULL) | ⚠️ | Add default or backfill first |
| Drop column | ⚠️ | Remove code references first |
| Rename column | ❌ | Use add/migrate/drop pattern |
| Add index | ⚠️ | Use CONCURRENTLY |
| Drop index | ✅ | Usually safe |
| Change column type | ❌ | Risky - use add/migrate/drop |

## Connection Management

```python
# SQLAlchemy connection pool
from sqlalchemy import create_engine

engine = create_engine(
    DATABASE_URL,
    pool_size=10,           # Connections to maintain
    max_overflow=20,        # Extra connections under load
    pool_timeout=30,        # Wait time for connection
    pool_recycle=1800,      # Recycle connections (30 min)
    pool_pre_ping=True,     # Check connection health
)

# Context manager for connections
from contextlib import contextmanager

@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Usage
with get_db() as db:
    users = db.query(User).all()
```

## Backup & Recovery

```bash
# PostgreSQL backup
pg_dump -Fc database_name > backup.dump

# Restore
pg_restore -d database_name backup.dump

# Point-in-time recovery (requires WAL archiving)
# postgresql.conf
archive_mode = on
archive_command = 'cp %p /archive/%f'
```

## Security

```sql
-- Principle of least privilege
CREATE ROLE app_read;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_read;

CREATE ROLE app_write;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_write;

-- Row-level security
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_documents ON documents
    FOR ALL
    USING (user_id = current_user_id());

-- Encrypt sensitive data
CREATE EXTENSION pgcrypto;

-- Store encrypted
INSERT INTO users (ssn_encrypted)
VALUES (pgp_sym_encrypt('123-45-6789', 'secret_key'));

-- Retrieve
SELECT pgp_sym_decrypt(ssn_encrypted, 'secret_key') FROM users;
```

## Monitoring

```sql
-- Slow queries (PostgreSQL)
-- In postgresql.conf:
log_min_duration_statement = 1000  -- Log queries > 1s

-- Active queries
SELECT pid, query, state, wait_event_type, query_start
FROM pg_stat_activity
WHERE state != 'idle';

-- Table sizes
SELECT
    relname AS table,
    pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;

-- Index usage
SELECT
    indexrelname AS index,
    idx_scan AS scans,
    pg_size_pretty(pg_relation_size(indexrelid)) AS size
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```
