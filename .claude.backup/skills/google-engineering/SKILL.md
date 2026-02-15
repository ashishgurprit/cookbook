# Google Engineering Practices

> Best practices from Google's engineering culture.
> Sources: Google Engineering Practices, SRE Book, Testing on the Toilet

## Core Principles

### 1. Code Review Standards

**Every CL (changelist) should:**
- Do ONE thing well
- Be small (< 400 lines ideal)
- Have a clear description
- Include tests

**Reviewer's job:**
- Respond within 1 business day
- Focus on: design, functionality, complexity, tests, naming, comments, style
- Approve if "good enough" - don't block on perfection

**Author's job:**
- Keep CLs small and focused
- Respond to all comments
- Don't take feedback personally

### 2. Design Documents

For significant changes, write a design doc BEFORE coding:

```markdown
# Design Doc: [Feature Name]

## Context & Problem
What problem are we solving? Why now?

## Goals & Non-Goals
### Goals
- [Specific, measurable goal]

### Non-Goals
- [What we're explicitly NOT doing]

## Proposed Solution
[Technical approach]

## Alternatives Considered
| Option | Pros | Cons |
|--------|------|------|
| Option A | ... | ... |
| Option B | ... | ... |

## Security/Privacy Considerations
[Any concerns?]

## Testing Plan
[How will we verify this works?]

## Rollout Plan
[How will we deploy safely?]
```

### 3. Small CLs Philosophy

```
┌─────────────────────────────────────────────────────────────┐
│                 SMALL CL BENEFITS                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Faster reviews      │  Easier to understand               │
│  Fewer bugs          │  Easier to roll back                │
│  Less wasted work    │  Easier to merge                    │
│  Better design       │  Less blocking                      │
│                                                             │
│  Rule of thumb: If you can't review it in 15 min,          │
│  it's probably too big.                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4. Testing on the Toilet (TotT)

Bite-sized testing wisdom:

**Test Behavior, Not Implementation**
```python
# BAD - tests implementation
def test_user_service():
    service = UserService()
    assert service._cache == {}  # Testing private state

# GOOD - tests behavior
def test_get_user_returns_user():
    service = UserService()
    user = service.get_user("123")
    assert user.id == "123"
```

**Don't Mock What You Don't Own**
```python
# BAD - mocking third-party library internals
@mock.patch('requests.Session._send')
def test_api_call(mock_send):
    ...

# GOOD - wrap third-party, mock your wrapper
class HttpClient:
    def get(self, url): return requests.get(url)

@mock.patch.object(HttpClient, 'get')
def test_api_call(mock_get):
    ...
```

**Prefer Fakes Over Mocks**
```python
# Fake - real implementation for testing
class FakeDatabase:
    def __init__(self):
        self.data = {}

    def save(self, key, value):
        self.data[key] = value

    def get(self, key):
        return self.data.get(key)
```

### 5. Error Handling

```python
# Google's error handling principles

# 1. Fail fast, fail loud
def process_payment(amount):
    if amount <= 0:
        raise ValueError(f"Invalid amount: {amount}")

# 2. Use specific exceptions
class PaymentDeclinedError(Exception):
    pass

class InsufficientFundsError(PaymentDeclinedError):
    pass

# 3. Include context in errors
raise PaymentDeclinedError(
    f"Payment of ${amount} declined for user {user_id}: {reason}"
)

# 4. Don't catch and ignore
try:
    process()
except Exception:
    pass  # NEVER DO THIS
```

### 6. Readability

Google's code readability standards:

**Naming**
- Variables: `user_count` not `n` or `uc`
- Booleans: `is_valid`, `has_permission`, `can_edit`
- Functions: `calculate_total()` not `calc()` or `do_thing()`

**Comments**
```python
# BAD - says what code does
i += 1  # increment i

# GOOD - says WHY
i += 1  # Skip header row

# GOOD - explains non-obvious behavior
# Using insertion sort here because n < 10 and it's faster
# for small arrays than quicksort due to lower overhead
```

**Function Length**
- If you can't see the whole function on screen, it's too long
- Extract helper functions
- Each function should do ONE thing

### 7. SRE Principles

**Error Budgets**
- Define acceptable error rate (e.g., 99.9% = 43 min downtime/month)
- If within budget: ship fast
- If over budget: focus on reliability

**Postmortems (Blameless)**
```markdown
## Incident Report: [Title]

**Date**: YYYY-MM-DD
**Duration**: X hours
**Impact**: [Users affected]

### Timeline
- HH:MM - [Event]
- HH:MM - [Event]

### Root Cause
[What actually caused it]

### Resolution
[How we fixed it]

### Action Items
- [ ] [Preventive measure] - Owner - Due date
```

## Quick Reference

| Practice | Do | Don't |
|----------|-----|-------|
| CL Size | < 400 lines | Monster PRs |
| Reviews | Within 1 day | Block on nitpicks |
| Testing | Test behavior | Test implementation |
| Errors | Fail fast, be specific | Catch and ignore |
| Comments | Explain why | Explain what |
| Functions | Single responsibility | Kitchen sink |
