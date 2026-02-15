# Testing Strategies Skill

> Auto-discovered when testing tasks detected.

## When to Apply

Activates on: "test", "spec", "coverage", "mock", "fixture", "TDD", "integration", "e2e"

## The Testing Pyramid

```
                    /\
                   /  \    E2E Tests
                  /    \   (10% - User flows)
                 /──────\
                /        \
               /          \  Integration Tests
              /            \ (20% - Service boundaries)
             /──────────────\
            /                \
           /                  \  Contract Tests
          /                    \ (20% - FE/BE agreement)
         /────────────────────────\
        /                          \
       /                            \  Unit Tests
      /                              \ (50% - Logic)
     /────────────────────────────────\
```

## Test Types

### Unit Tests (50%)
Test individual functions/methods in isolation.

```python
def test_calculate_discount():
    assert calculate_discount(100, 0.1) == 90
    assert calculate_discount(100, 0) == 100
    assert calculate_discount(0, 0.5) == 0
```

**When to use**: Pure functions, utility methods, business logic

### Contract Tests (20%)
Verify frontend and backend agree on data formats.

```python
def test_frontend_backend_ids_match():
    """Frontend IDs must exist in backend."""
    frontend_ids = ["plan_basic", "plan_pro", "plan_enterprise"]
    backend_ids = list(PRICING_PLANS.keys())

    for fid in frontend_ids:
        assert fid in backend_ids, f"'{fid}' not recognized by backend"
```

**When to use**: API contracts, shared types, ID mappings

### Integration Tests (20%)
Test service boundaries and external integrations.

```python
@pytest.mark.integration
def test_user_creation_with_real_database():
    # Test with actual database, not mocks
    user = create_user("test@example.com", "un42YcgdaeQreBdzKP0PAOyRD4n2")

    assert user.id is not None
    assert User.get(user.id) == user
```

**When to use**: Database operations, external APIs, auth flows

### E2E Tests (10%)
Test complete user journeys.

```python
@pytest.mark.e2e
def test_complete_purchase_flow():
    # Login
    login(TEST_USER)

    # Add to cart
    add_to_cart(PRODUCT_ID)

    # Checkout
    result = checkout(PAYMENT_INFO)

    assert result.status == "success"
    assert get_user_credits() == EXPECTED_CREDITS
```

**When to use**: Critical user paths, smoke tests

### Smoke Tests (Post-Deploy)
Verify deployment succeeded.

```bash
#!/bin/bash
API_URL="${1:-https://api.example.com}"

# Health check
curl -sf "$API_URL/health" || exit 1

# Auth works (should be 401, not 500)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/protected")
[ "$STATUS" -eq 401 ] || exit 1

echo "✓ Smoke tests passed"
```

## Test Fixtures

### Realistic IDs
```python
# Don't use fake UUIDs for auth providers
REALISTIC_USER_IDS = [
    "un42YcgdaeQreBdzKP0PAOyRD4n2",  # Firebase
    "auth0|abc123def456",             # Auth0
    "google-oauth2|123456789",        # Google
    str(uuid.uuid4()),                # Actual UUID
]

@pytest.mark.parametrize("user_id", REALISTIC_USER_IDS)
def test_user_operations(user_id):
    user = create_user(user_id)
    assert user.success
```

### Test Data Factories
```python
from faker import Faker
fake = Faker()

def make_user(**overrides):
    return {
        "email": fake.email(),
        "name": fake.name(),
        "created_at": fake.date_time(),
        **overrides
    }
```

## Mocking Guidelines

### Do Mock
- External APIs (Stripe, SendGrid)
- Time/dates for determinism
- Random values

### Don't Mock
- Your own code (test the real thing)
- Database in integration tests
- Auth providers in integration tests

## Coverage Targets

| Type | Target | Rationale |
|------|--------|-----------|
| Unit | 80%+ | Core logic covered |
| Integration | Key paths | Service boundaries |
| Contract | 100% | All shared types |
| E2E | Critical paths | User journeys |

## Test Organization

```
tests/
├── unit/                 # Fast, isolated
│   ├── test_utils.py
│   └── test_services.py
├── integration/          # Slower, real deps
│   ├── test_database.py
│   └── test_auth.py
├── contracts/            # FE/BE agreement
│   └── test_api_contracts.py
├── e2e/                  # Full flows
│   └── test_purchase.py
├── fixtures/             # Shared test data
│   ├── users.py
│   └── products.py
└── conftest.py           # Pytest config
```

## Running Tests

```bash
# Unit tests (fast)
pytest tests/unit -v

# Integration (needs DB)
pytest tests/integration -v --tb=short

# Contracts (CI blocker)
pytest tests/contracts -v

# E2E (slow)
pytest tests/e2e -v --slow

# All with coverage
pytest --cov=src --cov-report=html
```

## CI Configuration

```yaml
test:
  stages:
    - unit        # Fast, run first
    - contracts   # Block if FE/BE mismatch
    - integration # Real database
    - e2e         # Full flows (optional on PR)
```

---

## Test Templates Library

### Available Templates

Use these ready-to-use templates to quickly create comprehensive tests:

#### Unit Test Templates

**Jest/JavaScript:**
```bash
cp .claude/skills/testing-strategies/templates/unit/jest-unit-test.template.js tests/unit/{feature}.test.js
```

Features:
- Complete test suite structure (setup, teardown, hooks)
- Happy path, edge cases, error handling
- Mock/spy examples
- Async/await patterns
- Snapshot testing
- Performance tests
- Coverage notes

**PyTest/Python:**
```bash
cp .claude/skills/testing-strategies/templates/unit/pytest-unit-test.template.py tests/unit/test_{feature}.py
```

Features:
- Fixtures for test data
- Parametrized tests
- Mock/patch examples
- Async tests (pytest-asyncio)
- Property-based testing (hypothesis)
- Benchmark tests
- Test organization with classes

**Go:**
```bash
cp .claude/skills/testing-strategies/templates/unit/go-unit-test.template_test.go {package}_test.go
```

Features:
- Table-driven tests
- Testify suite setup
- Mock interfaces
- Context and timeout tests
- Benchmark tests
- Fuzz testing (Go 1.18+)
- Example tests for godoc

#### Integration Test Templates

**API Integration:**
```bash
cp .claude/skills/testing-strategies/templates/integration/api-integration-test.template.js tests/integration/api-{resource}.test.js
```

Features:
- Complete CRUD operations testing
- Authentication and authorization tests
- Pagination, filtering, sorting
- Error handling and validation
- Rate limiting tests
- Security tests (SQL injection, XSS)
- Database verification

#### E2E Test Templates

**Playwright:**
```bash
cp .claude/skills/testing-strategies/templates/e2e/playwright-e2e-test.template.spec.ts tests/e2e/{feature}.spec.ts
```

Features:
- Complete user workflows
- Authentication flows
- Form validation
- CRUD operations
- Navigation testing
- File upload tests
- Accessibility testing
- Responsive design tests
- Visual regression testing
- Network error handling

### Test Fixtures Library

**Common Fixtures:**
```javascript
import { userFixtures, apiFixtures, edgeCaseFixtures } from '.claude/skills/testing-strategies/templates/fixtures/common-fixtures';

// Use in tests
const user = userFixtures.validUser();
const response = apiFixtures.successResponse({ id: 1 });
const malicious = edgeCaseFixtures.specialCharacters.sql;
```

Available fixtures:
- **User fixtures**: validUser, adminUser, inactiveUser, userList
- **API fixtures**: successResponse, errorResponse, paginatedResponse
- **Database fixtures**: product, order, comment
- **Form fixtures**: loginForm, registrationForm, contactForm
- **Edge cases**: emptyValues, invalidEmails, specialCharacters, boundaryValues
- **Date fixtures**: today, yesterday, dateRange
- **File fixtures**: mockFile, imageFile, pdfFile, largeFile
- **Error fixtures**: standardError, networkError, timeoutError
- **Mock functions**: mockApiSuccess, mockApiError, mockApiDelayed

### Coverage Requirement Checker

**Check test coverage against thresholds:**
```bash
./.claude/skills/testing-strategies/scripts/check-coverage.sh
```

**Strict mode (fail if below threshold):**
```bash
./.claude/skills/testing-strategies/scripts/check-coverage.sh --strict
```

**Configure thresholds:**
```bash
export LINE_COVERAGE_THRESHOLD=85
export BRANCH_COVERAGE_THRESHOLD=80
export FUNCTION_COVERAGE_THRESHOLD=100
./.claude/skills/testing-strategies/scripts/check-coverage.sh
```

Supports:
- Jest/Istanbul (coverage/coverage-summary.json)
- PyTest (coverage.xml or .coverage)
- Go test (coverage.out)

Default thresholds:
- Line coverage: 80%
- Branch coverage: 75%
- Function coverage: 100%
- Statement coverage: 80%

### Quick Start Guide

**1. Choose the right template:**
- Writing unit tests? Use unit test templates
- Testing API endpoints? Use integration template
- Testing user flows? Use E2E template

**2. Copy and customize:**
```bash
# For JavaScript unit tests
cp .claude/skills/testing-strategies/templates/unit/jest-unit-test.template.js tests/unit/my-feature.test.js

# Replace placeholders:
# - {ModuleName} → MyFeature
# - {functionName} → myFunction
# - {modulePath} → path/to/module
```

**3. Use fixtures for test data:**
```javascript
import { userFixtures } from '.claude/skills/testing-strategies/templates/fixtures/common-fixtures';

test('should handle valid user', () => {
  const user = userFixtures.validUser();
  expect(processUser(user)).toBeDefined();
});
```

**4. Run tests with coverage:**
```bash
# Jest
npm test -- --coverage

# PyTest
pytest --cov=src --cov-report=html

# Go
go test -coverprofile=coverage.out ./...
```

**5. Verify coverage:**
```bash
./.claude/skills/testing-strategies/scripts/check-coverage.sh --strict
```

### Best Practices

**Test Organization:**
1. Keep unit tests fast (< 100ms each)
2. Use fixtures for consistent test data
3. Group related tests in describe/context blocks
4. Use descriptive test names that explain intent
5. Follow AAA pattern: Arrange, Act, Assert

**Test Coverage:**
1. Aim for 80%+ line coverage
2. Focus on critical paths, not percentages
3. Test edge cases and error conditions
4. Don't test framework code
5. Mock external dependencies in unit tests

**Test Maintenance:**
1. Keep tests simple and readable
2. Avoid test interdependencies
3. Clean up test data after each test
4. Use helper functions to reduce duplication
5. Update tests when requirements change

**CI/CD Integration:**
1. Run unit tests on every commit
2. Run integration tests before merge
3. Run E2E tests on staging
4. Enforce coverage thresholds
5. Fail build on test failures

### Template Checklist

When using templates, ensure you:

- [ ] Replace all placeholder text ({ModuleName}, {functionName}, etc.)
- [ ] Remove unused test sections
- [ ] Add project-specific test cases
- [ ] Configure appropriate test data
- [ ] Set up necessary mocks/fixtures
- [ ] Verify coverage meets thresholds
- [ ] Add tests to CI/CD pipeline
- [ ] Document any custom test helpers
- [ ] Update test names to match feature
- [ ] Review and simplify before committing

---

**Templates Location:** `.claude/skills/testing-strategies/templates/`

**Fixtures Location:** `.claude/skills/testing-strategies/templates/fixtures/`

**Scripts Location:** `.claude/skills/testing-strategies/scripts/`
