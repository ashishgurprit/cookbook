# API Patterns Skill

> Auto-discovered when API tasks detected.

## When to Apply

Activates on: "endpoint", "API", "REST", "route", "request", "response", "HTTP", "webhook"

## REST Conventions

### HTTP Methods
| Method | Purpose | Idempotent |
|--------|---------|------------|
| GET | Retrieve resource(s) | Yes |
| POST | Create resource | No |
| PUT | Replace resource | Yes |
| PATCH | Partial update | Yes |
| DELETE | Remove resource | Yes |

### URL Structure
```
GET    /api/v1/users          # List users
GET    /api/v1/users/:id      # Get single user
POST   /api/v1/users          # Create user
PUT    /api/v1/users/:id      # Replace user
PATCH  /api/v1/users/:id      # Update user
DELETE /api/v1/users/:id      # Delete user

# Nested resources
GET    /api/v1/users/:id/posts
POST   /api/v1/users/:id/posts
```

### Query Parameters
```
# Pagination
?page=1&limit=20
?cursor=abc123

# Filtering
?status=active&role=admin

# Sorting
?sort=created_at&order=desc

# Field selection
?fields=id,name,email
```

## Response Format

### Success Response
```json
{
  "data": { ... },
  "meta": {
    "page": 1,
    "limit": 20,
    "total": 100
  }
}
```

### Error Response
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": [
      {
        "field": "email",
        "message": "Must be a valid email address"
      }
    ]
  }
}
```

## HTTP Status Codes

### Success
- `200 OK` - Successful GET, PUT, PATCH
- `201 Created` - Successful POST
- `204 No Content` - Successful DELETE

### Client Errors
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Not authenticated
- `403 Forbidden` - Not authorized
- `404 Not Found` - Resource doesn't exist
- `409 Conflict` - Resource conflict
- `422 Unprocessable Entity` - Validation failed
- `429 Too Many Requests` - Rate limited

### Server Errors
- `500 Internal Server Error` - Unexpected error
- `502 Bad Gateway` - Upstream error
- `503 Service Unavailable` - Temporarily down

## Validation Pattern

```typescript
// Request validation schema
const createUserSchema = {
  body: {
    email: { type: 'email', required: true },
    name: { type: 'string', minLength: 2, maxLength: 100 },
    password: { type: 'string', minLength: 8 }
  }
};
```

## Authentication Pattern

```typescript
// Middleware pattern
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({
      error: { code: 'UNAUTHORIZED', message: 'No token provided' }
    });
  }

  try {
    const user = await verifyToken(token);
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      error: { code: 'INVALID_TOKEN', message: 'Token is invalid or expired' }
    });
  }
}
```

## Error Handling Pattern

```typescript
// Centralized error handler
function errorHandler(err, req, res, next) {
  console.error(err);

  if (err instanceof ValidationError) {
    return res.status(422).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: err.message,
        details: err.details
      }
    });
  }

  if (err instanceof NotFoundError) {
    return res.status(404).json({
      error: { code: 'NOT_FOUND', message: err.message }
    });
  }

  // Unknown errors - don't leak details
  return res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred'
    }
  });
}
```

## Rate Limiting

```typescript
const rateLimitConfig = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // requests per window
  message: {
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many requests, please try again later'
    }
  }
};
```

## Contract Testing

```python
def test_frontend_backend_ids_match():
    """Verify frontend IDs exist in backend."""
    frontend_ids = ["plan_basic", "plan_pro"]
    backend_ids = list(PLANS.keys())

    for fid in frontend_ids:
        assert fid in backend_ids, f"Frontend uses '{fid}' not in backend"
```
