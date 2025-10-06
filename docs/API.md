# FerriteDB API Documentation

This document provides comprehensive API documentation for FerriteDB.

## 🌐 Base URL

```
http://localhost:8090/api
```

## 🔐 Authentication

FerriteDB uses JWT-based authentication with access and refresh tokens.

### Login

**POST** `/auth/login`

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "role": "user",
    "verified": true,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  },
  "token": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

### Register

**POST** `/auth/register`

```json
{
  "email": "newuser@example.com",
  "password": "securepassword",
  "password_confirm": "securepassword"
}
```

### Refresh Token

**POST** `/auth/refresh`

```json
{
  "refresh_token": "eyJ..."
}
```

### Get Current User

**GET** `/auth/me`

Headers: `Authorization: Bearer <access_token>`

## 📊 Collections API

### List Records

**GET** `/collections/{collection}/records`

Query Parameters:
- `page` (int): Page number (default: 1)
- `per_page` (int): Records per page (default: 30, max: 500)
- `filter` (string): Filter expression
- `sort` (string): Sort expression (e.g., "created_at", "-updated_at")
- `fields` (string): Comma-separated field list
- `expand` (string): Expand related records

**Example:**
```bash
GET /api/collections/posts/records?page=1&per_page=10&filter=published=true&sort=-created_at
```

**Response:**
```json
{
  "page": 1,
  "per_page": 10,
  "total_items": 25,
  "total_pages": 3,
  "items": [
    {
      "id": "uuid",
      "collection_id": "uuid",
      "data": {
        "title": "Hello World",
        "content": "My first post!",
        "published": true,
        "author_id": "uuid"
      },
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```#
## Create Record

**POST** `/collections/{collection}/records`

Headers: `Authorization: Bearer <access_token>`

```json
{
  "title": "New Post",
  "content": "This is a new post",
  "published": false,
  "author_id": "uuid"
}
```

### Get Record

**GET** `/collections/{collection}/records/{id}`

Headers: `Authorization: Bearer <access_token>`

### Update Record

**PATCH** `/collections/{collection}/records/{id}`

Headers: `Authorization: Bearer <access_token>`

```json
{
  "title": "Updated Title",
  "published": true
}
```

### Delete Record

**DELETE** `/collections/{collection}/records/{id}`

Headers: `Authorization: Bearer <access_token>`

## 📁 File Storage API

### Upload File

**POST** `/files/{collection}/{record_id}/{field}`

Headers: `Authorization: Bearer <access_token>`

Form Data:
- `file`: File to upload

**Example:**
```bash
curl -X POST http://localhost:8090/api/files/posts/uuid/featured_image \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@image.jpg"
```

### Download File

**GET** `/files/{collection}/{record_id}/{field}`

### Delete File

**DELETE** `/files/{collection}/{record_id}/{field}`

Headers: `Authorization: Bearer <access_token>`

## 🔍 Health & Monitoring

### Health Check

**GET** `/health`

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-01-01T00:00:00Z",
  "service": "ferritedb",
  "version": "1.0.0"
}
```

### Readiness Check

**GET** `/readyz`

**Response:**
```json
{
  "status": "ready",
  "timestamp": "2025-01-01T00:00:00Z",
  "service": "ferritedb",
  "version": "1.0.0",
  "checks": {
    "database": "healthy",
    "storage": "healthy"
  }
}
```

### Metrics (if enabled)

**GET** `/metrics`

Returns Prometheus-formatted metrics.

## 📡 WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8090/realtime');
```

### Subscribe to Collection

```json
{
  "type": "subscribe",
  "collection": "posts",
  "filter": "record.published = true"
}
```

### Unsubscribe

```json
{
  "type": "unsubscribe",
  "collection": "posts"
}
```

### Real-time Events

```json
{
  "event_type": "created",
  "collection": "posts",
  "record_id": "uuid",
  "data": { ... },
  "timestamp": "2025-01-01T00:00:00Z"
}
```

## 🛡️ Access Rules

Rules use CEL-like expressions for fine-grained access control.

### Available Variables

- `@request.auth.id` - Current user ID
- `@request.auth.email` - Current user email
- `@request.auth.role` - Current user role
- `@request.auth.verified` - User verification status
- `record.*` - Record fields
- `@now` - Current timestamp

### Rule Examples

```javascript
// Public read access
"true"

// Authenticated users only
"@request.auth.id != ''"

// Owner or admin access
"record.owner_id = @request.auth.id || @request.auth.role = 'admin'"

// Published content or owner
"record.published = true || record.author_id = @request.auth.id"

// Time-based access
"record.publish_date <= @now"
```

## 📋 Error Responses

All API errors follow a consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid field value",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    }
  }
}
```

### Common Error Codes

- `AUTHENTICATION_REQUIRED` (401)
- `FORBIDDEN` (403)
- `NOT_FOUND` (404)
- `VALIDATION_ERROR` (400)
- `RATE_LIMITED` (429)
- `INTERNAL_ERROR` (500)

## 🔧 Rate Limiting

API endpoints are rate limited:

- **Auth endpoints**: 5 requests/second
- **API endpoints**: 10 requests/second
- **File uploads**: 2 requests/second

Rate limit headers:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

---

For more detailed examples and interactive documentation, visit the Swagger UI at `/docs` when running FerriteDB.