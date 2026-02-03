# 🔗 Link Shortener API Documentation

<div align="center">
  
  **Comprehensive REST API for URL shortening with advanced analytics and management capabilities**
  
  ![API](https://img.shields.io/badge/API-REST-blue?style=for-the-badge)
  ![Version](https://img.shields.io/badge/Version-1.0.0-green?style=for-the-badge)
  ![Auth](https://img.shields.io/badge/Auth-API%20Key-orange?style=for-the-badge)
  
</div>

---

## 🌟 Overview

This API provides complete CRUD operations for shortened links with advanced features including:
- 🔐 API key authentication
- 📊 Click analytics and tracking
- ⚡ Rate limiting and security
- 🗺️ Geographic data collection  
- 📱 Device and browser analytics
- 🔔 Push notifications
- 🛡️ Enterprise-grade security

**Base URL**: `https://yourdomain.com` (replace with your deployment URL)

---

## 🔐 Authentication

All API endpoints require authentication using an API key in the `Authorization` header:

```http
Authorization: your-secret-api-key-here
```

### 🔧 Setting up your API Key

1. Add your API key to the `.env` file:
```env
API_KEY=your-secret-api-key-here
```

2. Generate a secure API key (recommended):
```bash
# Generate a secure 32-character API key
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 🛡️ Security Best Practices
- **Never expose your API key** in client-side code
- **Use HTTPS** in production to prevent key interception  
- **Rotate API keys** regularly for enhanced security
- **Monitor API usage** through logs for suspicious activity

---

## ⚡ Rate Limiting

Multi-tier rate limiting protects against abuse:

| Tier | Limit | Window | Scope |
|------|-------|--------|-------|
| **Global** | 100 requests | 15 minutes | Per IP address |
| **API Routes** | 50 requests | 15 minutes | Per API key |
| **Auth Routes** | 5 attempts | 15 minutes | Per IP address |

### Rate Limit Headers
Response headers provide real-time limit information:
```http
RateLimit-Limit: 50
RateLimit-Remaining: 45
RateLimit-Reset: 1640995200
```

### Rate Limit Bypass
- **Admin users** with valid JWT tokens bypass global limits
- **Authenticated API requests** bypass global IP limits

---

## 🚀 Endpoints

### 1. Create a Shortened Link

Creates a new shortened link or updates an existing one with full tracking capabilities.

**Endpoint**: `POST /api/links`

**Headers**:
```http
Authorization: your-api-key-here
Content-Type: application/json
```

**Request Body**:
```json
{
  "shortened": "mylink",      // Optional: Custom short code (auto-generated if omitted)
  "targetUrl": "https://example.com"  // Required: Destination URL
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "message": "Link created/updated successfully",
  "data": {
    "shortened": "mylink",
    "targetUrl": "https://example.com",
    "visitCount": 0,
    "trackingEnabled": true,       // Analytics tracking status
    "notificationEnabled": true,   // Push notification status
    "createdAt": "2024-01-01T12:00:00.000Z",
    "shortUrl": "https://yourdomain.com/mylink"
  }
}
```

**Example using cURL**:
```bash
curl -X POST http://localhost:3000/api/links \
  -H "Authorization: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"targetUrl":"https://example.com"}'
```

**Example using JavaScript (fetch)**:
```javascript
fetch('http://localhost:3000/api/links', {
  method: 'POST',
  headers: {
    'Authorization': 'your-api-key-here',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    shortened: 'mylink',
    targetUrl: 'https://example.com'
  })
})
.then(res => res.json())
.then(data => console.log(data));
```

**Error Responses**:
- `400 Bad Request`: Missing targetUrl or reserved shortened key
- `401 Unauthorized`: Missing or invalid API key
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

---

### 2. Get All Links

Retrieves all shortened links, sorted by visit count (descending).

**Endpoint**: `GET /api/links`

**Headers**:
```http
Authorization: your-api-key-here
```

**Response** (200 OK):
```json
{
  "success": true,
  "count": 2,
  "data": [
    {
      "shortened": "popular",
      "targetUrl": "https://example.com",
      "visitCount": 150,
      "shortUrl": "http://localhost:3000/popular"
    },
    {
      "shortened": "mylink",
      "targetUrl": "https://another-example.com",
      "visitCount": 25,
      "shortUrl": "http://localhost:3000/mylink"
    }
  ]
}
```

**Example using cURL**:
```bash
curl -X GET http://localhost:3000/api/links \
  -H "Authorization: your-api-key-here"
```

**Example using JavaScript (fetch)**:
```javascript
fetch('http://localhost:3000/api/links', {
  headers: {
    'Authorization': 'your-api-key-here'
  }
})
.then(res => res.json())
.then(data => console.log(data));
```

---

### 3. Get a Single Link

Retrieves details of a specific shortened link.

**Endpoint**: `GET /api/links/:shortened`

**Headers**:
```http
Authorization: your-api-key-here
```

**URL Parameters**:
- `shortened`: The short code of the link

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "shortened": "mylink",
    "targetUrl": "https://example.com",
    "visitCount": 42,
    "shortUrl": "http://localhost:3000/mylink"
  }
}
```

**Example using cURL**:
```bash
curl -X GET http://localhost:3000/api/links/mylink \
  -H "Authorization: your-api-key-here"
```

**Example using JavaScript (fetch)**:
```javascript
fetch('http://localhost:3000/api/links/mylink', {
  headers: {
    'Authorization': 'your-api-key-here'
  }
})
.then(res => res.json())
.then(data => console.log(data));
```

**Error Responses**:
- `404 Not Found`: Shortened link not found
- `401 Unauthorized`: Missing or invalid API key

---

### 4. Update a Link

Updates the target URL of an existing shortened link.

**Endpoint**: `PUT /api/links/:shortened`

**Headers**:
```http
Authorization: your-api-key-here
Content-Type: application/json
```

**URL Parameters**:
- `shortened`: The short code of the link to update

**Request Body**:
```json
{
  "targetUrl": "https://new-example.com"  // Required: New destination URL
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Link updated successfully",
  "data": {
    "shortened": "mylink",
    "targetUrl": "https://new-example.com",
    "visitCount": 42,
    "shortUrl": "http://localhost:3000/mylink"
  }
}
```

**Example using cURL**:
```bash
curl -X PUT http://localhost:3000/api/links/mylink \
  -H "Authorization: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"targetUrl":"https://new-example.com"}'
```

**Example using JavaScript (fetch)**:
```javascript
fetch('http://localhost:3000/api/links/mylink', {
  method: 'PUT',
  headers: {
    'Authorization': 'your-api-key-here',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    targetUrl: 'https://new-example.com'
  })
})
.then(res => res.json())
.then(data => console.log(data));
```

**Error Responses**:
- `400 Bad Request`: Missing targetUrl
- `404 Not Found`: Shortened link not found
- `401 Unauthorized`: Missing or invalid API key

---

### 5. Delete a Link

Deletes a shortened link permanently.

**Endpoint**: `DELETE /api/links/:shortened`

**Headers**:
```http
Authorization: your-api-key-here
```

**URL Parameters**:
- `shortened`: The short code of the link to delete

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Link deleted successfully",
  "data": {
    "shortened": "mylink",
    "targetUrl": "https://example.com",
    "visitCount": 42
  }
}
```

**Example using cURL**:
```bash
curl -X DELETE http://localhost:3000/api/links/mylink \
  -H "Authorization: your-api-key-here"
```

**Example using JavaScript (fetch)**:
```javascript
fetch('http://localhost:3000/api/links/mylink', {
  method: 'DELETE',
  headers: {
    'Authorization': 'your-api-key-here'
  }
})
.then(res => res.json())
.then(data => console.log(data));
```

**Error Responses**:
- `404 Not Found`: Shortened link not found
- `401 Unauthorized`: Missing or invalid API key

---

## 📊 Analytics & Tracking Features

### Link Analytics Overview
Each shortened link automatically collects comprehensive analytics data including:

- **🗺️ Geographic Data**: Country, region, city, coordinates
- **💻 Device Information**: Browser, OS, device type, model
- **🔄 User Behavior**: Referrer source, language preferences
- **🤖 Bot Detection**: Automatic filtering of automated traffic
- **⏰ Temporal Tracking**: Visit timestamps and patterns

### Privacy & Control
- **Per-link tracking toggle**: Enable/disable analytics for individual links
- **Notification controls**: Toggle real-time click notifications
- **IP handling**: Secure IP address processing with geographic resolution
- **GDPR compliance**: Data retention and deletion controls

### Accessing Analytics Data
Analytics data is primarily accessible through the admin dashboard at `/admin/track/:shortCode`. The tracking data includes:

```json
{
  "link": {
    "shortened": "example",
    "targetUrl": "https://example.com", 
    "visitCount": 150,
    "trackingEnabled": true,
    "notificationEnabled": true
  },
  "tracking": {
    "visits": [{
      "visitNumber": 1,
      "timestamp": "2024-01-01T12:00:00.000Z",
      "ipAddress": "192.168.1.1",
      "geographic": {
        "country": "US",
        "region": "CA", 
        "city": "San Francisco",
        "coordinates": [37.7749, -122.4194]
      },
      "userAgent": {
        "browser": { "name": "Chrome", "version": "120.0" },
        "os": { "name": "Windows", "version": "10" },
        "device": { "type": "desktop", "model": null }
      },
      "isBot": false,
      "referrer": "https://google.com",
      "acceptLanguage": "en-US,en;q=0.9"
    }]
  }
}
```

---

## 🔔 Push Notifications

### Real-time Click Alerts
LinkShortener supports optional push notifications via [ntfy.sh](https://ntfy.sh) for real-time click alerts.

### Setup Instructions
1. **Set up ntfy topic**:
```env
NTFY_TOPIC=your-unique-topic-name
```

2. **Subscribe on mobile**: Download ntfy app and subscribe to your topic
3. **Configure per link**: Enable/disable notifications for individual links via admin dashboard

### Notification Content
When a link is clicked, you receive:
- **Title**: "Click Detected"  
- **Message**: Target URL information
- **Action Button**: Direct link to tracking dashboard
- **Timestamp**: When the click occurred

### Privacy Considerations
- Notifications only include the target URL, no visitor data
- Can be toggled per link for granular control
- No data is sent to ntfy servers beyond basic notification content

---

## 🛡️ Advanced Security Features

### Input Validation
- **URL validation**: Target URLs are validated and sanitized
- **Payload limits**: Request bodies limited to 10KB
- **MongoDB injection protection**: All inputs sanitized using express-mongo-sanitize
- **XSS prevention**: Output encoding and secure headers

### Reserved Keywords
Protected system paths that cannot be used as short codes:
- `admin` - Admin dashboard access
- `api` - API endpoints namespace  
- `track` - Analytics tracking routes

### Security Headers
Production deployments include comprehensive security headers:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY  
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

---

## ⚡ Performance & Scalability

### Database Optimization
- **Indexed fields**: All query fields properly indexed
- **Connection pooling**: Optimized MongoDB connection management
- **Lean queries**: Minimal data transfer for API responses

### Caching Strategy
- **Static assets**: Browser caching with proper cache headers
- **API responses**: Conditional requests with ETags
- **Session management**: Efficient JWT-based authentication

### Monitoring & Logging
- **Structured logging**: JSON-formatted logs with Pino
- **Request tracking**: Unique request IDs for debugging
- **Performance metrics**: Response time tracking
- **Error aggregation**: Comprehensive error details

---

## 🔧 Advanced Configuration

### Environment Variables Reference
```env
# Core System
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/db
API_KEY=32-character-hex-string
JWT_SECRET=secure-jwt-signing-key
PORT=3000

# Security
ADMIN_PASSWORD_HASH=bcrypt-hashed-password
CSRF_SECRET=csrf-protection-secret
COOKIE_PARSER_SECRET=cookie-signing-secret

# Features  
DOMAIN_URL=yourdomain.com
NTFY_TOPIC=your-notification-topic
LOG_LEVEL=info
NODE_ENV=production
```

### Production Checklist
- ✅ Generate secure, random secrets for all keys
- ✅ Use HTTPS in production environments
- ✅ Configure proper CORS policies
- ✅ Set up database backups and monitoring
- ✅ Implement log rotation and archival
- ✅ Configure reverse proxy with rate limiting
- ✅ Set up health check endpoints
- ✅ Enable database connection pooling

---

## 🧪 Testing & Validation

### API Testing Examples

**Health Check**:
```bash
curl -I https://yourdomain.com/
# Should return: 200 OK
```

**Rate Limit Testing**:
```bash
# Test rate limiting
for i in {1..60}; do
  curl -X GET https://yourdomain.com/api/links \
    -H "Authorization: your-api-key" \
    -w "%{http_code}\n" -o /dev/null -s
done
```

**Load Testing**:
```bash
# Using Apache Bench (ab)
ab -n 1000 -c 10 -H "Authorization: your-api-key" \
  https://yourdomain.com/api/links
```

### Validation Scripts
```javascript
// Validate API key functionality
const testApiIntegration = async () => {
  const baseUrl = 'https://yourdomain.com';
  const apiKey = 'your-api-key';
  
  // Test create, read, update, delete
  const createResp = await fetch(`${baseUrl}/api/links`, {
    method: 'POST',
    headers: {
      'Authorization': apiKey,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      shortened: 'test-' + Date.now(),
      targetUrl: 'https://example.com'  
    })
  });
  
  console.log('Create:', createResp.status);
  const link = await createResp.json();
  
  // Continue with other operations...
};
```

---

## 📚 Error Responses

All error responses follow this format:

```json
{
  "error": "Error Type",
  "message": "Detailed error message"
}
```

### Common Error Codes

| Status Code | Error Type | Description |
|------------|------------|-------------|
| 400 | Bad Request | Invalid or missing required fields |
| 401 | Unauthorized | Missing or invalid API key |
| 404 | Not Found | Resource not found |
| 413 | Payload Too Large | Request body exceeds 10KB limit |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |

---

## Reserved Keywords

The following shortened codes are reserved and cannot be used:
- `admin`
- `api`

Attempting to create links with these codes will result in a `400 Bad Request` error.

---

## Request Size Limits

All requests are limited to **10KB** to prevent abuse. Requests exceeding this limit will receive a `413 Payload Too Large` error.

---

## Complete Example: Creating and Managing a Link

```javascript
const API_KEY = 'your-api-key-here';
const BASE_URL = 'http://localhost:3000';

// 1. Create a link
async function createLink() {
  const response = await fetch(`${BASE_URL}/api/links`, {
    method: 'POST',
    headers: {
      'Authorization': API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      shortened: 'docs',
      targetUrl: 'https://github.com/dhivijit/LinkShortner'
    })
  });
  const data = await response.json();
  console.log('Created:', data);
  return data.data.shortened;
}

// 2. Get the link details
async function getLink(shortened) {
  const response = await fetch(`${BASE_URL}/api/links/${shortened}`, {
    headers: { 'Authorization': API_KEY }
  });
  const data = await response.json();
  console.log('Link details:', data);
}

// 3. Update the link
async function updateLink(shortened) {
  const response = await fetch(`${BASE_URL}/api/links/${shortened}`, {
    method: 'PUT',
    headers: {
      'Authorization': API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      targetUrl: 'https://github.com/dhivijit/LinkShortner/blob/main/README.md'
    })
  });
  const data = await response.json();
  console.log('Updated:', data);
}

// 4. Get all links
async function getAllLinks() {
  const response = await fetch(`${BASE_URL}/api/links`, {
    headers: { 'Authorization': API_KEY }
  });
  const data = await response.json();
  console.log('All links:', data);
}

// 5. Delete the link
async function deleteLink(shortened) {
  const response = await fetch(`${BASE_URL}/api/links/${shortened}`, {
    method: 'DELETE',
    headers: { 'Authorization': API_KEY }
  });
  const data = await response.json();
  console.log('Deleted:', data);
}

// Run all operations
(async () => {
  const shortened = await createLink();
  await getLink(shortened);
  await updateLink(shortened);
  await getAllLinks();
  await deleteLink(shortened);
})();
```

---

## Python Example

```python
import requests

API_KEY = 'your-api-key-here'
BASE_URL = 'http://localhost:3000'
HEADERS = {'Authorization': API_KEY}

# Create a link
def create_link():
    response = requests.post(
        f'{BASE_URL}/api/links',
        headers={**HEADERS, 'Content-Type': 'application/json'},
        json={'shortened': 'python', 'targetUrl': 'https://python.org'}
    )
    return response.json()

# Get all links
def get_all_links():
    response = requests.get(f'{BASE_URL}/api/links', headers=HEADERS)
    return response.json()

# Get single link
def get_link(shortened):
    response = requests.get(f'{BASE_URL}/api/links/{shortened}', headers=HEADERS)
    return response.json()

# Update link
def update_link(shortened, new_url):
    response = requests.put(
        f'{BASE_URL}/api/links/{shortened}',
        headers={**HEADERS, 'Content-Type': 'application/json'},
        json={'targetUrl': new_url}
    )
    return response.json()

# Delete link
def delete_link(shortened):
    response = requests.delete(f'{BASE_URL}/api/links/{shortened}', headers=HEADERS)
    return response.json()

# Example usage
if __name__ == '__main__':
    # Create
    result = create_link()
    print('Created:', result)
    
    # Get all
    links = get_all_links()
    print('All links:', links)
    
    # Update
    updated = update_link('python', 'https://docs.python.org')
    print('Updated:', updated)
    
    # Delete
    deleted = delete_link('python')
    print('Deleted:', deleted)
```

---

## Security Best Practices

1. **Keep your API key secret**: Never commit it to version control or share it publicly
2. **Use HTTPS in production**: Always use HTTPS to prevent API key interception
3. **Rotate API keys regularly**: Change your API key periodically for security
4. **Monitor API usage**: Check logs for suspicious activity
5. **Set appropriate rate limits**: Adjust rate limits based on your needs
6. **Use environment variables**: Store sensitive data like API keys in `.env` files

---

## Support

For issues or questions, please visit: https://github.com/dhivijit/LinkShortner
