# 🔗 LinkShortener

<div align="center">
  
  ![LinkShortener](https://img.shields.io/badge/LinkShortener-v1.0.0-blue?style=for-the-badge)
  ![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white)
  ![Express.js](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge)
  ![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)
  
  **A powerful, secure, and feature-rich link shortening service built for personal and professional use.**
  
  [🚀 Quick Start](#-quick-start) • [✨ Features](#-features) • [📱 Demo](#-demo) • [🔌 API](#-api-documentation) • [🛠️ Deployment](#️-deployment)
  
</div>

---

## ✨ Features

### 🎯 **Core Functionality**
- **🔗 Link Shortening**: Create custom or auto-generated short URLs
- **📊 Advanced Analytics**: Detailed click tracking with geographic data, device info, and user behavior
- **🎛️ Admin Dashboard**: Beautiful, responsive web interface for link management
- **🔄 Dynamic Updates**: Change target URLs without breaking existing short links
- **📱 QR Code Generation**: Built-in QR codes for easy mobile sharing
- **🔔 Push Notifications**: Optional real-time click notifications via ntfy.sh

### 🛡️ **Enterprise-Grade Security**
- **🔐 JWT Authentication**: Secure session management
- **🛡️ CSRF Protection**: Cross-site request forgery prevention
- **⚡ Rate Limiting**: Multi-tier protection against abuse
- **🧹 Input Sanitization**: MongoDB injection prevention
- **🤖 Bot Detection**: Automatic filtering of non-human traffic
- **📝 Audit Logging**: Comprehensive request logging with Pino

### 🔌 **Developer Experience**
- **🚀 REST API**: Complete CRUD operations with API key authentication
- **📖 Comprehensive Documentation**: Detailed API docs with examples
- **⚡ Production Ready**: HTTPS redirects, security headers, optimized for deployment
- **🔧 Environment Configuration**: Flexible setup with environment variables
- **📱 Responsive Design**: Bootstrap-based UI that works on all devices

---

## 🚀 Quick Start

### Prerequisites
- **Node.js** (v16+ recommended)
- **MongoDB** (Atlas or self-hosted)

### Installation

```bash
# Clone the repository
git clone https://github.com/dhivijit/LinkShortner.git
cd LinkShortner

# Install dependencies
npm install

# Create environment file
cp .env.example .env
# Edit .env with your configuration

# Generate admin password hash
node -e "console.log(require('bcrypt').hashSync('your-admin-password', 12))"

# Start the application
npm start          # Production
npm run dev        # Development (with auto-reload)
```

### 🔧 Environment Configuration

Create a `.env` file with the following variables:

```env
# Required
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/linkshortener
ADMIN_PASSWORD_HASH=your-bcrypt-hashed-password
API_KEY=your-secret-api-key
JWT_SECRET=your-jwt-secret-key
CSRF_SECRET=your-csrf-secret
COOKIE_PARSER_SECRET=your-cookie-secret

# Optional
PORT=3000
DOMAIN_URL=yourdomain.com
NTFY_TOPIC=your-ntfy-topic          # For push notifications
LOG_LEVEL=info                      # debug, info, warn, error
NODE_ENV=production                 # development, production
```

---

## 📱 Demo

### Admin Dashboard
*Beautiful, responsive admin interface with real-time statistics and comprehensive link management*

![Admin Dashboard](docs/dashboard.png)

### Click Analytics
*Detailed tracking with geographic data, device information, and visit patterns*

![Click Analytics](docs/trackinganalytics.png)

---

## 🎛️ Admin Interface

### Access the Dashboard
1. Navigate to `/admin/login`
2. Enter your admin password
3. Manage links from the intuitive dashboard

### Dashboard Features
- **📊 Real-time Statistics**: Total links, visits, and active links
- **🔗 Link Management**: Create, edit, delete, and track links
- **📈 Click Analytics**: Detailed visitor insights and geographic data
- **⚙️ Settings Control**: Toggle tracking and notifications per link
- **📱 QR Codes**: Generate QR codes for any short link
- **📋 Quick Actions**: Copy links, view stats, manage settings

---

## 🔌 API Documentation

### Authentication
All API endpoints require authentication using your API key in the `Authorization` header:

```bash
Authorization: your-api-key-here
```

### Quick API Examples

**Create a short link:**
```bash
curl -X POST http://localhost:3000/api/links \
  -H "Authorization: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://example.com", "shortened": "example"}'
```

**Get all links:**
```bash
curl -X GET http://localhost:3000/api/links \
  -H "Authorization: your-api-key"
```

**Update a link:**
```bash
curl -X PUT http://localhost:3000/api/links/example \
  -H "Authorization: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://new-example.com"}'
```

> 📖 **Complete API Documentation**: See [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) for detailed endpoints, examples, and error handling.

---

## 🏗️ Architecture

### Tech Stack
- **Backend**: Node.js + Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: JWT + bcrypt password hashing
- **Frontend**: EJS templates + Bootstrap 4
- **Security**: Express Rate Limit, CSRF protection, input sanitization
- **Logging**: Pino for structured, high-performance logging
- **Analytics**: Custom tracking with geographic IP resolution

### Data Models

#### Link Schema
```javascript
{
  shortened: String (unique),     // Short code
  targetUrl: String,              // Destination URL
  visitCount: Number,             // Total clicks
  trackingEnabled: Boolean,       // Analytics toggle
  notificationEnabled: Boolean,   // Push notification toggle
  createdAt: Date                 // Creation timestamp
}
```

#### Tracking Schema (per link)
```javascript
{
  shortened: String,              // Reference to link
  targetUrl: String,              // Current target
  visits: [{                      // Array of visit records
    visitNumber: Number,
    timestamp: Date,
    ipAddress: String,
    geographic: { country, region, city, coordinates },
    userAgent: { browser, os, device, engine },
    isBot: Boolean,
    referrer: String,
    acceptLanguage: String
  }]
}
```

---

## 🛡️ Security Features

### Multi-Layer Protection
- **🔐 JWT Authentication**: Secure session management with HTTP-only cookies
- **🛡️ CSRF Protection**: Prevents cross-site request forgery attacks
- **⚡ Rate Limiting**: 
  - Global: 100 requests/15min per IP
  - API: 50 requests/15min per API key
  - Auth: 5 attempts/15min per IP
- **🧹 Input Sanitization**: MongoDB injection prevention
- **📝 Request Validation**: Payload size limits and content validation
- **🔒 Production Security**: HTTPS enforcement, secure headers

### Best Practices Implemented
- Encrypted password storage with bcrypt
- Secure cookie configuration
- Environment variable configuration
- Comprehensive error handling
- Structured logging for security monitoring

---

## 🛠️ Deployment

### Vercel (Recommended)
1. Fork this repository
2. Connect to Vercel
3. Set environment variables in Vercel dashboard
4. Deploy automatically

### Traditional VPS
1. Clone repository on server
2. Set up environment variables
3. Use PM2 or similar for process management
4. Configure reverse proxy (nginx/Apache)
5. Set up SSL certificate

### Environment Checklist
- ✅ Set all required environment variables
- ✅ Configure MongoDB connection
- ✅ Generate secure secrets (API keys, JWT secret)
- ✅ Set up HTTPS in production
- ✅ Configure domain URL
- ✅ (Optional) Set up ntfy.sh for notifications

---

## 📊 Analytics & Tracking

### What We Track
- **🗺️ Geographic Data**: Country, region, city, coordinates
- **💻 Device Information**: Browser, OS, device type
- **🔄 User Behavior**: Referrer, language preferences, visit patterns
- **🕒 Temporal Data**: Visit timestamps, return visitor analysis
- **🤖 Bot Detection**: Automatic filtering of non-human traffic

### Tracking Features
- **⚙️ Tracking Toggle**: Enable/disable tracking per link
- **🔔 Notification Control**: Enable/disable click notifications per link

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **🐛 Report Bugs**: Open an issue with details
2. **💡 Feature Requests**: Suggest new functionality
3. **🔧 Code Contributions**: Fork, branch, code, test, PR
4. **📖 Documentation**: Improve docs and examples
5. **🧪 Testing**: Add tests and improve coverage

### Development Setup
```bash
# Clone and setup
npm install
npm run dev

```

---

## 📄 License

This project is licensed under the ISC License.

---

## 🆘 Support

- **📚 Documentation**: Check [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md)
- **🐛 Issues**: [GitHub Issues](https://github.com/dhivijit/LinkShortner/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/dhivijit/LinkShortner/discussions)
- **📧 Email**: Create an issue for direct contact

---

<div align="center">
  
  **⭐ Star this repository if you find it useful! ⭐**
  
  Made with ❤️ by [dhivijit](https://github.com/dhivijit)
  
  [🏠 Home](https://github.com/dhivijit/LinkShortner) • [📖 Docs](docs/API_DOCUMENTATION.md) • [🐛 Issues](https://github.com/dhivijit/LinkShortner/issues) • [🚀 Releases](https://github.com/dhivijit/LinkShortner/releases)
  
</div>
