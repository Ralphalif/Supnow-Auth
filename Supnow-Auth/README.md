# .NET Core Authentication Service

A secure authentication service implementation using .NET Core, featuring JWT tokens, refresh tokens, and various security measures.

## Features

- JWT token-based authentication
- Refresh token mechanism
- Account lockout protection
- Password strength validation
- Two-factor authentication support
- Rate limiting
- Email verification
- Secure password hashing
- Security headers
- CORS protection
- HTTPS enforcement

## Prerequisites

- .NET Core 6.0 or later
- SQL Server (or your preferred database)
- SMTP server for email verification

## Project Structure

```
├── Controllers/
│   └── AuthController.cs        # Authentication endpoints
├── Services/
│   └── AuthService.cs          # Authentication business logic
├── Models/
│   ├── ApplicationUser.cs      # User entity model
│   └── AuthModels.cs          # Request/Response models
├── Middleware/
│   └── SecurityHeadersMiddleware.cs  # Security headers
└── Program.cs                  # Application configuration
```

## Setup and Configuration

### 1. Database Setup

PostgreSQL is recommended for this authentication service due to its:
- Strong security features
- ACID compliance
- JSON support (useful for storing user metadata)
- Excellent performance with indexing
- Built-in UUID generation
- Row-level security

Add the following to your `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=auth_service;Username=your_username;Password=your_password"
  }
}
```

### 2. JWT Configuration

Configure JWT settings in `appsettings.json`:

```json
{
  "Jwt": {
    "Key": "Your-Very-Long-And-Secure-Secret-Key-Here",
    "Issuer": "YourAppName",
    "Audience": "YourAppUsers"
  }
}
```

### 3. Email Service Configuration

```json
{
  "EmailSettings": {
    "SmtpServer": "smtp.example.com",
    "SmtpPort": 587,
    "SmtpUsername": "your-email@example.com",
    "SmtpPassword": "your-password"
  }
}
```

## Security Features

### Authentication Flow
1. User registers or logs in
2. System validates credentials
3. JWT token and refresh token are generated
4. Tokens are returned to client
5. Client includes JWT in subsequent requests

### Account Protection
- Account lockout after 5 failed attempts
- 15-minute lockout duration
- Brute force protection with random delays
- IP tracking for login attempts
- Rate limiting on authentication endpoints

### Password Security
- Minimum length: 8 characters
- Must contain:
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters
- Secure hashing using ASP.NET Core Identity

## API Endpoints

### Authentication Endpoints

#### Register New User
```http
POST /api/auth/register
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "confirmPassword": "SecurePass123!"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePass123!"
}
```

#### Refresh Token
```http
POST /api/auth/refresh-token
Content-Type: application/json

{
    "refreshToken": "your-refresh-token"
}
```

### Response Format
```json
{
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "random-refresh-token",
    "expiresIn": 3600,
    "requiresTwoFactor": false
}
```

## Implementation Guide

### 1. Protecting Routes
```csharp
[Authorize]
[ApiController]
[Route("api/[controller]")]
public class SecuredController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok("This is a protected endpoint");
    }
}
```

### 2. Client Implementation
```javascript
// Add token to requests
const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
};

// Make authenticated request
fetch('api/secured', {
    method: 'GET',
    headers: headers
});
```

## Security Best Practices

1. **Environment Security**
   - Use HTTPS in production
   - Enable HSTS
   - Configure proper CORS policies

2. **Token Security**
   - Short JWT expiration times
   - Secure token storage
   - Regular token rotation

3. **Application Security**
   - Input validation
   - Rate limiting
   - Security headers
   - Error handling

4. **Monitoring**
   - Login attempt logging
   - Security event tracking
   - Regular audit logs

## Error Handling

The service uses standard HTTP status codes:

- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 429: Too Many Requests
- 500: Internal Server Error

Each error response includes:
```json
{
    "message": "Error description",
    "errorCode": "ERROR_CODE",
    "details": ["Additional error details if any"]
}
```

## Logging

The service implements comprehensive logging:

```csharp
// Security events
_logger.LogWarning($"Failed login attempt for user {request.Email}");
_logger.LogInformation($"Successful login for user {user.Email} from IP {GetUserIp()}");
_logger.LogError($"Account locked for user {request.Email} due to multiple failed attempts");
```

## Testing

Run the included tests:

```bash
dotnet test
```

Key test areas:
- Authentication flow
- Token validation
- Password validation
- Rate limiting
- Security headers

## Deployment

1. **Environment Variables**
   - Move sensitive data to environment variables
   - Use different settings for each environment

2. **SSL/TLS**
   - Install valid SSL certificate
   - Configure HTTPS redirection
   - Enable HSTS in production

3. **Database**
   - Run migrations
   - Backup user data
   - Secure connection strings

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Coding Standards
- Follow C# coding conventions
- Include XML documentation
- Add appropriate unit tests
- Update README if needed

## Support

For support, please:
1. Check existing issues
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected behavior
   - Actual behavior

## License

This project is licensed under the MIT License - see the LICENSE file for details

## Acknowledgments

- ASP.NET Core Identity
- JWT Authentication
- Microsoft.Extensions.Logging
- Entity Framework Core