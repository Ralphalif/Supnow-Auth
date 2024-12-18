# .NET Core Authentication Service

A secure authentication service implementation using .NET Core 8.0, featuring JWT tokens, refresh tokens, and various security measures.

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
- Docker support
- PostgreSQL database

## Prerequisites

- .NET Core 8.0
- Docker and Docker Compose
- PostgreSQL (containerized or local)
- SMTP server for email verification

## Project Structure

```
├── Controllers/
│   └── AuthController.cs        # Authentication endpoints
├── Services/
│   ├── AuthService.cs          # Authentication business logic
│   └── IEmailService.cs        # Email service interface
├── Models/
│   ├── ApplicationUser.cs      # User entity model
│   └── AuthModels.cs          # Request/Response models
├── Data/
│   └── ApplicationDbContext.cs # Database context
├── Middleware/
│   └── SecurityHeadersMiddleware.cs  # Security headers
└── Program.cs                  # Application configuration
```

## Docker Setup

### 1. Build and Run with Docker Compose

```bash
# Build and start the containers
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop containers
docker-compose down
```

The services will be available at:
- API: http://localhost:5002 and https://localhost:5003
- Database: localhost:5433

### 2. Configuration

Update `appsettings.json` for your environment:

```json
{
  "Jwt": {
    "Key": "Your-Very-Long-And-Secure-Secret-Key-Here",
    "Issuer": "YourAppName",
    "Audience": "YourAppUsers"
  },
  "ConnectionStrings": {
    "DefaultConnection": "Host=auth-db;Database=supnow_auth;Username=postgres;Password=your_password"
  },
  "AllowedOrigins": [
    "http://localhost:3000",
    "http://localhost:5002",
    "https://localhost:5003"
  ]
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

## Development

### Local Setup

1. Clone the repository
2. Update configuration in appsettings.json
3. Run with Docker Compose or locally

### Running Locally

```bash
dotnet restore
dotnet run
```

### Database Migrations

```bash
# Create migration
dotnet ef migrations add InitialCreate -o Data/Migrations

# Apply migration
dotnet ef database update
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License

## Support

For support:
1. Check existing issues
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected behavior
   - Actual behavior