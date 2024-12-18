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
- Comprehensive test coverage

## Project Structure

```
├── src/
│   └── Supnow-Auth/
│       ├── Controllers/
│       │   └── AuthController.cs     # Authentication endpoints
│       ├── Services/
│       │   ├── AuthService.cs       # Authentication business logic
│       │   └── IEmailService.cs     # Email service interface
│       ├── Models/
│       │   ├── ApplicationUser.cs   # User entity model
│       │   ├── AuthModels.cs       # Request/Response models
│       │   └── ErrorResponse.cs    # Standard error response model
│       ├── Data/
│       │   └── ApplicationDbContext.cs # Database context
│       └── Middleware/
│           └── SecurityHeadersMiddleware.cs  # Security headers
├── tests/
│   └── Supnow-Auth.Tests/
│       ├── AuthControllerTests.cs   # Controller unit tests
│       └── AuthServiceTests.cs      # Service unit tests
├── Dockerfile
└── docker-compose.yml
```

## Prerequisites

- .NET Core 8.0
- Docker and Docker Compose
- PostgreSQL (containerized or local)
- SMTP server for email verification

## Development

### Local Setup

1. Clone the repository
2. Update configuration in appsettings.json
3. Run with Docker Compose or locally

### Running Locally

```bash
dotnet restore
dotnet build
dotnet run --project src/Supnow-Auth/Supnow-Auth.csproj
```

### Running Tests

```bash
# Run all tests
dotnet test

# Run tests with coverage
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=lcov

# Run specific test project
dotnet test tests/Supnow-Auth.Tests/Supnow-Auth.Tests.csproj
```

### Docker Setup

```bash
# Build and start the containers
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop containers
docker-compose down
```

### Data Persistence

The PostgreSQL data is persisted in a local directory at `./data/postgres`. This ensures:
- Data survives container restarts and removals
- Easy access to database files for backup
- Direct inspection of data files when needed

```bash
# To completely reset the database (warning: destroys all data)
rm -rf ./data/postgres/*
```

The services will be available at:
- API: http://localhost:5002
- Database: localhost:5433

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

Response:
```json
{
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "random-refresh-token",
    "expiresIn": 3600,
    "requiresTwoFactor": false
}
```

Error Response:
```json
{
    "message": "Registration failed"
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

## Testing

The project includes comprehensive unit tests for both controllers and services:

### Controller Tests
- Registration validation
- Login authentication
- Token refresh
- Error handling
- Response type validation

### Service Tests
- User registration logic
- Login validation
- Token generation and validation
- Password strength validation
- Account lockout functionality

### Running Tests with Coverage

```bash
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=lcov /p:CoverletOutput=./lcov.info
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
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