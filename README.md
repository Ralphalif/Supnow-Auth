# Supnow Authentication Service

A secure authentication service built with ASP.NET Core 8.0, providing user authentication and authorization features for the Supnow platform.

## Features

- User registration and login
- JWT token-based authentication
- Refresh token mechanism
- Apple Sign In integration
- Two-factor authentication support
- Account lockout protection
- Password strength validation
- Email verification
- Message bus integration for event publishing

## Prerequisites

- .NET 8.0 SDK
- PostgreSQL 15+
- RabbitMQ
- SendGrid account (for email services)
- Apple Developer Account (for Apple Sign In)

## Configuration

### 1. Database Setup

```bash
# Create the database
createdb supnow_auth

# Apply migrations
dotnet ef database update
```

### 2. Environment Configuration

Update `appsettings.json` with your configuration:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=supnow_auth;Username=postgres;Password=your_password"
  },
  "RabbitMQ": {
    "Host": "localhost",
    "Port": "5672",
    "Username": "guest",
    "Password": "guest"
  },
  "Jwt": {
    "Key": "your-super-secret-key-with-at-least-32-characters",
    "Issuer": "supnow-auth",
    "Audience": "supnow-clients"
  },
  "SmtpSettings": {
    "Host": "smtp.sendgrid.net",
    "Port": "587",
    "Username": "apikey",
    "Password": "your-sendgrid-api-key-here",
    "FromEmail": "noreply@supnow.com",
    "FromName": "Supnow Auth"
  },
  "Authentication": {
    "Apple": {
      "ClientId": "your.apple.client.id",
      "TeamId": "your.apple.team.id",
      "KeyId": "your.apple.key.id",
      "PrivateKey": "your.apple.private.key"
    }
  }
}
```

### 3. Apple Sign In Setup

1. Register your app in the Apple Developer Console
2. Generate a Services ID and configure Sign In with Apple
3. Create a Key in the Apple Developer Console
4. Update the Apple authentication settings in `appsettings.json`

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login with email and password
- `POST /api/auth/apple` - Sign in with Apple
- `POST /api/auth/refresh-token` - Refresh an expired JWT token
- `POST /api/auth/revoke` - Revoke a refresh token

### Request Examples

#### Register
```json
POST /api/auth/register
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "confirmPassword": "SecurePassword123!"
}
```

#### Login
```json
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

#### Apple Sign In
```json
POST /api/auth/apple
{
  "idToken": "apple.id.token",
  "authorizationCode": "apple.auth.code",
  "name": "User Name",  // Optional, only on first sign in
  "email": "user@example.com"  // Optional, only on first sign in
}
```

## Security Features

- Password Requirements:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character
- Account lockout after 5 failed login attempts (15-minute lockout)
- Secure JWT token generation and validation
- Email verification for new accounts
- Apple ID token validation
- Protection against timing attacks
- HTTPS enforcement
- Secure headers middleware

## Development

```bash
# Restore dependencies
dotnet restore

# Run the application
dotnet run --project src/Supnow-Auth/Supnow-Auth.csproj

# Run tests
dotnet test
```

## Docker Support

```bash
# Build the container
docker build -t supnow-auth .

# Run with Docker Compose
docker-compose up
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.