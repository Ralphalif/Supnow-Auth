using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Security.Authentication;
using Microsoft.EntityFrameworkCore;
using Models;

namespace Services;

public class AuthService(
    IConfiguration configuration,
    UserManager<ApplicationUser> userManager,
    IEmailService emailService,
    IMessageBusService messageBus,
    ILogger<AuthService> logger) : IAuthService
{
    private readonly IConfiguration _configuration = configuration;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly IEmailService _emailService = emailService;
    private readonly IMessageBusService _messageBus = messageBus;
    private readonly ILogger<AuthService> _logger = logger;

    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            await Task.Delay(Random.Shared.Next(100, 500));
            throw new AuthenticationException("Invalid credentials");
        }

        if (user.IsLockedOut && user.LockoutEnd > DateTime.UtcNow)
        {
            throw new AuthenticationException("Account is temporarily locked. Please try again later.");
        }

        if (!await _userManager.CheckPasswordAsync(user, request.Password))
        {
            user.FailedLoginAttempts++;
            user.LastLoginAttempt = DateTime.UtcNow;

            if (user.FailedLoginAttempts >= 5)
            {
                user.IsLockedOut = true;
                user.LockoutEnd = DateTime.UtcNow.AddMinutes(15);
                _logger.LogWarning($"Account locked for user {request.Email} due to multiple failed attempts");
            }

            await _userManager.UpdateAsync(user);
            throw new AuthenticationException("Invalid credentials");
        }

        user.FailedLoginAttempts = 0;
        user.LastLoginAttempt = DateTime.UtcNow;

        var token = GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _userManager.UpdateAsync(user);

        _logger.LogInformation($"Successful login for user {user.Email} from IP {GetUserIp()}");

        return new AuthResponse
        {
            Token = token,
            RefreshToken = refreshToken,
            ExpiresIn = 3600,
            RequiresTwoFactor = user.TwoFactorEnabled
        };
    }

    public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
    {
        if (await _userManager.FindByEmailAsync(request.Email) != null)
        {
            throw new InvalidOperationException("Email already registered");
        }

        if (!IsPasswordStrong(request.Password))
        {
            throw new InvalidOperationException("Password does not meet security requirements");
        }

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            EmailConfirmed = false
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        _messageBus.PublishUserRegistered(user.Id, user.Email);

        _logger.LogInformation($"New user registered: {user.Email}");

        return await LoginAsync(new LoginRequest
        {
            Email = request.Email,
            Password = request.Password
        });
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        if (string.IsNullOrEmpty(token))
            return false;

        var key = _configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT key not configured");
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key)),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidAudience = _configuration["Jwt:Audience"],
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            tokenHandler.ValidateToken(token, validationParameters, out _);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsPasswordStrong(string password)
    {
        return password.Length >= 8 &&
               password.Any(char.IsUpper) &&
               password.Any(char.IsLower) &&
               password.Any(char.IsDigit) &&
               password.Any(c => !char.IsLetterOrDigit(c));
    }

    private static string GetUserIp()
    {
        return "0.0.0.0";
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var key = _configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT key not configured");
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? throw new InvalidOperationException("User email not set")),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public async Task<AuthResponse> RefreshTokenAsync(string refreshToken)
    {
        var user = await _userManager.Users
            .FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);

        if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            throw new AuthenticationException("Invalid refresh token");
        }

        var token = GenerateJwtToken(user);
        var newRefreshToken = GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _userManager.UpdateAsync(user);

        return new AuthResponse
        {
            Token = token,
            RefreshToken = newRefreshToken,
            ExpiresIn = 3600,
            RequiresTwoFactor = user.TwoFactorEnabled
        };
    }

    public async Task<bool> RevokeTokenAsync(string refreshToken)
    {
        var user = await _userManager.Users
            .FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);

        if (user == null)
            return false;

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return true;
    }

    public async Task<AuthResponse> SignInWithAppleAsync(AppleAuthRequest request)
    {
        // Log the incoming request
        _logger.LogInformation("Starting Apple Sign In process");
        _logger.LogInformation($"ID Token present: {!string.IsNullOrEmpty(request.IdToken)}");
        _logger.LogInformation($"Authorization Code present: {!string.IsNullOrEmpty(request.AuthorizationCode)}");

        // Validate the Apple ID token
        var appleConfig = _configuration.GetSection("Authentication:Apple").Get<Dictionary<string, string>>();
        _logger.LogWarning($"Apple Config - ClientId: {appleConfig["ClientId"]}");

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://appleid.apple.com",
            ValidateAudience = true,
            ValidAudiences = new[] { appleConfig["ClientId"], "Nanrepo.SupNow-xCode" },
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = await GetAppleSigningKey(request),
            ValidateLifetime = true
        };

        _logger.LogWarning($"Validation Parameters - Valid Audiences: {string.Join(", ", validationParameters.ValidAudiences)}");

        ClaimsPrincipal validatedToken;
        try
        {
            var handler = new JwtSecurityTokenHandler();
            // Log the token details before validation
            var jwtToken = handler.ReadJwtToken(request.IdToken);
            _logger.LogWarning($"Token Audience: {string.Join(", ", jwtToken.Audiences)}");
            _logger.LogWarning($"Token Issuer: {jwtToken.Issuer}");
            _logger.LogWarning($"Token Subject: {jwtToken.Subject}");
            _logger.LogWarning($"All Token Claims: {string.Join(", ", jwtToken.Claims.Select(c => $"{c.Type}: {c.Value}"))}");

            validatedToken = handler.ValidateToken(request.IdToken, validationParameters, out _);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Apple ID token validation failed");
            _logger.LogError($"Validation Parameters: ValidAudiences = [{string.Join(", ", validationParameters.ValidAudiences)}], ValidIssuer = {validationParameters.ValidIssuer}");
            _logger.LogError($"Token raw value: {request.IdToken}");
            throw new AuthenticationException("Invalid Apple ID token");
        }

        var appleSubClaim = validatedToken.FindFirst(ClaimTypes.NameIdentifier)?.Value 
            ?? validatedToken.FindFirst("sub")?.Value;

        // Log all claims for debugging
        _logger.LogWarning($"Request Email: '{request.Email}'");
        _logger.LogWarning($"Claims Email: '{validatedToken.FindFirst(ClaimTypes.Email)?.Value ?? "null"}'");
        _logger.LogWarning($"Alt Email Claim: '{validatedToken.FindFirst("email")?.Value ?? "null"}'");

        // Handle email more carefully
        string? email = null;
        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            email = request.Email;
            _logger.LogWarning($"Using email from request: '{email}'");
        }
        else if (!string.IsNullOrWhiteSpace(validatedToken.FindFirst(ClaimTypes.Email)?.Value))
        {
            email = validatedToken.FindFirst(ClaimTypes.Email)?.Value;
            _logger.LogWarning($"Using email from ClaimTypes.Email: '{email}'");
        }
        else if (!string.IsNullOrWhiteSpace(validatedToken.FindFirst("email")?.Value))
        {
            email = validatedToken.FindFirst("email")?.Value;
            _logger.LogWarning($"Using email from 'email' claim: '{email}'");
        }

        if (string.IsNullOrEmpty(appleSubClaim))
        {
            throw new AuthenticationException("User ID not provided by Apple");
        }

        // Find user by Apple ID first
        var user = await _userManager.Users.FirstOrDefaultAsync(u => u.AppleUserId == appleSubClaim);
        _logger.LogWarning($"User lookup by Apple ID {appleSubClaim}: {(user != null ? "Found" : "Not found")}");

        if (user == null && !string.IsNullOrEmpty(email))
        {
            // If not found by Apple ID, try to find by email
            user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                // Update existing user with Apple ID
                user.AppleUserId = appleSubClaim;
                await _userManager.UpdateAsync(user);
                _logger.LogWarning($"Updated existing user with Apple ID: {user.Email}");
            }
        }

        if (user == null)
        {
            // Generate a temporary email using their Apple User ID
            var tempEmail = $"apple_{appleSubClaim}@supnow.temp";
            _logger.LogWarning($"Creating new user with temporary email: {tempEmail}");

            try 
            {
                user = new ApplicationUser
                {
                    UserName = tempEmail,
                    Email = tempEmail,
                    EmailConfirmed = true, // Mark as confirmed since we generated it
                    AppleUserId = appleSubClaim
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError($"Failed to create user: {errors}");
                    throw new InvalidOperationException($"Failed to create user: {errors}");
                }

                _messageBus.PublishUserRegistered(user.Id, tempEmail);
                _logger.LogWarning($"New user registered via Apple with temporary email: {tempEmail}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creating user with temp email '{tempEmail}'");
                throw;
            }
        }

        var token = GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _userManager.UpdateAsync(user);

        return new AuthResponse
        {
            Token = token,
            RefreshToken = refreshToken,
            ExpiresIn = 3600,
            RequiresTwoFactor = user.TwoFactorEnabled
        };
    }

    private async Task<SecurityKey> GetAppleSigningKey(AppleAuthRequest request)
    {
        using var client = new HttpClient();
        var response = await client.GetFromJsonAsync<AppleKeyResponse>("https://appleid.apple.com/auth/keys");
        if (response?.Keys == null || !response.Keys.Any())
        {
            throw new AuthenticationException("Unable to retrieve Apple signing keys");
        }

        // Read the token to get the kid
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(request.IdToken);
        var kid = jwtToken.Header.Kid;
        _logger.LogWarning($"Looking for key with kid: {kid}");

        // Find the matching key
        var key = response.Keys.FirstOrDefault(k => k.Kid == kid);
        if (key == null)
        {
            _logger.LogError($"No matching key found for kid: {kid}. Available keys: {string.Join(", ", response.Keys.Select(k => k.Kid))}");
            throw new AuthenticationException("No matching Apple signing key found");
        }

        _logger.LogWarning($"Found matching key: {key.Kid}");
        return new JsonWebKey
        {
            Kty = key.Kty,
            Kid = key.Kid,
            Use = key.Use,
            N = key.N,
            E = key.E,
            Alg = key.Alg
        };
    }
}

public class AppleKeyResponse
{
    public required List<AppleKey> Keys { get; set; }
}

public class AppleKey
{
    public required string Kty { get; set; }
    public required string Kid { get; set; }
    public required string Use { get; set; }
    public required string Alg { get; set; }
    public required string N { get; set; }
    public required string E { get; set; }
}