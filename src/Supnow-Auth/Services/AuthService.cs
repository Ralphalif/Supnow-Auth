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

        _messageBus.PublishUserRegistered(user.Id, user.UserName, user.Email);

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

    private static string GenerateFriendlyUsername()
    {
        var adjectives = new[] {
            "Happy", "Clever", "Brave", "Gentle", "Swift", "Bright", "Warm", "Cool", 
            "Noble", "Kind", "Wild", "Calm", "Bold", "Smart", "Fresh", "Wise",
            "Mighty", "Sunny", "Lucky", "Jolly", "Witty", "Proud", "Fancy", "Eager",
            "Lively", "Merry", "Cosmic", "Rapid", "Royal", "Magic", "Super", "Perky",
            "Shiny", "Mystic", "Crazy", "Funky", "Sweet", "Silly", "Quiet", "Sleepy",
            "Ninja", "Cyber", "Hyper", "Mega", "Ultra", "Epic", "Alpha", "Prime"
        };
        
        var nouns = new[] {
            "Panda", "Tiger", "Eagle", "Dolphin", "Lion", "Wolf", "Bear", "Fox",
            "Hawk", "Owl", "Dragon", "Phoenix", "Unicorn", "Falcon", "Raven", "Teddy",
            "Koala", "Penguin", "Shark", "Whale", "Monkey", "Zebra", "Turtle", "Rabbit",
            "Jaguar", "Panther", "Lynx", "Leopard", "Rhino", "Giraffe", "Gorilla", "Seal",
            "Octopus", "Raccoon", "Badger", "Beaver", "Cheetah", "Cobra", "Condor", "Cougar",
            "Coyote", "Deer", "Elephant", "Gazelle", "Hamster", "Hedgehog", "Hippo", "Llama"
        };

        var random = new Random();
        var adjective = adjectives[random.Next(adjectives.Length)];
        var noun = nouns[random.Next(nouns.Length)];
        var number = random.Next(100, 10000);

        return $"{adjective}_{noun}{number}";
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
            ValidAudiences = new[] { appleConfig["ClientId"], "com.Nanrepo.SupNow-xCode" },
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
            var username = GenerateFriendlyUsername();
            var tempEmail = $"apple_{appleSubClaim}@supnow.temp";
            _logger.LogWarning($"Creating new user with temporary email: {tempEmail}");

            try 
            {
                user = new ApplicationUser
                {
                    UserName = username,
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

                _messageBus.PublishUserRegistered(user.Id, user.UserName, tempEmail);
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

    public async Task<AuthResponse> SignInWithGoogleAsync(GoogleAuthRequest request)
    {
        // Log the incoming request
        _logger.LogInformation("Starting Google Sign In process");
        _logger.LogInformation($"ID Token present: {!string.IsNullOrEmpty(request.IdToken)}");

        // Validate the Google ID token
        var googleConfig = _configuration.GetSection("Authentication:Google").Get<Dictionary<string, string>>();
        _logger.LogWarning($"Google Config - ClientId: {googleConfig["ClientId"]}");

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://accounts.google.com",
            ValidateAudience = true,
            ValidAudiences = new[] { googleConfig["ClientId"] },
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = await GetGoogleSigningKey(request),
            ValidateLifetime = true
        };

        ClaimsPrincipal validatedToken;
        try
        {
            var handler = new JwtSecurityTokenHandler();
            validatedToken = handler.ValidateToken(request.IdToken, validationParameters, out _);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Google ID token validation failed");
            throw new AuthenticationException("Invalid Google ID token");
        }

        var googleSubClaim = validatedToken.FindFirst(ClaimTypes.NameIdentifier)?.Value 
            ?? validatedToken.FindFirst("sub")?.Value;

        // Handle email carefully
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

        if (string.IsNullOrEmpty(googleSubClaim))
        {
            throw new AuthenticationException("User ID not provided by Google");
        }

        // Find user by Google ID first
        var user = await _userManager.Users.FirstOrDefaultAsync(u => u.GoogleUserId == googleSubClaim);
        _logger.LogWarning($"User lookup by Google ID {googleSubClaim}: {(user != null ? "Found" : "Not found")}");

        if (user == null && !string.IsNullOrEmpty(email))
        {
            // If not found by Google ID, try to find by email
            user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                // Update existing user with Google ID
                user.GoogleUserId = googleSubClaim;
                await _userManager.UpdateAsync(user);
                _logger.LogWarning($"Updated existing user with Google ID: {user.Email}");
            }
        }

        if (user == null)
        {
            var username = GenerateFriendlyUsername();
            var tempEmail = email ?? $"google_{googleSubClaim}@supnow.temp";
            _logger.LogWarning($"Creating new user with email: {tempEmail}");

            try 
            {
                user = new ApplicationUser
                {
                    UserName = username,
                    Email = tempEmail,
                    EmailConfirmed = true, // Mark as confirmed since it's from Google
                    GoogleUserId = googleSubClaim
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError($"Failed to create user: {errors}");
                    throw new InvalidOperationException($"Failed to create user: {errors}");
                }

                _messageBus.PublishUserRegistered(user.Id, user.UserName, tempEmail);
                _logger.LogWarning($"New user registered via Google: {tempEmail}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creating user with email '{tempEmail}'");
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

    private async Task<SecurityKey> GetGoogleSigningKey(GoogleAuthRequest request)
    {
        using var client = new HttpClient();
        var response = await client.GetFromJsonAsync<GoogleKeyResponse>("https://www.googleapis.com/oauth2/v3/certs");
        if (response?.Keys == null || !response.Keys.Any())
        {
            throw new AuthenticationException("Unable to retrieve Google signing keys");
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
            _logger.LogError($"No matching key found for kid: {kid}");
            throw new AuthenticationException("No matching Google signing key found");
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

public class GoogleKeyResponse
{
    public required List<GoogleKey> Keys { get; set; }
}

public class GoogleKey
{
    public required string Kty { get; set; }
    public required string Kid { get; set; }
    public required string Use { get; set; }
    public required string Alg { get; set; }
    public required string N { get; set; }
    public required string E { get; set; }
}