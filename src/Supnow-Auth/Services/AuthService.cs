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

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

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
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
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
} 