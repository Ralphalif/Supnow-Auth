using Microsoft.AspNetCore.Identity;

namespace Models;

public class ApplicationUser : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
    public int FailedLoginAttempts { get; set; }
    public DateTime? LastLoginAttempt { get; set; }
    public bool IsLockedOut { get; set; }
    public string? TwoFactorSecretKey { get; set; }
    public string? AppleUserId { get; set; }
    public string? GoogleUserId { get; set; }
} 