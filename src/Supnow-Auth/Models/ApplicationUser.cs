using Microsoft.AspNetCore.Identity;
using System;

namespace Models;

public class ApplicationUser : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
    public int FailedLoginAttempts { get; set; }
    public DateTime? LastLoginAttempt { get; set; }
    public bool IsLockedOut { get; set; }
    public DateTime? LockoutEnd { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public string? TwoFactorSecretKey { get; set; }
} 