using Microsoft.AspNetCore.Identity;
using System;

namespace Models;

public class ApplicationUser : IdentityUser
{
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
    public DateTime? LastLoginAttempt { get; set; }
    public int FailedLoginAttempts { get; set; }
    public bool IsLockedOut { get; set; }
    public new DateTime? LockoutEnd { get; set; }
    public new bool TwoFactorEnabled { get; set; }
    public string TwoFactorSecretKey { get; set; }
} 