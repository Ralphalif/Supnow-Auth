using System.ComponentModel.DataAnnotations;

namespace Models;

/// <summary>
/// Login request model
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// User's email address
    /// </summary>
    /// <example>user@example.com</example>
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    /// <summary>
    /// User's password
    /// </summary>
    /// <example>SecurePass123!</example>
    [Required]
    [MinLength(8)]
    public required string Password { get; set; }
}

/// <summary>
/// Registration request model
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// User's email address
    /// </summary>
    /// <example>user@example.com</example>
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    /// <summary>
    /// User's password
    /// </summary>
    /// <example>SecurePass123!</example>
    [Required]
    [MinLength(8)]
    public required string Password { get; set; }

    /// <summary>
    /// Confirmation of the password
    /// </summary>
    /// <example>SecurePass123!</example>
    [Required]
    [Compare(nameof(Password))]
    public required string ConfirmPassword { get; set; }
}

/// <summary>
/// Authentication response model
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// JWT token for API authentication
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Token used to refresh the JWT when it expires
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Token expiration time in seconds
    /// </summary>
    /// <example>3600</example>
    public int ExpiresIn { get; set; }

    /// <summary>
    /// Indicates if two-factor authentication is required
    /// </summary>
    public bool RequiresTwoFactor { get; set; }
}

public class RefreshTokenRequest
{
    [Required]
    public required string RefreshToken { get; set; }
} 