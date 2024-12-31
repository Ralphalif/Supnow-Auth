namespace Models;

public class AppleAuthRequest
{
    public required string IdToken { get; set; }
    public required string AuthorizationCode { get; set; }
    public string? Name { get; set; }  // Only provided on first sign in
    public string? Email { get; set; } // Only provided on first sign in
} 