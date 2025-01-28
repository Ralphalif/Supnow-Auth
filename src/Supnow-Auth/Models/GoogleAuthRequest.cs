namespace Models;

public class GoogleAuthRequest
{
    public required string IdToken { get; set; }  // JWT token from Google
    public string? Email { get; set; }  // Optional email from the request
    public string? Name { get; set; }  // Optional name from the request
} 