using Models;

namespace Services;

public interface IAuthService
{
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken);
    Task<bool> RevokeTokenAsync(string refreshToken);
    Task<bool> ValidateTokenAsync(string token);
    Task<AuthResponse> SignInWithAppleAsync(AppleAuthRequest request);
    Task<AuthResponse> SignInWithGoogleAsync(GoogleAuthRequest request);
} 