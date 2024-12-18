using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using Controllers;
using Services;
using Models;
using System.Threading.Tasks;
using Xunit;
using System.Security.Authentication;
using System;

namespace Supnow_Auth.Tests;

public class AuthControllerTests
{
    private readonly AuthController _controller;
    private readonly Mock<IAuthService> _mockAuthService;
    private readonly Mock<ILogger<AuthController>> _mockLogger;

    public AuthControllerTests()
    {
        _mockAuthService = new Mock<IAuthService>();
        _mockLogger = new Mock<ILogger<AuthController>>();
        _controller = new AuthController(_mockAuthService.Object, _mockLogger.Object);
    }

    [Fact]
    public async Task Register_EmailAlreadyExists_ReturnsBadRequest()
    {
        // Arrange
        var request = new RegisterRequest 
        { 
            Email = "existing@example.com", 
            Password = "Test123!", 
            ConfirmPassword = "Test123!" 
        };

        _mockAuthService
            .Setup(x => x.RegisterAsync(It.IsAny<RegisterRequest>()))
            .ThrowsAsync(new InvalidOperationException("Email already registered"));

        // Act
        var result = await _controller.Register(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.NotNull(badRequestResult.Value);
        var response = Assert.IsType<ErrorResponse>(badRequestResult.Value);
        Assert.Equal("Registration failed", response.message);
    }

    [Fact]
    public async Task RefreshToken_InvalidToken_ReturnsUnauthorized()
    {
        // Arrange
        var request = new RefreshTokenRequest { RefreshToken = "invalid-token" };
        
        _mockAuthService
            .Setup(x => x.RefreshTokenAsync(It.IsAny<string>()))
            .ThrowsAsync(new AuthenticationException("Invalid refresh token"));

        // Act
        var result = await _controller.RefreshToken(request);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }
}