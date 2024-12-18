using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using Moq;
using Services;
using Models;
using System.Security.Authentication;
using Xunit;
using Microsoft.EntityFrameworkCore;

namespace Supnow_Auth.Tests;

public class AuthServiceTests
{
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<IConfiguration> _mockConfiguration;
    private readonly Mock<IEmailService> _mockEmailService;
    private readonly Mock<ILogger<AuthService>> _mockLogger;
    private readonly AuthService _service;

    public AuthServiceTests()
    {
        var userStore = new Mock<IUserStore<ApplicationUser>>();
        _mockUserManager = new Mock<UserManager<ApplicationUser>>(
            userStore.Object, 
            It.IsAny<IOptions<IdentityOptions>>(),
            It.IsAny<IPasswordHasher<ApplicationUser>>(),
            It.IsAny<IEnumerable<IUserValidator<ApplicationUser>>>(),
            It.IsAny<IEnumerable<IPasswordValidator<ApplicationUser>>>(),
            It.IsAny<ILookupNormalizer>(),
            It.IsAny<IdentityErrorDescriber>(),
            It.IsAny<IServiceProvider>(),
            It.IsAny<ILogger<UserManager<ApplicationUser>>>());
            
        _mockConfiguration = new Mock<IConfiguration>();
        _mockEmailService = new Mock<IEmailService>();
        _mockLogger = new Mock<ILogger<AuthService>>();

        // Setup configuration
        var mockConfigSection = new Mock<IConfigurationSection>();
        mockConfigSection.Setup(x => x.Value).Returns("your-secret-key-that-is-long-enough-for-testing");
        _mockConfiguration.Setup(x => x["Jwt:Key"]).Returns("your-secret-key-that-is-long-enough-for-testing");
        _mockConfiguration.Setup(x => x["Jwt:Issuer"]).Returns("test-issuer");
        _mockConfiguration.Setup(x => x["Jwt:Audience"]).Returns("test-audience");

        _service = new AuthService(
            _mockConfiguration.Object,
            _mockUserManager.Object,
            _mockEmailService.Object,
            _mockLogger.Object
        );
    }

    [Fact]
    public async Task LoginAsync_ValidCredentials_ReturnsAuthResponse()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Email = "test@example.com",
            UserName = "test@example.com"
        };

        var loginRequest = new LoginRequest
        {
            Email = "test@example.com",
            Password = "Test123!"
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(loginRequest.Email))
            .ReturnsAsync(user);
        _mockUserManager.Setup(x => x.CheckPasswordAsync(user, loginRequest.Password))
            .ReturnsAsync(true);
        _mockUserManager.Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _service.LoginAsync(loginRequest);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Token);
        Assert.NotNull(result.RefreshToken);
        Assert.Equal(3600, result.ExpiresIn);
    }

    [Fact]
    public async Task LoginAsync_InvalidCredentials_ThrowsAuthenticationException()
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Email = "test@example.com",
            Password = "WrongPassword!"
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act & Assert
        await Assert.ThrowsAsync<AuthenticationException>(
            () => _service.LoginAsync(loginRequest));
    }

    [Fact]
    public async Task RegisterAsync_NewUser_ReturnsAuthResponse()
    {
        // Arrange
        var registerRequest = new RegisterRequest
        {
            Email = "new@example.com",
            Password = "Test123!",
            ConfirmPassword = "Test123!"
        };

        var newUser = new ApplicationUser 
        { 
            Email = registerRequest.Email,
            UserName = registerRequest.Email
        };

        bool _firstCall = true;

        // Setup for initial email check and subsequent login
        _mockUserManager.Setup(x => x.FindByEmailAsync(registerRequest.Email))
            .Returns<string>(email => Task.FromResult(
                email == registerRequest.Email && !_firstCall ? newUser : null
            ));

        // Setup for user creation
        _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), registerRequest.Password))
            .ReturnsAsync(IdentityResult.Success)
            .Callback(() => _firstCall = false);

        _mockUserManager.Setup(x => x.GenerateEmailConfirmationTokenAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync("email-token");

        _mockUserManager.Setup(x => x.CheckPasswordAsync(It.IsAny<ApplicationUser>(), registerRequest.Password))
            .ReturnsAsync(true);

        _mockUserManager.Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _service.RegisterAsync(registerRequest);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Token);
        Assert.NotNull(result.RefreshToken);
    }

    [Fact]
    public async Task RegisterAsync_ExistingEmail_ThrowsInvalidOperationException()
    {
        // Arrange
        var registerRequest = new RegisterRequest
        {
            Email = "existing@example.com",
            Password = "Test123!",
            ConfirmPassword = "Test123!"
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(registerRequest.Email))
            .ReturnsAsync(new ApplicationUser());

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _service.RegisterAsync(registerRequest));
    }
} 