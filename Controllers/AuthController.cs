using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;
using Services;
using Models;
using System.Security.Authentication;

namespace Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Register a new user
        /// </summary>
        /// <param name="model">Registration details including email and password</param>
        /// <returns>Authentication result with JWT token</returns>
        /// <response code="200">Returns the authentication token</response>
        /// <response code="400">If the registration details are invalid</response>
        /// <response code="409">If the email is already registered</response>
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status409Conflict)]
        public async Task<IActionResult> Register([FromBody] RegisterRequest model)
        {
            try
            {
                var response = await _authService.RegisterAsync(model);
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed");
                return BadRequest(new { message = "Registration failed" });
            }
        }

        /// <summary>
        /// Authenticate a user
        /// </summary>
        /// <param name="model">Login credentials</param>
        /// <returns>Authentication result with JWT token</returns>
        /// <response code="200">Returns the authentication token</response>
        /// <response code="400">If the credentials are invalid</response>
        /// <response code="401">If authentication fails</response>
        /// <response code="403">If the account is locked out</response>
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> Login([FromBody] LoginRequest model)
        {
            try
            {
                var response = await _authService.LoginAsync(model);
                return Ok(response);
            }
            catch (AuthenticationException ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Refresh an expired JWT token
        /// </summary>
        /// <param name="model">Refresh token details</param>
        /// <returns>New JWT token and refresh token</returns>
        /// <response code="200">Returns new authentication tokens</response>
        /// <response code="400">If the refresh token is invalid</response>
        /// <response code="401">If the refresh token has expired</response>
        [HttpPost("refresh-token")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model)
        {
            try
            {
                var response = await _authService.RefreshTokenAsync(model.RefreshToken);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
        }
    }
} 