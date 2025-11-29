using Microsoft.AspNetCore.Mvc;
using Maliev.AuthService.Api.Models.Request;
using Maliev.AuthService.Api.Models.Response;
using Maliev.AuthService.Api.Services;

namespace Maliev.AuthService.Api.Controllers;

/// <summary>
/// Handles user authentication, token management (login, refresh, validate, revoke, logout),
/// and service-to-service authentication.
/// </summary>
[ApiController]
[Route("auth/v1")]
public class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly ILogger<AuthenticationController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticationController"/> class.
    /// </summary>
    /// <param name="authenticationService">The service responsible for authentication logic.</param>
    /// <param name="logger">The logger for this controller.</param>
    public AuthenticationController(
        IAuthenticationService authenticationService,
        ILogger<AuthenticationController> logger)
    {
        _authenticationService = authenticationService;
        _logger = logger;
    }

    /// <summary>
    /// Authenticates a user with email and password.
    /// </summary>
    /// <param name="request">The login request containing user credentials.</param>
    /// <returns>
    /// An <see cref="IActionResult"/> containing the authentication response with JWT and refresh tokens.
    /// Returns <see cref="BadRequestResult"/> if validation fails.
    /// Returns <see cref="UnauthorizedResult"/> for invalid credentials.
    /// Returns a 423 (Locked) status code if the account is locked.
    /// Returns a 429 (Too Many Requests) status code if rate limited.
    /// </returns>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authenticationService.AuthenticateAsync(request, ipAddress);

        if (!result.Success)
        {
            if (result.ErrorCode == "account_locked")
            {
                return StatusCode(423, new
                {
                    error = result.ErrorCode,
                    error_description = result.ErrorDescription,
                    locked_until = result.LockedUntil?.ToString("o")
                });
            }

            if (result.ErrorCode == "rate_limit_exceeded")
            {
                if (result.RetryAfter.HasValue)
                {
                    var retryAfterSeconds = (int)(result.RetryAfter.Value - DateTime.UtcNow).TotalSeconds;
                    Response.Headers["Retry-After"] = retryAfterSeconds.ToString();
                }

                return StatusCode(429, new ErrorResponse
                {
                    Error = result.ErrorCode ?? "rate_limit_exceeded",
                    ErrorDescription = result.ErrorDescription ?? "Too many requests"
                });
            }

            return Unauthorized(new ErrorResponse
            {
                Error = result.ErrorCode!,
                ErrorDescription = result.ErrorDescription!
            });
        }

        return Ok(result.Response);
    }

    /// <summary>
    /// Refreshes an authentication token.
    /// </summary>
    /// <param name="request">The refresh request containing the refresh token.</param>
    /// <returns>
    /// An <see cref="IActionResult"/> containing a new set of JWT and refresh tokens.
    /// Returns <see cref="BadRequestResult"/> if validation fails.
    /// Returns <see cref="UnauthorizedResult"/> if the refresh token is invalid.
    /// </returns>
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authenticationService.RefreshTokenAsync(request, ipAddress);

        if (result == null)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = "invalid_token",
                ErrorDescription = "Invalid or expired refresh token"
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Validates a JWT access token.
    /// </summary>
    /// <param name="request">The validate request containing the access token.</param>
    /// <returns>
    /// An <see cref="IActionResult"/> with the validation result.
    /// Returns <see cref="OkObjectResult"/> with a <see cref="ValidateResponse"/> indicating if the token is valid, along with its claims.
    /// Returns <see cref="BadRequestResult"/> if validation of the request model fails.
    /// </returns>
    [HttpPost("validate")]
    public async Task<IActionResult> Validate([FromBody] ValidateRequest request)
    {

        var result = await _authenticationService.ValidateTokenAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Revokes a refresh token, invalidating it for future use.
    /// </summary>
    /// <param name="request">The revoke request containing the refresh token.</param>
    /// <returns>
    /// An <see cref="IActionResult"/>.
    /// Returns <see cref="NoContentResult"/> on successful revocation.
    /// Returns <see cref="BadRequestResult"/> if validation fails or the token cannot be revoked.
    /// </returns>
    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke([FromBody] RevokeRequest request)
    {

        var result = await _authenticationService.RevokeTokenAsync(request);

        if (!result)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "revocation_failed",
                ErrorDescription = "Failed to revoke token"
            });
        }

        return NoContent();
    }

    /// <summary>
    /// Logs a user out by invalidating their refresh token.
    /// </summary>
    /// <param name="request">The logout request containing the refresh token.</param>
    /// <returns>
    /// An <see cref="IActionResult"/>.
    /// Returns <see cref="NoContentResult"/> on successful logout.
    /// Returns <see cref="BadRequestResult"/> if validation fails.
    /// Returns <see cref="UnauthorizedResult"/> if the token is invalid.
    /// </returns>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {

        var result = await _authenticationService.LogoutAsync(request);

        if (!result)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = "invalid_token",
                ErrorDescription = "Invalid refresh token"
            });
        }

        return NoContent();
    }

    /// <summary>
    /// Authenticates a service using client credentials (client_id and client_secret).
    /// </summary>
    /// <param name="request">The service login request containing client credentials.</param>
    /// <returns>
    /// An <see cref="IActionResult"/> containing the service authentication response with a JWT.
    /// Returns <see cref="BadRequestResult"/> if validation fails.
    /// Returns <see cref="UnauthorizedResult"/> for invalid credentials.
    /// </returns>
    [HttpPost("service/login")]
    public async Task<IActionResult> ServiceLogin([FromBody] ServiceLoginRequest request)
    {

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authenticationService.AuthenticateServiceAsync(request, ipAddress);

        if (result == null)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = "invalid_credentials",
                ErrorDescription = "Invalid client credentials"
            });
        }

        return Ok(result);
    }
}
