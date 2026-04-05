using Asp.Versioning;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.AuthService.Api.Controllers;

/// <summary>
/// Handles user authentication, token management (login, refresh, validate, revoke, logout),
/// and service-to-service authentication.
/// </summary>
[ApiController]
[ApiVersion("1")]
[Route("auth/v{version:apiVersion}")]
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
    /// <remarks>
    /// Primary entry point for users to log into the MALIEV platform.
    /// **Process:**
    /// 1. Verifies credentials against the database.
    /// 2. Resolves principal roles and permissions via the IAM Service.
    /// 3. Issues a JWT access token containing these permissions.
    /// 4. Issues a secure refresh token for session persistence.
    /// **Security:**
    /// - Subject to rate limiting (IP-based).
    /// - Implements account lockout after multiple failed attempts.
    /// </remarks>
    /// <param name="request">The login request containing user credentials.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Authentication response with JWT and refresh tokens.</returns>
    /// <response code="200">Successful login. Returns access and refresh tokens.</response>
    /// <response code="401">Invalid credentials.</response>
    /// <response code="423">Account is locked due to too many failed attempts.</response>
    /// <response code="429">Too many requests from this IP address.</response>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
    {

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        _logger.LogInformation("AuthenticateAsync called with IP: {IpAddress}", ipAddress ?? "null");
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
    /// <remarks>
    /// Used when an access token (JWT) has expired. Exchange a valid refresh token for a new access token and a new refresh token (rotation).
    /// </remarks>
    /// <param name="request">The refresh request containing the refresh token.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>A new set of JWT and refresh tokens.</returns>
    /// <response code="200">Tokens refreshed successfully.</response>
    /// <response code="401">If the refresh token is invalid, expired, or has already been used.</response>
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request, CancellationToken cancellationToken)
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
    /// <remarks>
    /// Internal endpoint used by other microservices to verify that a token is valid, hasn't been revoked, and to see its associated claims.
    /// </remarks>
    /// <param name="request">The validate request containing the access token.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The validation result.</returns>
    /// <response code="200">Returns token validity status and payload.</response>
    [HttpPost("validate")]
    public async Task<IActionResult> Validate([FromBody] ValidateRequest request, CancellationToken cancellationToken)
    {

        var result = await _authenticationService.ValidateTokenAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Revokes a refresh token.
    /// </summary>
    /// <remarks>
    /// Manually invalidates a refresh token. Useful for administrative session termination.
    /// </remarks>
    /// <param name="request">The revoke request containing the refresh token.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Success status.</returns>
    /// <response code="204">Token successfully revoked.</response>
    /// <response code="400">If the token is invalid or cannot be revoked.</response>
    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke([FromBody] RevokeRequest request, CancellationToken cancellationToken)
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
    /// Logs a user out.
    /// </summary>
    /// <remarks>
    /// The recommended way to end a user session. Invalidates the provided refresh token.
    /// </remarks>
    /// <param name="request">The logout request containing the refresh token.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Success status.</returns>
    /// <response code="204">Logged out successfully.</response>
    /// <response code="401">If the token was already invalid.</response>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request, CancellationToken cancellationToken)
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
    /// Authenticates a service using client credentials.
    /// </summary>
    /// <remarks>
    /// Machine-to-machine authentication using a `client_id` and `client_secret` (API Key).
    /// </remarks>
    /// <param name="request">The service login request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Service authentication response with a JWT.</returns>
    /// <response code="200">Successful authentication.</response>
    /// <response code="401">Invalid client credentials.</response>
    [HttpPost("service/login")]
    public async Task<IActionResult> ServiceLogin([FromBody] ServiceLoginRequest request, CancellationToken cancellationToken)
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

    /// <summary>
    /// Exchanges a verified Google Workspace identity for a platform JWT.
    /// </summary>
    /// <remarks>
    /// Used by the Intranet BFF after successful Google OAuth authentication.
    /// Assumes the email has already been validated by Google (trusted provider).
    ///
    /// **Process:**
    /// 1. Validates email is @maliev.com domain.
    /// 2. Looks up employee by email in EmployeeService.
    /// 3. Resolves permissions from IAM Service.
    /// 4. Issues JWT with embedded permissions.
    /// 5. Issues refresh token for session persistence.
    ///
    /// **Auto-Provisioning:**
    /// If employee doesn't exist, triggers auto-provisioning with minimal permissions.
    /// </remarks>
    /// <param name="request">The Google exchange request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Authentication response with JWT and refresh tokens.</returns>
    /// <response code="200">Successful exchange. Returns access and refresh tokens.</response>
    /// <response code="403">Non-@maliev.com email or inactive employee account.</response>
    /// <response code="503">EmployeeService unavailable.</response>
    [HttpPost("exchange/google")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> ExchangeGoogleToken([FromBody] GoogleExchangeRequest request, CancellationToken cancellationToken)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        var result = await _authenticationService.ExchangeGoogleTokenAsync(request, ipAddress);

        if (!result.Success)
        {
            if (result.ErrorCode == "employee_not_found" || result.ErrorCode == "inactive_account")
            {
                return StatusCode(403, new ErrorResponse
                {
                    Error = result.ErrorCode,
                    ErrorDescription = result.ErrorDescription!
                });
            }

            if (result.ErrorCode == "invalid_domain")
            {
                return StatusCode(403, new ErrorResponse
                {
                    Error = result.ErrorCode,
                    ErrorDescription = "Only @maliev.com email addresses are allowed"
                });
            }

            if (result.ErrorCode == "service_unavailable")
            {
                return StatusCode(503, new ErrorResponse
                {
                    Error = result.ErrorCode,
                    ErrorDescription = result.ErrorDescription!
                });
            }

            if (result.ErrorCode == "provision_failed")
            {
                return StatusCode(403, new ErrorResponse
                {
                    Error = result.ErrorCode,
                    ErrorDescription = result.ErrorDescription!
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
}
