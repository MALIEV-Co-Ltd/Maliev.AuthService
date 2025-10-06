using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Maliev.AuthService.Api.Controllers;

/// <summary>
/// Authentication controller providing JWT token operations.
/// </summary>
[ApiController]
[Route("auth")]
[Produces("application/json")]
public class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(
        IAuthenticationService authenticationService,
        ILogger<AuthenticationController> logger)
    {
        _authenticationService = authenticationService;
        _logger = logger;
    }

    /// <summary>
    /// Authenticates user and returns access + refresh tokens.
    /// </summary>
    /// <param name="request">Login credentials.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Login response with tokens.</returns>
    [HttpPost("login")]
    [EnableRateLimiting("FixedLoginRateLimit")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "invalid_request",
                Message = "Invalid request parameters",
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        var result = await _authenticationService.LoginAsync(request, cancellationToken);

        if (result == null)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = "invalid_credentials",
                Message = "Invalid username or password",
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Refreshes access token using refresh token (with rotation).
    /// </summary>
    /// <param name="request">Refresh request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>New tokens.</returns>
    [HttpPost("refresh")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "invalid_request",
                Message = "Invalid request parameters",
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        var result = await _authenticationService.RefreshAsync(request, cancellationToken);

        if (result == null)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = "token_family_invalidated",
                Message = "Refresh token is invalid, expired, or has been reused",
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Validates access token and returns user identity.
    /// </summary>
    /// <param name="request">Validation request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>User identity.</returns>
    [HttpPost("validate")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(ValidateResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Validate([FromBody] ValidateRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "invalid_request",
                Message = "Invalid request parameters",
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        var result = await _authenticationService.ValidateAsync(request, cancellationToken);

        if (result == null)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = "token_revoked",
                Message = "Access token is invalid, expired, or has been revoked",
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Revokes an access token.
    /// </summary>
    /// <param name="request">Revocation request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>No content on success.</returns>
    [HttpPost("revoke")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Revoke([FromBody] RevokeRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "invalid_request",
                Message = "Invalid request parameters",
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        var result = await _authenticationService.RevokeAsync(request, cancellationToken);

        if (!result)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = "invalid_token",
                Message = "Token cannot be revoked",
                CorrelationId = HttpContext.TraceIdentifier
            });
        }

        return NoContent();
    }
}
