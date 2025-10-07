using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Maliev.AuthService.Api.Models.Request;
using Maliev.AuthService.Api.Models.Response;
using Maliev.AuthService.Api.Services;

namespace Maliev.AuthService.Api.Controllers;

[ApiController]
[Route("v1/auth")]
public class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly IValidator<LoginRequest> _loginValidator;
    private readonly IValidator<RefreshRequest> _refreshValidator;
    private readonly IValidator<ValidateRequest> _validateValidator;
    private readonly IValidator<RevokeRequest> _revokeValidator;
    private readonly IValidator<LogoutRequest> _logoutValidator;
    private readonly IValidator<ServiceLoginRequest> _serviceLoginValidator;
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(
        IAuthenticationService authenticationService,
        IValidator<LoginRequest> loginValidator,
        IValidator<RefreshRequest> refreshValidator,
        IValidator<ValidateRequest> validateValidator,
        IValidator<RevokeRequest> revokeValidator,
        IValidator<LogoutRequest> logoutValidator,
        IValidator<ServiceLoginRequest> serviceLoginValidator,
        ILogger<AuthenticationController> logger)
    {
        _authenticationService = authenticationService;
        _loginValidator = loginValidator;
        _refreshValidator = refreshValidator;
        _validateValidator = validateValidator;
        _revokeValidator = revokeValidator;
        _logoutValidator = logoutValidator;
        _serviceLoginValidator = serviceLoginValidator;
        _logger = logger;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var validationResult = await _loginValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new
            {
                error = "validation_error",
                error_description = "Validation failed",
                errors = validationResult.Errors.Select(e => e.ErrorMessage).ToArray()
            });
        }

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

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        var validationResult = await _refreshValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "validation_error",
                ErrorDescription = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage))
            });
        }

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

    [HttpPost("validate")]
    public async Task<IActionResult> Validate([FromBody] ValidateRequest request)
    {
        var validationResult = await _validateValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "validation_error",
                ErrorDescription = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage))
            });
        }

        var result = await _authenticationService.ValidateTokenAsync(request);
        return Ok(result);
    }

    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke([FromBody] RevokeRequest request)
    {
        var validationResult = await _revokeValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "validation_error",
                ErrorDescription = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage))
            });
        }

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

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        var validationResult = await _logoutValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "validation_error",
                ErrorDescription = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage))
            });
        }

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

    [HttpPost("service/login")]
    public async Task<IActionResult> ServiceLogin([FromBody] ServiceLoginRequest request)
    {
        var validationResult = await _serviceLoginValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "validation_error",
                ErrorDescription = string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage))
            });
        }

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
