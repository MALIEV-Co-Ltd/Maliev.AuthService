using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.AuthService.Api.Authorization;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Infrastructure.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Api.Controllers;

/// <summary>
/// Handles caller-bound, server-verified WebAuthn authentication ceremonies.
/// </summary>
[ApiController]
[ApiVersion("2")]
[Route("auth/v{version:apiVersion}/passkey/auth")]
public sealed class PasskeyAuthenticationController(
    IPasskeyService passkeyService,
    IOptions<PasskeyWebAuthnOptions> options,
    ILogger<PasskeyAuthenticationController> logger) : ControllerBase
{
    private readonly PasskeyWebAuthnOptions _options = options.Value;

    /// <summary>
    /// Starts a discoverable-credential WebAuthn authentication ceremony.
    /// </summary>
    /// <param name="request">The server-owned application audience.</param>
    /// <param name="cancellationToken">Token used to cancel the request.</param>
    /// <returns>One-time browser assertion options.</returns>
    /// <response code="200">The one-time assertion options were issued.</response>
    /// <response code="400">The request attempted to supply identity context.</response>
    /// <response code="403">The service caller is not bound to the application.</response>
    /// <response code="503">Passkey authentication is unavailable.</response>
    [HttpPost("begin")]
    [RequirePermission(AuthPermissions.ExchangeIdentities)]
    [ProducesResponseType(typeof(PasskeyAuthBeginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    [RequestSizeLimit(4 * 1024)]
    public async Task<IActionResult> Begin(
        [FromBody] PasskeyAuthBeginRequest request,
        CancellationToken cancellationToken)
    {
        if (!TryGetBoundCaller(request.Application, out var serviceName, out var application))
        {
            return Forbid();
        }

        if (request.PrincipalId.HasValue)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "passkey_flow_invalid",
                ErrorDescription = "Passkey authentication must use a discoverable credential flow"
            });
        }

        request.Application = application;
        var result = await passkeyService.BeginAuthenticationAsync(
            request,
            serviceName,
            cancellationToken);
        if (result is null)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new ErrorResponse
            {
                Error = "passkey_temporarily_unavailable",
                ErrorDescription = "Passkey authentication is temporarily unavailable"
            });
        }

        logger.LogInformation(
            "Passkey ceremony issued for application {Application} with trace {TraceIdentifier}",
            application,
            HttpContext.TraceIdentifier);
        return Ok(result);
    }

    /// <summary>
    /// Completes a WebAuthn ceremony and returns identity only after cryptographic verification.
    /// </summary>
    /// <param name="request">The assertion and opaque one-time flow identifier.</param>
    /// <param name="cancellationToken">Token used to cancel the request.</param>
    /// <returns>The verified canonical principal identity.</returns>
    /// <response code="200">The assertion was verified and state committed.</response>
    /// <response code="401">The assertion or ceremony was invalid.</response>
    /// <response code="403">The service caller is not bound to the application.</response>
    /// <response code="503">Verification could not safely commit authenticator state.</response>
    [HttpPost("complete")]
    [RequirePermission(AuthPermissions.ExchangeIdentities)]
    [ProducesResponseType(typeof(PasskeyAuthCompleteResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    [RequestSizeLimit(32 * 1024)]
    public async Task<IActionResult> Complete(
        [FromBody] PasskeyAuthCompleteRequest request,
        CancellationToken cancellationToken)
    {
        if (!TryGetBoundCaller(request.Application, out var serviceName, out var application))
        {
            return Forbid();
        }

        request.Application = application;
        var result = await passkeyService.CompleteAuthenticationAsync(
            request,
            serviceName,
            cancellationToken);
        if (!result.Success)
        {
            var retryable = result.Error is
                "passkey_temporarily_unavailable" or
                "passkey_unavailable";
            var statusCode = retryable
                ? StatusCodes.Status503ServiceUnavailable
                : StatusCodes.Status401Unauthorized;
            logger.LogWarning(
                "Passkey ceremony rejected for application {Application} with status {StatusCode} and trace {TraceIdentifier}",
                application,
                statusCode,
                HttpContext.TraceIdentifier);
            return StatusCode(statusCode, new ErrorResponse
            {
                Error = retryable ? "passkey_temporarily_unavailable" : "authentication_failed",
                ErrorDescription = retryable
                    ? "Passkey authentication is temporarily unavailable"
                    : "Passkey authentication failed"
            });
        }

        logger.LogInformation(
            "Passkey ceremony completed for application {Application} with trace {TraceIdentifier}",
            application,
            HttpContext.TraceIdentifier);
        return Ok(result);
    }

    private bool TryGetBoundCaller(
        string? requestedApplication,
        out string serviceName,
        out string application)
    {
        var userType = User.FindFirst("user_type")?.Value;
        serviceName = User.FindFirst("service_name")?.Value ?? string.Empty;
        application = NormalizeSelector(requestedApplication);
        _options.Bindings.TryGetValue(application, out var binding);
        var allowed = string.Equals(userType, "service", StringComparison.OrdinalIgnoreCase) &&
            application.Length > 0 &&
            !string.IsNullOrWhiteSpace(serviceName) &&
            binding is not null &&
            !string.IsNullOrWhiteSpace(binding.ServiceName) &&
            string.Equals(serviceName, binding.ServiceName, StringComparison.OrdinalIgnoreCase);
        if (!allowed)
        {
            logger.LogWarning(
                "Rejected passkey exchange for application {Application} from service caller {ServiceName}",
                application.Length == 0 ? "invalid" : application,
                NormalizeSelector(serviceName) is { Length: > 0 } normalizedService
                    ? normalizedService
                    : "invalid");
        }

        return allowed;
    }

    private static string NormalizeSelector(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().ToLowerInvariant();
        return normalized is { Length: <= 64 } &&
            normalized.All(character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')
            ? normalized
            : string.Empty;
    }
}
