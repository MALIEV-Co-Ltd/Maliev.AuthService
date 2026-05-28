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
    private readonly IEmailVerificationService _emailVerificationService;
    private readonly IPasskeyService _passkeyService;
    private readonly ILogger<AuthenticationController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticationController"/> class.
    /// </summary>
    /// <param name="authenticationService">The service responsible for authentication logic.</param>
    /// <param name="emailVerificationService">The service responsible for email verification.</param>
    /// <param name="passkeyService">The service responsible for WebAuthn passkey operations.</param>
    /// <param name="logger">The logger for this controller.</param>
    public AuthenticationController(
        IAuthenticationService authenticationService,
        IEmailVerificationService emailVerificationService,
        IPasskeyService passkeyService,
        ILogger<AuthenticationController> logger)
    {
        _authenticationService = authenticationService;
        _emailVerificationService = emailVerificationService;
        _passkeyService = passkeyService;
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

    /// <summary>
    /// Exchanges a verified customer Google identity for a customer JWT.
    /// </summary>
    /// <remarks>
    /// Used by the public Web BFF after successful customer Google authentication.
    /// Customer Google accounts are not restricted to the MALIEV Workspace domain.
    /// </remarks>
    /// <param name="request">The customer Google exchange request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Authentication response with JWT and refresh tokens.</returns>
    /// <response code="200">Successful exchange. Returns access and refresh tokens.</response>
    /// <response code="401">Google identity is invalid or unverified.</response>
    /// <response code="503">CustomerService or IAM is unavailable.</response>
    [HttpPost("exchange/google/customer")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> ExchangeCustomerGoogleToken([FromBody] CustomerGoogleExchangeRequest request, CancellationToken cancellationToken)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authenticationService.ExchangeCustomerGoogleTokenAsync(request, ipAddress);

        if (!result.Success)
        {
            if (result.ErrorCode == "service_unavailable")
            {
                return StatusCode(503, new ErrorResponse
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

    /// <summary>
    /// Starts a customer password reset through CustomerService.
    /// </summary>
    /// <param name="request">The password reset request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Reset request status.</returns>
    /// <response code="200">Reset request accepted.</response>
    /// <response code="503">CustomerService is unavailable.</response>
    [HttpPost("password-reset/request")]
    [ProducesResponseType(typeof(PasswordResetResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequest request, CancellationToken cancellationToken)
    {
        var result = await _authenticationService.RequestPasswordResetAsync(request);
        if (result == null)
        {
            return StatusCode(503, new ErrorResponse
            {
                Error = "service_unavailable",
                ErrorDescription = "Customer account service is currently unavailable"
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Confirms a customer password reset through CustomerService.
    /// </summary>
    /// <param name="request">The password reset confirmation request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Password reset status.</returns>
    /// <response code="200">Password reset completed.</response>
    /// <response code="400">Reset token is invalid.</response>
    [HttpPost("password-reset/confirm")]
    [ProducesResponseType(typeof(ConfirmPasswordResetResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ConfirmPasswordReset([FromBody] ConfirmPasswordResetRequest request, CancellationToken cancellationToken)
    {
        var result = await _authenticationService.ConfirmPasswordResetAsync(request);
        if (result == null || !result.Reset)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "invalid_reset_token",
                ErrorDescription = "Invalid or expired password reset token"
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Initiates email verification for a user principal.
    /// </summary>
    /// <remarks>
    /// Sends a verification email with a unique token to the specified email address.
    /// Subsequent requests for the same principal within the cooldown period will return
    /// a 400 with a cooldown_until timestamp.
    /// </remarks>
    /// <param name="request">The verification initiation request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Verification initiation result.</returns>
    /// <response code="200">Verification email sent successfully.</response>
    /// <response code="400">Verification already initiated within cooldown period.</response>
    [HttpPost("initiate-email-verification")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> InitiateEmailVerification([FromBody] InitiateVerificationRequest request, CancellationToken cancellationToken)
    {
        var result = await _emailVerificationService.InitiateVerificationAsync(
            request.PrincipalId, request.Email, request.FirstName, cancellationToken);

        if (!result.Success)
        {
            return BadRequest(new ErrorResponse
            {
                Error = result.ErrorCode!,
                ErrorDescription = result.ErrorDescription!
            });
        }

        return Ok(new { message = "Verification email sent" });
    }

    /// <summary>
    /// Verifies an email address using a verification token.
    /// </summary>
    /// <remarks>
    /// Validates the provided token and, if valid, marks the associated email as verified.
    /// Tokens are one-time use and expire after a configured duration.
    /// </remarks>
    /// <param name="request">The verify email request containing the token.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Verification result.</returns>
    /// <response code="200">Email verified successfully.</response>
    /// <response code="400">Token is invalid or expired.</response>
    [HttpPost("verify-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request, CancellationToken cancellationToken)
    {
        var result = await _emailVerificationService.VerifyEmailAsync(request.Token, cancellationToken);

        if (!result.Success)
        {
            return BadRequest(new ErrorResponse
            {
                Error = result.ErrorCode!,
                ErrorDescription = result.ErrorDescription!
            });
        }

        return Ok(new { message = "Email verified successfully" });
    }

    /// <summary>
    /// Resends a verification email for a user principal.
    /// </summary>
    /// <remarks>
    /// Generates a new verification token and sends a new email to the principal's
    /// email address. Subject to the same cooldown rules as initial verification.
    /// </remarks>
    /// <param name="request">The resend verification request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Resend initiation result.</returns>
    /// <response code="200">Verification email resent successfully.</response>
    /// <response code="400">Resend not allowed (cooldown active or email already verified).</response>
    [HttpPost("resend-verification-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResendVerificationEmail([FromBody] ResendVerificationRequest request, CancellationToken cancellationToken)
    {
        var result = await _emailVerificationService.ResendVerificationAsync(request.PrincipalId, cancellationToken);

        if (!result.Success)
        {
            return BadRequest(new ErrorResponse
            {
                Error = result.ErrorCode!,
                ErrorDescription = result.ErrorDescription!
            });
        }

        return Ok(new { message = "Verification email resent" });
    }

    /// <summary>
    /// Checks if a user principal's email is verified.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The email verification status.</returns>
    /// <response code="200">Returns the principal ID and verification status.</response>
    [HttpGet("me")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> GetPrincipalVerificationStatus([FromQuery] Guid principalId, CancellationToken cancellationToken)
    {
        var isVerified = await _emailVerificationService.IsEmailVerifiedAsync(principalId, cancellationToken);

        return Ok(new { principalId, emailVerified = isVerified });
    }

    /// <summary>
    /// Begins WebAuthn passkey registration by generating a challenge and creation options.
    /// </summary>
    /// <remarks>
    /// Returns credential creation options needed by the client to invoke navigator.credentials.create().
    /// The challenge is stored server-side and expires after 5 minutes.
    /// </remarks>
    /// <param name="request">The registration begin request containing the principal ID.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>WebAuthn credential creation options.</returns>
    /// <response code="200">Registration challenge created successfully.</response>
    [HttpPost("passkey/register/begin")]
    [ProducesResponseType(typeof(PasskeyRegistrationBeginResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> BeginPasskeyRegistration([FromBody] PasskeyRegistrationBeginRequest request, CancellationToken cancellationToken)
    {
        var result = await _passkeyService.BeginRegistrationAsync(request.PrincipalId, cancellationToken);
        return Ok(result);
    }

    /// <summary>
    /// Completes WebAuthn passkey registration by verifying and storing the credential.
    /// </summary>
    /// <remarks>
    /// Verifies the challenge, enforces max passkeys per principal, and stores the credential.
    /// Publishes a PasskeyRegisteredEvent upon success.
    /// </remarks>
    /// <param name="request">The registration completion request with authenticator response.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Registration result.</returns>
    /// <response code="200">Passkey registered successfully.</response>
    /// <response code="400">Registration failed (challenge expired, duplicate credential, or max reached).</response>
    [HttpPost("passkey/register/complete")]
    [ProducesResponseType(typeof(PasskeyRegistrationCompleteResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CompletePasskeyRegistration([FromBody] PasskeyRegistrationCompleteRequest request, CancellationToken cancellationToken)
    {
        var result = await _passkeyService.CompleteRegistrationAsync(request, cancellationToken);

        if (!result.Success)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "registration_failed",
                ErrorDescription = result.Error ?? "Failed to complete passkey registration"
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Begins WebAuthn passkey authentication by generating a challenge and credential request options.
    /// </summary>
    /// <remarks>
    /// Returns credential request options needed by the client to invoke navigator.credentials.get().
    /// If a principal ID is provided, the allowed credentials are scoped to that principal.
    /// </remarks>
    /// <param name="request">The authentication begin request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>WebAuthn credential request options.</returns>
    /// <response code="200">Authentication challenge created successfully.</response>
    [HttpPost("passkey/auth/begin")]
    [ProducesResponseType(typeof(PasskeyAuthBeginResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> BeginPasskeyAuthentication([FromBody] PasskeyAuthBeginRequest request, CancellationToken cancellationToken)
    {
        var result = await _passkeyService.BeginAuthenticationAsync(request.PrincipalId, cancellationToken);
        return Ok(result);
    }

    /// <summary>
    /// Completes WebAuthn passkey authentication by verifying the assertion signature.
    /// </summary>
    /// <remarks>
    /// Validates the authenticator signature against the stored public key.
    /// Updates the sign count and last used timestamp on successful verification.
    /// </remarks>
    /// <param name="request">The authentication completion request with assertion response.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Authentication result with principal information.</returns>
    /// <response code="200">Authentication successful.</response>
    /// <response code="401">Invalid credential or signature.</response>
    [HttpPost("passkey/auth/complete")]
    [ProducesResponseType(typeof(PasskeyAuthCompleteResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> CompletePasskeyAuthentication([FromBody] PasskeyAuthCompleteRequest request, CancellationToken cancellationToken)
    {
        var result = await _passkeyService.CompleteAuthenticationAsync(request, cancellationToken);

        if (!result.Success)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = "authentication_failed",
                ErrorDescription = result.Error ?? "Invalid credentials"
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Lists all passkey credentials for a principal.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>List of passkey credentials.</returns>
    /// <response code="200">Returns the list of credentials.</response>
    [HttpGet("passkey/credentials")]
    [ProducesResponseType(typeof(PasskeyListResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> ListPasskeyCredentials([FromQuery] Guid principalId, CancellationToken cancellationToken)
    {
        var result = await _passkeyService.ListCredentialsAsync(principalId, cancellationToken);
        return Ok(result);
    }

    /// <summary>
    /// Deletes a passkey credential.
    /// </summary>
    /// <param name="credentialId">The credential identifier.</param>
    /// <param name="principalId">The principal who owns the credential.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Deletion result.</returns>
    /// <response code="204">Credential deleted successfully.</response>
    /// <response code="404">Credential not found.</response>
    [HttpDelete("passkey/credentials/{credentialId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeletePasskeyCredential(Guid credentialId, [FromQuery] Guid principalId, CancellationToken cancellationToken)
    {
        var result = await _passkeyService.DeleteCredentialAsync(credentialId, principalId, cancellationToken);

        if (!result)
        {
            return NotFound(new ErrorResponse
            {
                Error = "credential_not_found",
                ErrorDescription = "Credential not found"
            });
        }

        return NoContent();
    }
}
