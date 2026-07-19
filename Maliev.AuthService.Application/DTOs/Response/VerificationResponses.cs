namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>
/// Result of initiating or resending email verification.
/// </summary>
/// <param name="Success">Whether the operation was accepted.</param>
/// <param name="ErrorCode">Error code on failure.</param>
/// <param name="ErrorDescription">Error description on failure.</param>
/// <param name="CooldownUntil">When the user can request a new verification email.</param>
public record InitiateVerificationResult(bool Success, string? ErrorCode, string? ErrorDescription, DateTime? CooldownUntil);

/// <summary>
/// Result of verifying an email with a token.
/// </summary>
/// <param name="Success">Whether the email was verified successfully.</param>
/// <param name="ErrorCode">Error code on failure.</param>
/// <param name="ErrorDescription">Error description on failure.</param>
public record VerifyEmailResult(bool Success, string? ErrorCode, string? ErrorDescription);
