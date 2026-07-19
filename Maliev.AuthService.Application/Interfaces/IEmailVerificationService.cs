using Maliev.AuthService.Application.DTOs.Response;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Service interface for email verification operations.
/// </summary>
public interface IEmailVerificationService
{
    /// <summary>
    /// Initiates email verification for a user principal.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="email">The email address to verify.</param>
    /// <param name="firstName">The user's first name for personalization.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The initiation result.</returns>
    Task<InitiateVerificationResult> InitiateVerificationAsync(Guid principalId, string email, string firstName, CancellationToken ct);

    /// <summary>
    /// Verifies an email using a verification token.
    /// </summary>
    /// <param name="token">The verification token.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The verification result.</returns>
    Task<VerifyEmailResult> VerifyEmailAsync(string token, CancellationToken ct);

    /// <summary>
    /// Resends a verification email for a user principal.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The initiation result.</returns>
    Task<InitiateVerificationResult> ResendVerificationAsync(Guid principalId, CancellationToken ct);

    /// <summary>
    /// Checks if a user principal's email is verified.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if the email is verified, otherwise false.</returns>
    Task<bool> IsEmailVerifiedAsync(Guid principalId, CancellationToken ct);
}
