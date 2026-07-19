using Maliev.AuthService.Application.Identity;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Validates Google Identity Services credentials at the AuthService trust boundary.
/// </summary>
public interface IGoogleIdentityTokenValidator
{
    /// <summary>
    /// Validates a raw Google ID token for a configured MALIEV application.
    /// </summary>
    /// <param name="credential">The raw Google Identity Services credential.</param>
    /// <param name="application">The configured MALIEV application selector.</param>
    /// <param name="exchangeType">The employee or customer exchange boundary.</param>
    /// <param name="expectedNonce">The one-time nonce issued for this browser exchange.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The verified identity or a safe validation failure.</returns>
    Task<GoogleIdentityValidationResult> ValidateAsync(
        string credential,
        string application,
        GoogleIdentityExchangeType exchangeType,
        string expectedNonce,
        CancellationToken cancellationToken = default);
}
