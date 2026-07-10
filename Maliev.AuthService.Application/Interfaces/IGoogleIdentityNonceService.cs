using Maliev.AuthService.Application.Identity;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Issues and atomically consumes one-time nonces for Google Identity Services exchanges.
/// </summary>
public interface IGoogleIdentityNonceService
{
    /// <summary>Issues a nonce bound to one service caller, application, and exchange type.</summary>
    Task<GoogleIdentityNonceIssue> IssueAsync(
        string serviceName,
        string application,
        GoogleIdentityExchangeType exchangeType,
        CancellationToken cancellationToken = default);

    /// <summary>Atomically consumes a valid matching nonce.</summary>
    Task<bool> ConsumeAsync(
        string nonce,
        string serviceName,
        string application,
        GoogleIdentityExchangeType exchangeType,
        CancellationToken cancellationToken = default);
}
