using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Data.Repositories;

/// <summary>
/// Repository interface for revoked access token operations.
/// </summary>
public interface IRevokedAccessTokenRepository
{
    /// <summary>
    /// Checks if an access token JTI is revoked.
    /// </summary>
    Task<bool> IsRevokedAsync(string jti, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds an access token to the revocation list.
    /// </summary>
    Task RevokeAsync(RevokedAccessToken revokedToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes expired revoked tokens older than the specified date.
    /// </summary>
    Task DeleteExpiredRevocationsAsync(DateTime olderThan, CancellationToken cancellationToken = default);
}
