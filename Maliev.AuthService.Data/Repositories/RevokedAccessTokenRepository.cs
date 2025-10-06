using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Data.Repositories;

/// <summary>
/// Repository implementation for revoked access token operations.
/// </summary>
public class RevokedAccessTokenRepository : IRevokedAccessTokenRepository
{
    private readonly AuthDbContext _context;

    public RevokedAccessTokenRepository(AuthDbContext context)
    {
        _context = context;
    }

    public async Task<bool> IsRevokedAsync(string jti, CancellationToken cancellationToken = default)
    {
        return await _context.RevokedAccessTokens
            .AnyAsync(rat => rat.Jti == jti, cancellationToken);
    }

    public async Task RevokeAsync(RevokedAccessToken revokedToken, CancellationToken cancellationToken = default)
    {
        _context.RevokedAccessTokens.Add(revokedToken);
        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task DeleteExpiredRevocationsAsync(DateTime olderThan, CancellationToken cancellationToken = default)
    {
        await _context.RevokedAccessTokens
            .Where(rat => rat.ExpiresAt < olderThan)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
