using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Data.Repositories;

/// <summary>
/// Repository implementation for refresh token operations.
/// </summary>
public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly AuthDbContext _context;

    public RefreshTokenRepository(AuthDbContext context)
    {
        _context = context;
    }

    public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        return await _context.RefreshTokens
            .Include(rt => rt.TokenFamily)
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash, cancellationToken);
    }

    public async Task<RefreshToken> CreateAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default)
    {
        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync(cancellationToken);
        return refreshToken;
    }

    public async Task<bool> MarkAsUsedAsync(Guid id, byte[] version, CancellationToken cancellationToken = default)
    {
        var token = await _context.RefreshTokens.FindAsync([id], cancellationToken);
        if (token == null || !token.Version.SequenceEqual(version))
        {
            return false; // Optimistic concurrency conflict
        }

        token.IsUsed = true;

        try
        {
            await _context.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            return false; // Concurrent modification detected
        }
    }

    public async Task RevokeTokenFamilyAsync(Guid familyId, CancellationToken cancellationToken = default)
    {
        await _context.RefreshTokens
            .Where(rt => rt.FamilyId == familyId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(rt => rt.IsRevoked, true),
                cancellationToken);
    }

    public async Task DeleteExpiredTokensAsync(DateTime olderThan, CancellationToken cancellationToken = default)
    {
        await _context.RefreshTokens
            .Where(rt => rt.ExpiresAt < olderThan)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
