using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using System.Threading;

namespace Maliev.AuthService.Api.Services
{
    public interface IRefreshTokenRepository
    {
        Task<int> CleanExpiredAndRevokedTokensAsync(CancellationToken cancellationToken = default);
        Task<RefreshToken?> GetRefreshTokenByTokenAsync(string token, CancellationToken cancellationToken = default);
        void AddRefreshToken(RefreshToken refreshToken);
        void UpdateRefreshToken(RefreshToken refreshToken);
        Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
    }
}