using Maliev.AuthService.Api.Models;
using System.Threading;

namespace Maliev.AuthService.Api.Services
{
    public interface IValidationCacheService
    {
        Task<ValidationResult?> GetValidationResultAsync(string username, string userType, CancellationToken cancellationToken = default);

        Task SetValidationResultAsync(string username, string userType, ValidationResult result, CancellationToken cancellationToken = default);

        Task InvalidateUserValidationAsync(string username, CancellationToken cancellationToken = default);

        Task ClearExpiredEntriesAsync(CancellationToken cancellationToken = default);
    }
}