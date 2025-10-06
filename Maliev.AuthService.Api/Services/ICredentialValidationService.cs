using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service interface for credential validation with caching.
/// </summary>
public interface ICredentialValidationService
{
    /// <summary>
    /// Validates user credentials (with external service call and caching).
    /// </summary>
    Task<ExternalValidationResult?> ValidateCredentialsAsync(string username, string password, UserType userType, CancellationToken cancellationToken = default);
}
