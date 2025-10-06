namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service interface for caching validation results.
/// </summary>
public interface IValidationCacheService
{
    /// <summary>
    /// Gets cached validation result for a user.
    /// </summary>
    ExternalValidationResult? Get(string username, string userType);

    /// <summary>
    /// Caches a successful validation result.
    /// </summary>
    void Set(string username, string userType, ExternalValidationResult result);

    /// <summary>
    /// Removes a cached validation result.
    /// </summary>
    void Remove(string username, string userType);
}
