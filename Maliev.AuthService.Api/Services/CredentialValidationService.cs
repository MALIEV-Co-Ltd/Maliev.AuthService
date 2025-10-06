using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service implementation for credential validation with external services and caching.
/// </summary>
public class CredentialValidationService : ICredentialValidationService
{
    private readonly IExternalValidationService _externalValidationService;
    private readonly IValidationCacheService _cacheService;
    private readonly ILogger<CredentialValidationService> _logger;

    public CredentialValidationService(
        IExternalValidationService externalValidationService,
        IValidationCacheService cacheService,
        ILogger<CredentialValidationService> logger)
    {
        _externalValidationService = externalValidationService;
        _cacheService = cacheService;
        _logger = logger;
    }

    public async Task<ExternalValidationResult?> ValidateCredentialsAsync(
        string username,
        string password,
        UserType userType,
        CancellationToken cancellationToken = default)
    {
        var userTypeString = userType.ToString().ToLowerInvariant();

        // Check cache first (only for password validation, not initial lookup)
        // Note: Caching is disabled for security - always validate with external service

        // Call external service based on user type
        ExternalValidationResult? result = userType switch
        {
            UserType.Customer => await _externalValidationService.ValidateCustomerAsync(username, password, cancellationToken),
            UserType.Employee => await _externalValidationService.ValidateEmployeeAsync(username, password, cancellationToken),
            _ => null
        };

        if (result != null)
        {
            // Cache successful validation (for potential future use)
            _cacheService.Set(username, userTypeString, result);
            _logger.LogInformation("Credential validation successful for {UserType} user: {Username}", userTypeString, username);
        }
        else
        {
            _logger.LogWarning("Credential validation failed for {UserType} user: {Username}", userTypeString, username);
        }

        return result;
    }
}
