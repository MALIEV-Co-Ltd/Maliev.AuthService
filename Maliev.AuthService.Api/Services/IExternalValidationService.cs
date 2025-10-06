namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service interface for validating credentials with external services.
/// </summary>
public interface IExternalValidationService
{
    /// <summary>
    /// Validates customer credentials with Customer Service.
    /// </summary>
    Task<ExternalValidationResult?> ValidateCustomerAsync(string username, string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates employee credentials with Employee Service.
    /// </summary>
    Task<ExternalValidationResult?> ValidateEmployeeAsync(string username, string password, CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of external credential validation.
/// </summary>
public record ExternalValidationResult(
    string UserId,
    string Username,
    string Email,
    string[] Roles,
    string[] Permissions
);
