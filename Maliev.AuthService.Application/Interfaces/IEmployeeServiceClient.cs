namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Client for interacting with the Employee Service API.
/// </summary>
public interface IEmployeeServiceClient
{
    /// <summary>
    /// Retrieves an employee by their email address.
    /// </summary>
    /// <param name="email">The employee's email address.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>HTTP response containing employee details.</returns>
    Task<HttpResponseMessage> GetEmployeeByEmailAsync(
        string email,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Provisions a new employee in the system.
    /// </summary>
    /// <param name="request">The employee provisioning request.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>HTTP response containing provisioned employee details.</returns>
    Task<HttpResponseMessage> ProvisionEmployeeAsync(
        object request,
        CancellationToken cancellationToken = default);
}
