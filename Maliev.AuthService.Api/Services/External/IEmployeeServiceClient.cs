namespace Maliev.AuthService.Api.Services.External;

/// <summary>
/// Client for interacting with the Employee Service API
/// </summary>
public interface IEmployeeServiceClient
{
    /// <summary>
    /// Retrieves an employee by their email address
    /// </summary>
    /// <param name="email">The employee's email address</param>
    /// <returns>HTTP response containing employee details</returns>
    Task<HttpResponseMessage> GetEmployeeByEmailAsync(string email);

    /// <summary>
    /// Provisions a new employee in the system
    /// </summary>
    /// <param name="request">The employee provisioning request</param>
    /// <returns>HTTP response containing provisioned employee details</returns>
    Task<HttpResponseMessage> ProvisionEmployeeAsync(object request);
}
