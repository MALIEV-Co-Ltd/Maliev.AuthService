using System.Net.Http.Json;
using Maliev.AuthService.Application.Interfaces;

namespace Maliev.AuthService.Infrastructure.HttpClients;

/// <summary>
/// HTTP client implementation for the Employee Service API.
/// </summary>
public class EmployeeServiceClient : IEmployeeServiceClient
{
    private readonly HttpClient _httpClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="EmployeeServiceClient"/> class.
    /// </summary>
    /// <param name="httpClient">The HTTP client instance.</param>
    public EmployeeServiceClient(HttpClient httpClient)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    /// <inheritdoc/>
    public async Task<HttpResponseMessage> GetEmployeeByEmailAsync(
        string email,
        CancellationToken cancellationToken = default)
    {
        var encodedEmail = Uri.EscapeDataString(email);
        return await _httpClient.GetAsync(
            $"/employee/v1/employees/by-email/{encodedEmail}",
            cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<HttpResponseMessage> ProvisionEmployeeAsync(
        object request,
        CancellationToken cancellationToken = default)
    {
        return await _httpClient.PostAsJsonAsync(
            "/employee/v1/employees/auto-provision",
            request,
            cancellationToken);
    }
}
