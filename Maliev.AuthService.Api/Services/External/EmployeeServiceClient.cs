namespace Maliev.AuthService.Api.Services.External;

/// <summary>
/// HTTP client implementation for the Employee Service API
/// </summary>
public class EmployeeServiceClient : IEmployeeServiceClient
{
    private readonly HttpClient _httpClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="EmployeeServiceClient"/> class
    /// </summary>
    /// <param name="httpClient">The HTTP client instance</param>
    public EmployeeServiceClient(HttpClient httpClient)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    /// <inheritdoc/>
    public async Task<HttpResponseMessage> GetEmployeeByEmailAsync(string email)
    {
        var encodedEmail = Uri.EscapeDataString(email);
        return await _httpClient.GetAsync($"/employee/v1/employees/by-email/{encodedEmail}");
    }

    /// <inheritdoc/>
    public async Task<HttpResponseMessage> ProvisionEmployeeAsync(object request)
    {
        return await _httpClient.PostAsJsonAsync("/employee/v1/employees/auto-provision", request);
    }
}
