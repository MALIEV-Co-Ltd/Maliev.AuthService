namespace Maliev.AuthService.Api.Options;

/// <summary>
/// Configuration for external validation services (Customer and Employee services).
/// Maps to "ExternalServices" section in appsettings.json.
/// </summary>
public class ExternalServiceOptions
{
    public const string SectionName = "ExternalServices";

    /// <summary>
    /// Base URL for Customer Service validation endpoint.
    /// Example: https://customer-service/api/v1
    /// </summary>
    public required string CustomerServiceUrl { get; set; }

    /// <summary>
    /// Base URL for Employee Service validation endpoint.
    /// Example: https://employee-service/api/v1
    /// </summary>
    public required string EmployeeServiceUrl { get; set; }

    /// <summary>
    /// HTTP request timeout in milliseconds. Default: 5000 (5 seconds).
    /// </summary>
    public int TimeoutMs { get; set; } = 5000;

    /// <summary>
    /// Maximum number of retry attempts for failed requests. Default: 3.
    /// </summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>
    /// Base delay for exponential backoff in milliseconds. Default: 500ms.
    /// </summary>
    public int RetryDelayMs { get; set; } = 500;
}
