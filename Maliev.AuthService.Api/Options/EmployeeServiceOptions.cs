namespace Maliev.AuthService.Api.Options;

/// <summary>
/// Configuration for Employee Service external validation.
/// Maps to "EmployeeService" section in appsettings.json.
/// </summary>
public class EmployeeServiceOptions
{
    public const string SectionName = "EmployeeService";

    /// <summary>
    /// Full URL for Employee Service validation endpoint.
    /// Example: http://maliev-employee-service.maliev-dev.svc.cluster.local:8080/employees/v1/validate
    /// </summary>
    public required string ValidationEndpoint { get; set; }

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
