namespace Maliev.AuthService.Api.Options;

/// <summary>
/// Configuration for Customer Service external validation.
/// Maps to "CustomerService" section in appsettings.json.
/// </summary>
public class CustomerServiceOptions
{
    public const string SectionName = "CustomerService";

    /// <summary>
    /// Full URL for Customer Service validation endpoint.
    /// Example: http://maliev-customer-service.maliev-dev.svc.cluster.local:8080/customers/v1/validate
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
