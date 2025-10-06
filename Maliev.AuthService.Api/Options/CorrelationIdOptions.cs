namespace Maliev.AuthService.Api.Options;

/// <summary>
/// Correlation ID configuration for request tracing.
/// Maps to "CorrelationId" section in appsettings.json.
/// </summary>
public class CorrelationIdOptions
{
    public const string SectionName = "CorrelationId";

    /// <summary>
    /// HTTP header name for correlation ID. Default: "X-Correlation-Id".
    /// </summary>
    public string HeaderName { get; set; } = "X-Correlation-Id";

    /// <summary>
    /// Include correlation ID in response headers. Default: true.
    /// </summary>
    public bool IncludeInResponse { get; set; } = true;

    /// <summary>
    /// Update Serilog context with correlation ID. Default: true.
    /// </summary>
    public bool UpdateLogContext { get; set; } = true;
}
