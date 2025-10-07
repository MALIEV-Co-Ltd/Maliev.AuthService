namespace Maliev.AuthService.Api.Models.Request;

/// <summary>
/// Request model for service-to-service authentication.
/// </summary>
public class ServiceLoginRequest
{
    /// <summary>
    /// Service client identifier (pattern: service-{environment}-{name})
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Service client secret
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;
}
