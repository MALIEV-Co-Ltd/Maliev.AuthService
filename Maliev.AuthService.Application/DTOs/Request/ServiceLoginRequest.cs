using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for service-to-service authentication.
/// </summary>
public class ServiceLoginRequest
{
    /// <summary>
    /// Service client identifier (pattern: service-{environment}-{name}).
    /// </summary>
    [Required]
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Service client secret.
    /// </summary>
    [Required]
    public string ClientSecret { get; set; } = string.Empty;
}
