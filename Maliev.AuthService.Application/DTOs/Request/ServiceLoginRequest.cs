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
    [StringLength(100, MinimumLength = 3)]
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Service client secret.
    /// </summary>
    [Required]
    [StringLength(512, MinimumLength = 16)]
    public string ClientSecret { get; set; } = string.Empty;
}
