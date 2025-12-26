namespace Maliev.AuthService.Api.Models.Response;

/// <summary>
/// Standard error response model.
/// </summary>
public class ErrorResponse
{
    /// <summary>
    /// Error code or type
    /// </summary>
    public string Error { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable error description
    /// </summary>
    public string ErrorDescription { get; set; } = string.Empty;

    /// <summary>
    /// Validation errors (for 400 Bad Request)
    /// </summary>
    public List<string>? Errors { get; set; }

    /// <summary>
    /// Locked until timestamp (for 423 Locked)
    /// </summary>
    public DateTime? LockedUntil { get; set; }

    /// <summary>
    /// Detailed exception information (only populated in development)
    /// </summary>
    public string? Details { get; set; }
}
