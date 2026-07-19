using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for starting a customer password reset.
/// </summary>
public class PasswordResetRequest
{
    /// <summary>
    /// Customer email address.
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}

/// <summary>
/// Request model for confirming a customer password reset.
/// </summary>
public class ConfirmPasswordResetRequest
{
    /// <summary>
    /// Customer email address.
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Password reset token.
    /// </summary>
    [Required]
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// New password.
    /// </summary>
    [Required]
    [MinLength(12)]
    public string NewPassword { get; set; } = string.Empty;
}
