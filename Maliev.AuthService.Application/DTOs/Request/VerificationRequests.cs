using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request to initiate email verification for a user principal.
/// </summary>
public class InitiateVerificationRequest
{
    /// <summary>
    /// The principal identifier.
    /// </summary>
    [Required]
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// The email address to verify.
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// The user's first name for personalized email.
    /// </summary>
    [Required]
    public string FirstName { get; set; } = string.Empty;
}

/// <summary>
/// Request to verify an email using a verification token.
/// </summary>
public class VerifyEmailRequest
{
    /// <summary>
    /// The verification token from the email.
    /// </summary>
    [Required]
    public string Token { get; set; } = string.Empty;
}

/// <summary>
/// Request to resend a verification email.
/// </summary>
public class ResendVerificationRequest
{
    /// <summary>
    /// The principal identifier.
    /// </summary>
    [Required]
    public Guid PrincipalId { get; set; }
}
