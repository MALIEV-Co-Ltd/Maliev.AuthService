namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>
/// Response model for starting a customer password reset.
/// </summary>
public class PasswordResetResponse
{
    /// <summary>
    /// Whether the reset request was accepted.
    /// </summary>
    public bool Accepted { get; set; }
}

/// <summary>
/// Response model for confirming a customer password reset.
/// </summary>
public class ConfirmPasswordResetResponse
{
    /// <summary>
    /// Whether the password reset was completed.
    /// </summary>
    public bool Reset { get; set; }
}
