namespace Maliev.AuthService.Api.Models.Response;

public class AuthenticationResult
{
    public bool Success { get; set; }
    public LoginResponse? Response { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorDescription { get; set; }
    public DateTime? LockedUntil { get; set; }
    public DateTime? RetryAfter { get; set; }
}
