namespace Maliev.AuthService.Api.Services
{
    public interface ICredentialValidationService
    {
        CredentialValidationResult ValidateCredentials(string username, string password);
        string SanitizeInput(string input);
        bool ContainsSuspiciousPatterns(string input);
    }

    public class CredentialValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new();
        public string? SanitizedUsername { get; set; }
        public string? SanitizedPassword { get; set; }
        
        public void AddError(string error) => Errors.Add(error);
    }
}