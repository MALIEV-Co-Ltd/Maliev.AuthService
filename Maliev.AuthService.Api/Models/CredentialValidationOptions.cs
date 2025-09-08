namespace Maliev.AuthService.Api.Models
{
    public class CredentialValidationOptions
    {
        public const string SectionName = "CredentialValidation";

        public bool EnableSanitization { get; set; } = true;

        public int UsernameMinLength { get; set; } = 3;
        public int UsernameMaxLength { get; set; } = 100;

        public int PasswordMinLength { get; set; } = 6;
        public int PasswordMaxLength { get; set; } = 200;

        public bool AllowSpecialCharacters { get; set; } = true;
        public bool RequireAlphanumeric { get; set; } = false;

        public string[] ForbiddenCharacters { get; set; } = Array.Empty<string>();
        public string[] SuspiciousPatterns { get; set; } = Array.Empty<string>();
    }
}