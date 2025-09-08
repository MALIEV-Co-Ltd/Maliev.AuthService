using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.JwtToken.Models
{
    public class JwtOptions
    {
        public const string SectionName = "Jwt";

        [Required(ErrorMessage = "JWT Issuer is required")]
        [MinLength(1, ErrorMessage = "JWT Issuer cannot be empty")]
        public string Issuer { get; set; } = string.Empty;

        [Required(ErrorMessage = "JWT Audience is required")]
        [MinLength(1, ErrorMessage = "JWT Audience cannot be empty")]
        public string Audience { get; set; } = string.Empty;

        [Required(ErrorMessage = "JWT SecurityKey is required")]
        [MinLength(32, ErrorMessage = "JWT SecurityKey must be at least 32 characters for security")]
        public string SecurityKey { get; set; } = string.Empty;

        /// <summary>
        /// Validates that all required JWT configuration is present
        /// </summary>
        public bool IsValid => !string.IsNullOrEmpty(Issuer) &&
                              !string.IsNullOrEmpty(Audience) &&
                              !string.IsNullOrEmpty(SecurityKey) &&
                              SecurityKey.Length >= 32;
    }
}