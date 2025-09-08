using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class CredentialValidationOptions
    {
        public const string SectionName = "CredentialValidation";
        
        [Range(1, 256, ErrorMessage = "Username minimum length must be between 1 and 256")]
        public int UsernameMinLength { get; set; } = 3;
        
        [Range(1, 256, ErrorMessage = "Username maximum length must be between 1 and 256")]
        public int UsernameMaxLength { get; set; } = 50;
        
        [Range(1, 256, ErrorMessage = "Password minimum length must be between 1 and 256")]
        public int PasswordMinLength { get; set; } = 4;
        
        [Range(1, 256, ErrorMessage = "Password maximum length must be between 1 and 256")]
        public int PasswordMaxLength { get; set; } = 100;
        
        public bool AllowSpecialCharacters { get; set; } = true;
        public bool RequireAlphanumeric { get; set; } = false;
        public bool EnableSanitization { get; set; } = true;
        
        /// <summary>
        /// Characters that are considered dangerous and will be rejected
        /// </summary>
        public string ForbiddenCharacters { get; set; } = "<>&\"'%;()+=";
        
        /// <summary>
        /// Patterns that are considered suspicious (SQL injection, script injection)
        /// </summary>
        public List<string> SuspiciousPatterns { get; set; } = new()
        {
            "script:",
            "javascript:",
            "vbscript:",
            "onload=",
            "onerror=",
            "eval(",
            "exec(",
            "execute(",
            "drop table",
            "union select",
            "insert into",
            "delete from",
            "update set",
            "create table",
            "alter table",
            "--",
            "/*",
            "*/"
        };
    }
}