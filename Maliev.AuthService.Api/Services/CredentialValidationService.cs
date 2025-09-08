using Maliev.AuthService.Api.Models;
using Microsoft.Extensions.Options;
using System.Text.RegularExpressions;
using System.Web;

namespace Maliev.AuthService.Api.Services
{
    public class CredentialValidationService : ICredentialValidationService
    {
        private readonly CredentialValidationOptions _options;
        private readonly ILogger<CredentialValidationService> _logger;

        public CredentialValidationService(
            IOptions<CredentialValidationOptions> options,
            ILogger<CredentialValidationService> logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        public CredentialValidationResult ValidateCredentials(string username, string password)
        {
            var result = new CredentialValidationResult { IsValid = true };

            // Validate username
            if (string.IsNullOrWhiteSpace(username))
            {
                result.AddError("Username cannot be null or empty");
                result.IsValid = false;
            }
            else
            {
                var usernameValidation = ValidateInput(username, "Username", _options.UsernameMinLength, _options.UsernameMaxLength);
                if (!usernameValidation.IsValid)
                {
                    result.Errors.AddRange(usernameValidation.Errors);
                    result.IsValid = false;
                }
                else
                {
                    result.SanitizedUsername = _options.EnableSanitization ? SanitizeInput(username) : username;
                }
            }

            // Validate password
            if (string.IsNullOrWhiteSpace(password))
            {
                result.AddError("Password cannot be null or empty");
                result.IsValid = false;
            }
            else
            {
                var passwordValidation = ValidateInput(password, "Password", _options.PasswordMinLength, _options.PasswordMaxLength);
                if (!passwordValidation.IsValid)
                {
                    result.Errors.AddRange(passwordValidation.Errors);
                    result.IsValid = false;
                }
                else
                {
                    result.SanitizedPassword = _options.EnableSanitization ? SanitizeInput(password) : password;
                }
            }

            if (result.Errors.Any())
            {
                _logger.LogWarning("Credential validation failed for username: {Username}. Errors: {Errors}", 
                    username ?? "[null]", string.Join(", ", result.Errors));
            }

            return result;
        }

        private InputValidationResult ValidateInput(string input, string fieldName, int minLength, int maxLength)
        {
            var result = new InputValidationResult { IsValid = true };

            // Length validation
            if (input.Length < minLength)
            {
                result.AddError($"{fieldName} must be at least {minLength} characters long");
            }

            if (input.Length > maxLength)
            {
                result.AddError($"{fieldName} cannot exceed {maxLength} characters");
            }

            // Character validation
            if (!_options.AllowSpecialCharacters && ContainsSpecialCharacters(input))
            {
                result.AddError($"{fieldName} contains forbidden special characters");
            }

            if (_options.RequireAlphanumeric && !ContainsAlphanumeric(input))
            {
                result.AddError($"{fieldName} must contain both letters and numbers");
            }

            // Forbidden character validation
            if (ContainsForbiddenCharacters(input))
            {
                result.AddError($"{fieldName} contains forbidden characters: {_options.ForbiddenCharacters}");
            }

            // Suspicious pattern validation
            if (ContainsSuspiciousPatterns(input))
            {
                result.AddError($"{fieldName} contains suspicious patterns that may indicate injection attempts");
            }

            // Control character validation
            if (ContainsControlCharacters(input))
            {
                result.AddError($"{fieldName} contains control characters which are not allowed");
            }

            return result;
        }

        public string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // HTML encode to prevent XSS
            var sanitized = HttpUtility.HtmlEncode(input);

            // Remove or replace specific dangerous characters
            sanitized = sanitized.Replace("<", "&lt;")
                                 .Replace(">", "&gt;")
                                 .Replace("\"", "&quot;")
                                 .Replace("'", "&#x27;")
                                 .Replace("/", "&#x2F;");

            // Remove control characters except common whitespace
            sanitized = Regex.Replace(sanitized, @"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", string.Empty);

            return sanitized.Trim();
        }

        public bool ContainsSuspiciousPatterns(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            var lowerInput = input.ToLowerInvariant();
            return _options.SuspiciousPatterns.Any(pattern => 
                lowerInput.Contains(pattern.ToLowerInvariant()));
        }

        private bool ContainsSpecialCharacters(string input)
        {
            return input.Any(c => !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c));
        }

        private bool ContainsAlphanumeric(string input)
        {
            return input.Any(char.IsLetter) && input.Any(char.IsDigit);
        }

        private bool ContainsForbiddenCharacters(string input)
        {
            return _options.ForbiddenCharacters.Any(forbidden => input.Contains(forbidden));
        }

        private bool ContainsControlCharacters(string input)
        {
            // Allow common whitespace characters (space, tab, newline, carriage return)
            return input.Any(c => char.IsControl(c) && c != ' ' && c != '\t' && c != '\n' && c != '\r');
        }

        private class InputValidationResult
        {
            public bool IsValid { get; set; }
            public List<string> Errors { get; set; } = new();
            
            public void AddError(string error) => Errors.Add(error);
        }
    }
}