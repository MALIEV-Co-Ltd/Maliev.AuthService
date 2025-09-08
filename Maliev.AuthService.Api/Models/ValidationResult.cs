namespace Maliev.AuthService.Api.Models
{
    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public string? ErrorMessage { get; set; }
        public Dictionary<string, object>? UserData { get; set; }

        // Properties for external service validation
        public bool Exists { get; set; }

        public string? UserType { get; set; }
        public List<string> Roles { get; set; } = new();
        public string? Error { get; set; }
        public int? StatusCode { get; set; }

        public static ValidationResult Success(Dictionary<string, object>? userData = null)
        {
            return new ValidationResult
            {
                IsValid = true,
                UserData = userData
            };
        }

        public static ValidationResult Failure(string errorMessage)
        {
            return new ValidationResult
            {
                IsValid = false,
                ErrorMessage = errorMessage
            };
        }
    }
}