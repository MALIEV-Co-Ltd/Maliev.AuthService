namespace Maliev.AuthService.Api.Models
{
    public class ValidationResult
    {
        public bool Exists { get; set; }
        public string UserType { get; set; } = string.Empty;
        public List<string> Roles { get; set; } = new List<string>();
        public string? Error { get; set; }
        public int? StatusCode { get; set; }
    }
}
