using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class EmployeeServiceOptions
    {
        public const string SectionName = "EmployeeService";
        
        [Url(ErrorMessage = "Employee service validation endpoint must be a valid URL")]
        public string? ValidationEndpoint { get; set; }
        
        public bool IsConfigured => !string.IsNullOrEmpty(ValidationEndpoint);
    }
}