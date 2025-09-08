using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class EmployeeServiceOptions
    {
        public const string SectionName = "EmployeeService";

        [Required(ErrorMessage = "Employee Service ValidationEndpoint is required")]
        [Url(ErrorMessage = "Employee Service ValidationEndpoint must be a valid URL")]
        public string ValidationEndpoint { get; set; } = string.Empty;

        public bool IsConfigured => !string.IsNullOrEmpty(ValidationEndpoint);
    }
}