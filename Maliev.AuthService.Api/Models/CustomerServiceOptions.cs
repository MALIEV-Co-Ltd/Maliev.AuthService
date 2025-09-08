using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class CustomerServiceOptions
    {
        public const string SectionName = "CustomerService";

        [Required(ErrorMessage = "Customer Service ValidationEndpoint is required")]
        [Url(ErrorMessage = "Customer Service ValidationEndpoint must be a valid URL")]
        public string ValidationEndpoint { get; set; } = string.Empty;

        public bool IsConfigured => !string.IsNullOrEmpty(ValidationEndpoint);
    }
}