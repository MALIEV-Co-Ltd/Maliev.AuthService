using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class CustomerServiceOptions
    {
        public const string SectionName = "CustomerService";
        
        [Url(ErrorMessage = "Customer service validation endpoint must be a valid URL")]
        public string? ValidationEndpoint { get; set; }
        
        public bool IsConfigured => !string.IsNullOrEmpty(ValidationEndpoint);
    }
}