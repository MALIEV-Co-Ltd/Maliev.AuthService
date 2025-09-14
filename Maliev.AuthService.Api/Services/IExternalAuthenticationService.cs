using Maliev.AuthService.Api.Models;
using System.Net;

namespace Maliev.AuthService.Api.Services
{
    public interface IExternalAuthenticationService
    {
        Task<ValidationResult> ValidateCredentialsAsync(
            string validationEndpoint,
            StringContent jsonContent,
            UserType userType);
    }
}