using Maliev.AuthService.Api.Models;
using System.Net;
using System.Threading;

namespace Maliev.AuthService.Api.Services
{
    public interface IExternalAuthenticationService
    {
        Task<ValidationResult> ValidateCredentialsAsync(
            string validationEndpoint,
            StringContent jsonContent,
            UserType userType,
            CancellationToken cancellationToken = default);
    }
}