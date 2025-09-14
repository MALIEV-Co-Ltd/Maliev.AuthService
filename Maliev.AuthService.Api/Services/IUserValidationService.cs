using Maliev.AuthService.Api.Models;
using System.Net;
using System.Threading;

namespace Maliev.AuthService.Api.Services
{
    public interface IUserValidationService
    {
        Task<ValidationResult> ValidateUserAsync(
            string username,
            string password,
            CustomerServiceOptions customerServiceOptions,
            EmployeeServiceOptions employeeServiceOptions,
            CancellationToken cancellationToken = default);
    }
}