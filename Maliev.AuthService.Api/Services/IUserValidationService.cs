using Maliev.AuthService.Api.Models;
using System.Net;

namespace Maliev.AuthService.Api.Services
{
    public interface IUserValidationService
    {
        Task<ValidationResult> ValidateUserAsync(
            string username,
            string password,
            CustomerServiceOptions customerServiceOptions,
            EmployeeServiceOptions employeeServiceOptions);
    }
}