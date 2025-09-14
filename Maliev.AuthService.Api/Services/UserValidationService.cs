using Maliev.AuthService.Api.Models;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Maliev.AuthService.Api.Services
{
    public class UserValidationService : IUserValidationService
    {
        private readonly IExternalAuthenticationService _externalAuthenticationService;
        private readonly IValidationCacheService _validationCacheService;
        private readonly ILogger<UserValidationService> _logger;

        public UserValidationService(
            IExternalAuthenticationService externalAuthenticationService,
            IValidationCacheService validationCacheService,
            ILogger<UserValidationService> logger)
        {
            _externalAuthenticationService = externalAuthenticationService;
            _validationCacheService = validationCacheService;
            _logger = logger;
        }

        public async Task<ValidationResult> ValidateUserAsync(
            string username,
            string password,
            CustomerServiceOptions customerServiceOptions,
            EmployeeServiceOptions employeeServiceOptions)
        {
            var userValidationRequest = new UserValidationRequest { Username = username, Password = password };
            var jsonContent = new StringContent(JsonSerializer.Serialize(userValidationRequest), Encoding.UTF8, "application/json");

            ValidationResult validationResult = new ValidationResult { Exists = false };

            // Try validating with CustomerService (check cache first)
            if (!string.IsNullOrEmpty(customerServiceOptions.ValidationEndpoint))
            {
                _logger.LogDebug("Attempting to validate with CustomerService at {Endpoint}", customerServiceOptions.ValidationEndpoint);

                // Check cache first
                var cachedResult = await _validationCacheService.GetValidationResultAsync(username, "Customer");
                if (cachedResult != null)
                {
                    validationResult = cachedResult;
                    _logger.LogDebug("CustomerService validation result from cache: Exists={Exists}, Type={Type}", validationResult.Exists, validationResult.UserType);
                }
                else
                {
                    validationResult = await _externalAuthenticationService.ValidateCredentialsAsync(
                        customerServiceOptions.ValidationEndpoint, 
                        jsonContent, 
                        UserType.Customer);
                    _logger.LogDebug("CustomerService validation result: Exists={Exists}, Type={Type}, Error={Error}", validationResult.Exists, validationResult.UserType, validationResult.Error);

                    // Cache the result
                    await _validationCacheService.SetValidationResultAsync(username, "Customer", validationResult);
                }
            }

            // If not found in CustomerService, try EmployeeService (check cache first)
            if (!validationResult.Exists && !string.IsNullOrEmpty(employeeServiceOptions.ValidationEndpoint))
            {
                _logger.LogDebug("Attempting to validate with EmployeeService at {Endpoint}", employeeServiceOptions.ValidationEndpoint);

                // Check cache first
                var cachedResult = await _validationCacheService.GetValidationResultAsync(username, "Employee");
                if (cachedResult != null)
                {
                    validationResult = cachedResult;
                    _logger.LogDebug("EmployeeService validation result from cache: Exists={Exists}, Type={Type}", validationResult.Exists, validationResult.UserType);
                }
                else
                {
                    validationResult = await _externalAuthenticationService.ValidateCredentialsAsync(
                        employeeServiceOptions.ValidationEndpoint, 
                        jsonContent, 
                        UserType.Employee);
                    _logger.LogDebug("EmployeeService validation result: Exists={Exists}, Type={Type}, Error={Error}", validationResult.Exists, validationResult.UserType, validationResult.Error);

                    // Cache the result
                    await _validationCacheService.SetValidationResultAsync(username, "Employee", validationResult);
                }
            }

            return validationResult;
        }
    }
}