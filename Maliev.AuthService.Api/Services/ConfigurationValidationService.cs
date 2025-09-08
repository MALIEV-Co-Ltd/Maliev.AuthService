using Maliev.AuthService.Api.Models;
using Maliev.AuthService.JwtToken.Models;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Services
{
    public class ConfigurationValidationService : IConfigurationValidationService
    {
        private readonly IOptionsMonitor<JwtOptions> _jwtOptions;
        private readonly IOptionsMonitor<CustomerServiceOptions> _customerServiceOptions;
        private readonly IOptionsMonitor<EmployeeServiceOptions> _employeeServiceOptions;
        private readonly IOptionsMonitor<RateLimitOptions> _rateLimitOptions;
        private readonly IOptionsMonitor<CacheOptions> _cacheOptions;
        private readonly HttpClient _httpClient;
        private readonly ILogger<ConfigurationValidationService> _logger;

        public ConfigurationValidationService(
            IOptionsMonitor<JwtOptions> jwtOptions,
            IOptionsMonitor<CustomerServiceOptions> customerServiceOptions,
            IOptionsMonitor<EmployeeServiceOptions> employeeServiceOptions,
            IOptionsMonitor<RateLimitOptions> rateLimitOptions,
            IOptionsMonitor<CacheOptions> cacheOptions,
            HttpClient httpClient,
            ILogger<ConfigurationValidationService> logger)
        {
            _jwtOptions = jwtOptions;
            _customerServiceOptions = customerServiceOptions;
            _employeeServiceOptions = employeeServiceOptions;
            _rateLimitOptions = rateLimitOptions;
            _cacheOptions = cacheOptions;
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<ConfigValidationResult> ValidateConfigurationAsync()
        {
            var result = new ConfigValidationResult { IsValid = true };

            // Validate all configuration sections
            var jwtResult = await ValidateJwtConfigurationAsync();
            var servicesResult = await ValidateExternalServicesAsync();

            // Combine results
            result.Errors.AddRange(jwtResult.Errors);
            result.Warnings.AddRange(jwtResult.Warnings);
            result.Errors.AddRange(servicesResult.Errors);
            result.Warnings.AddRange(servicesResult.Warnings);

            // Validate other configuration options
            ValidateRateLimitConfiguration(result);
            ValidateCacheConfiguration(result);

            result.IsValid = !result.Errors.Any();
            return result;
        }

        public async Task<ConfigValidationResult> ValidateJwtConfigurationAsync()
        {
            var result = new ConfigValidationResult { IsValid = true };
            var jwt = _jwtOptions.CurrentValue;

            // Validate using DataAnnotations
            var validationResults = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
            var validationContext = new ValidationContext(jwt);
            
            if (!Validator.TryValidateObject(jwt, validationContext, validationResults, true))
            {
                foreach (var validationError in validationResults)
                {
                    result.AddError($"JWT Configuration: {validationError.ErrorMessage}");
                }
            }

            // Additional security validations
            if (!string.IsNullOrEmpty(jwt.SecurityKey))
            {
                if (jwt.SecurityKey.Length < 32)
                {
                    result.AddError("JWT SecurityKey must be at least 32 characters for security");
                }
                
                if (jwt.SecurityKey.Contains("test", StringComparison.OrdinalIgnoreCase) || 
                    jwt.SecurityKey.Contains("sample", StringComparison.OrdinalIgnoreCase))
                {
                    result.AddWarning("JWT SecurityKey appears to contain test/sample values - ensure production keys are used");
                }
            }

            // Validate issuer and audience are not default values
            if (jwt.Issuer?.Contains("localhost", StringComparison.OrdinalIgnoreCase) == true ||
                jwt.Issuer?.Contains("test", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.AddWarning("JWT Issuer appears to be a development value - ensure production values are used");
            }

            result.IsValid = !result.Errors.Any();
            return result;
        }

        public async Task<ConfigValidationResult> ValidateExternalServicesAsync()
        {
            var result = new ConfigValidationResult { IsValid = true };
            var customer = _customerServiceOptions.CurrentValue;
            var employee = _employeeServiceOptions.CurrentValue;

            // At least one service must be configured
            if (!customer.IsConfigured && !employee.IsConfigured)
            {
                result.AddError("At least one external validation service (Customer or Employee) must be configured");
                result.IsValid = false;
                return result;
            }

            // Validate Customer Service
            if (customer.IsConfigured)
            {
                if (!Uri.TryCreate(customer.ValidationEndpoint, UriKind.Absolute, out var customerUri))
                {
                    result.AddError($"Customer service validation endpoint is not a valid URL: {customer.ValidationEndpoint}");
                }
                else
                {
                    // Test connectivity
                    var isReachable = await TestExternalServiceConnectivityAsync(customer.ValidationEndpoint);
                    if (!isReachable)
                    {
                        result.AddWarning($"Customer service endpoint may not be reachable: {customer.ValidationEndpoint}");
                    }
                }
            }

            // Validate Employee Service
            if (employee.IsConfigured)
            {
                if (!Uri.TryCreate(employee.ValidationEndpoint, UriKind.Absolute, out var employeeUri))
                {
                    result.AddError($"Employee service validation endpoint is not a valid URL: {employee.ValidationEndpoint}");
                }
                else
                {
                    // Test connectivity
                    var isReachable = await TestExternalServiceConnectivityAsync(employee.ValidationEndpoint);
                    if (!isReachable)
                    {
                        result.AddWarning($"Employee service endpoint may not be reachable: {employee.ValidationEndpoint}");
                    }
                }
            }

            result.IsValid = !result.Errors.Any();
            return result;
        }

        public async Task<bool> TestExternalServiceConnectivityAsync(string endpoint, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogDebug("Testing connectivity to external service: {Endpoint}", endpoint);
                
                using var response = await _httpClient.GetAsync(endpoint, cancellationToken);
                // Accept any response (even 404, 401, etc.) as long as we can connect
                _logger.LogDebug("External service connectivity test result: {StatusCode}", response.StatusCode);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to connect to external service: {Endpoint}", endpoint);
                return false;
            }
        }

        private void ValidateRateLimitConfiguration(ConfigValidationResult result)
        {
            var rateLimits = _rateLimitOptions.CurrentValue;

            // Validate using DataAnnotations
            var validationResults = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
            var validationContext = new ValidationContext(rateLimits);
            
            if (!Validator.TryValidateObject(rateLimits, validationContext, validationResults, true))
            {
                foreach (var validationError in validationResults)
                {
                    result.AddError($"Rate Limit Configuration: {validationError.ErrorMessage}");
                }
            }

            // Validate nested objects
            ValidateNestedObject(rateLimits.TokenEndpoint, "Rate Limit Token Endpoint", result);
            ValidateNestedObject(rateLimits.RefreshEndpoint, "Rate Limit Refresh Endpoint", result);
            ValidateNestedObject(rateLimits.Global, "Rate Limit Global", result);
        }

        private void ValidateCacheConfiguration(ConfigValidationResult result)
        {
            var cache = _cacheOptions.CurrentValue;

            // Validate using DataAnnotations
            var validationResults = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
            var validationContext = new ValidationContext(cache);
            
            if (!Validator.TryValidateObject(cache, validationContext, validationResults, true))
            {
                foreach (var validationError in validationResults)
                {
                    result.AddError($"Cache Configuration: {validationError.ErrorMessage}");
                }
            }

            ValidateNestedObject(cache.ValidationCache, "Validation Cache", result);
        }

        private void ValidateNestedObject(object obj, string contextName, ConfigValidationResult result)
        {
            var validationResults = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
            var validationContext = new ValidationContext(obj);
            
            if (!Validator.TryValidateObject(obj, validationContext, validationResults, true))
            {
                foreach (var validationError in validationResults)
                {
                    result.AddError($"{contextName}: {validationError.ErrorMessage}");
                }
            }
        }
    }
}