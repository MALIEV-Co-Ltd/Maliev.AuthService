using Maliev.AuthService.Api.Services;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Maliev.AuthService.Api.HealthChecks
{
    public class ConfigurationHealthCheck : IHealthCheck
    {
        private readonly IConfigurationValidationService _configValidationService;
        private readonly ILogger<ConfigurationHealthCheck> _logger;

        public ConfigurationHealthCheck(
            IConfigurationValidationService configValidationService,
            ILogger<ConfigurationHealthCheck> logger)
        {
            _configValidationService = configValidationService;
            _logger = logger;
        }

        public async Task<HealthCheckResult> CheckHealthAsync(
            HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var validationResult = await _configValidationService.ValidateConfigurationAsync();

                if (validationResult.IsValid)
                {
                    var data = new Dictionary<string, object>();
                    
                    if (validationResult.Warnings.Any())
                    {
                        data["warnings"] = validationResult.Warnings;
                        return HealthCheckResult.Healthy("Configuration is valid with warnings", data);
                    }
                    
                    return HealthCheckResult.Healthy("Configuration is valid");
                }
                else
                {
                    var data = new Dictionary<string, object>
                    {
                        ["errors"] = validationResult.Errors,
                        ["warnings"] = validationResult.Warnings
                    };

                    _logger.LogError("Configuration validation failed: {Errors}", 
                        string.Join("; ", validationResult.Errors));

                    return HealthCheckResult.Unhealthy("Configuration validation failed", data: data);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Configuration health check failed");
                return HealthCheckResult.Unhealthy("Configuration health check failed", ex);
            }
        }
    }
}