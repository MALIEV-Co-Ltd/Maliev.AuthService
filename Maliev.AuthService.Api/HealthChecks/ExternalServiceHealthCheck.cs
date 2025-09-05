using Microsoft.Extensions.Diagnostics.HealthChecks;
using Maliev.AuthService.Api.Services;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using Microsoft.Extensions.Options;
using Maliev.AuthService.Api.Models;

namespace Maliev.AuthService.Api.HealthChecks
{
    public class ExternalServiceHealthCheck : IHealthCheck
    {
        private readonly ExternalAuthServiceHttpClient _httpClient;
        private readonly CustomerServiceOptions _customerServiceOptions;
        private readonly EmployeeServiceOptions _employeeServiceOptions;

        public ExternalServiceHealthCheck(
            ExternalAuthServiceHttpClient httpClient,
            IOptions<CustomerServiceOptions> customerServiceOptions,
            IOptions<EmployeeServiceOptions> employeeServiceOptions)
        {
            _httpClient = httpClient;
            _customerServiceOptions = customerServiceOptions.Value;
            _employeeServiceOptions = employeeServiceOptions.Value;
        }

        public async Task<HealthCheckResult> CheckHealthAsync(
            HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Attempt to validate with CustomerService
                if (!string.IsNullOrEmpty(_customerServiceOptions.ValidationEndpoint))
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, _customerServiceOptions.ValidationEndpoint);
                    var response = await _httpClient.Client.SendAsync(request, cancellationToken);
                    if (response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.Unauthorized) // Unauthorized is also a valid response for health check, means service is reachable
                    {
                        return HealthCheckResult.Healthy("External Customer Service is healthy.");
                    }
                    return HealthCheckResult.Unhealthy($"External Customer Service returned {response.StatusCode}.");
                }

                // Attempt to validate with EmployeeService if CustomerService is not configured
                if (!string.IsNullOrEmpty(_employeeServiceOptions.ValidationEndpoint))
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, _employeeServiceOptions.ValidationEndpoint);
                    var response = await _httpClient.Client.SendAsync(request, cancellationToken);
                    if (response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        return HealthCheckResult.Healthy("External Employee Service is healthy.");
                    }
                    return HealthCheckResult.Unhealthy($"External Employee Service returned {response.StatusCode}.");
                }

                return HealthCheckResult.Degraded("No external service validation endpoint configured.");
            }
            catch (HttpRequestException ex)
            {
                return HealthCheckResult.Unhealthy("External service is unreachable.", ex);
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy("An unexpected error occurred during external service health check.", ex);
            }
        }
    }
}