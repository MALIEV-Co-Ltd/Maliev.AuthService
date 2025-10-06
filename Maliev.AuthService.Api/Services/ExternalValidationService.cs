using System.Net;
using System.Net.Http.Json;
using Maliev.AuthService.Api.Options;
using Microsoft.Extensions.Options;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service implementation for validating credentials with external services.
/// Uses Polly for resilience (retry + circuit breaker).
/// </summary>
public class ExternalValidationService : IExternalValidationService
{
    private readonly HttpClient _httpClient;
    private readonly CustomerServiceOptions _customerOptions;
    private readonly EmployeeServiceOptions _employeeOptions;
    private readonly ILogger<ExternalValidationService> _logger;
    private readonly ResiliencePipeline<HttpResponseMessage> _resiliencePipeline;

    public ExternalValidationService(
        HttpClient httpClient,
        IOptions<CustomerServiceOptions> customerOptions,
        IOptions<EmployeeServiceOptions> employeeOptions,
        IOptions<CircuitBreakerOptions> circuitBreakerOptions,
        ILogger<ExternalValidationService> logger)
    {
        _httpClient = httpClient;
        _customerOptions = customerOptions.Value;
        _employeeOptions = employeeOptions.Value;
        _logger = logger;

        // Configure resilience pipeline with retry + circuit breaker
        // Use customer service retry settings (both services should have same config)
        _resiliencePipeline = new ResiliencePipelineBuilder<HttpResponseMessage>()
            .AddRetry(new RetryStrategyOptions<HttpResponseMessage>
            {
                MaxRetryAttempts = _customerOptions.MaxRetries,
                Delay = TimeSpan.FromMilliseconds(_customerOptions.RetryDelayMs),
                BackoffType = DelayBackoffType.Exponential,
                ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                    .Handle<HttpRequestException>()
                    .HandleResult(r => r.StatusCode >= HttpStatusCode.InternalServerError)
            })
            .AddCircuitBreaker(new CircuitBreakerStrategyOptions<HttpResponseMessage>
            {
                FailureRatio = circuitBreakerOptions.Value.FailureThreshold / 10.0,
                MinimumThroughput = circuitBreakerOptions.Value.MinimumThroughput,
                SamplingDuration = TimeSpan.FromSeconds(circuitBreakerOptions.Value.SamplingDurationSeconds),
                BreakDuration = TimeSpan.FromSeconds(circuitBreakerOptions.Value.DurationOfBreakSeconds),
                ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                    .Handle<HttpRequestException>()
                    .HandleResult(r => r.StatusCode >= HttpStatusCode.InternalServerError)
            })
            .Build();
    }

    public async Task<ExternalValidationResult?> ValidateCustomerAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        return await ValidateAsync(_customerOptions.ValidationEndpoint, "customer", username, password, cancellationToken);
    }

    public async Task<ExternalValidationResult?> ValidateEmployeeAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        return await ValidateAsync(_employeeOptions.ValidationEndpoint, "employee", username, password, cancellationToken);
    }

    private async Task<ExternalValidationResult?> ValidateAsync(
        string validationEndpoint,
        string userType,
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        try
        {
            var request = new { username, password };
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, validationEndpoint)
            {
                Content = JsonContent.Create(request)
            };

            requestMessage.Headers.Add("X-Request-Timeout", _customerOptions.TimeoutMs.ToString());

            var response = await _resiliencePipeline.ExecuteAsync(
                async ct => await _httpClient.SendAsync(requestMessage, ct),
                cancellationToken);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var result = await response.Content.ReadFromJsonAsync<ExternalValidationDto>(cancellationToken);
                if (result != null)
                {
                    return new ExternalValidationResult(
                        result.UserId,
                        result.Username,
                        result.Email,
                        result.Roles ?? [],
                        result.Permissions ?? []
                    );
                }
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.NotFound)
            {
                _logger.LogWarning("Credential validation failed for {UserType} user: {Username}", userType, username);
                return null; // Invalid credentials
            }

            _logger.LogError("External service error ({UserType}): {StatusCode}", userType, response.StatusCode);
            return null;
        }
        catch (BrokenCircuitException)
        {
            _logger.LogError("Circuit breaker open for {UserType} service", userType);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating {UserType} credentials for {Username}", userType, username);
            return null;
        }
    }

    private record ExternalValidationDto(string UserId, string Username, string Email, string[]? Roles, string[]? Permissions);
}
