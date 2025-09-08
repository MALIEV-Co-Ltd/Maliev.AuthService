using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace Maliev.AuthService.Api.Services
{
    public class MetricsService : IMetricsService, IDisposable
    {
        private readonly Meter _meter;
        private readonly Counter<long> _authAttempts;
        private readonly Counter<long> _authSuccesses;
        private readonly Counter<long> _authFailures;
        private readonly Counter<long> _tokenRefreshes;
        private readonly Counter<long> _rateLimitHits;
        private readonly Counter<long> _cacheHits;
        private readonly Counter<long> _cacheMisses;
        private readonly Histogram<double> _externalServiceDuration;
        private readonly Histogram<double> _requestDuration;
        private readonly Counter<long> _healthChecks;
        private readonly Counter<long> _configValidations;

        private readonly ILogger<MetricsService> _logger;
        private readonly ConcurrentDictionary<string, object> _metrics = new();

        public MetricsService(ILogger<MetricsService> logger)
        {
            _logger = logger;
            _meter = new Meter("Maliev.AuthService", "1.0.0");

            // Initialize counters and histograms
            _authAttempts = _meter.CreateCounter<long>(
                "auth_attempts_total",
                description: "Total number of authentication attempts");

            _authSuccesses = _meter.CreateCounter<long>(
                "auth_successes_total",
                description: "Total number of successful authentications");

            _authFailures = _meter.CreateCounter<long>(
                "auth_failures_total",
                description: "Total number of failed authentications");

            _tokenRefreshes = _meter.CreateCounter<long>(
                "token_refreshes_total",
                description: "Total number of token refresh attempts");

            _rateLimitHits = _meter.CreateCounter<long>(
                "rate_limit_hits_total",
                description: "Total number of rate limit hits");

            _cacheHits = _meter.CreateCounter<long>(
                "cache_hits_total",
                description: "Total number of cache hits");

            _cacheMisses = _meter.CreateCounter<long>(
                "cache_misses_total",
                description: "Total number of cache misses");

            _externalServiceDuration = _meter.CreateHistogram<double>(
                "external_service_duration_ms",
                "ms",
                "Duration of external service calls in milliseconds");

            _requestDuration = _meter.CreateHistogram<double>(
                "request_duration_ms",
                "ms",
                "Duration of HTTP requests in milliseconds");

            _healthChecks = _meter.CreateCounter<long>(
                "health_checks_total",
                description: "Total number of health check executions");

            _configValidations = _meter.CreateCounter<long>(
                "config_validations_total",
                description: "Total number of configuration validations");
        }

        public void IncrementAuthenticationAttempt(string userType)
        {
            _authAttempts.Add(1, new KeyValuePair<string, object?>("user_type", userType));
            _logger.LogDebug("Authentication attempt recorded for user type: {UserType}", userType);
        }

        public void IncrementAuthenticationSuccess(string userType)
        {
            _authSuccesses.Add(1, new KeyValuePair<string, object?>("user_type", userType));
            _logger.LogInformation("Authentication success recorded for user type: {UserType}", userType);
        }

        public void IncrementAuthenticationFailure(string userType, string reason)
        {
            _authFailures.Add(1,
                new KeyValuePair<string, object?>("user_type", userType),
                new KeyValuePair<string, object?>("reason", reason));
            _logger.LogWarning("Authentication failure recorded for user type: {UserType}, reason: {Reason}", userType, reason);
        }

        public void IncrementTokenRefresh()
        {
            _tokenRefreshes.Add(1);
            _logger.LogDebug("Token refresh recorded");
        }

        public void IncrementRateLimitHit(string endpoint)
        {
            _rateLimitHits.Add(1, new KeyValuePair<string, object?>("endpoint", endpoint));
            _logger.LogWarning("Rate limit hit recorded for endpoint: {Endpoint}", endpoint);
        }

        public void IncrementCacheHit(string cacheType)
        {
            _cacheHits.Add(1, new KeyValuePair<string, object?>("cache_type", cacheType));
            _logger.LogDebug("Cache hit recorded for type: {CacheType}", cacheType);
        }

        public void IncrementCacheMiss(string cacheType)
        {
            _cacheMisses.Add(1, new KeyValuePair<string, object?>("cache_type", cacheType));
            _logger.LogDebug("Cache miss recorded for type: {CacheType}", cacheType);
        }

        public void RecordExternalServiceCallDuration(string service, TimeSpan duration, bool success)
        {
            _externalServiceDuration.Record(duration.TotalMilliseconds,
                new KeyValuePair<string, object?>("service", service),
                new KeyValuePair<string, object?>("success", success));
            _logger.LogDebug("External service call duration recorded: {Service}, {Duration}ms, Success: {Success}",
                service, duration.TotalMilliseconds, success);
        }

        public void RecordRequestDuration(string endpoint, TimeSpan duration)
        {
            _requestDuration.Record(duration.TotalMilliseconds,
                new KeyValuePair<string, object?>("endpoint", endpoint));
            _logger.LogDebug("Request duration recorded: {Endpoint}, {Duration}ms", endpoint, duration.TotalMilliseconds);
        }

        public void RecordHealthCheckStatus(string checkName, bool healthy)
        {
            _healthChecks.Add(1,
                new KeyValuePair<string, object?>("check_name", checkName),
                new KeyValuePair<string, object?>("healthy", healthy));
            _logger.LogDebug("Health check status recorded: {CheckName}, Healthy: {Healthy}", checkName, healthy);
        }

        public void RecordConfigurationValidationResult(bool valid, int errorCount)
        {
            _configValidations.Add(1,
                new KeyValuePair<string, object?>("valid", valid),
                new KeyValuePair<string, object?>("error_count", errorCount));
            _logger.LogInformation("Configuration validation result recorded: Valid: {Valid}, Errors: {ErrorCount}", valid, errorCount);
        }

        public void Dispose()
        {
            _meter?.Dispose();
        }
    }
}