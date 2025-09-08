namespace Maliev.AuthService.Api.Services
{
    public interface IMetricsService
    {
        void IncrementAuthenticationAttempt(string userType);
        void IncrementAuthenticationSuccess(string userType);
        void IncrementAuthenticationFailure(string userType, string reason);
        void IncrementTokenRefresh();
        void IncrementRateLimitHit(string endpoint);
        void IncrementCacheHit(string cacheType);
        void IncrementCacheMiss(string cacheType);
        void RecordExternalServiceCallDuration(string service, TimeSpan duration, bool success);
        void RecordRequestDuration(string endpoint, TimeSpan duration);
        
        // Health and monitoring
        void RecordHealthCheckStatus(string checkName, bool healthy);
        void RecordConfigurationValidationResult(bool valid, int errorCount);
    }
}