using Serilog.Context;

namespace Maliev.AuthService.Api.Middleware
{
    public class CorrelationIdMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<CorrelationIdMiddleware> _logger;
        private const string CorrelationIdHeader = "X-Correlation-ID";

        public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var correlationId = GetOrCreateCorrelationId(context);
            
            // Add to response headers
            context.Response.Headers.TryAdd(CorrelationIdHeader, correlationId);
            
            // Add to Serilog LogContext for structured logging
            using (LogContext.PushProperty("CorrelationId", correlationId))
            {
                _logger.LogDebug("Request started with CorrelationId: {CorrelationId}", correlationId);
                await _next(context);
                _logger.LogDebug("Request completed with CorrelationId: {CorrelationId}", correlationId);
            }
        }

        private static string GetOrCreateCorrelationId(HttpContext context)
        {
            // Try to get correlation ID from request headers first
            if (context.Request.Headers.TryGetValue(CorrelationIdHeader, out var headerValue))
            {
                var correlationId = headerValue.FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(correlationId))
                {
                    return correlationId;
                }
            }

            // Generate new correlation ID if not provided
            return Guid.NewGuid().ToString("D");
        }
    }

    public static class CorrelationIdMiddlewareExtensions
    {
        public static IApplicationBuilder UseCorrelationId(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<CorrelationIdMiddleware>();
        }
    }
}