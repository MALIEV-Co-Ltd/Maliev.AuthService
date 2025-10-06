using Maliev.AuthService.Api.Options;
using Microsoft.Extensions.Options;
using Serilog.Context;

namespace Maliev.AuthService.Api.Middleware;

/// <summary>
/// Middleware for adding correlation ID to requests for tracing.
/// </summary>
public class CorrelationIdMiddleware
{
    private readonly RequestDelegate _next;
    private readonly CorrelationIdOptions _options;

    public CorrelationIdMiddleware(RequestDelegate next, IOptions<CorrelationIdOptions> options)
    {
        _next = next;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Get or generate correlation ID
        var correlationId = context.Request.Headers[_options.HeaderName].FirstOrDefault()
            ?? Guid.NewGuid().ToString();

        // Add to response headers
        if (_options.IncludeInResponse)
        {
            context.Response.Headers[_options.HeaderName] = correlationId;
        }

        // Add to Serilog context
        if (_options.UpdateLogContext)
        {
            using (LogContext.PushProperty("CorrelationId", correlationId))
            {
                // Store in HttpContext for access in controllers
                context.TraceIdentifier = correlationId;
                await _next(context);
            }
        }
        else
        {
            context.TraceIdentifier = correlationId;
            await _next(context);
        }
    }
}
