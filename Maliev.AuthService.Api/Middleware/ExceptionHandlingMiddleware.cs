using System.Net;
using System.Text.Json;
using Maliev.AuthService.Api.Models;

namespace Maliev.AuthService.Api.Middleware;

/// <summary>
/// Global exception handling middleware for consistent error responses.
/// </summary>
public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;
    private readonly IHostEnvironment _environment;

    public ExceptionHandlingMiddleware(
        RequestDelegate next,
        ILogger<ExceptionHandlingMiddleware> logger,
        IHostEnvironment environment)
    {
        _next = next;
        _logger = logger;
        _environment = environment;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception occurred");
            await HandleExceptionAsync(context, ex);
        }
    }

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";

        var (statusCode, errorCode, message) = exception switch
        {
            ArgumentException => (HttpStatusCode.BadRequest, "invalid_argument", exception.Message),
            UnauthorizedAccessException => (HttpStatusCode.Unauthorized, "unauthorized", "Unauthorized access"),
            _ => (HttpStatusCode.InternalServerError, "internal_error", "An unexpected error occurred")
        };

        context.Response.StatusCode = (int)statusCode;

        var errorResponse = new ErrorResponse
        {
            Error = errorCode,
            Message = _environment.IsDevelopment() ? exception.Message : message,
            CorrelationId = context.TraceIdentifier
        };

        var json = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        });

        await context.Response.WriteAsync(json);
    }
}
