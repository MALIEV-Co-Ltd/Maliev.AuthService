using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json;

namespace Maliev.AuthService.Api.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;
        private readonly IHostEnvironment _env;

        public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger, IHostEnvironment env)
        {
            _next = next;
            _logger = logger;
            _env = env;
        }

        public async Task InvokeAsync(HttpContext httpContext)
        {
            try
            {
                await _next(httpContext);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred: {Message}", ex.Message);
                await HandleExceptionAsync(httpContext, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/problem+json";
            context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

            var problemDetails = new ProblemDetails
            {
                Status = (int)HttpStatusCode.InternalServerError,
                Title = "An error occurred while processing your request.",
                Type = "https://tools.ietf.org/html/rfc7807#section-3.1",
                Detail = _env.IsDevelopment() ? exception.ToString() : "An unexpected error occurred."
            };

            if (_env.IsDevelopment())
            {
                problemDetails.Extensions.Add("traceId", context.TraceIdentifier);
            }

            var problemDetailsJson = JsonSerializer.Serialize(problemDetails);
            await context.Response.WriteAsync(problemDetailsJson);
        }
    }
}