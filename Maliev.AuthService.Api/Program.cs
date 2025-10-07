using FluentValidation;
using Microsoft.EntityFrameworkCore;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Api.Validators;
using Maliev.AuthService.Api.Models.Request;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Serilog Configuration
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .WriteTo.Console()
    .CreateLogger();

builder.Host.UseSerilog();

// Database Configuration
if (!builder.Environment.IsEnvironment("Testing"))
{
    var connectionString = builder.Configuration.GetConnectionString("RefreshTokenDbContext")
        ?? throw new InvalidOperationException("Database connection string not configured");

    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseNpgsql(connectionString));
}

// Services
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower;
    });
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpClient();
builder.Services.AddMemoryCache();

// Health Checks
builder.Services.AddHealthChecks()
    .AddDbContextCheck<AuthDbContext>(tags: new[] { "readiness" });

// Application Services
builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
builder.Services.AddScoped<ITokenValidator, TokenValidator>();
builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IAccountLockoutService, AccountLockoutService>();
builder.Services.AddScoped<IRateLimitService, RateLimitService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

// Validators
builder.Services.AddScoped<IValidator<LoginRequest>, LoginRequestValidator>();
builder.Services.AddScoped<IValidator<RefreshRequest>, RefreshRequestValidator>();
builder.Services.AddScoped<IValidator<ValidateRequest>, ValidateRequestValidator>();
builder.Services.AddScoped<IValidator<RevokeRequest>, RevokeRequestValidator>();
builder.Services.AddScoped<IValidator<LogoutRequest>, LogoutRequestValidator>();
builder.Services.AddScoped<IValidator<ServiceLoginRequest>, ServiceLoginRequestValidator>();

var app = builder.Build();

// Configure base path for all routes
app.UsePathBase("/auth");

// Configure the HTTP request pipeline.

// For testing: Set a fake IP address
if (app.Environment.IsEnvironment("Testing"))
{
    app.Use(async (context, next) =>
    {
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.100");
        await next(context);
    });
}

app.UseMiddleware<Maliev.AuthService.Api.Middleware.CorrelationIdMiddleware>();
app.UseMiddleware<Maliev.AuthService.Api.Middleware.ExceptionHandlingMiddleware>();

// Swagger UI (disabled in production)
if (!app.Environment.IsProduction())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.RoutePrefix = "swagger");
}

app.UseHttpsRedirection();
app.UseAuthorization();

// Health check endpoints (path base adds /auth prefix)
app.MapGet("/liveness", () => "Healthy").AllowAnonymous();
app.MapHealthChecks("/readiness", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Tags.Contains("readiness")
});

app.MapControllers();

app.Run();

// Make Program class accessible to tests
public partial class Program { }
