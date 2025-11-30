using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;

var builder = WebApplication.CreateBuilder(args);

// --- Secrets & Configuration ---
builder.AddGoogleSecretManagerVolume(); // Load secrets from /mnt/secrets if available

// --- Infrastructure & Observability ---
builder.AddServiceDefaults(); // OpenTelemetry, health checks, resilience
builder.AddRedisDistributedCache(instanceName: "Auth:"); // Redis with in-memory fallback
builder.AddMassTransitWithRabbitMq(); // RabbitMQ message bus (non-blocking startup)
builder.AddPostgresDbContext<AuthDbContext>(); // PostgreSQL with retry logic

// --- API Configuration ---
builder.AddDefaultCors(); // CORS from CORS:AllowedOrigins config
builder.AddApiDocumentation(); // OpenAPI + Scalar (dev/staging only)
builder.Services.AddHttpClient();

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower;
    });

// --- Application Services ---
builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
builder.Services.AddScoped<ITokenValidator, TokenValidator>();
builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IAccountLockoutService, AccountLockoutService>();
builder.Services.AddScoped<IRateLimitService, RateLimitService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

// Build the application
var app = builder.Build();
var logger = app.Services.GetRequiredService<ILogger<Program>>();

// --- Database Migrations ---
if (!app.Environment.IsEnvironment("Testing"))
{
    try
    {
        await app.MigrateDatabaseAsync<AuthDbContext>();
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Database migration failed - application may not function correctly");
        // Don't throw - allow app to start for debugging
    }
}

// --- Testing Environment Setup ---
if (app.Environment.IsEnvironment("Testing"))
{
    app.Use(async (context, next) =>
    {
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.100");
        await next(context);
    });
}

// --- Middleware Pipeline ---
app.UseMiddleware<Maliev.AuthService.Api.Middleware.CorrelationIdMiddleware>();
app.UseMiddleware<Maliev.AuthService.Api.Middleware.ExceptionHandlingMiddleware>();
app.UseHttpsRedirection();
app.UseRouting();
app.UseCors();
app.UseAuthorization();

// --- Endpoints ---
app.MapControllers();
app.MapDefaultEndpoints(servicePrefix: "auth"); // Health checks and metrics
app.MapApiDocumentation(servicePrefix: "auth"); // OpenAPI + Scalar at /auth/openapi and /auth/scalar

logger.LogInformation("AuthService started successfully on {Environment} environment", app.Environment.EnvironmentName);

await app.RunAsync();

/// <summary>
/// Main program class for the application
/// </summary>
public partial class Program { }
