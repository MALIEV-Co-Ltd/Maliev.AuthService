using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;

var builder = WebApplication.CreateBuilder(args);

// --- Secrets & Configuration ---
builder.AddGoogleSecretManagerVolume(); // Load secrets from /mnt/secrets if available

// --- Infrastructure & Observability ---
builder.AddServiceDefaults(); // OpenTelemetry, health checks, resilience
builder.AddStandardMiddleware(options =>
{
    options.EnableRequestLogging = true;
});
builder.AddServiceMeters("auth-meter"); // Register service meters for OpenTelemetry business metrics

// Register DbContext for all environments (test factory provides connection string via environment variables)
builder.AddPostgresDbContext<AuthDbContext>(connectionName: "AuthDbContext"); // PostgreSQL with retry logic

// Only add Redis and MassTransit when not in Testing environment
// In testing, the TestWebApplicationFactory handles these configurations separately
if (!builder.Environment.IsEnvironment("Testing"))
{
    builder.AddRedisDistributedCache(instanceName: "auth:"); // Redis with in-memory fallback
    builder.AddMassTransitWithRabbitMq(); // RabbitMQ message bus (non-blocking startup)
}

// JWT Authentication
builder.AddJwtAuthentication();

// --- API Configuration ---
builder.AddDefaultCors(); // CORS from CORS:AllowedOrigins config
builder.AddDefaultApiVersioning(); // API versioning with URL segment reader

// Add OpenAPI (must be in Program.cs for XML comments to work via source generator)
if (!builder.Environment.IsProduction())
{
    builder.AddStandardOpenApi(
        title: "MALIEV Auth Service API",
        description: "Centralized authentication service for the Maliev platform. Provides user login with email/password, JWT access token issuance with IAM-resolved permissions and roles, refresh token rotation, token validation for service-to-service calls, and session management including logout and token revocation.");
}

builder.Services.AddHttpClient();

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower;
    });

// --- Application Services ---
builder.AddServiceClient<IIAMClient, IAMClient>("IAM");

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

// --- Middleware Pipeline ---
// In testing environment, allow setting IP address from header for rate limiting tests
if (app.Environment.IsEnvironment("Testing"))
{
    app.Use(async (context, next) =>
    {
        if (context.Request.Headers.TryGetValue("X-Test-Client-IP", out var ipValue))
        {
            if (System.Net.IPAddress.TryParse(ipValue.ToString(), out var ipAddress))
            {
                context.Connection.RemoteIpAddress = ipAddress;
            }
        }
        await next();
    });
}

app.UseStandardMiddleware();
app.UseHttpsRedirection();
app.UseRouting();
app.UseCors();
app.UseAuthorization();

// --- Endpoints ---
app.MapControllers();
app.MapDefaultEndpoints(servicePrefix: "auth"); // Health checks: /auth/liveness, /auth/readiness
app.MapApiDocumentation(servicePrefix: "auth"); // OpenAPI: /auth/openapi/v1.json, Scalar UI: /auth/scalar

logger.LogInformation("AuthService started successfully on {Environment} environment", app.Environment.EnvironmentName);

await app.RunAsync();

/// <summary>
/// Main program class for the application
/// </summary>
public partial class Program { }
