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

// Register DbContext for all environments
builder.AddPostgresDbContext<AuthDbContext>(connectionName: "AuthDbContext"); // PostgreSQL with retry logic

builder.AddRedisDistributedCache(instanceName: "auth:"); // Redis with in-memory fallback
builder.AddMassTransitWithRabbitMq(); // RabbitMQ message bus (non-blocking startup)

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
builder.Services.AddHttpClient("ExternalValidation")
    .AddStandardResilienceHandler();

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower;
    });

// --- Application Services ---
// IAM Client with service account authentication
// Register service account token provider
builder.Services.AddSingleton<Maliev.Aspire.ServiceDefaults.IAM.IServiceAccountTokenProvider>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    return new Maliev.Aspire.ServiceDefaults.IAM.ServiceAccountTokenProvider(config, "auth");
});

// Register authentication handler
builder.Services.AddTransient<Maliev.Aspire.ServiceDefaults.IAM.ServiceAccountAuthenticationHandler>();

// Register typed IAM client with service account authentication
builder.Services.AddHttpClient<IIAMServiceClient, IAMServiceClient>(client =>
{
    var baseUrl = builder.Configuration["Services:IAMService:BaseUrl"]
        ?? throw new InvalidOperationException("Services:IAMService:BaseUrl is required");
    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromMinutes(5);
})
.AddHttpMessageHandler<Maliev.Aspire.ServiceDefaults.IAM.ServiceAccountAuthenticationHandler>()
.AddStandardResilienceHandler();

// IAM Integration
builder.Services.AddIAMRegistration<AuthIAMRegistrationService>("auth");

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
await app.MigrateDatabaseAsync<AuthDbContext>();

// --- Middleware Pipeline ---
app.UseStandardMiddleware();
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}
app.UseRouting();
app.UseCors();
app.UseAuthorization();

// --- Endpoints ---
app.MapControllers();
app.MapDefaultEndpoints(servicePrefix: "auth"); // Health checks: /auth/liveness, /auth/readiness
app.MapApiDocumentation(servicePrefix: "auth"); // OpenAPI: /auth/openapi/v1.json, Scalar UI: /auth/scalar

await app.RunAsync();

/// <summary>
/// Main program class for the application
/// </summary>
public partial class Program { }
