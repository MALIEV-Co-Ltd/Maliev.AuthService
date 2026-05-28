using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Infrastructure.HttpClients;
using Maliev.AuthService.Infrastructure.Services;

// Initialize bootstrap logging
using var loggerFactory = LoggerFactory.Create(logBuilder => logBuilder.AddConsole());
var bootstrapLogger = loggerFactory.CreateLogger("Program");

try
{
    Program.Log.StartingHost(bootstrapLogger, "Auth Service");

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

    builder.AddStandardCache("auth:"); // Redis + in-memory fallback, memory-optimized // Redis with in-memory fallback
    builder.AddMassTransitWithRabbitMq(x =>
    {
        // Register all event consumers here
    }); // RabbitMQ message bus (non-blocking startup)

    // JWT Authentication
    builder.AddJwtAuthentication();

    // --- API Configuration ---
    builder.AddStandardCors(); // CORS with fail-fast validation
    builder.AddDefaultApiVersioning(); // API versioning with URL segment reader

    // Add OpenAPI (must be in Program.cs for XML comments to work via source generator)
    if (!builder.Environment.IsProduction())
    {
        builder.AddStandardOpenApi(
            title: "MALIEV Auth Service API",
            description: "Centralized authentication service for the Maliev platform. Provides user login with email/password, JWT access token issuance with IAM-resolved permissions and roles, refresh token rotation, token validation for service-to-service calls, and session management including logout and token revocation.");
    }

    // Register the authentication handler and token provider for service-to-service calls

    builder.Services.AddTransient<Maliev.Aspire.ServiceDefaults.IAM.IServiceAccountTokenProvider>(sp =>
    {
        var config = sp.GetRequiredService<IConfiguration>();
        return new Maliev.Aspire.ServiceDefaults.IAM.ServiceAccountTokenProvider(config, "auth");
    });
    builder.Services.AddTransient<Maliev.Aspire.ServiceDefaults.IAM.ServiceAccountAuthenticationHandler>();

    builder.Services.AddHttpClient();

    builder.Services.AddHttpClient("ExternalValidation")
        .AddServiceDiscovery()
        .AddHttpMessageHandler<Maliev.Aspire.ServiceDefaults.IAM.ServiceAccountAuthenticationHandler>()
        .AddStandardResilienceHandler();

    // Authenticated client for EmployeeService calls (Lookup/Provision)
    builder.AddAuthenticatedServiceClient<
        IEmployeeServiceClient,
        EmployeeServiceClient
    >("EmployeeService", sourceServiceName: "AuthService");

    builder.Services.AddControllers()
        .AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower;
        });

    // --- Application Services ---
    builder.Services.AddHttpClient<IIAMServiceClient, IAMServiceClient>(client =>
    {
        // Check if there's an explicit URL configured (for GKE deployment)
        var explicitUrl = builder.Configuration["Services:IAMService:BaseUrl"];

        if (!string.IsNullOrEmpty(explicitUrl))
        {
            // Use explicit URL for GKE/production
            client.BaseAddress = new Uri(explicitUrl);
        }
        else
        {
            // Prefer HTTPS when Aspire exposes it so redirects do not strip the
            // service-account Authorization header before IAM permission resolution.
            client.BaseAddress = new Uri("https+http://IAMService");
        }

        client.DefaultRequestHeaders.Add("X-Service-Name", "auth");
        client.Timeout = TimeSpan.FromSeconds(90);
    })
    .AddServiceDiscovery()
    .AddHttpMessageHandler<Maliev.Aspire.ServiceDefaults.IAM.ServiceAccountAuthenticationHandler>();


    // IAM Integration
    builder.Services.AddIAMRegistration<AuthIAMRegistrationService>("auth");

    builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
    builder.Services.AddScoped<ITokenValidator, TokenValidator>();
    builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
    builder.Services.AddScoped<IAccountLockoutService, AccountLockoutService>();
    builder.Services.AddScoped<IRateLimitService, RateLimitService>();
    builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
    builder.Services.AddScoped<IEmailVerificationService, EmailVerificationService>();

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

    Program.Log.ServiceStarted(logger, "Auth Service");
    await app.RunAsync();
}
catch (Exception ex)
{
    Program.Log.HostTerminated(bootstrapLogger, ex, "Auth Service");
    throw;
}
finally
{
    loggerFactory.Dispose();
}

/// <summary>
/// Main program class for the application
/// </summary>
public partial class Program
{
    internal static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information, Message = "Starting {ServiceName} host")]
        public static partial void StartingHost(ILogger logger, string serviceName);

        [LoggerMessage(Level = LogLevel.Critical, Message = "{ServiceName} host terminated unexpectedly during startup")]
        public static partial void HostTerminated(ILogger logger, Exception ex, string serviceName);

        [LoggerMessage(Level = LogLevel.Information, Message = "{ServiceName} started successfully")]
        public static partial void ServiceStarted(ILogger logger, string serviceName);
    }
}
