using Fido2NetLib;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Infrastructure.HttpClients;
using Maliev.AuthService.Infrastructure.Security;
using Maliev.AuthService.Infrastructure.Services;
using MassTransit;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http.Features;

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
        x.AddEntityFrameworkOutbox<AuthDbContext>(options =>
        {
            _ = options.UsePostgres();
            options.UseBusOutbox();
        });

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
    builder.Services.AddScoped<IGoogleIdTokenVerifier, GoogleJsonWebSignatureVerifier>();
    builder.Services.AddScoped<IGoogleIdentityTokenValidator, GoogleIdentityTokenValidator>();
    builder.Services.AddSingleton(TimeProvider.System);
    builder.Services.AddScoped<IGoogleIdentityNonceService, GoogleIdentityNonceService>();
    builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
    builder.Services.AddScoped<IEmailVerificationService, EmailVerificationService>();
    builder.Services.AddOptions<ServiceLoginRateLimitOptions>()
        .Bind(builder.Configuration.GetSection("RateLimiting:ServiceLogin"))
        .ValidateDataAnnotations()
        .ValidateOnStart();
    builder.Services.AddScoped<IServiceLoginRateLimiter>(services =>
        new RedisServiceLoginRateLimiter(
            services.GetService<StackExchange.Redis.IConnectionMultiplexer>(),
            services.GetRequiredService<IOptions<ServiceLoginRateLimitOptions>>(),
            services.GetRequiredService<ILogger<RedisServiceLoginRateLimiter>>()));
    builder.Services.AddOptions<ServiceTokenOptions>()
        .Bind(builder.Configuration.GetSection("Jwt"))
        .ValidateDataAnnotations()
        .ValidateOnStart();
    builder.Services.AddOptions<PasskeyWebAuthnOptions>()
        .Bind(builder.Configuration.GetSection("Passkey"))
        .Validate(
            static options => !options.Enabled || IsValidPasskeyConfiguration(options),
            "Enabled passkey authentication requires a valid RP ID, exact HTTPS origins, and bounded ceremony settings")
        .ValidateOnStart();
    builder.Services.AddScoped<IFido2>(services =>
    {
        var options = services.GetRequiredService<IOptions<PasskeyWebAuthnOptions>>().Value;
        return new Fido2(new Fido2Configuration
        {
            ServerDomain = options.RpId,
            ServerName = options.RpName,
            Origins = options.AllowedOrigins.ToHashSet(StringComparer.Ordinal),
            Timeout = (uint)options.TimeoutMilliseconds,
            ChallengeSize = options.ChallengeSize,
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Allowed,
            BackedUpCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Allowed
        });
    });
    builder.Services.AddScoped<IPasskeyCeremonyStore, PasskeyCeremonyStore>();
    builder.Services.AddScoped<IPasskeyAssertionVerifier, PasskeyAssertionVerifier>();
    builder.Services.AddScoped<IPasskeyService, PasskeyService>();

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
    app.Use(async (context, next) =>
    {
        if (HttpMethods.IsPost(context.Request.Method) &&
            context.Request.Path.Equals("/auth/v1/service/login", StringComparison.OrdinalIgnoreCase))
        {
            const long maximumBodyBytes = 4096;
            var bodySizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
            if (bodySizeFeature is { IsReadOnly: false })
            {
                bodySizeFeature.MaxRequestBodySize = maximumBodyBytes;
            }

            if (context.Request.ContentLength > maximumBodyBytes)
            {
                context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                return;
            }
        }

        await next(context);
    });
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

static bool IsValidPasskeyConfiguration(PasskeyWebAuthnOptions options)
{
    if (string.IsNullOrWhiteSpace(options.RpId) ||
        string.IsNullOrWhiteSpace(options.RpName) ||
        options.AllowedOrigins is not { Count: > 0 } ||
        options.Bindings is not { Count: > 0 } ||
        options.TimeoutMilliseconds is < 30_000 or > 600_000 ||
        options.ChallengeSize is < 32 or > 64 ||
        options.CeremonyLifetimeMinutes is < 1 or > 10 ||
        options.MaxOutstandingCeremoniesPerApplication is < 1 or > 4_096)
    {
        return false;
    }

    if (Uri.CheckHostName(options.RpId) == UriHostNameType.Unknown ||
        options.Bindings.Any(binding =>
            !IsCanonicalPasskeySelector(binding.Key, 64) ||
            binding.Value is null ||
            !IsBoundedPasskeyServiceName(binding.Value.ServiceName) ||
            binding.Value.PrincipalType is not (UserType.Customer or UserType.Employee)))
    {
        return false;
    }

    return options.AllowedOrigins.All(origin =>
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsolutePath != "/" ||
            !(uri.Scheme == Uri.UriSchemeHttps ||
              uri.Scheme == Uri.UriSchemeHttp && uri.Host == "localhost"))
        {
            return false;
        }

        return string.Equals(uri.Host, options.RpId, StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith($".{options.RpId}", StringComparison.OrdinalIgnoreCase);
    });
}

static bool IsCanonicalPasskeySelector(string value, int maximumLength) =>
    value is { Length: > 0 } &&
    value.Length <= maximumLength &&
    string.Equals(value, value.Trim().ToLowerInvariant(), StringComparison.Ordinal) &&
    value.All(character =>
        character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

static bool IsBoundedPasskeyServiceName(string? value) =>
    value is { Length: > 0 and <= 128 } &&
    string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
    value.All(character =>
        character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.');

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
