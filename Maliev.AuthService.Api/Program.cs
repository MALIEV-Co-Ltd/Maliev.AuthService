using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using MassTransit;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

// Configure simple console logging for consistent output throughout startup
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.SingleLine = true;
    options.IncludeScopes = false;
    options.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
    options.UseUtcTimestamp = true;
});

// Create bootstrap logger for pre-build diagnostics (safe, doesn't use DI container)
using var loggerFactory = LoggerFactory.Create(loggingBuilder =>
{
    loggingBuilder.AddSimpleConsole(options =>
    {
        options.SingleLine = true;
        options.IncludeScopes = false;
        options.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
        options.UseUtcTimestamp = true;
    });
});
var bootstrapLogger = loggerFactory.CreateLogger<Program>();

try
{
    bootstrapLogger.LogInformation("===== AuthService Starting =====");

    // Load secrets from Google Secret Manager (Kubernetes /mnt/secrets volume mount)
    var secretsPath = "/mnt/secrets";
    if (Directory.Exists(secretsPath))
    {
        builder.Configuration.AddKeyPerFile(directoryPath: secretsPath, optional: true);
        bootstrapLogger.LogInformation("Loaded secrets from {SecretsPath}", secretsPath);
    }
    else
    {
        bootstrapLogger.LogInformation("Secrets path {SecretsPath} not found, using environment variables", secretsPath);
    }

    // Redis Distributed Cache Configuration
    var redisConnectionString = builder.Configuration.GetConnectionString("redis");
    bootstrapLogger.LogInformation("Configuring Redis cache (connection string present: {HasRedis})", !string.IsNullOrEmpty(redisConnectionString));

    if (!builder.Environment.IsEnvironment("Testing"))
    {
        if (!string.IsNullOrEmpty(redisConnectionString))
        {
            try
            {
                bootstrapLogger.LogInformation("Configuring Redis distributed cache at {RedisConnection}", redisConnectionString);
                var redisOptions = ConfigurationOptions.Parse(redisConnectionString);
                redisOptions.ConnectTimeout = 5000; // 5 second timeout
                redisOptions.SyncTimeout = 5000;
                redisOptions.AbortOnConnectFail = false; // Don't throw on failure

                builder.Services.AddStackExchangeRedisCache(options =>
                {
                    options.ConfigurationOptions = redisOptions;
                    options.InstanceName = "Auth:";
                });

                // Note: IConnectionMultiplexer removed - distributed cache will connect lazily
                // Can add back later if direct Redis access is needed
                bootstrapLogger.LogInformation("Redis distributed cache configured (will connect on first use)");
            }
            catch (Exception ex)
            {
                bootstrapLogger.LogWarning(ex, "Failed to configure Redis, falling back to in-memory cache");
            }
        }
        else
        {
            bootstrapLogger.LogInformation("Redis connection string not configured, using in-memory cache only");
        }
    }

    builder.Services.AddMemoryCache(); // Fallback in-memory cache

    // RabbitMQ Configuration (MassTransit)
    var rabbitmqConnectionString = builder.Configuration.GetConnectionString("rabbitmq");

    if (!string.IsNullOrEmpty(rabbitmqConnectionString) && !builder.Environment.IsEnvironment("Testing"))
    {
        bootstrapLogger.LogInformation("Configuring MassTransit with RabbitMQ");
        builder.Services.AddMassTransit(x =>
        {
            // Add consumers here if needed in the future
            // x.AddConsumer<SomeEventConsumer>();

            x.UsingRabbitMq((context, cfg) =>
            {
                cfg.Host(rabbitmqConnectionString);
                cfg.ConfigureEndpoints(context);
            });
        });
        bootstrapLogger.LogInformation("MassTransit configured successfully");
    }
    else
    {
        bootstrapLogger.LogInformation("RabbitMQ not configured (connection string: {HasRabbitMQ})", !string.IsNullOrEmpty(rabbitmqConnectionString));
    }

    // Database Configuration
    if (!builder.Environment.IsEnvironment("Testing"))
    {
        bootstrapLogger.LogInformation("Configuring database connection");
        var connectionString = builder.Configuration.GetConnectionString("AuthDbContext")
            ?? throw new InvalidOperationException("Database connection string not configured");

        builder.Services.AddDbContext<AuthDbContext>(options =>
        {
            options.UseNpgsql(connectionString, npgsqlOptions =>
            {
                npgsqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 5,
                    maxRetryDelay: TimeSpan.FromSeconds(10),
                    errorCodesToAdd: null);
            });

            // Suppress "Failed executing DbCommand" logs (EventId 20102) which occur during migration checks
            // Actual failures will still throw exceptions and be logged by the try-catch block
            options.ConfigureWarnings(warnings =>
                warnings.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.CommandError));
        });
        bootstrapLogger.LogInformation("Database context configured successfully");
    }

    // Services
    builder.Services.AddControllers()
        .AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower;
        });
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddOpenApi();
    builder.Services.AddHttpClient();

    // CORS Configuration
    var corsOrigins = builder.Configuration["CORS:AllowedOrigins"]?.Split(',', StringSplitOptions.RemoveEmptyEntries)
        ?? new[] { "http://localhost:3000" };

    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy =>
        {
            policy.WithOrigins(corsOrigins)
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        });
    });

    // Health Checks
    var healthChecksBuilder = builder.Services.AddHealthChecks()
        .AddDbContextCheck<AuthDbContext>(tags: new[] { "db", "ready" });

    // Add Redis health check if enabled
    // NOTE: AddServiceDefaults() already adds a Redis health check if the "redis" connection string is present.
    // We don't need to add it again here to avoid "Duplicate health checks were registered with the name(s): redis" exception.
    /*
    if (!string.IsNullOrEmpty(redisConnectionString))
    {
        healthChecksBuilder.AddRedis(redisConnectionString, "redis", tags: new[] { "db", "ready" });
    }
    */

    // Application Services
    builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
    builder.Services.AddScoped<ITokenValidator, TokenValidator>();
    builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
    builder.Services.AddScoped<IAccountLockoutService, AccountLockoutService>();
    builder.Services.AddScoped<IRateLimitService, RateLimitService>();
    builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

    // Validators


    // Add service defaults for .NET Aspire (includes OpenTelemetry logging)
    bootstrapLogger.LogInformation("Adding Aspire service defaults");
    builder.AddServiceDefaults();

    bootstrapLogger.LogInformation("Building application");
    var app = builder.Build();

    // Get final logger from the built application (safe, uses final DI container)
    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("Application built successfully");

    // TEMPORARILY DISABLED - Testing if migrations are causing startup hang
    // Run database migrations on startup (skip in Testing environment)
    /*
    if (!app.Environment.IsEnvironment("Testing"))
    {
        logger.LogInformation("Starting database migration process");
        using (var scope = app.Services.CreateScope())
        {
            try
            {
                logger.LogInformation("Resolving AuthDbContext");
                var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
                logger.LogInformation("AuthDbContext resolved successfully");
                
                // Use EF Core Execution Strategy (native resilience) for database migrations
                logger.LogInformation("Creating execution strategy");
                var strategy = dbContext.Database.CreateExecutionStrategy();
                logger.LogInformation("Execution strategy created successfully");
                
                logger.LogInformation("Executing migration strategy");

                await strategy.ExecuteAsync(async () => 
                {
                    // Pre-check connectivity to avoid "Failed executing DbCommand" error logs
                    int retryCount = 0;
                    logger.LogInformation("Checking database connectivity");
                    while (!await dbContext.Database.CanConnectAsync())
                    {
                        if (retryCount >= 20)
                        {
                            logger.LogWarning("Database connectivity check failed after 20 attempts");
                            break;
                        }
                        retryCount++;
                        logger.LogInformation("Waiting for database connectivity (Attempt {Attempt})...", retryCount);
                        await Task.Delay(TimeSpan.FromSeconds(1));
                    }

                    logger.LogInformation("Applying database migrations...");
                    await dbContext.Database.MigrateAsync();
                    logger.LogInformation("Database migrations applied successfully");
                });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to apply database migrations");
                throw;
            }
        }
        logger.LogInformation("Database migration process completed");
    }
    */
    logger.LogInformation("Database migrations SKIPPED for testing");

    // Log startup configuration
    if (Directory.Exists(secretsPath))
    {
        logger.LogInformation("Loaded secrets from Google Secret Manager at {SecretsPath}", secretsPath);
    }
    else
    {
        logger.LogInformation("Secrets path {SecretsPath} not found. Using environment variables.", secretsPath);
    }

    if (!string.IsNullOrEmpty(redisConnectionString) && !builder.Environment.IsEnvironment("Testing"))
    {
        logger.LogInformation("Redis distributed cache configured with connection string");
    }
    else
    {
        logger.LogInformation("Redis connection string not found or environment is Testing - using in-memory cache only");
    }

    if (!string.IsNullOrEmpty(rabbitmqConnectionString) && !builder.Environment.IsEnvironment("Testing"))
    {
        logger.LogInformation("MassTransit configured with RabbitMQ");
    }
    else
    {
        logger.LogInformation("RabbitMQ connection string not found or environment is Testing - MassTransit disabled");
    }

    logger.LogInformation("CORS configured with origins: {Origins}", string.Join(", ", corsOrigins));

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

    app.UseHttpsRedirection();
    app.UseRouting();
    app.UseCors();
    app.UseAuthorization();

    // Scalar API Documentation (development and staging only)
    if (app.Environment.IsDevelopment() || app.Environment.IsStaging())
    {
        app.MapOpenApi("/auth/openapi/{documentName}.json");
        app.MapScalarApiReference("/auth/scalar", options =>
        {
            options.WithOpenApiRoutePattern("/auth/openapi/{documentName}.json");
        });

        logger.LogInformation("OpenAPI available at: /auth/openapi/v1.json");
        logger.LogInformation("Scalar API reference available at: /auth/scalar");
    }

    // Map controllers with /auth prefix
    logger.LogInformation("Mapping controllers...");
    app.MapControllers();
    logger.LogInformation("Controllers mapped successfully");

    // Map Aspire default endpoints (/health, /alive, /metrics)
    logger.LogInformation("Mapping Aspire default endpoints...");
    app.MapDefaultEndpoints();
    logger.LogInformation("Aspire default endpoints mapped successfully");

    // Additional custom health checks with /auth prefix for ingress compatibility
    logger.LogInformation("Mapping custom health checks...");
    app.MapGet("/auth/liveness", () => "Healthy").AllowAnonymous();
    app.MapHealthChecks("/auth/readiness", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
    {
        Predicate = healthCheck => healthCheck.Tags.Contains("readiness")
    });
    logger.LogInformation("Custom health checks mapped successfully");

    logger.LogInformation("AuthService started successfully");

    app.Run();
}
catch (Exception ex)
{
    // Log fatal exception to bootstrap logger (since it's safe)
    bootstrapLogger.LogCritical(ex, "AuthService terminated unexpectedly during startup");
    throw; // Re-throw to ensure process exits with error code
}

/// <summary>
/// Main program class for the application
/// </summary>
// Make Program class accessible to tests
public partial class Program { }
