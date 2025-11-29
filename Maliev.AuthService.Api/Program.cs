using MassTransit;
using Microsoft.EntityFrameworkCore;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Api.Models.Request;
using Scalar.AspNetCore;
using Prometheus;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

// Load secrets from Google Secret Manager (Kubernetes /mnt/secrets volume mount)
var secretsPath = "/mnt/secrets";
if (Directory.Exists(secretsPath))
{
    builder.Configuration.AddKeyPerFile(directoryPath: secretsPath, optional: true);
}

// Redis Distributed Cache Configuration
var redisConnectionString = builder.Configuration.GetConnectionString("redis");

if (!builder.Environment.IsEnvironment("Testing"))
{
    if (!string.IsNullOrEmpty(redisConnectionString))
    {
        try
        {
            var redisOptions = ConfigurationOptions.Parse(redisConnectionString);
            redisOptions.ConnectTimeout = 5000; // 5 second timeout
            redisOptions.SyncTimeout = 5000;
            redisOptions.AbortOnConnectFail = false; // Don't throw on failure
            
            builder.Services.AddStackExchangeRedisCache(options =>
            {
                options.ConfigurationOptions = redisOptions;
                options.InstanceName = "Auth:";
            });

            var redis = ConnectionMultiplexer.Connect(redisOptions);
            builder.Services.AddSingleton<IConnectionMultiplexer>(redis);
        }
        catch (Exception ex)
        {
            // Log warning but don't crash - fall back to in-memory cache
            Console.WriteLine($"Warning: Failed to connect to Redis: {ex.Message}. Using in-memory cache.");
        }
    }
}

builder.Services.AddMemoryCache(); // Fallback in-memory cache

// RabbitMQ Configuration (MassTransit)
var rabbitmqConnectionString = builder.Configuration.GetConnectionString("rabbitmq");

if (!string.IsNullOrEmpty(rabbitmqConnectionString) && !builder.Environment.IsEnvironment("Testing"))
{
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
}

// Database Configuration
if (!builder.Environment.IsEnvironment("Testing"))
{
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
if (!string.IsNullOrEmpty(redisConnectionString))
{
    healthChecksBuilder.AddRedis(redisConnectionString, "redis", tags: new[] { "db", "ready" });
}

// Application Services
builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
builder.Services.AddScoped<ITokenValidator, TokenValidator>();
builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IAccountLockoutService, AccountLockoutService>();
builder.Services.AddScoped<IRateLimitService, RateLimitService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

// Validators


// Add service defaults for .NET Aspire (includes OpenTelemetry logging)
builder.AddServiceDefaults();

var app = builder.Build();

// Get logger for startup logging
var logger = app.Services.GetRequiredService<ILogger<Program>>();

// Run database migrations on startup (skip in Testing environment)
if (!app.Environment.IsEnvironment("Testing"))
{
    using (var scope = app.Services.CreateScope())
    {
        try
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            
            // Use EF Core Execution Strategy (native resilience) for database migrations
            var strategy = dbContext.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () => 
            {
                // Pre-check connectivity to avoid "Failed executing DbCommand" error logs
                int retryCount = 0;
                while (!await dbContext.Database.CanConnectAsync())
                {
                    if (retryCount >= 20) break;
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
}

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

// Configure base path for all routes
// app.UsePathBase("/auth");

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
app.MapControllers();

// Map Aspire default endpoints (/health, /alive, /metrics)
app.MapDefaultEndpoints();

// Additional custom health checks with /auth prefix for ingress compatibility
app.MapGet("/auth/liveness", () => "Healthy").AllowAnonymous();
app.MapHealthChecks("/auth/readiness", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Tags.Contains("readiness")
});

logger.LogInformation("AuthService started successfully");

app.Run();

/// <summary>
/// Main program class for the application
/// </summary>
// Make Program class accessible to tests
public partial class Program { }
