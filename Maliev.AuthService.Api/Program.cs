using FluentValidation;
using MassTransit;
using Microsoft.EntityFrameworkCore;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Api.Validators;
using Maliev.AuthService.Api.Models.Request;
using Scalar.AspNetCore;
using Serilog;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

// Serilog Configuration
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .WriteTo.Console()
    .CreateLogger();

builder.Host.UseSerilog();

// Load secrets from Google Secret Manager (Kubernetes /mnt/secrets volume mount)
var secretsPath = "/mnt/secrets";
if (Directory.Exists(secretsPath))
{
    builder.Configuration.AddKeyPerFile(directoryPath: secretsPath, optional: true);
    Log.Information("Loaded secrets from Google Secret Manager at {SecretsPath}", secretsPath);
}
else
{
    Log.Warning("Secrets path {SecretsPath} not found. Running without Secret Manager", secretsPath);
}

// Redis Distributed Cache Configuration
var redisConnectionString = builder.Configuration["Redis:ConnectionString"];
var redisEnabled = bool.TryParse(builder.Configuration["Redis:Enabled"], out var isRedisEnabled) && isRedisEnabled;

if (redisEnabled && !string.IsNullOrEmpty(redisConnectionString) && !builder.Environment.IsEnvironment("Testing"))
{
    try
    {
        builder.Services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = redisConnectionString;
            options.InstanceName = "Auth:";
        });

        var redis = ConnectionMultiplexer.Connect(redisConnectionString);
        builder.Services.AddSingleton<IConnectionMultiplexer>(redis);

        Log.Information("Redis distributed cache configured: {RedisConnectionString}", redisConnectionString);
    }
    catch (Exception ex)
    {
        Log.Warning(ex, "Redis connection failed - will use in-memory cache fallback");
    }
}
else
{
    Log.Information("Redis disabled or not configured - using in-memory cache only");
}

builder.Services.AddMemoryCache(); // Fallback in-memory cache

// RabbitMQ Configuration (MassTransit)
var rabbitmqHost = builder.Configuration["RabbitMQ:Host"] ?? "localhost";
var rabbitmqPort = int.TryParse(builder.Configuration["RabbitMQ:Port"], out var port) ? port : 5672;
var rabbitmqUser = builder.Configuration["RabbitMQ:Username"] ?? "guest";
var rabbitmqPassword = builder.Configuration["RabbitMQ:Password"] ?? "guest";
var rabbitmqVhost = builder.Configuration["RabbitMQ:VirtualHost"] ?? "/";
var rabbitmqEnabled = bool.TryParse(builder.Configuration["RabbitMQ:Enabled"], out var isRabbitmqEnabled) && isRabbitmqEnabled;

if (rabbitmqEnabled && !builder.Environment.IsEnvironment("Testing"))
{
    builder.Services.AddMassTransit(x =>
    {
        // Add consumers here if needed in the future
        // x.AddConsumer<SomeEventConsumer>();

        x.UsingRabbitMq((context, cfg) =>
        {
            cfg.Host(rabbitmqHost, (ushort)rabbitmqPort, rabbitmqVhost, h =>
            {
                h.Username(rabbitmqUser);
                h.Password(rabbitmqPassword);
            });

            cfg.ConfigureEndpoints(context);
        });
    });

    Log.Information("MassTransit configured with RabbitMQ: {Host}:{Port}", rabbitmqHost, rabbitmqPort);
}
else
{
    Log.Information("RabbitMQ/MassTransit disabled by configuration");
}

// Database Configuration
if (!builder.Environment.IsEnvironment("Testing"))
{
    var connectionString = builder.Configuration.GetConnectionString("AuthDbContext")
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
builder.Services.AddOpenApi();
builder.Services.AddHttpClient();

// Health Checks
var healthChecksBuilder = builder.Services.AddHealthChecks()
    .AddDbContextCheck<AuthDbContext>(tags: new[] { "readiness" });

// Add Redis health check if enabled
if (redisEnabled && !string.IsNullOrEmpty(redisConnectionString))
{
    healthChecksBuilder.AddRedis(redisConnectionString, "redis", tags: new[] { "readiness" });
}

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

// Add service defaults for .NET Aspire
builder.AddServiceDefaults();

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

// Scalar API Documentation (disabled in production)
if (!app.Environment.IsProduction())
{
    app.MapOpenApi("/openapi/{documentName}.json");
    app.MapScalarApiReference(options =>
    {
        options
            .WithTitle("Maliev Auth Service API")
            .WithTheme(Scalar.AspNetCore.ScalarTheme.Saturn)
            .WithDefaultHttpClient(Scalar.AspNetCore.ScalarTarget.CSharp, Scalar.AspNetCore.ScalarClient.HttpClient)
            .WithEndpointPrefix("/scalar/{documentName}")
            .WithOpenApiRoutePattern("/openapi/{documentName}.json");
    });
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
