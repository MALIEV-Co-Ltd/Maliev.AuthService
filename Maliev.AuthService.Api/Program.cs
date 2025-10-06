using System.Threading.RateLimiting;
using HealthChecks.UI.Client;
using Maliev.AuthService.Api.HealthChecks;
using Maliev.AuthService.Api.Middleware;
using Maliev.AuthService.Api.Options;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Repositories;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// **Serilog Configuration** (Console only)
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .WriteTo.Console()
    .CreateLogger();

builder.Host.UseSerilog();

// **Secrets from Google Secret Manager**
var secretsPath = "/mnt/secrets";
if (Directory.Exists(secretsPath))
{
    builder.Configuration.AddKeyPerFile(directoryPath: secretsPath, optional: true);
}

// **Options Configuration**
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
builder.Services.Configure<ExternalServiceOptions>(builder.Configuration.GetSection(ExternalServiceOptions.SectionName));
builder.Services.Configure<RateLimitOptions>(builder.Configuration.GetSection(RateLimitOptions.SectionName));
builder.Services.Configure<CircuitBreakerOptions>(builder.Configuration.GetSection(CircuitBreakerOptions.SectionName));
builder.Services.Configure<CacheOptions>(builder.Configuration.GetSection(CacheOptions.SectionName));
builder.Services.Configure<CorrelationIdOptions>(builder.Configuration.GetSection(CorrelationIdOptions.SectionName));
builder.Services.Configure<DatabaseOptions>(builder.Configuration.GetSection(DatabaseOptions.SectionName));
builder.Services.Configure<HealthCheckConfiguration>(builder.Configuration.GetSection(HealthCheckConfiguration.SectionName));

// **Database Configuration**
var connectionString = builder.Configuration.GetSection(DatabaseOptions.SectionName).Get<DatabaseOptions>()?.ConnectionString
    ?? builder.Configuration.GetConnectionString("AuthDbContext")
    ?? "Server=localhost;Port=5432;Database=auth_db;User Id=postgres;Password=postgres;";

builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseNpgsql(connectionString, npgsqlOptions =>
    {
        npgsqlOptions.CommandTimeout(30);
        npgsqlOptions.EnableRetryOnFailure(maxRetryCount: 3, maxRetryDelay: TimeSpan.FromSeconds(30), errorCodesToAdd: null);
    });
});

// **Repository Registration**
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<ITokenFamilyRepository, TokenFamilyRepository>();
builder.Services.AddScoped<IRevokedAccessTokenRepository, RevokedAccessTokenRepository>();

// **Service Registration**
builder.Services.AddSingleton<ITokenGenerator, TokenGenerator>();
builder.Services.AddSingleton<ITokenValidator, TokenValidator>();
builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<ICredentialValidationService, CredentialValidationService>();
builder.Services.AddScoped<IValidationCacheService, ValidationCacheService>();

// **HttpClient for External Services**
builder.Services.AddHttpClient<IExternalValidationService, ExternalValidationService>();

// **Memory Cache** (Simple configuration without SizeLimit)
builder.Services.AddMemoryCache();

// **Rate Limiting**
builder.Services.AddRateLimiter(rateLimiterOptions =>
{
    var rateLimitOptions = builder.Configuration.GetSection(RateLimitOptions.SectionName).Get<RateLimitOptions>() ?? new RateLimitOptions();

    rateLimiterOptions.AddPolicy(rateLimitOptions.PolicyName, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = rateLimitOptions.LoginAttemptLimit,
                Window = TimeSpan.FromSeconds(rateLimitOptions.WindowSeconds),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));
});

// **Health Checks**
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("database", tags: ["readiness"]);

// **Controllers**
builder.Services.AddControllers();

// **OpenAPI/Swagger**
builder.Services.AddOpenApi();

var app = builder.Build();

// **Apply Database Migrations** (Development only)
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await dbContext.Database.MigrateAsync();
}

// **Middleware Pipeline** (EXACT ORDER)
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseMiddleware<CorrelationIdMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseRateLimiter();

// **Health Check Endpoints**
app.MapGet("/auth/liveness", () => Results.Ok(new { status = "Healthy" }))
    .WithName("Liveness")
    .WithOpenApi();

app.MapHealthChecks("/auth/readiness", new HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Tags.Contains("readiness"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
}).WithName("Readiness");

// **Controllers**
app.MapControllers();

app.Run();

// Make Program class accessible to tests
public partial class Program { }
