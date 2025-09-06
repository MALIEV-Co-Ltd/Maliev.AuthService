using Maliev.AuthService.JwtToken.Models;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Maliev.AuthService.Api.Data;
using Microsoft.EntityFrameworkCore;
using Asp.Versioning;
using Microsoft.OpenApi.Models;
using Asp.Versioning.ApiExplorer;
using Microsoft.Extensions.Options;
using Swashbuckle.AspNetCore.SwaggerGen;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Maliev.AuthService.Api.HealthChecks;
using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Npgsql.EntityFrameworkCore.PostgreSQL;
using Maliev.AuthService.Api.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Load secrets.yaml
builder.Configuration.AddYamlFile("secrets.yaml", optional: true, reloadOnChange: true);

// Load secrets from mounted volume in GKE
var secretsPath = "/mnt/secrets";
if (Directory.Exists(secretsPath))
{
    builder.Configuration.AddKeyPerFile(directoryPath: secretsPath, optional: true);
}

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
}).AddApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

builder.Services.AddTransient<IConfigureOptions<SwaggerGenOptions>, Maliev.AuthService.Api.Configurations.ConfigureSwaggerOptions>();
builder.Services.AddSwaggerGen();

// Register Typed HttpClient for ExternalAuthServiceHttpClient
builder.Services.AddHttpClient<ExternalAuthServiceHttpClient>();

// Configure strongly-typed configuration options
builder.Services.Configure<CustomerServiceOptions>(builder.Configuration.GetSection("CustomerService"));
builder.Services.Configure<EmployeeServiceOptions>(builder.Configuration.GetSection("EmployeeService"));
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

// Configure RefreshToken DbContext
if (builder.Environment.IsEnvironment("Testing"))
{
    builder.Services.AddDbContext<RefreshTokenDbContext>(options =>
        options.UseInMemoryDatabase("TestDb"));
}
else
{
    builder.Services.AddDbContext<RefreshTokenDbContext>(options =>
    {
        options.UseNpgsql(builder.Configuration.GetConnectionString("RefreshTokenDbContext"));
    });
}

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// Configure Token Generator
builder.Services.AddSingleton<ITokenGenerator, TokenGenerator>();

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(
        policy =>
        {
            policy.WithOrigins(
                "https://api.maliev.com",
                "http://api.maliev.com")
            .AllowAnyHeader()
            .AllowAnyMethod();
        });
});

// JWT Bearer authentication configuration
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    var jwtOptions = new JwtOptions();
    builder.Configuration.GetSection("Jwt").Bind(jwtOptions);

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtOptions.Issuer,
        ValidAudience = jwtOptions.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SecurityKey ?? throw new InvalidOperationException("Jwt:SecurityKey not configured.")))
    };
});

builder.Services.AddAuthorization();

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // Only loopback proxies are allowed by default.
    // Clear that restriction because forwarders are being added.
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddHealthChecks()
    .AddDbContextCheck<RefreshTokenDbContext>("RefreshTokenDbContext", tags: new[] { "readiness" })
    .AddCheck<ExternalServiceHealthCheck>("External Services Check", tags: new[] { "readiness" });

var app = builder.Build();

app.UseForwardedHeaders();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
}

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
    foreach (var description in provider.ApiVersionDescriptions)
    {
        c.SwaggerEndpoint($"./{description.GroupName}/swagger.json", description.GroupName.ToUpperInvariant());
    }
    c.RoutePrefix = "auth/swagger";
});

// Secure Swagger UI
app.UseWhen(context => context.Request.Path.StartsWithSegments("/auth/swagger"), appBuilder =>
{
    appBuilder.UseAuthorization();
});

app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();



app.MapHealthChecks("/auth/liveness", new HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Tags.Contains("liveness")
});

app.MapHealthChecks("/auth/readiness", new HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Tags.Contains("readiness"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapControllers();

app.Run();
