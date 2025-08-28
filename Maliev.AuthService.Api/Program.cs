using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Maliev.AuthService.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authorization;

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
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthService API", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme,
                    Id="Bearer"
                }
            },
            new string[]{}
        }
    });
});

// Register Typed HttpClient for ExternalAuthServiceHttpClient
builder.Services.AddHttpClient<ExternalAuthServiceHttpClient>();

// Configure strongly-typed configuration options
builder.Services.Configure<CustomerServiceOptions>(builder.Configuration.GetSection("CustomerService"));
builder.Services.Configure<EmployeeServiceOptions>(builder.Configuration.GetSection("EmployeeService"));

// Configure RefreshToken DbContext
if (Environment.GetEnvironmentVariable("TESTING") != "true")
{
    builder.Services.AddDbContext<RefreshTokenDbContext>(options =>
    {
        options.UseSqlServer(builder.Configuration.GetConnectionString("RefreshTokenDbContext"));
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
                "http://*.maliev.com",
                "https://*.maliev.com")
            .SetIsOriginAllowedToAllowWildcardSubdomains()
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
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSecurityKey"]!))
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "AuthService API V1");
    c.RoutePrefix = "auth/swagger";
});

// Secure Swagger UI
app.UseWhen(context => context.Request.Path.StartsWithSegments("/auth/swagger"), appBuilder =>
{
    appBuilder.UseAuthorization();
});

app.UseExceptionHandler("/auth/error"); // Add ProblemDetails exception handler
app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

// Liveness probe endpoint
app.MapGet("/auth/liveness", () => "Healthy");

// Readiness probe endpoint
app.MapGet("/auth/readiness", () => "Healthy");

app.MapControllers();

app.Run();