using Maliev.AuthService.JwtToken.Models;
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
using Asp.Versioning;
using Asp.Versioning.ApiExplorer;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Api
{
    public class Program
    {
        public static void Main(string[] args)
        {
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

            builder.Services.AddSwaggerGen(option =>
            {
                var provider = builder.Services.BuildServiceProvider().GetRequiredService<IApiVersionDescriptionProvider>();
                foreach (var description in provider.ApiVersionDescriptions)
                {
                    option.SwaggerDoc(description.GroupName, new OpenApiInfo { Title = "AuthService API", Version = description.ApiVersion.ToString() });
                }

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
                            "https://api.maliev.com",
                            "http://test.maliev.com",
                            "https://test.maliev.com")
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
                var serviceProvider = builder.Services.BuildServiceProvider();
                var jwtOptions = serviceProvider.GetRequiredService<IOptions<JwtOptions>>().Value;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtOptions.Issuer,
                    ValidAudience = jwtOptions.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SecurityKey))
                };
            });

            builder.Services.AddAuthorization();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
                foreach (var description in provider.ApiVersionDescriptions)
                {
                    c.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json", description.GroupName.ToUpperInvariant());
                }
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
        }
    }
}