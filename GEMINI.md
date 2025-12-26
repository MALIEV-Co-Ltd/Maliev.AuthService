# Maliev.AuthService Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-12-21

## Active Technologies

- .NET 10.0 + ASP.NET Core, Entity Framework Core (Npgsql), Aspire Service Defaults, Microsoft.Extensions.Http.Resilience (Polly v8)

## Project Structure

```text
Maliev.AuthService.Api/
Maliev.AuthService.Data/
Maliev.AuthService.Tests/
```

## Commands

# Add commands for .NET 10.0
- Build: `dotnet build`
- Test: `dotnet test`
- Run: `dotnet run --project Maliev.AuthService.Api`

## Code Style

.NET 10.0: Follow standard conventions. NO AutoMapper, NO FluentValidation, NO FluentAssertions.

## Recent Changes

- 002-iam-integration: Added support for IAM service integration to resolve permissions and roles, embedding them in JWT tokens.
- 002-service-api-key-auth: (Reverted) Added service-to-service authentication using API keys.

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
