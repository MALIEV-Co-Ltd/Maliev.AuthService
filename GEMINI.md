# Project Overview

This project is an authentication service built with ASP.NET Core. It provides endpoints for user and employee authentication, and for generating JWT tokens. The service uses ASP.NET Core Identity for user management and JWT for token-based authentication. It also includes a testing project, which indicates a commitment to code quality.

The main technologies used are:
- ASP.NET Core
- Entity Framework Core
- JWT for authentication
- Swashbuckle.AspNetCore for API documentation (available in all environments and secured with JWT)

The solution is divided into three projects:
- `Maliev.AuthService.Api`: The main API project, containing controllers, models, and the application's entry point.
- `Maliev.AuthService.JwtToken`: A project for generating JWT tokens.
- `Maliev.AuthService.Tests`: A project for integration and unit tests.

# Building and Running

To build and run this project, you will need the .NET SDK installed.

**Build:**
```bash
dotnet build
```

**Run:**
To run the application, navigate to the `Maliev.AuthService.Api` directory and use the `dotnet run` command:
```bash
cd Maliev.AuthService.Api
dotnet run
```
The API will be available at the URLs specified in `Properties/launchSettings.json`.

**Testing:**
To run the tests, navigate to the `Maliev.AuthService.Tests` directory and use the `dotnet test` command:
```bash
cd Maliev.AuthService.Tests
dotnet test
```

# Development Conventions

- **Authentication:** The service uses JWT for token-based authentication. The `AuthenticationController` provides endpoints for validating user credentials and generating JWT tokens.
- **User Management:** The service uses ASP.NET Core Identity. The `ApplicationUser` and `ApplicationEmployee` models have been removed as they were not actively used.
- **Configuration:** The application uses `appsettings.json` for general settings and `secrets.yaml` for sensitive data like connection strings and JWT keys.
- **CORS:** The service is configured to allow requests from `*.maliev.com` subdomains.
- **API Documentation:** The project uses Swashbuckle.AspNetCore to generate API documentation, which is available in all environments and secured with JWT. The Swagger UI is accessible at `/auth/swagger`.
- **Health Checks:** The application exposes liveness and readiness probe endpoints for Kubernetes.
  - Liveness: `/auth/liveness`
  - Readiness: `/auth/readiness`