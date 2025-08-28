# Maliev.AuthService

This project is an authentication service built with ASP.NET Core. It provides endpoints for user and employee authentication, and for generating JWT tokens. The service uses ASP.NET Core Identity for user management and JWT for token-based authentication.

## Main Technologies Used
- ASP.NET Core
- Entity Framework Core
- JWT for authentication
- Swashbuckle.AspNetCore for API documentation

## Building and Running

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

## Testing

To run the tests, navigate to the `Maliev.AuthService.Tests` directory and use the `dotnet test` command:
```bash
cd Maliev.AuthService.Tests
dotnet test
```

## Key Features

- **Authentication:** Provides endpoints for validating user credentials and generating JWT tokens.
- **User Management:** Uses ASP.NET Core Identity. The `ApplicationUser` and `ApplicationEmployee` models have been removed as they were not actively used.
- **Configuration:** The application uses `appsettings.json` for general settings and `secrets.yaml` for sensitive data like connection strings and JWT keys.
- **CORS:** The service is configured to allow requests from `*.maliev.com` subdomains.
- **API Documentation:** Swagger UI is available at `/auth/swagger` and is secured with JWT.
- **Health Checks:** Exposes liveness (`/auth/liveness`) and readiness (`/auth/readiness`) probe endpoints for Kubernetes.