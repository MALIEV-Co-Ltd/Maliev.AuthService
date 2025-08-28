# Maliev.AuthService

This project is an authentication service built with ASP.NET Core. It provides endpoints for user authentication and for generating JWT tokens.

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
- **User Management:** Uses ASP.NET Core Identity.
- **API Documentation:** Swagger UI is available at `/auth/swagger` and is secured with JWT.
- **Health Checks:** Exposes liveness (`/auth/liveness`) and readiness (`/auth/readiness`) probe endpoints for Kubernetes.