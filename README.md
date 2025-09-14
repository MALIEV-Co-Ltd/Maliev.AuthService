# Maliev Authentication Service

A secure, production-ready authentication service built with ASP.NET Core 9.0. Provides JWT token-based authentication with refresh token support, advanced security features, and comprehensive observability.

[![.NET Version](https://img.shields.io/badge/.NET-9.0-blue.svg)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/your-repo/actions)

## 🚀 Overview

The Maliev Authentication Service is a robust authentication solution that provides:

- **JWT Token Authentication** with refresh token support
- **Multi-user Type Support** for Customers and Employees
- **External Service Integration** for user validation
- **Advanced Security Features** including rate limiting and input validation
- **Comprehensive Observability** with structured logging and metrics
- **Modern Architecture** with clean separation of concerns

## 🏗️ Architecture

The service follows a clean architecture pattern with the following key components:

```
Maliev.AuthService/
├── Maliev.AuthService.Api/          # Main API project with controllers
├── Maliev.AuthService.Data/         # Data access layer with Entity Framework
├── Maliev.AuthService.JwtToken/     # JWT token generation utilities
├── Maliev.AuthService.Common/       # Shared components and exceptions
└── Maliev.AuthService.Tests/        # Unit and integration tests
```

## 🔧 Key Features

### Authentication & Authorization
- **JWT Bearer Token Authentication** with configurable expiration
- **Refresh Token Support** for seamless user experience
- **Basic Authentication** with secure credential handling
- **Role-based Access Control** with claim-based authorization

### Security
- **Rate Limiting** with configurable policies per endpoint
- **Input Validation & Sanitization** to prevent injection attacks
- **Secure Credential Storage** with proper hashing and encryption
- **HTTPS Enforcement** for production deployments

### Performance & Scalability
- **Database Optimization** with Entity Framework Core
- **Asynchronous Operations** for non-blocking I/O
- **Caching Strategies** for improved response times

### Observability
- **Structured Logging** with Serilog and correlation ID tracking
- **Health Checks** for Kubernetes-ready deployments
- **Custom Metrics** for performance monitoring
- **Distributed Tracing** support

## 📋 Prerequisites

- **.NET 9.0 SDK** - [Download here](https://dotnet.microsoft.com/download/dotnet/9.0)
- **PostgreSQL 13+** or compatible database
- **Docker** (optional) - For containerized deployment

## 🚀 Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/your-repo/Maliev.AuthService.git
cd Maliev.AuthService
dotnet build
```

### 2. Configure Settings

Create `appsettings.Development.json`:

```json
{
  "ConnectionStrings": {
    "RefreshTokenDbContext": "Host=localhost;Database=MalievAuth;Username=your_user;Password=your_password"
  },
  "Jwt": {
    "Issuer": "https://localhost:5001",
    "Audience": "maliev-auth-service", 
    "SecurityKey": "your-super-secret-key-that-is-at-least-256-bits-long-for-security"
  },
  "CustomerService": {
    "ValidationEndpoint": "https://customer-service.example.com/validate"
  },
  "EmployeeService": {
    "ValidationEndpoint": "https://employee-service.example.com/validate"
  }
}
```

### 3. Run Database Migrations

```bash
cd Maliev.AuthService.Api
dotnet ef database update
```

### 4. Start the Service

```bash
dotnet run
```

The API will be available at:
- **HTTP**: `http://localhost:5000`
- **HTTPS**: `https://localhost:5001`
- **Swagger UI**: `https://localhost:5001/auth/swagger`

## 🧪 Testing

### Run Unit Tests

```bash
dotnet test
```

### Run with Coverage

```bash
dotnet test --collect:"XPlat Code Coverage"
```

## 📊 API Endpoints

### Token Generation
```
POST /auth/v1/token
Authorization: Basic base64encoded(username:password)
```

### Token Refresh
```
POST /auth/v1/token/refresh
Content-Type: application/json

{
  "accessToken": "expired-access-token",
  "refreshToken": "valid-refresh-token"
}
```

## 🛠️ Development

### Project Structure

The solution is organized with a clean separation of concerns:

- **Controllers** - Handle HTTP requests and responses
- **Services** - Implement business logic with dependency injection
- **Repositories** - Abstract data access operations
- **Models** - Define data structures and DTOs
- **Exceptions** - Custom exception types for better error handling

### Code Quality

- **SOLID Principles** - Following object-oriented design principles
- **Dependency Injection** - For loose coupling and testability
- **Async/Await** - Non-blocking operations throughout
- **Comprehensive Logging** - Structured logging with contextual information
- **Unit Testing** - High test coverage with xUnit and Moq

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.