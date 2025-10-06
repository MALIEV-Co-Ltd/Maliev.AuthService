# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy solution and project files
COPY Maliev.AuthService.sln ./
COPY Maliev.AuthService.Api/Maliev.AuthService.Api.csproj ./Maliev.AuthService.Api/
COPY Maliev.AuthService.Data/Maliev.AuthService.Data.csproj ./Maliev.AuthService.Data/

# Restore dependencies
RUN dotnet restore Maliev.AuthService.sln

# Copy source code
COPY Maliev.AuthService.Api/ ./Maliev.AuthService.Api/
COPY Maliev.AuthService.Data/ ./Maliev.AuthService.Data/

# Build the application
WORKDIR /src/Maliev.AuthService.Api
RUN dotnet build -c Release -o /app/build --no-restore

# Publish stage
FROM build AS publish
RUN dotnet publish -c Release -o /app/publish --no-build

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

# Create non-root user
RUN groupadd -r authservice && useradd -r -g authservice authservice

# Copy published application
COPY --from=publish /app/publish .

# Set ownership
RUN chown -R authservice:authservice /app

# Switch to non-root user
USER authservice

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl --fail http://localhost:8080/auth/liveness || exit 1

# Set environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

ENTRYPOINT ["dotnet", "Maliev.AuthService.Api.dll"]
