using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class DtoValidationTests
{
    [Fact]
    public void LoginRequest_WithValidData_SetsProperties()
    {
        var request = new LoginRequest
        {
            Username = "test@example.com",
            Password = "password123",
            UserType = "customer"
        };

        Assert.Equal("test@example.com", request.Username);
        Assert.Equal("password123", request.Password);
        Assert.Equal("customer", request.UserType);
    }

    [Fact]
    public void RefreshRequest_WithValidData_SetsProperties()
    {
        var request = new RefreshRequest
        {
            RefreshToken = "refresh-token-value"
        };

        Assert.Equal("refresh-token-value", request.RefreshToken);
    }

    [Fact]
    public void RevokeRequest_WithValidData_SetsProperties()
    {
        var request = new RevokeRequest
        {
            Token = "token-to-revoke",
            Reason = "user logout"
        };

        Assert.Equal("token-to-revoke", request.Token);
        Assert.Equal("user logout", request.Reason);
    }

    [Fact]
    public void LogoutRequest_WithValidData_SetsProperties()
    {
        var request = new LogoutRequest
        {
            RefreshToken = "refresh-token"
        };

        Assert.Equal("refresh-token", request.RefreshToken);
    }

    [Fact]
    public void ValidateRequest_WithValidData_SetsProperties()
    {
        var request = new ValidateRequest
        {
            AccessToken = "access-token-value"
        };

        Assert.Equal("access-token-value", request.AccessToken);
    }

    [Fact]
    public void ServiceLoginRequest_WithValidData_SetsProperties()
    {
        var request = new ServiceLoginRequest
        {
            ClientId = "client-id",
            ClientSecret = "client-secret"
        };

        Assert.Equal("client-id", request.ClientId);
        Assert.Equal("client-secret", request.ClientSecret);
    }

    [Fact]
    public void GoogleExchangeRequest_WithValidData_SetsProperties()
    {
        var request = new GoogleExchangeRequest
        {
            Email = "user@maliev.com",
            FullName = "Test User"
        };

        Assert.Equal("user@maliev.com", request.Email);
        Assert.Equal("Test User", request.FullName);
    }

    [Fact]
    public void TokenResponse_SetsPropertiesCorrectly()
    {
        var response = new TokenResponse
        {
            AccessToken = "access-token",
            RefreshToken = "refresh-token",
            TokenType = "Bearer",
            ExpiresIn = 900
        };

        Assert.Equal("access-token", response.AccessToken);
        Assert.Equal("refresh-token", response.RefreshToken);
        Assert.Equal("Bearer", response.TokenType);
        Assert.Equal(900, response.ExpiresIn);
    }

    [Fact]
    public void LoginResponse_SetsPropertiesCorrectly()
    {
        var response = new LoginResponse
        {
            AccessToken = "access-token",
            RefreshToken = "refresh-token",
            TokenType = "Bearer",
            ExpiresIn = 900,
            User = new UserIdentityResponse
            {
                UserId = "user-123",
                UserType = "customer",
                Email = "user@example.com",
                Name = "Test User"
            }
        };

        Assert.NotNull(response.User);
        Assert.Equal("user-123", response.User.UserId);
        Assert.Equal("customer", response.User.UserType);
        Assert.Equal("user@example.com", response.User.Email);
    }

    [Fact]
    public void ValidateResponse_WithValidToken_SetsProperties()
    {
        var response = new ValidateResponse
        {
            Valid = true,
            UserId = "user-123",
            UserType = "customer",
            Email = "user@example.com",
            Name = "Test User",
            Roles = new List<string> { "admin", "user" },
            Permissions = new List<string> { "read", "write" }
        };

        Assert.True(response.Valid);
        Assert.Equal("user-123", response.UserId);
        Assert.Equal("customer", response.UserType);
        Assert.Equal(2, response.Roles.Count);
        Assert.Equal(2, response.Permissions.Count);
    }

    [Fact]
    public void ValidateResponse_WithInvalidToken_SetsError()
    {
        var response = new ValidateResponse
        {
            Valid = false,
            Error = "Invalid token"
        };

        Assert.False(response.Valid);
        Assert.Equal("Invalid token", response.Error);
    }

    [Fact]
    public void ErrorResponse_SetsPropertiesCorrectly()
    {
        var response = new ErrorResponse
        {
            Error = "invalid_credentials",
            ErrorDescription = "Invalid username or password"
        };

        Assert.Equal("invalid_credentials", response.Error);
        Assert.Equal("Invalid username or password", response.ErrorDescription);
    }

    [Fact]
    public void AuthenticationResult_Success_SetsResponse()
    {
        var result = new AuthenticationResult
        {
            Success = true,
            PrincipalId = Guid.NewGuid(),
            Response = new LoginResponse
            {
                AccessToken = "token",
                RefreshToken = "refresh"
            }
        };

        Assert.True(result.Success);
        Assert.NotNull(result.Response);
    }

    [Fact]
    public void AuthenticationResult_Failure_SetsErrorInfo()
    {
        var result = new AuthenticationResult
        {
            Success = false,
            ErrorCode = "account_locked",
            ErrorDescription = "Account is locked",
            LockedUntil = DateTime.UtcNow.AddMinutes(15)
        };

        Assert.False(result.Success);
        Assert.Equal("account_locked", result.ErrorCode);
        Assert.NotNull(result.LockedUntil);
    }
}
