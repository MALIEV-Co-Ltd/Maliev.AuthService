using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class AuthenticationServiceDtoTests
{
    [Fact]
    public void LoginRequest_SetsValues()
    {
        var request = new LoginRequest
        {
            Username = "user@test.com",
            Password = "password123",
            UserType = "customer"
        };

        Assert.Equal("user@test.com", request.Username);
        Assert.Equal("password123", request.Password);
        Assert.Equal("customer", request.UserType);
    }

    [Fact]
    public void RefreshRequest_SetsValues()
    {
        var request = new RefreshRequest
        {
            RefreshToken = "refresh-token-value"
        };

        Assert.Equal("refresh-token-value", request.RefreshToken);
    }

    [Fact]
    public void RevokeRequest_SetsValues()
    {
        var request = new RevokeRequest
        {
            Token = "token",
            Reason = "reason"
        };

        Assert.Equal("token", request.Token);
        Assert.Equal("reason", request.Reason);
    }

    [Fact]
    public void ServiceLoginRequest_SetsValues()
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
    public void GoogleExchangeRequest_SetsValues()
    {
        var request = new GoogleExchangeRequest
        {
            Credential = "google-id-token",
            Application = "intranet"
        };

        Assert.Equal("google-id-token", request.Credential);
        Assert.Equal("intranet", request.Application);
    }

    [Fact]
    public void TokenResponse_HasRequiredProperties()
    {
        var response = new TokenResponse
        {
            AccessToken = "token",
            RefreshToken = "refresh-token",
            TokenType = "Bearer",
            ExpiresIn = 3600
        };

        Assert.Equal("token", response.AccessToken);
        Assert.Equal("refresh-token", response.RefreshToken);
    }

    [Fact]
    public void LoginResponse_HasRequiredProperties()
    {
        var response = new LoginResponse
        {
            AccessToken = "token",
            RefreshToken = "refresh",
            TokenType = "Bearer",
            ExpiresIn = 900,
            User = new UserIdentityResponse
            {
                UserId = "user-123",
                UserType = "customer"
            }
        };

        Assert.NotNull(response.User);
        Assert.Equal("user-123", response.User.UserId);
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
                AccessToken = "token"
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
            ErrorCode = "invalid_credentials",
            ErrorDescription = "Invalid username or password"
        };

        Assert.False(result.Success);
        Assert.Equal("invalid_credentials", result.ErrorCode);
    }

    [Fact]
    public void ValidateResponse_ValidToken_HasClaims()
    {
        var result = new ValidateResponse
        {
            Valid = true,
            UserId = "user-123",
            UserType = "customer",
            Roles = new List<string> { "admin" },
            Permissions = new List<string> { "read" }
        };

        Assert.True(result.Valid);
        Assert.Equal("user-123", result.UserId);
        Assert.Single(result.Roles);
    }

    [Fact]
    public void ValidateResponse_InvalidToken_HasError()
    {
        var result = new ValidateResponse
        {
            Valid = false,
            Error = "Invalid token"
        };

        Assert.False(result.Valid);
        Assert.Equal("Invalid token", result.Error);
    }

    [Fact]
    public void ErrorResponse_HasProperties()
    {
        var result = new ErrorResponse
        {
            Error = "error_code",
            ErrorDescription = "Error description"
        };

        Assert.Equal("error_code", result.Error);
        Assert.Equal("Error description", result.ErrorDescription);
    }

    [Fact]
    public void UserIdentityResponse_HasProperties()
    {
        var user = new UserIdentityResponse
        {
            UserId = "user-123",
            UserType = "employee",
            Email = "user@test.com",
            Name = "Test User"
        };

        Assert.Equal("user-123", user.UserId);
        Assert.Equal("employee", user.UserType);
        Assert.Equal("user@test.com", user.Email);
        Assert.Equal("Test User", user.Name);
    }
}
