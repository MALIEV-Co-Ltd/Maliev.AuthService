namespace Maliev.AuthService.Tests.Contract;

// Shared response models for contract tests
public record LoginResponse(string AccessToken, string RefreshToken, string TokenType, int ExpiresIn);
public record ValidateResponse(string UserId, string UserType, string Username, string Email, string[] Roles, string[] Permissions);
public record ErrorResponse(string Error, string? Message = null);
