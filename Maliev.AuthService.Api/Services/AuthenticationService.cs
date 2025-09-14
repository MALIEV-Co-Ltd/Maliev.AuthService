using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Common.Exceptions;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;

namespace Maliev.AuthService.Api.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly ITokenGenerator _tokenGenerator;
        private readonly ILogger<AuthenticationService> _logger;
        private readonly IUserValidationService _userValidationService;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly ICredentialValidationService _credentialValidationService;

        public AuthenticationService(
            ITokenGenerator tokenGenerator,
            ILogger<AuthenticationService> logger,
            IUserValidationService userValidationService,
            IRefreshTokenRepository refreshTokenRepository,
            ICredentialValidationService credentialValidationService)
        {
            _tokenGenerator = tokenGenerator;
            _logger = logger;
            _userValidationService = userValidationService;
            _refreshTokenRepository = refreshTokenRepository;
            _credentialValidationService = credentialValidationService;
        }

        public async Task<IActionResult> GenerateTokensAsync(
            string authorizationHeader,
            CustomerServiceOptions customerServiceOptions,
            EmployeeServiceOptions employeeServiceOptions,
            string? clientIpAddress,
            CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Token generation requested.");
            _logger.LogDebug("Authorization Header: {Header}", authorizationHeader);

            if (System.Net.Http.Headers.AuthenticationHeaderValue.TryParse(authorizationHeader, out var authHeader) && 
                authHeader.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
            {
                if (authHeader.Parameter == null)
                {
                    return new BadRequestObjectResult("Invalid authorization header format");
                }

                string[] parameter;
                try
                {
                    parameter = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter)).Split(':', 2);
                }
                catch (FormatException)
                {
                    return new BadRequestObjectResult("Invalid Base64 encoding in authorization header");
                }

                if (parameter.Length != 2)
                {
                    return new BadRequestObjectResult("Invalid credential format in authorization header");
                }

                var rawUsername = parameter[0];
                var rawPassword = parameter[1];

                // Validate credentials
                var credentialValidation = _credentialValidationService.ValidateCredentials(rawUsername, rawPassword);
                if (!credentialValidation.IsValid)
                {
                    _logger.LogWarning("Invalid credentials provided: {Errors}", string.Join(", ", credentialValidation.Errors));
                    return new BadRequestObjectResult($"Invalid credentials: {string.Join(", ", credentialValidation.Errors)}");
                }

                var username = credentialValidation.SanitizedUsername!;
                var password = credentialValidation.SanitizedPassword!;
                _logger.LogDebug("Validated and sanitized username: {Username}", username);
                // Do not log password for security reasons

                try
                {
                    // Validate user against external services
                    var validationResult = await _userValidationService.ValidateUserAsync(
                        username,
                        password,
                        customerServiceOptions,
                        employeeServiceOptions,
                        cancellationToken);

                    if (validationResult.Exists)
                    {
                        _logger.LogInformation("User exists. Generating tokens.");
                        var accessToken = _tokenGenerator.GenerateJwtToken(username, validationResult.Roles);
                        var refreshTokenString = _tokenGenerator.GenerateRefreshTokenString();

                        var refreshToken = new RefreshToken
                        {
                            Token = refreshTokenString,
                            Expires = DateTime.UtcNow.AddDays(7),
                            Created = DateTime.UtcNow,
                            Username = username,
                            CreatedByIp = clientIpAddress
                        };
                        _refreshTokenRepository.AddRefreshToken(refreshToken);
                        await _refreshTokenRepository.SaveChangesAsync(cancellationToken);
                        _logger.LogInformation("Tokens generated and refresh token saved.");

                        return new OkObjectResult(new { AccessToken = accessToken, RefreshToken = refreshTokenString });
                    }
                    else
                    {
                        _logger.LogWarning("User does not exist or validation failed. Returning Unauthorized. Error: {Error}", validationResult.Error);
                        return new UnauthorizedObjectResult(validationResult.Error ?? "User does not exist or validation failed.");
                    }
                }
                catch (ExternalServiceValidationException ex)
                {
                    _logger.LogError(ex, "External service validation failed");
                    var statusCode = ex.StatusCode ?? (int)HttpStatusCode.InternalServerError;
                    return new ObjectResult($"External service validation failed: {ex.Message}") { StatusCode = statusCode };
                }
                catch (TokenGenerationException ex)
                {
                    _logger.LogError(ex, "Token generation failed");
                    return new ObjectResult($"Token generation failed: {ex.Message}") { StatusCode = (int)HttpStatusCode.InternalServerError };
                }
                catch (DatabaseOperationException ex)
                {
                    _logger.LogError(ex, "Database operation failed");
                    return new ObjectResult("A database error occurred while processing your request.") { StatusCode = (int)HttpStatusCode.InternalServerError };
                }
            }
            else
            {
                _logger.LogWarning("Authorization header is missing or not in Basic format. Returning BadRequest.");
                return new BadRequestResult();
            }
        }

        public async Task<IActionResult> RefreshTokensAsync(
            string accessToken,
            string refreshToken,
            string? clientIpAddress,
            CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Token refresh requested.");
            _logger.LogInformation("Request - AccessToken: {AccessToken}", accessToken.Length > 8 ? accessToken.Substring(0, 8) + "..." : accessToken);
            _logger.LogInformation("Request - RefreshToken: {RefreshToken}", refreshToken.Length > 8 ? refreshToken.Substring(0, 8) + "..." : refreshToken);

            // Clean up expired and revoked refresh tokens
            try
            {
                await _refreshTokenRepository.CleanExpiredAndRevokedTokensAsync(cancellationToken);
            }
            catch (DatabaseOperationException ex)
            {
                _logger.LogError(ex, "Database operation failed during token cleanup");
                return new ObjectResult("A database error occurred while processing your request.") { StatusCode = (int)HttpStatusCode.InternalServerError };
            }

            if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("Invalid client request: AccessToken or RefreshToken is null or empty.");
                return new BadRequestObjectResult("Invalid client request");
            }

            try
            {
                var savedRefreshToken = await _refreshTokenRepository.GetRefreshTokenByTokenAsync(refreshToken, cancellationToken);
                _logger.LogInformation("Saved RefreshToken from DB - Token: {Token}", savedRefreshToken?.Token != null && savedRefreshToken.Token.Length > 8 ? savedRefreshToken.Token.Substring(0, 8) + "..." : savedRefreshToken?.Token);
                _logger.LogInformation("Saved RefreshToken from DB - Username: {Username}", savedRefreshToken?.Username);
                _logger.LogInformation("Saved RefreshToken from DB - IsActive: {IsActive}", savedRefreshToken?.IsActive);

                if (savedRefreshToken == null)
                {
                    _logger.LogWarning("Invalid refresh token: Not found in DB.");
                    return new UnauthorizedObjectResult("Invalid refresh token");
                }

                if (savedRefreshToken.IsActive == false)
                {
                    _logger.LogWarning("Invalid refresh token: Not active.");
                    return new UnauthorizedObjectResult("Invalid refresh token");
                }

                var principal = _tokenGenerator.GetPrincipalFromExpiredToken(accessToken);
                var username = principal.Identity?.Name;

                if (savedRefreshToken.Username != username)
                {
                    _logger.LogWarning("Invalid refresh token: Username mismatch. Saved: {SavedUsername}, From Token/Request: {UsernameFromToken}", savedRefreshToken.Username, username);
                    return new UnauthorizedObjectResult("Invalid refresh token");
                }

                var (newAccessToken, newRefreshTokenString) = _tokenGenerator.RefreshToken(accessToken, refreshToken);
                _logger.LogInformation("New AccessToken generated.");
                _logger.LogInformation("New RefreshToken generated.");

                // Revoke old refresh token
                savedRefreshToken.Revoked = DateTime.UtcNow;
                _refreshTokenRepository.UpdateRefreshToken(savedRefreshToken);
                await _refreshTokenRepository.SaveChangesAsync(cancellationToken);
                _logger.LogInformation("Old RefreshToken revoked and saved to DB.");

                // Save new refresh token to database
                var newRefreshToken = new RefreshToken
                {
                    Token = newRefreshTokenString,
                    Expires = DateTime.UtcNow.AddDays(7),
                    Created = DateTime.UtcNow,
                    Username = username,
                    CreatedByIp = clientIpAddress,
                    ReplacedByToken = refreshToken
                };
                _refreshTokenRepository.AddRefreshToken(newRefreshToken);
                await _refreshTokenRepository.SaveChangesAsync(cancellationToken);
                _logger.LogInformation("New RefreshToken saved to DB.");

                return new OkObjectResult(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken.Token });
            }
            catch (InvalidRefreshTokenException ex)
            {
                _logger.LogError(ex, "Invalid refresh token exception");
                return new UnauthorizedObjectResult(ex.Message);
            }
            catch (TokenGenerationException ex)
            {
                _logger.LogError(ex, "Token generation failed");
                return new ObjectResult($"Token generation failed: {ex.Message}") { StatusCode = (int)HttpStatusCode.InternalServerError };
            }
            catch (DatabaseOperationException ex)
            {
                _logger.LogError(ex, "Database operation failed");
                return new ObjectResult("A database error occurred while processing your request.") { StatusCode = (int)HttpStatusCode.InternalServerError };
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogError(ex, "SecurityTokenException: {Message}", ex.Message);
                return new UnauthorizedObjectResult(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "General Exception: {Message}", ex.Message);
                return new ObjectResult($"An error occurred during token refresh: {ex.Message}") { StatusCode = (int)HttpStatusCode.InternalServerError };
            }
        }
    }
}