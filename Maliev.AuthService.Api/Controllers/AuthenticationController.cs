using Maliev.AuthService.Api.Data;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using System.Text.Json;
using Asp.Versioning;

namespace Maliev.AuthService.Api.Controllers
{
    [ApiController]
    [Route("auth/v{version:apiVersion}")]
    [ApiVersion("1.0")]
    public class AuthenticationController : ControllerBase
    {
        private readonly ITokenGenerator _tokenGenerator;
        private readonly ExternalAuthServiceHttpClient _externalAuthServiceHttpClient;
        private readonly RefreshTokenDbContext _dbContext;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly CustomerServiceOptions _customerServiceOptions;
        private readonly EmployeeServiceOptions _employeeServiceOptions;

        public AuthenticationController(
            ITokenGenerator tokenGenerator,
            ExternalAuthServiceHttpClient externalAuthServiceHttpClient,
            RefreshTokenDbContext dbContext,
            ILogger<AuthenticationController> logger,
            IOptions<CustomerServiceOptions> customerServiceOptions,
            IOptions<EmployeeServiceOptions> employeeServiceOptions)
        {
            _tokenGenerator = tokenGenerator;
            _externalAuthServiceHttpClient = externalAuthServiceHttpClient;
            _dbContext = dbContext;
            _logger = logger;
            _customerServiceOptions = customerServiceOptions.Value;
            _employeeServiceOptions = employeeServiceOptions.Value;
        }

        [HttpPost("token")]
        public async Task<IActionResult> Token()
        {
            _logger.LogInformation("Token endpoint called.");
            var header = Request.Headers["Authorization"].ToString();
                        _logger.LogDebug("Authorization Header: {Header}", header);

            if (header != null && header.StartsWith("Basic "))
            {
                var rawCredentialBase64 = header.Substring("Basic ".Length).Trim();
                var rawCredentialString = Encoding.UTF8.GetString(Convert.FromBase64String(rawCredentialBase64));
                var credential = rawCredentialString.Split(":", 2);

                var username = credential[0];
                var password = credential[1];
                _logger.LogDebug("Extracted Username: {Username}", username);
                // Do not log password for security reasons

                var credentials = new { username = username, password = password };

                ValidationResult customerValidationResult = new ValidationResult { Exists = false };
                ValidationResult employeeValidationResult = new ValidationResult { Exists = false };

                // Try validating with CustomerService
                if (!string.IsNullOrEmpty(_customerServiceOptions.ValidationEndpoint))
                {
                    _logger.LogDebug("Attempting to validate with CustomerService at {Endpoint}", _customerServiceOptions.ValidationEndpoint);
                    customerValidationResult = await ValidateCredentials(
                        _customerServiceOptions.ValidationEndpoint,
                        credentials,
                        "Customer");
                    _logger.LogDebug("CustomerService validation result: Exists={Exists}, Type={Type}, Error={Error}", customerValidationResult.Exists, customerValidationResult.UserType, customerValidationResult.Error);
                }

                // If not found in CustomerService, try EmployeeService
                if (!customerValidationResult.Exists && !string.IsNullOrEmpty(_employeeServiceOptions.ValidationEndpoint))
                {
                    _logger.LogDebug("Attempting to validate with EmployeeService at {Endpoint}", _employeeServiceOptions.ValidationEndpoint);
                    employeeValidationResult = await ValidateCredentials(
                        _employeeServiceOptions.ValidationEndpoint,
                        credentials,
                        "Employee");
                    _logger.LogDebug("EmployeeService validation result: Exists={Exists}, Type={Type}, Error={Error}", employeeValidationResult.Exists, employeeValidationResult.UserType, employeeValidationResult.Error);
                }

                ValidationResult finalValidationResult = customerValidationResult.Exists ? customerValidationResult : employeeValidationResult;

                if (finalValidationResult.Exists)
                {
                    _logger.LogInformation("User exists. Generating tokens.");
                    // Generate access token and refresh token string
                    var accessToken = _tokenGenerator.GenerateJwtToken(username, finalValidationResult.Roles);
                    var refreshTokenString = _tokenGenerator.GenerateRefreshTokenString();

                    // Save refresh token to database
                    var refreshToken = new RefreshToken
                    {
                        Token = refreshTokenString,
                        Expires = DateTime.UtcNow.AddDays(7),
                        Created = DateTime.UtcNow,
                        Username = username,
                        CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()
                    };
                    _dbContext.RefreshTokens.Add(refreshToken);
                    await _dbContext.SaveChangesAsync();
                    _logger.LogInformation("Tokens generated and refresh token saved.");

                    return Ok(new { AccessToken = accessToken, RefreshToken = refreshTokenString });
                }
                else
                {
                    _logger.LogWarning("User does not exist or validation failed. Returning Unauthorized. Error: {Error}", finalValidationResult.Error);
                    return Unauthorized(finalValidationResult.Error ?? "User does not exist or validation failed.");
                }
            }
            else
            {
                _logger.LogWarning("Authorization header is missing or not in Basic format. Returning BadRequest.");
                return BadRequest();
            }
        }

        [HttpPost("token/refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            _logger.LogInformation("RefreshToken endpoint called.");
            _logger.LogInformation("Request - AccessToken: {AccessToken}", request.AccessToken.Length > 8 ? request.AccessToken.Substring(0, 8) + "..." : request.AccessToken);
            _logger.LogInformation("Request - RefreshToken: {RefreshToken}", request.RefreshToken.Length > 8 ? request.RefreshToken.Substring(0, 8) + "..." : request.RefreshToken);

            // Clean up expired and revoked refresh tokens
            await _dbContext.CleanExpiredAndRevokedTokensAsync();

            if (request == null || string.IsNullOrEmpty(request.AccessToken) || string.IsNullOrEmpty(request.RefreshToken))
            {
                _logger.LogWarning("Invalid client request: AccessToken or RefreshToken is null or empty.");
                return BadRequest("Invalid client request");
            }

            try
            {
                var savedRefreshToken = await _dbContext.RefreshTokens.SingleOrDefaultAsync(rt => rt.Token == request.RefreshToken);
                _logger.LogInformation("Saved RefreshToken from DB - Token: {Token}", savedRefreshToken?.Token != null && savedRefreshToken.Token.Length > 8 ? savedRefreshToken.Token.Substring(0, 8) + "..." : savedRefreshToken?.Token);
                _logger.LogInformation("Saved RefreshToken from DB - Username: {Username}", savedRefreshToken?.Username);
                _logger.LogInformation("Saved RefreshToken from DB - IsActive: {IsActive}", savedRefreshToken?.IsActive);

                if (savedRefreshToken == null)
                {
                    _logger.LogWarning("Invalid refresh token: Not found in DB.");
                    return Unauthorized("Invalid refresh token");
                }

                if (savedRefreshToken.IsActive == false)
                {
                    _logger.LogWarning("Invalid refresh token: Not active.");
                    return Unauthorized("Invalid refresh token");
                }

                var principal = _tokenGenerator.GetPrincipalFromExpiredToken(request.AccessToken);
                var username = principal.Identity?.Name;

                if (savedRefreshToken.Username != username)
                {
                    _logger.LogWarning("Invalid refresh token: Username mismatch. Saved: {SavedUsername}, From Token/Request: {UsernameFromToken}", savedRefreshToken.Username, username);
                    return Unauthorized("Invalid refresh token");
                }

                var (newAccessToken, newRefreshTokenString) = _tokenGenerator.RefreshToken(request.AccessToken, request.RefreshToken);
                _logger.LogInformation("New AccessToken generated.");
                _logger.LogInformation("New RefreshToken generated.");

                // Revoke old refresh token
                savedRefreshToken.Revoked = DateTime.UtcNow;
                _dbContext.RefreshTokens.Update(savedRefreshToken);
                await _dbContext.SaveChangesAsync();
                _logger.LogInformation("Old RefreshToken revoked and saved to DB.");

                // Save new refresh token to database
                var newRefreshToken = new RefreshToken
                {
                    Token = newRefreshTokenString,
                    Expires = DateTime.UtcNow.AddDays(7),
                    Created = DateTime.UtcNow,
                    Username = username,
                    CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    ReplacedByToken = request.RefreshToken
                };
                _dbContext.RefreshTokens.Add(newRefreshToken);
                await _dbContext.SaveChangesAsync();
                _logger.LogInformation("New RefreshToken saved to DB.");

                return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken.Token });
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogError(ex, "SecurityTokenException: {Message}", ex.Message);
                return Unauthorized(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "General Exception: {Message}", ex.Message);
                return StatusCode((int)HttpStatusCode.InternalServerError, $"An error occurred during token refresh: {ex.Message}");
            }
        }

        public async Task<ValidationResult> ValidateCredentials(
            string validationEndpoint,
            object credentials,
            string userType)
        {
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Post, validationEndpoint) { Content = jsonContent };
                var response = await _externalAuthServiceHttpClient.Client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    List<string> roles = new List<string>();
                    try
                    {
                        // Assuming the external service returns a JSON object with a 'roles' array
                        using (JsonDocument doc = JsonDocument.Parse(responseBody))
                        {
                            if (doc.RootElement.TryGetProperty("roles", out JsonElement rolesElement) && rolesElement.ValueKind == JsonValueKind.Array)
                            {
                                foreach (JsonElement role in rolesElement.EnumerateArray())
                                {
                                    roles.Add(role.GetString() ?? string.Empty);
                                }
                            }
                        }
                    }
                    catch (JsonException ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse roles from external service response for {UserType}. Using default role.", userType);
                    }

                    if (!roles.Any())
                    {
                        roles.Add(userType); // Default role if none found or parsing failed
                    }

                    return new ValidationResult { Exists = true, UserType = userType, Roles = roles };
                }
                else
                {
                    string errorMessage = $"External authentication service returned {response.StatusCode} for {userType} validation.";
                    _logger.LogWarning(errorMessage);
                    return new ValidationResult { Exists = false, UserType = userType, Error = errorMessage, StatusCode = (int)response.StatusCode };
                }
            }
            catch (HttpRequestException ex)
            {
                string errorMessage = $"HttpRequestException during {userType} validation: {ex.Message}";
                _logger.LogError(ex, errorMessage);
                return new ValidationResult { Exists = false, UserType = userType, Error = errorMessage };
            }
            catch (Exception ex)
            {
                string errorMessage = $"An unexpected error occurred during {userType} validation: {ex.Message}";
                _logger.LogError(ex, errorMessage);
                return new ValidationResult { Exists = false, UserType = userType, Error = errorMessage };
            }
        }

        
    private string? GetUsernameFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
            if (jwtToken == null)
            {
                _logger.LogWarning("GetUsernameFromToken: Failed to read JWT token. Token is null after ReadToken.");
                return null;
            }
            return jwtToken?.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Name)?.Value;
        }
    }

    public class RefreshTokenRequest
    {
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
    }
}
