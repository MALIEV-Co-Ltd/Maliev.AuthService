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
using System.Net.Http.Headers;
using Microsoft.AspNetCore.RateLimiting;

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
        private readonly IValidationCacheService _validationCacheService;

        public AuthenticationController(
            ITokenGenerator tokenGenerator,
            ExternalAuthServiceHttpClient externalAuthServiceHttpClient,
            RefreshTokenDbContext dbContext,
            ILogger<AuthenticationController> logger,
            IOptions<CustomerServiceOptions> customerServiceOptions,
            IOptions<EmployeeServiceOptions> employeeServiceOptions,
            IValidationCacheService validationCacheService)
        {
            _tokenGenerator = tokenGenerator;
            _externalAuthServiceHttpClient = externalAuthServiceHttpClient;
            _dbContext = dbContext;
            _logger = logger;
            _customerServiceOptions = customerServiceOptions.Value;
            _employeeServiceOptions = employeeServiceOptions.Value;
            _validationCacheService = validationCacheService;
        }

        [HttpPost("token")]
        [EnableRateLimiting("TokenPolicy")]
        public async Task<IActionResult> Token()
        {
            _logger.LogInformation("Token endpoint called.");
            var header = Request.Headers["Authorization"].ToString();
            _logger.LogDebug("Authorization Header: {Header}", header);

            if (System.Net.Http.Headers.AuthenticationHeaderValue.TryParse(header, out var authHeader) && authHeader.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
            {
                if (authHeader.Parameter == null)
                {
                    return BadRequest("Invalid authorization header format");
                }
                var parameter = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter)).Split(':', 2);
                var username = parameter[0];
                var password = parameter[1];
                _logger.LogDebug("Extracted Username: {Username}", username);
                // Do not log password for security reasons

                var userInfo = new { username };
                var jsonContent = new StringContent(JsonSerializer.Serialize(userInfo), Encoding.UTF8, "application/json");

                ValidationResult validationResult = new ValidationResult { Exists = false };

                // Try validating with CustomerService (check cache first)
                if (!string.IsNullOrEmpty(_customerServiceOptions.ValidationEndpoint))
                {
                    _logger.LogDebug("Attempting to validate with CustomerService at {Endpoint}", _customerServiceOptions.ValidationEndpoint);
                    
                    // Check cache first
                    var cachedResult = await _validationCacheService.GetValidationResultAsync(username, "Customer");
                    if (cachedResult != null)
                    {
                        validationResult = cachedResult;
                        _logger.LogDebug("CustomerService validation result from cache: Exists={Exists}, Type={Type}", validationResult.Exists, validationResult.UserType);
                    }
                    else
                    {
                        validationResult = await ValidateCredentials(_customerServiceOptions.ValidationEndpoint, jsonContent, "Customer");
                        _logger.LogDebug("CustomerService validation result: Exists={Exists}, Type={Type}, Error={Error}", validationResult.Exists, validationResult.UserType, validationResult.Error);
                        
                        // Cache the result
                        await _validationCacheService.SetValidationResultAsync(username, "Customer", validationResult);
                    }
                }

                // If not found in CustomerService, try EmployeeService (check cache first)
                if (!validationResult.Exists && !string.IsNullOrEmpty(_employeeServiceOptions.ValidationEndpoint))
                {
                    _logger.LogDebug("Attempting to validate with EmployeeService at {Endpoint}", _employeeServiceOptions.ValidationEndpoint);
                    
                    // Check cache first
                    var cachedResult = await _validationCacheService.GetValidationResultAsync(username, "Employee");
                    if (cachedResult != null)
                    {
                        validationResult = cachedResult;
                        _logger.LogDebug("EmployeeService validation result from cache: Exists={Exists}, Type={Type}", validationResult.Exists, validationResult.UserType);
                    }
                    else
                    {
                        validationResult = await ValidateCredentials(_employeeServiceOptions.ValidationEndpoint, jsonContent, "Employee");
                        _logger.LogDebug("EmployeeService validation result: Exists={Exists}, Type={Type}, Error={Error}", validationResult.Exists, validationResult.UserType, validationResult.Error);
                        
                        // Cache the result
                        await _validationCacheService.SetValidationResultAsync(username, "Employee", validationResult);
                    }
                }

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
                        CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()
                    };
                    _dbContext.RefreshTokens.Add(refreshToken);
                    await _dbContext.SaveChangesAsync();
                    _logger.LogInformation("Tokens generated and refresh token saved.");

                    return Ok(new { AccessToken = accessToken, RefreshToken = refreshTokenString });
                }
                else
                {
                    _logger.LogWarning("User does not exist or validation failed. Returning Unauthorized. Error: {Error}", validationResult.Error);
                    return Unauthorized(validationResult.Error ?? "User does not exist or validation failed.");
                }
            }
            else
            {
                _logger.LogWarning("Authorization header is missing or not in Basic format. Returning BadRequest.");
                return BadRequest();
            }
        }

        [HttpPost("token/refresh")]
        [EnableRateLimiting("RefreshPolicy")]
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

        /// <summary>
        /// Validates user existence with external ASP.NET Identity services
        /// </summary>
        /// <param name="validationEndpoint">The validation endpoint URL configured via CustomerServiceOptions or EmployeeServiceOptions</param>
        /// <param name="jsonContent">JSON payload containing only username: {"username": "user123"}</param>
        /// <param name="userType">Type of user (Customer or Employee)</param>
        /// <returns>ValidationResult indicating if user exists in ASP.NET Identity database and their roles</returns>
        /// <remarks>
        /// Validation endpoints are configured via external configuration (secrets/environment variables):
        /// - CustomerService:ValidationEndpoint for customer validation
        /// - EmployeeService:ValidationEndpoint for employee validation
        /// 
        /// Expected request format: POST to validation endpoint with JSON body:
        /// {
        ///   "username": "user123"
        /// }
        /// 
        /// Expected response format:
        /// {
        ///   "exists": true,
        ///   "roles": ["Customer", "Premium"] // ASP.NET Identity roles, optional
        /// }
        /// 
        /// The validation endpoints should query the respective ASP.NET Identity database
        /// to verify if the user exists and return their assigned roles.
        /// 
        /// If "exists" is false or missing, user is considered non-existent.
        /// If "roles" is missing, defaults to the userType (Customer/Employee).
        /// </remarks>
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<ValidationResult> ValidateCredentials(
            string validationEndpoint,
            StringContent jsonContent,
            string userType)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Post, validationEndpoint) { Content = jsonContent };
                var response = await _externalAuthServiceHttpClient.Client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    bool userExists = false;
                    List<string> roles = new List<string>();
                    
                    try
                    {
                        // Parse the response to check if user exists and get roles
                        using (JsonDocument doc = JsonDocument.Parse(responseBody))
                        {
                            // Check if user exists
                            if (doc.RootElement.TryGetProperty("exists", out JsonElement existsElement))
                            {
                                userExists = existsElement.GetBoolean();
                            }
                            
                            // Get roles if provided
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
                        _logger.LogWarning(ex, "Failed to parse response from external service for {UserType}. Assuming user doesn't exist.", userType);
                        userExists = false;
                    }

                    if (userExists)
                    {
                        // Add default role if no roles provided
                        if (!roles.Any())
                        {
                            roles.Add(userType); // Default role if none found
                        }
                        
                        return new ValidationResult { Exists = true, UserType = userType, Roles = roles };
                    }
                    else
                    {
                        return new ValidationResult { Exists = false, UserType = userType, Error = $"User not found in {userType} service." };
                    }
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
