using Asp.Versioning;
using Maliev.AuthService.Common.Exceptions;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Maliev.AuthService.Api.Controllers
{
    [ApiController]
    [Route("auth/v{version:apiVersion}")]
    [ApiVersion("1.0")]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly CustomerServiceOptions _customerServiceOptions;
        private readonly EmployeeServiceOptions _employeeServiceOptions;

        public AuthenticationController(
            IAuthenticationService authenticationService,
            ILogger<AuthenticationController> logger,
            IOptions<CustomerServiceOptions> customerServiceOptions,
            IOptions<EmployeeServiceOptions> employeeServiceOptions)
        {
            _authenticationService = authenticationService;
            _logger = logger;
            _customerServiceOptions = customerServiceOptions.Value;
            _employeeServiceOptions = employeeServiceOptions.Value;
        }

        [HttpPost("token")]
        [EnableRateLimiting("TokenPolicy")]
        public async Task<IActionResult> Token(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Token endpoint called.");
            var header = Request.Headers["Authorization"].ToString();
            var traceId = HttpContext.TraceIdentifier;
            
            var result = await _authenticationService.GenerateTokensAsync(
                header,
                _customerServiceOptions,
                _employeeServiceOptions,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                traceId,
                cancellationToken);
                
            return result;
        }

        [HttpPost("token/refresh")]
        [EnableRateLimiting("RefreshPolicy")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("RefreshToken endpoint called.");
            
            if (request == null)
            {
                _logger.LogWarning("Invalid client request: Request is null.");
                return BadRequest("Invalid client request");
            }
            
            var traceId = HttpContext.TraceIdentifier;
            var result = await _authenticationService.RefreshTokensAsync(
                request.AccessToken,
                request.RefreshToken,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                traceId,
                cancellationToken);
                
            return result;
        }

        private string? GetUsernameFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            if (tokenHandler.ReadToken(token) is not JwtSecurityToken jwtToken)
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