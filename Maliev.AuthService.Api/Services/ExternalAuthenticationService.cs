using Maliev.AuthService.Api.Models;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Threading;

namespace Maliev.AuthService.Api.Services
{
    public class ExternalAuthenticationService : IExternalAuthenticationService
    {
        private readonly ExternalAuthServiceHttpClient _externalAuthServiceHttpClient;
        private readonly ILogger<ExternalAuthenticationService> _logger;

        public ExternalAuthenticationService(
            ExternalAuthServiceHttpClient externalAuthServiceHttpClient,
            ILogger<ExternalAuthenticationService> logger)
        {
            _externalAuthServiceHttpClient = externalAuthServiceHttpClient;
            _logger = logger;
        }

        public async Task<ValidationResult> ValidateCredentialsAsync(
            string validationEndpoint,
            StringContent jsonContent,
            UserType userType,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Post, validationEndpoint) { Content = jsonContent };
                var response = await _externalAuthServiceHttpClient.Client.SendAsync(request, cancellationToken);

                return HandleExternalServiceResponse(response, userType);
            }
            catch (HttpRequestException ex)
            {
                return HandleHttpRequestException(ex, userType);
            }
            catch (Exception ex)
            {
                return HandleGeneralException(ex, userType);
            }
        }

        private ValidationResult HandleExternalServiceResponse(
            HttpResponseMessage response,
            UserType userType)
        {
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    return HandleSuccessResponse(userType);

                case HttpStatusCode.NotFound:
                    return HandleNotFoundResponse(userType);

                case HttpStatusCode.BadRequest:
                    return HandleBadRequestResponse(userType);

                default:
                    return HandleOtherResponse(response, userType);
            }
        }

        private ValidationResult HandleSuccessResponse(UserType userType)
        {
            // 200 OK: Valid credentials, user exists
            _logger.LogDebug("{UserType} validation successful: User exists and credentials are valid", userType);
            var roles = new List<string> { userType.ToString() }; // Default role
            return new ValidationResult { Exists = true, UserType = userType.ToString(), Roles = roles };
        }

        private ValidationResult HandleNotFoundResponse(UserType userType)
        {
            // 404 NOT FOUND: User does not exist
            _logger.LogDebug("{UserType} validation: User not found", userType);
            return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = $"User not found in {userType} service." };
        }

        private ValidationResult HandleBadRequestResponse(UserType userType)
        {
            // 400 BAD REQUEST: Invalid request format or credentials
            _logger.LogWarning("{UserType} validation: Bad request - invalid credentials or request format", userType);
            return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = $"Invalid credentials for {userType} service." };
        }

        private ValidationResult HandleOtherResponse(
            HttpResponseMessage response,
            UserType userType)
        {
            // Other status codes: Service error
            string errorMessage = $"External authentication service returned {response.StatusCode} for {userType} validation.";
            _logger.LogWarning(errorMessage);
            return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = errorMessage, StatusCode = (int)response.StatusCode };
        }

        private ValidationResult HandleHttpRequestException(
            HttpRequestException ex,
            UserType userType)
        {
            string errorMessage = $"HttpRequestException during {userType} validation: {ex.Message}";
            _logger.LogError(ex, errorMessage);
            return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = errorMessage };
        }

        private ValidationResult HandleGeneralException(
            Exception ex,
            UserType userType)
        {
            string errorMessage = $"An unexpected error occurred during {userType} validation: {ex.Message}";
            _logger.LogError(ex, errorMessage);
            return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = errorMessage };
        }
    }
}