namespace Maliev.AuthService.Api.Services
{
    public interface IConfigurationValidationService
    {
        Task<ConfigValidationResult> ValidateConfigurationAsync();

        Task<ConfigValidationResult> ValidateJwtConfigurationAsync();

        Task<ConfigValidationResult> ValidateExternalServicesAsync();

        Task<bool> TestExternalServiceConnectivityAsync(string endpoint, CancellationToken cancellationToken = default);
    }

    public class ConfigValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new();
        public List<string> Warnings { get; set; } = new();

        public void AddError(string error)
        {
            Errors.Add(error);
        }

        public void AddWarning(string warning)
        {
            Warnings.Add(warning);
        }
    }
}