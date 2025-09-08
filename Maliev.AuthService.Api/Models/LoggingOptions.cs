namespace Maliev.AuthService.Api.Models
{
    public class LoggingOptions
    {
        public const string SectionName = "Logging";

        public bool EnableStructuredLogging { get; set; } = true;

        public bool EnableSensitiveDataLogging { get; set; } = false;

        public string LogLevel { get; set; } = "Information";
    }
}