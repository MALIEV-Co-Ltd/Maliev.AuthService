using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class LoggingOptions
    {
        public const string SectionName = "Serilog";
        
        public bool EnableStructuredLogging { get; set; } = true;
        public bool EnableFileLogging { get; set; } = true;
        public bool EnableConsoleLogging { get; set; } = true;
        public bool EnableCorrelationIds { get; set; } = true;
        
        [Required]
        public string LogLevel { get; set; } = "Information";
        
        public string LogFilePath { get; set; } = "logs/auth-service-.txt";
        public string LogFileRollingInterval { get; set; } = "Day";
        public int LogFileRetainedFileCountLimit { get; set; } = 31;
        public string LogFileOutputTemplate { get; set; } = 
            "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {CorrelationId} {SourceContext} {Message:lj}{NewLine}{Exception}";
        
        public Dictionary<string, string> LogLevelOverrides { get; set; } = new()
        {
            ["Microsoft.AspNetCore"] = "Warning",
            ["Microsoft.EntityFrameworkCore"] = "Warning",
            ["System.Net.Http.HttpClient"] = "Warning"
        };
        
        public List<string> SensitiveProperties { get; set; } = new()
        {
            "Password", "SecurityKey", "AccessToken", "RefreshToken", 
            "Authorization", "Cookie", "X-API-Key"
        };
    }
}