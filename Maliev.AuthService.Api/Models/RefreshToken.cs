using System;
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public required string Username { get; set; }

        [Required]
        public required string Token { get; set; }

        [Required]
        public DateTime Expires { get; set; }

        public bool IsRevoked { get; set; }

        public DateTime Created { get; set; }

        public string? CreatedByIp { get; set; }

        public DateTime? Revoked { get; set; }

        public string? RevokedByIp { get; set; }

        public string? ReplacedByToken { get; set; }

        public bool IsActive => !IsRevoked && Expires > DateTime.UtcNow;
    }
}