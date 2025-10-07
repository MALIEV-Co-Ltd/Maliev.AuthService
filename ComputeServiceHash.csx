using System;
using System.Security.Cryptography;
using System.Text;

var secret = "valid_service_secret";
using var sha256 = SHA256.Create();
var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
var hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
Console.WriteLine($"Secret: {secret}");
Console.WriteLine($"Hash: {hash}");
