$secret = 'valid_service_secret'
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($secret))
$hash = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ''
Write-Host "Secret: $secret"
Write-Host "SHA256 Hash: $hash"
