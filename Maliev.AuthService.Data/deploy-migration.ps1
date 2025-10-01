#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Universal database migration script for Maliev microservices
.DESCRIPTION
    Applies EF Core migrations using standard workflow. Automatically port-forwards
    into the PostgreSQL pod before running migrations.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServiceName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("dev", "staging", "prod")]
    [string]$Environment,

    [Parameter(Mandatory = $false)]
    [int]$LocalPort
)

# --- Service Config ---
$ServiceConfig = @{
    "auth"   = @{ DatabaseName="auth_app_db"; ConnectionStringName="ConnectionStrings__RefreshTokenDbContext"; DisplayName="AuthService" }
}

# --- Environment Config ---
$EnvironmentConfig = @{
    "dev"     = @{ Namespace="maliev-dev";     DisplayName="Development"; RequireConfirmation=$false }
    "staging" = @{ Namespace="maliev-staging"; DisplayName="Staging";     RequireConfirmation=$false }
    "prod"    = @{ Namespace="maliev-prod";    DisplayName="Production";  RequireConfirmation=$true  }
}

function Write-Log {
    param([string]$Message, [ValidateSet("INFO","SUCCESS","WARNING","ERROR")][string]$Level="INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) { "SUCCESS"{"Green"} "WARNING"{"Yellow"} "ERROR"{"Red"} default{"Cyan"} }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-DatabaseCredentials {
    $envPassword = [System.Environment]::GetEnvironmentVariable("PGPASSWORD")
    if ($envPassword) { Write-Log "Using PGPASSWORD from environment" "INFO"; return $envPassword }
    $securePassword = Read-Host "Enter PostgreSQL password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

function Get-UserInput {
    if (-not $ServiceName) {
        Write-Host "`nAvailable services:" -ForegroundColor Yellow
        $ServiceConfig.Keys | Sort-Object | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }
        do { $ServiceName = Read-Host "`nEnter service name" } while (-not $ServiceConfig.ContainsKey($ServiceName))
    }
    if (-not $Environment) {
        Write-Host "`nAvailable environments:" -ForegroundColor Yellow
        $EnvironmentConfig.Keys | Sort-Object | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }
        do { $Environment = Read-Host "`nEnter environment (dev/staging/prod)" } while (-not $EnvironmentConfig.ContainsKey($Environment))
    }
    if (-not $LocalPort) { $LocalPort = 5432 }
    return @{ ServiceName=$ServiceName; Environment=$Environment; LocalPort=[int]$LocalPort }
}

function Find-PostgresPod {
    param($Namespace)

    # Try common CNPG label first
    $pod = (& kubectl get pod -n $Namespace -l cnpg.io/cluster=postgres-cluster -o jsonpath="{.items[*].metadata.name}" 2>$null).Trim()
    if ($pod) { return ($pod -split '\s+')[0] }

    # Fallback: list pod names and choose first that starts with postgres-cluster
    $all = (& kubectl get pods -n $Namespace -o jsonpath="{.items[*].metadata.name}" 2>$null).Trim()
    if ($all) {
        foreach ($name in $all -split '\s+') {
            if ($name -like "postgres-cluster*") { return $name }
        }
    }

    # Last resort: if single pod exists return it
    $first = (& kubectl get pods -n $Namespace -o jsonpath="{.items[0].metadata.name}" 2>$null).Trim()
    if ($first) { return $first }

    return $null
}

function Wait-ForLocalPort {
    param($DbHost, $Port, $TimeoutSec = 20)
    $end = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $end) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect($DbHost, $Port, $null, $null)
            $wait = $iar.AsyncWaitHandle.WaitOne(1000)
            if ($wait -and $tcp.Connected) { $tcp.EndConnect($iar); $tcp.Close(); return $true }
            $tcp.Close()
        } catch { }
        Start-Sleep -Seconds 1
    }
    return $false
}

# --- MAIN ---
$pfProcess = $null
try {
    $userInput   = Get-UserInput
    $ServiceName = $userInput.ServiceName
    $Environment = $userInput.Environment
    $LocalPort   = $userInput.LocalPort

    $serviceConfig = $ServiceConfig[$ServiceName]
    if (-not $serviceConfig) { throw "Unknown service: $ServiceName" }

    $envConfig = $EnvironmentConfig[$Environment]
    if (-not $envConfig) { throw "Unknown environment: $Environment" }

    Write-Log "=== Universal Maliev Database Migration ===" "INFO"
    Write-Log "Service: $($serviceConfig.DisplayName)" "INFO"
    Write-Log "Environment: $($envConfig.DisplayName) ($($envConfig.Namespace))" "INFO"
    Write-Log "Database: $($serviceConfig.DatabaseName)" "INFO"
    Write-Log "Local Port: $LocalPort" "INFO"

    if ($envConfig.RequireConfirmation) {
        $confirmation = Read-Host "Type 'DEPLOY' to confirm production deployment"
        if ($confirmation -ne "DEPLOY") { Write-Log "Cancelled by user" "WARNING"; exit 1 }
    }

    Write-Log "Searching for PostgreSQL pod..." "INFO"
    $postgresPod = Find-PostgresPod -Namespace $envConfig.Namespace
    if (-not $postgresPod) { throw "No postgres pod found in namespace $($envConfig.Namespace)" }

    Write-Log "Starting port-forward to pod: $postgresPod" "INFO"
    $portForwardArgs = "port-forward", "-n", $envConfig.Namespace, $postgresPod, "$LocalPort`:5432"
    $pfProcess = Start-Process -FilePath "kubectl" -ArgumentList $portForwardArgs -WindowStyle Hidden -PassThru

    # Wait until localhost:$LocalPort accepts connections
    Write-Log "Waiting for localhost:$LocalPort to be ready (timeout 30s)..." "INFO"
    if (-not (Wait-ForLocalPort -DbHost "localhost" -Port $LocalPort -TimeoutSec 30)) {
        throw "Port-forward did not open localhost:$LocalPort within timeout."
    }

    # Get DB password and build connection string
    $DatabasePassword = Get-DatabaseCredentials
    $connectionString = 'Host=localhost;Port={0};Database={1};Username=postgres;Password={2};Pooling=true;' -f $LocalPort, $serviceConfig.DatabaseName, $DatabasePassword

    # Optional: also set env var for local processes (keeps original behavior)
    Set-Item -Path "env:$($serviceConfig.ConnectionStringName)" -Value $connectionString -ErrorAction SilentlyContinue
    Write-Log "Connection string configured in environment variable $($serviceConfig.ConnectionStringName)" "INFO"

    Write-Log "Applying EF Core migrations..." "INFO"
    # Use explicit --connection so design-time resolves the correct DB
    & dotnet ef database update --connection "$connectionString" --verbose

    if ($LASTEXITCODE -eq 0) {
        Write-Log "=== MIGRATION SUCCESSFUL ===" "SUCCESS"
    } else {
        throw "EF Core migration failed"
    }

} catch {
    Write-Log "Migration failed with exception: $($_.Exception.Message)" "ERROR"
    exit 1
} finally {
    if ($serviceConfig -and $serviceConfig.ConnectionStringName) {
        Remove-Item "env:$($serviceConfig.ConnectionStringName)" -ErrorAction SilentlyContinue
    }
    if ($pfProcess -and $pfProcess.Id) {
        Write-Log "Stopping port-forward (PID $($pfProcess.Id))..." "INFO"
        try { Stop-Process -Id $pfProcess.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
}
