#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Universal database migration script for Maliev microservices
.DESCRIPTION
    Applies EF Core migrations using standard workflow. All service-specific variables are configurable.
.PARAMETER ServiceName
    Name of the service (e.g., "auth", "country", "order")
.PARAMETER Environment
    Target environment: dev, staging, prod (default: staging)
.PARAMETER LocalPort
    Local port for port forwarding (default: 5432)
.EXAMPLE
    .\deploy-migration-v2.ps1 -ServiceName country -Environment staging -LocalPort 5433
.EXAMPLE
    .\deploy-migration-v2.ps1  # Will prompt for all values
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

# ===================================================================
# SERVICE CONFIGURATION - CUSTOMIZE THESE FOR EACH SERVICE
# ===================================================================

# Service-specific configuration mapping
$ServiceConfig = @{
    "auth" = @{
        DatabaseName = "auth_app_db"
        ConnectionStringName = "ConnectionStrings__RefreshTokenDbContext"
        DisplayName = "AuthService"
    }
    "country" = @{
        DatabaseName = "country_app_db"
        ConnectionStringName = "ConnectionStrings__CountryDbContext"
        DisplayName = "CountryService"
    }
    "order" = @{
        DatabaseName = "order_app_db"
        ConnectionStringName = "ConnectionStrings__OrderDbContext"
        DisplayName = "OrderService"
    }
    "currency" = @{
        DatabaseName = "currency_app_db"
        ConnectionStringName = "ConnectionStrings__CurrencyDbContext"
        DisplayName = "CurrencyService"
    }
    "material" = @{
        DatabaseName = "material_app_db"
        ConnectionStringName = "ConnectionStrings__MaterialDbContext"
        DisplayName = "MaterialService"
    }
    "customer" = @{
        DatabaseName = "customer_app_db"
        ConnectionStringName = "ConnectionStrings__CustomerDbContext"
        DisplayName = "CustomerService"
    }
    "supplier" = @{
        DatabaseName = "supplier_app_db"
        ConnectionStringName = "ConnectionStrings__SupplierDbContext"
        DisplayName = "SupplierService"
    }
    "upload" = @{
        DatabaseName = "upload_app_db"
        ConnectionStringName = "ConnectionStrings__UploadDbContext"
        DisplayName = "UploadService"
    }
}

# Environment Configuration
$EnvironmentConfig = @{
    "dev" = @{
        Namespace = "maliev-dev"
        DisplayName = "Development"
        RequireConfirmation = $false
    }
    "staging" = @{
        Namespace = "maliev-staging"
        DisplayName = "Staging"
        RequireConfirmation = $false
    }
    "prod" = @{
        Namespace = "maliev-prod"
        DisplayName = "Production"
        RequireConfirmation = $true
    }
}

# ===================================================================
# INTERACTIVE PROMPTS FOR MISSING PARAMETERS
# ===================================================================

function Get-UserInput {
    # Prompt for ServiceName if not provided
    if (-not $ServiceName) {
        Write-Host "`nAvailable services:" -ForegroundColor Yellow
        $ServiceConfig.Keys | Sort-Object | ForEach-Object {
            Write-Host "  - $_" -ForegroundColor Cyan
        }

        do {
            $ServiceName = Read-Host "`nEnter service name"
            if (-not $ServiceConfig.ContainsKey($ServiceName)) {
                Write-Host "Invalid service name. Please choose from the list above." -ForegroundColor Red
            }
        } while (-not $ServiceConfig.ContainsKey($ServiceName))
    }

    # Prompt for Environment if not provided
    if (-not $Environment) {
        Write-Host "`nAvailable environments:" -ForegroundColor Yellow
        $EnvironmentConfig.Keys | Sort-Object | ForEach-Object {
            Write-Host "  - $_" -ForegroundColor Cyan
        }

        do {
            $Environment = Read-Host "`nEnter environment (dev/staging/prod)"
            if (-not $EnvironmentConfig.ContainsKey($Environment)) {
                Write-Host "Invalid environment. Please choose: dev, staging, or prod" -ForegroundColor Red
            }
        } while (-not $EnvironmentConfig.ContainsKey($Environment))
    }

    # Prompt for LocalPort if not provided
    if (-not $LocalPort) {
        $LocalPort = Read-Host "`nEnter local port for connection (e.g., 5432, 5433)"
        if (-not $LocalPort) {
            $LocalPort = 5432
            Write-Host "Using default port: 5432" -ForegroundColor Yellow
        }
    }

    return @{
        ServiceName = $ServiceName
        Environment = $Environment
        LocalPort = [int]$LocalPort
    }
}

# ===================================================================
# LOGGING AND UTILITY FUNCTIONS
# ===================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "Cyan" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-DatabaseCredentials {
    # Try environment variable first
    $envPassword = [System.Environment]::GetEnvironmentVariable("PGPASSWORD")
    if ($envPassword) {
        Write-Log "Using password from environment variable: PGPASSWORD" "INFO"
        return $envPassword
    }

    # Fall back to prompting
    Write-Log "No password found in environment variable PGPASSWORD" "WARNING"
    $securePassword = Read-Host "Enter PostgreSQL password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

# ===================================================================
# MAIN EXECUTION
# ===================================================================

try {
    # Get user input for missing parameters
    $userInput = Get-UserInput
    $ServiceName = $userInput.ServiceName
    $Environment = $userInput.Environment
    $LocalPort = $userInput.LocalPort

    # Get configuration
    $serviceConfig = $ServiceConfig[$ServiceName]
    $envConfig = $EnvironmentConfig[$Environment]

    Write-Log "=== Universal Maliev Database Migration ===" "INFO"
    Write-Log "Service: $($serviceConfig.DisplayName)" "INFO"
    Write-Log "Environment: $($envConfig.DisplayName) ($($envConfig.Namespace))" "INFO"
    Write-Log "Database: $($serviceConfig.DatabaseName)" "INFO"
    Write-Log "Connection String: $($serviceConfig.ConnectionStringName)" "INFO"
    Write-Log "Local Port: $LocalPort" "INFO"

    # Production Safety Check
    if ($envConfig.RequireConfirmation) {
        Write-Log "=== PRODUCTION DEPLOYMENT WARNING ===" "WARNING"
        Write-Log "You are about to deploy to PRODUCTION environment!" "WARNING"
        Write-Log "Service: $($serviceConfig.DisplayName)" "WARNING"
        Write-Log "Environment: $($envConfig.DisplayName)" "WARNING"
        Write-Log "Namespace: $($envConfig.Namespace)" "WARNING"
        Write-Log "Database: $($serviceConfig.DatabaseName)" "WARNING"
        Write-Log "" "WARNING"

        $confirmation = Read-Host "Type 'DEPLOY' to confirm production deployment"
        if ($confirmation -ne "DEPLOY") {
            Write-Log "Production deployment cancelled by user" "WARNING"
            exit 1
        }
    }

    # Get database password
    $DatabasePassword = Get-DatabaseCredentials

    # Build connection string
    $connectionString = "Server=localhost;Port=$LocalPort;Database=$($serviceConfig.DatabaseName);User Id=postgres;Password=$DatabasePassword;"

    # Set environment variable for EF Core (using service-specific name)
    $connectionStringEnvVar = $serviceConfig.ConnectionStringName
    Set-Item -Path "env:$connectionStringEnvVar" -Value $connectionString

    Write-Log "Connection string configured for $connectionStringEnvVar" "INFO"
    Write-Log "Applying EF Core migrations..." "INFO"

    # Run EF Core migration (standard workflow)
    $migrationOutput = dotnet ef database update 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Log "=== MIGRATION SUCCESSFUL ===" "SUCCESS"
        Write-Log "Service: $($serviceConfig.DisplayName)" "SUCCESS"
        Write-Log "Database: $($serviceConfig.DatabaseName)" "SUCCESS"
        Write-Log "Environment: $($envConfig.DisplayName)" "SUCCESS"

        # Show migration output
        Write-Log "Migration Details:" "INFO"
        Write-Host $migrationOutput -ForegroundColor Gray
    } else {
        Write-Log "=== MIGRATION FAILED ===" "ERROR"
        Write-Log "Error Details:" "ERROR"
        Write-Host $migrationOutput -ForegroundColor Red
        exit 1
    }

} catch {
    Write-Log "Migration failed with exception: $($_.Exception.Message)" "ERROR"
    exit 1
} finally {
    # Clean up environment variables (dynamically)
    if ($serviceConfig -and $serviceConfig.ConnectionStringName) {
        $connectionStringEnvVar = $serviceConfig.ConnectionStringName
        Remove-Item "env:$connectionStringEnvVar" -ErrorAction SilentlyContinue
    }
}