#Requires -Version 5.1

<#
.SYNOPSIS
    Applies Entity Framework migrations to CloudNative-PG database via port forwarding
    
.DESCRIPTION
    This script sets up port forwarding to a CloudNative-PG PostgreSQL cluster,
    retrieves database credentials from Kubernetes secrets, and applies EF Core migrations.
    
    Works with any Maliev microservice by specifying the service name parameter.
    
.EXAMPLE
    # AuthService
    .\apply-migration.ps1 -ServiceName "auth"
    
    # OrderService  
    .\apply-migration.ps1 -ServiceName "order"
    
    # Interactive mode (prompts for all values)
    .\apply-migration.ps1
#>

param(
    [Parameter()]
    [string]$ServiceName,
    
    [Parameter()]
    [string]$LocalPort = "5433"
)

# Color functions
function Write-Info($message) { Write-Host $message -ForegroundColor Cyan }
function Write-Success($message) { Write-Host $message -ForegroundColor Green }
function Write-Warning($message) { Write-Host $message -ForegroundColor Yellow }
function Write-Error($message) { Write-Host $message -ForegroundColor Red }

# Cleanup function
function Cleanup {
    if ($portForwardJob) {
        Write-Info "Stopping port forward..."
        Stop-Job $portForwardJob -ErrorAction SilentlyContinue
        Remove-Job $portForwardJob -ErrorAction SilentlyContinue
    }
}

# Set up cleanup on script exit
$ErrorActionPreference = "Stop"
Register-EngineEvent PowerShell.Exiting -Action { Cleanup } | Out-Null

Write-Info "=== CloudNative-PG Migration Script ==="
Write-Info ""

try {
    # Check prerequisites
    Write-Info "Checking prerequisites..."
    
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        throw "kubectl not found in PATH. Please install kubectl and ensure it's configured."
    }
    
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "dotnet CLI not found in PATH. Please install .NET SDK."
    }

    # Determine database name from service parameter or prompt
    if (-not [string]::IsNullOrWhiteSpace($ServiceName)) {
        $databaseName = "${ServiceName}_app_db"  # Each service gets its own database
        Write-Info "Using service: $ServiceName"
        Write-Info "Database name: $databaseName"
        Write-Info ""
    }

    # Get user inputs (with defaults when ServiceName is provided)
    Write-Info "Please provide the following information:"
    
    if ([string]::IsNullOrWhiteSpace($ServiceName)) {
        $namespace = Read-Host "Kubernetes namespace (e.g., maliev-dev)"
    } else {
        $defaultNamespace = "maliev-dev"
        $namespaceInput = Read-Host "Kubernetes namespace [$defaultNamespace]"
        $namespace = if ([string]::IsNullOrWhiteSpace($namespaceInput)) { $defaultNamespace } else { $namespaceInput }
    }
    if ([string]::IsNullOrWhiteSpace($namespace)) {
        throw "Namespace cannot be empty"
    }

    if ([string]::IsNullOrWhiteSpace($ServiceName)) {
        $clusterName = Read-Host "PostgreSQL cluster name (e.g., postgres-cluster)"
    } else {
        $defaultCluster = "postgres-cluster"
        $clusterInput = Read-Host "PostgreSQL cluster name [$defaultCluster]"
        $clusterName = if ([string]::IsNullOrWhiteSpace($clusterInput)) { $defaultCluster } else { $clusterInput }
    }
    if ([string]::IsNullOrWhiteSpace($clusterName)) {
        throw "Cluster name cannot be empty"
    }

    if ([string]::IsNullOrWhiteSpace($ServiceName)) {
        $secretName = Read-Host "Database secret name (e.g., postgres-superuser-credentials)"
    } else {
        $defaultSecret = "postgres-superuser-credentials"
        $secretInput = Read-Host "Database secret name [$defaultSecret]"
        $secretName = if ([string]::IsNullOrWhiteSpace($secretInput)) { $defaultSecret } else { $secretInput }
    }
    if ([string]::IsNullOrWhiteSpace($secretName)) {
        throw "Secret name cannot be empty"
    }

    # Only prompt for database name if not already set from ServiceName
    if ([string]::IsNullOrWhiteSpace($databaseName)) {
        Write-Info ""
        Write-Info "DATABASE NAMING CONVENTION:"
        Write-Info "- AuthService: auth_app_db"
        Write-Info "- OrderService: order_app_db"
        Write-Info "- CustomerService: customer_app_db"
        Write-Info "- InvoiceService: invoice_app_db"
        Write-Info "- etc."
        Write-Info ""
        
        do {
            $databaseName = Read-Host "Database name (follow convention: [service]_app_db)"
            if ([string]::IsNullOrWhiteSpace($databaseName)) {
                Write-Error "Database name cannot be empty"
                continue
            }
            
            # Validate database name format
            if ($databaseName -notmatch '^[a-z][a-z0-9_]*_app_db$') {
                Write-Error "Invalid database name format. Must follow pattern: [service]_app_db (lowercase, underscores only)"
                Write-Info "Examples: auth_app_db, order_app_db, customer_app_db"
                $databaseName = $null
                continue
            }
            
            break
        } while ($true)
    }

    # Verify cluster exists
    Write-Info "Verifying PostgreSQL cluster exists..."
    $cluster = kubectl get cluster $clusterName -n $namespace -o json 2>$null | ConvertFrom-Json
    if (-not $cluster) {
        throw "PostgreSQL cluster '$clusterName' not found in namespace '$namespace'"
    }
    Write-Success "✓ Cluster '$clusterName' found"

    # Get credentials from secret
    Write-Info "Retrieving database credentials..."
    $username = kubectl get secret $secretName -n $namespace -o jsonpath="{.data.username}" 2>$null
    if (-not $username) {
        throw "Could not retrieve username from secret '$secretName'"
    }
    $username = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($username))

    $password = kubectl get secret $secretName -n $namespace -o jsonpath="{.data.password}" 2>$null
    if (-not $password) {
        throw "Could not retrieve password from secret '$secretName'"
    }
    $password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($password))
    Write-Success "✓ Credentials retrieved"

    # Check if port is available
    Write-Info "Checking if port $LocalPort is available..."
    $portTest = Test-NetConnection -ComputerName localhost -Port $LocalPort -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($portTest) {
        throw "Port $LocalPort is already in use. Please specify a different port or stop the service using this port."
    }
    Write-Success "✓ Port $LocalPort is available"

    # Start port forwarding
    Write-Info "Starting port forward to $clusterName-rw service..."
    $portForwardJob = Start-Job -ScriptBlock {
        param($namespace, $clusterName, $localPort)
        kubectl port-forward -n $namespace service/$clusterName-rw ${localPort}:5432
    } -ArgumentList $namespace, $clusterName, $LocalPort

    # Wait for port forward to be ready
    Write-Info "Waiting for port forward to be ready..."
    $maxAttempts = 30
    $attempt = 0
    $connected = $false

    do {
        Start-Sleep -Seconds 1
        $attempt++
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.ReceiveTimeout = 1000
            $tcpClient.SendTimeout = 1000
            $tcpClient.Connect("localhost", $LocalPort)
            $connected = $true
            $tcpClient.Close()
        } catch {
            # Connection not ready yet
        }
    } while (-not $connected -and $attempt -lt $maxAttempts)

    if (-not $connected) {
        throw "Port forward did not become ready within 30 seconds"
    }
    Write-Success "✓ Port forward is ready"

    # Build connection string (avoid exposing password in process list)
    # Escape any special characters in password
    $escapedPassword = $password -replace "'", "''"
    
    # Check if database exists and create if needed (using superuser privileges)
    Write-Info "Checking if database '$databaseName' exists..."
    
    # Connect to default postgres database to check/create target database
    $postgresConnectionString = "Host=localhost;Port=$LocalPort;Database=postgres;Username=$username;Password='$escapedPassword';SslMode=Disable"
    
    try {
        # Use kubectl exec to check if database exists (more reliable than psql on Windows)
        $checkDbQuery = "SELECT 1 FROM pg_database WHERE datname='$databaseName'"
        $dbExists = kubectl exec -n $namespace $clusterName-1 -- psql -U postgres -t -c $checkDbQuery 2>$null
        
        if ([string]::IsNullOrWhiteSpace($dbExists)) {
            Write-Info "Database '$databaseName' does not exist. Creating..."
            $createResult = kubectl exec -n $namespace $clusterName-1 -- psql -U postgres -c "CREATE DATABASE `"$databaseName`";" 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Success "✓ Database '$databaseName' created successfully"
            } else {
                throw "Failed to create database: $createResult"
            }
        } else {
            Write-Success "✓ Database '$databaseName' already exists"
        }
    } catch {
        Write-Warning "Could not verify/create database using kubectl. Attempting EF migration anyway..."
        Write-Info "Note: If migration fails, the database may need to be created manually."
    }
    
    $env:TEMP_MIGRATION_CONNECTION_STRING = "Host=localhost;Port=$LocalPort;Database=$databaseName;Username=$username;Password='$escapedPassword';SslMode=Disable"
    $env:ConnectionStrings__Default = $env:TEMP_MIGRATION_CONNECTION_STRING
    
    Write-Info "Testing connection with username: $username to database: $databaseName"
    Write-Info "Port: $LocalPort"
    Write-Info "Environment variable set: ConnectionStrings__Default"
    
    # Verify environment variable is set (without exposing password)
    if ($env:ConnectionStrings__Default) {
        $maskedConnectionString = $env:ConnectionStrings__Default -replace 'Password=.*?;', 'Password=***;'
        Write-Info "Connection string: $maskedConnectionString"
    } else {
        Write-Error "Environment variable not set properly!"
    }

    # Test database connection before applying migrations
    Write-Info "Testing database connection..."
    try {
        $testResult = kubectl exec -n $namespace $clusterName-1 -- psql -U postgres -d $databaseName -c "SELECT 1;" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "✓ Database connection test successful"
        } else {
            Write-Warning "Direct database connection test failed: $testResult"
        }
    } catch {
        Write-Warning "Could not test database connection directly"
    }
    
    Write-Info "Ready to apply migrations..."

    # Apply migrations
    Write-Info "Applying Entity Framework migrations..."
    Write-Warning "This will modify the database schema. Continue? (y/N)"
    $confirm = Read-Host
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Info "Migration cancelled by user"
        return
    }

    Write-Info "Setting connection string and applying migrations..."
    
    # Use design-time factory instead of startup project to avoid application startup issues
    # Pass connection string directly to avoid environment variable issues
    $migrationResult = dotnet ef database update --project . --connection "$env:TEMP_MIGRATION_CONNECTION_STRING" --verbose 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "✓ Migrations applied successfully!"
        Write-Info "Migration output:"
        Write-Host $migrationResult -ForegroundColor Gray
    } else {
        throw "Migration failed with exit code $LASTEXITCODE. Error: $migrationResult"
    }

} catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    exit 1
} finally {
    # Clean up environment variables
    Remove-Item Env:TEMP_MIGRATION_CONNECTION_STRING -ErrorAction SilentlyContinue
    Remove-Item Env:ConnectionStrings__Default -ErrorAction SilentlyContinue
    
    # Clean up port forward
    Cleanup
    
    Write-Info ""
    Write-Info "Script completed. Port forwarding has been stopped."
}