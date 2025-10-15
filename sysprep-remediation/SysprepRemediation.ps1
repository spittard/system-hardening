# =============================================================================
# Sysprep Remediation Script for Windows EC2 Instances
# =============================================================================
# This script remediates common issues after sysprep that disable:
# - Remote Desktop Protocol (RDP)
# - AWS Systems Manager (SSM) Agent
# - Administrator account access
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = ".\Config\RemediationConfig.json",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\Logs\SysprepRemediation.log",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# =============================================================================
# Configuration and Logging Setup
# =============================================================================

# Create logs directory if it doesn't exist
$LogDir = Split-Path $LogPath -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Import logging functions
. .\Modules\Logging.ps1

# Import configuration
. .\Modules\Configuration.ps1

# Initialize logging
Initialize-Logging -LogPath $LogPath -Verbose:$Verbose

# Load configuration
$Config = Get-RemediationConfig -ConfigFile $ConfigFile

Write-Log -Level "INFO" -Message "Starting Sysprep Remediation Script"
Write-Log -Level "INFO" -Message "Configuration loaded from: $ConfigFile"
Write-Log -Level "INFO" -Message "Log file: $LogPath"

# =============================================================================
# Main Remediation Functions
# =============================================================================

function Enable-RemoteDesktop {
    <#
    .SYNOPSIS
    Enables Remote Desktop Protocol (RDP) on the Windows instance
    #>
    param(
        [hashtable]$Config
    )
    
    Write-Log -Level "INFO" -Message "Starting RDP remediation..."
    
    try {
        # Enable RDP in registry
        Write-Log -Level "INFO" -Message "Setting fDenyTSConnections to 0"
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
        
        # Enable RDP firewall rules
        Write-Log -Level "INFO" -Message "Enabling RDP firewall rules"
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        
        # Restart Terminal Services
        Write-Log -Level "INFO" -Message "Restarting Terminal Services"
        Restart-Service TermService -Force -ErrorAction SilentlyContinue
        
        Write-Log -Level "SUCCESS" -Message "RDP successfully enabled"
        return $true
    }
    catch {
        Write-Log -Level "ERROR" -Message "Failed to enable RDP: $($_.Exception.Message)"
        return $false
    }
}

function Install-SSMAgent {
    <#
    .SYNOPSIS
    Installs or reinstalls AWS Systems Manager Agent
    #>
    param(
        [hashtable]$Config
    )
    
    Write-Log -Level "INFO" -Message "Starting SSM Agent remediation..."
    
    try {
        $ssmPath = "C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"
        $installerPath = "C:\AmazonSSMAgentSetup.exe"
        
        # Check if SSM Agent already exists
        if (Test-Path $ssmPath) {
            Write-Log -Level "INFO" -Message "SSM Agent found at: $ssmPath"
        } else {
            Write-Log -Level "WARN" -Message "SSM Agent not found. Downloading installer..."
            
            # Download SSM Agent installer
            $downloadUrl = $Config.SSMAgent.DownloadUrl
            Write-Log -Level "INFO" -Message "Downloading from: $downloadUrl"
            
            Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
            
            # Install SSM Agent silently
            Write-Log -Level "INFO" -Message "Installing SSM Agent..."
            Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait
            
            # Clean up installer
            Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        }
        
        # Configure and start SSM Agent service
        Write-Log -Level "INFO" -Message "Configuring SSM Agent service"
        Set-Service -Name "AmazonSSMAgent" -StartupType Automatic
        Start-Service -Name "AmazonSSMAgent"
        
        # Verify service is running
        $service = Get-Service -Name "AmazonSSMAgent" -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-Log -Level "SUCCESS" -Message "SSM Agent successfully installed and running"
            return $true
        } else {
            Write-Log -Level "ERROR" -Message "SSM Agent service is not running"
            return $false
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "Failed to install SSM Agent: $($_.Exception.Message)"
        return $false
    }
}

function Reset-AdministratorPassword {
    <#
    .SYNOPSIS
    Resets the Administrator account password
    #>
    param(
        [hashtable]$Config
    )
    
    Write-Log -Level "INFO" -Message "Starting Administrator password reset..."
    
    try {
        $newPassword = $Config.Administrator.NewPassword
        $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
        
        Write-Log -Level "INFO" -Message "Setting new Administrator password"
        Set-LocalUser -Name "Administrator" -Password $securePassword
        
        # Enable Administrator account if disabled
        Write-Log -Level "INFO" -Message "Enabling Administrator account"
        Enable-LocalUser -Name "Administrator"
        
        Write-Log -Level "SUCCESS" -Message "Administrator password successfully reset"
        return $true
    }
    catch {
        Write-Log -Level "ERROR" -Message "Failed to reset Administrator password: $($_.Exception.Message)"
        return $false
    }
}

function Test-SystemAccess {
    <#
    .SYNOPSIS
    Tests system access after remediation
    #>
    param(
        [hashtable]$Config
    )
    
    Write-Log -Level "INFO" -Message "Testing system access..."
    
    $results = @{
        RDP = $false
        SSM = $false
        Admin = $false
    }
    
    # Test RDP
    try {
        $rdpReg = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
        if ($rdpReg.fDenyTSConnections -eq 0) {
            $results.RDP = $true
            Write-Log -Level "SUCCESS" -Message "RDP is enabled"
        } else {
            Write-Log -Level "WARN" -Message "RDP is still disabled"
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "Failed to test RDP status"
    }
    
    # Test SSM Agent
    try {
        $ssmService = Get-Service -Name "AmazonSSMAgent" -ErrorAction SilentlyContinue
        if ($ssmService -and $ssmService.Status -eq "Running") {
            $results.SSM = $true
            Write-Log -Level "SUCCESS" -Message "SSM Agent is running"
        } else {
            Write-Log -Level "WARN" -Message "SSM Agent is not running"
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "Failed to test SSM Agent status"
    }
    
    # Test Administrator account
    try {
        $adminUser = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($adminUser -and $adminUser.Enabled) {
            $results.Admin = $true
            Write-Log -Level "SUCCESS" -Message "Administrator account is enabled"
        } else {
            Write-Log -Level "WARN" -Message "Administrator account is disabled"
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "Failed to test Administrator account status"
    }
    
    return $results
}

# =============================================================================
# Main Execution
# =============================================================================

Write-Log -Level "INFO" -Message "=== Sysprep Remediation Started ==="
Write-Log -Level "INFO" -Message "Script Version: 1.0.0"
Write-Log -Level "INFO" -Message "Execution Mode: $(if($WhatIf) {'What-If'} else {'Normal'})"

$remediationResults = @{
    RDP = $false
    SSM = $false
    Admin = $false
    Overall = $false
}

# Execute remediation steps
if ($Config.Remediation.EnableRDP) {
    $remediationResults.RDP = Enable-RemoteDesktop -Config $Config
}

if ($Config.Remediation.InstallSSMAgent) {
    $remediationResults.SSM = Install-SSMAgent -Config $Config
}

if ($Config.Remediation.ResetAdminPassword) {
    $remediationResults.Admin = Reset-AdministratorPassword -Config $Config
}

# Test system access
$testResults = Test-SystemAccess -Config $Config

# Determine overall success
$remediationResults.Overall = ($remediationResults.RDP -and $remediationResults.SSM -and $remediationResults.Admin)

# Log final results
Write-Log -Level "INFO" -Message "=== Remediation Results ==="
Write-Log -Level "INFO" -Message "RDP Enabled: $($remediationResults.RDP)"
Write-Log -Level "INFO" -Message "SSM Agent Installed: $($remediationResults.SSM)"
Write-Log -Level "INFO" -Message "Admin Password Reset: $($remediationResults.Admin)"
Write-Log -Level "INFO" -Message "Overall Success: $($remediationResults.Overall)"

if ($remediationResults.Overall) {
    Write-Log -Level "SUCCESS" -Message "=== Sysprep Remediation Completed Successfully ==="
    Write-Host "✅ Sysprep remediation completed successfully!" -ForegroundColor Green
    Write-Host "📋 Check the log file for detailed information: $LogPath" -ForegroundColor Cyan
} else {
    Write-Log -Level "ERROR" -Message "=== Sysprep Remediation Failed ==="
    Write-Host "❌ Sysprep remediation failed. Check the log file for details: $LogPath" -ForegroundColor Red
    exit 1
}

Write-Log -Level "INFO" -Message "=== Script Execution Complete ==="
