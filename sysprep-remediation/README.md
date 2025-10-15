# Sysprep Remediation Script

A comprehensive PowerShell solution for remediating Windows EC2 instances that have been affected by sysprep operations, which commonly disable RDP, SSM Agent, and Administrator access.

## 🚀 Features

- **Automated RDP Recovery**: Re-enables Remote Desktop Protocol access
- **SSM Agent Restoration**: Downloads and reinstalls AWS Systems Manager Agent
- **Administrator Password Reset**: Resets and enables the Administrator account
- **Comprehensive Logging**: Detailed audit trail with multiple log levels
- **Modular Configuration**: JSON-based configuration for different scenarios
- **Multiple Remediation Scenarios**: Pre-configured scenarios for different use cases
- **Error Handling**: Robust error handling and validation

## 📁 Project Structure

```
sysprep-remediation/
├── SysprepRemediation.ps1          # Main remediation script
├── Modules/
│   ├── Logging.ps1                 # Logging functionality
│   └── Configuration.ps1           # Configuration management
├── Config/
│   └── RemediationConfig.json      # Configuration file
├── Logs/                           # Log files (created automatically)
└── README.md                       # This file
```

## 🛠️ Installation

1. **Clone or download** this repository to your Windows EC2 instance
2. **Ensure PowerShell execution policy** allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. **Verify dependencies** are available (Internet access for SSM Agent download)

## 🚀 Quick Start

### Basic Usage

```powershell
# Run with default configuration
.\SysprepRemediation.ps1

# Run with custom log path
.\SysprepRemediation.ps1 -LogPath "C:\Logs\MyRemediation.log"

# Run in verbose mode
.\SysprepRemediation.ps1 -Verbose

# Test run (what-if mode)
.\SysprepRemediation.ps1 -WhatIf
```

### Using Different Scenarios

The script supports multiple pre-configured scenarios:

```powershell
# Full remediation (default)
.\SysprepRemediation.ps1

# Only enable RDP
.\SysprepRemediation.ps1 -Scenario "RDPOnly"

# Only reinstall SSM Agent
.\SysprepRemediation.ps1 -Scenario "SSMOnly"

# Only reset Administrator password
.\SysprepRemediation.ps1 -Scenario "PasswordOnly"

# Minimal remediation for testing
.\SysprepRemediation.ps1 -Scenario "Minimal"
```

## ⚙️ Configuration

### Configuration File

Edit `Config\RemediationConfig.json` to customize behavior:

```json
{
  "Remediation": {
    "EnableRDP": true,
    "InstallSSMAgent": true,
    "ResetAdminPassword": true,
    "CreateBackupUser": false
  },
  "Administrator": {
    "NewPassword": "YourSecurePassword123!",
    "EnableAccount": true,
    "ResetPassword": true
  },
  "SSMAgent": {
    "DownloadUrl": "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe"
  }
}
```

### Available Scenarios

| Scenario | Description | RDP | SSM | Password | Backup User |
|----------|-------------|-----|-----|----------|-------------|
| `FullRemediation` | Complete remediation | ✅ | ✅ | ✅ | ✅ |
| `RDPOnly` | Only enable RDP | ✅ | ❌ | ❌ | ❌ |
| `SSMOnly` | Only reinstall SSM Agent | ❌ | ✅ | ❌ | ❌ |
| `PasswordOnly` | Only reset password | ❌ | ❌ | ✅ | ❌ |
| `Minimal` | Minimal for testing | ✅ | ✅ | ❌ | ❌ |

## 📊 Logging

### Log Levels

- **DEBUG**: Detailed debugging information
- **INFO**: General information messages
- **WARN**: Warning messages
- **ERROR**: Error conditions
- **SUCCESS**: Successful operations

### Log Files

- **Location**: `.\Logs\SysprepRemediation.log` (default)
- **Format**: `[Timestamp] [Level] Message`
- **Rotation**: Manual (delete old logs as needed)

### Log Examples

```
[2024-01-15 10:30:45.123] [INFO] Starting Sysprep Remediation Script
[2024-01-15 10:30:45.456] [INFO] Configuration loaded from: .\Config\RemediationConfig.json
[2024-01-15 10:30:45.789] [INFO] Starting RDP remediation...
[2024-01-15 10:30:46.012] [SUCCESS] RDP successfully enabled
[2024-01-15 10:30:46.345] [INFO] Starting SSM Agent remediation...
[2024-01-15 10:30:50.678] [SUCCESS] SSM Agent successfully installed and running
```

## 🔧 Advanced Usage

### Custom Configuration

```powershell
# Load custom configuration
$config = Get-RemediationConfig -ConfigFile "C:\MyConfig\CustomConfig.json"

# Apply specific scenario
$config = Set-RemediationScenario -ScenarioName "RDPOnly" -Config $config

# Validate configuration
$validation = Validate-Configuration -Config $config
if (!$validation.IsValid) {
    Write-Warning "Configuration validation failed: $($validation.Errors -join ', ')"
}
```

### Logging Functions

```powershell
# Initialize custom logging
Initialize-Logging -LogPath "C:\Logs\Custom.log" -LogLevel "DEBUG" -Verbose

# Write custom log entries
Write-Log -Level "INFO" -Message "Custom operation started"
Write-Log -Level "ERROR" -Message "Operation failed" -Exception $_.Exception

# Export log summary
Export-LogSummary -LogPath ".\Logs\SysprepRemediation.log" -OutputPath ".\Logs\Summary.txt"
```

## 🛡️ Security Considerations

### Password Security

- **Change default passwords** in the configuration file
- **Use strong passwords** with mixed case, numbers, and special characters
- **Consider using AWS Secrets Manager** for production environments
- **Rotate passwords** regularly

### Network Security

- **Ensure HTTPS** is used for SSM Agent downloads
- **Verify download URLs** before execution
- **Use secure channels** for configuration file distribution

### Access Control

- **Run with appropriate privileges** (Administrator required)
- **Audit log files** regularly
- **Restrict access** to configuration files

## 🚨 Troubleshooting

### Common Issues

1. **Script execution blocked**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **SSM Agent download fails**
   - Check internet connectivity
   - Verify URL is accessible
   - Check firewall settings

3. **RDP not working after script**
   - Verify security group allows RDP (port 3389)
   - Check Windows Firewall settings
   - Restart the instance

4. **SSM Agent not connecting**
   - Verify IAM role has SSM permissions
   - Check SSM Agent service status
   - Review CloudWatch logs

### Debug Mode

```powershell
# Enable debug logging
.\SysprepRemediation.ps1 -LogLevel "DEBUG" -Verbose

# Check log statistics
$stats = Get-LogStatistics
Write-Host "Total log entries: $($stats.TotalLines)"
```

## 📋 Best Practices

### Before Running Script

1. **Create EBS snapshot** of the root volume
2. **Test in non-production** environment first
3. **Review configuration** settings
4. **Verify network connectivity**

### After Running Script

1. **Test RDP access** immediately
2. **Verify SSM Agent** in AWS console
3. **Change default passwords**
4. **Review log files** for any issues
5. **Clean up temporary files**

### Production Deployment

1. **Use version control** for configuration files
2. **Implement monitoring** for script execution
3. **Set up alerting** for failures
4. **Document customizations**

## 🔄 Recovery Methods

### Method 1: AWS Systems Manager Automation (Recommended)

1. Use `AWSSupport-ExecuteEC2Rescue` automation
2. Set `AllowOffline: true`
3. Monitor execution in Systems Manager console

### Method 2: Manual Volume Repair

1. Stop affected instance
2. Detach root volume
3. Attach to helper instance
4. Run this script on mounted volume
5. Reattach and restart

### Method 3: User Data Script

1. Stop instance
2. Update user data with script content
3. Start instance
4. Script executes on boot

## 📞 Support

For issues or questions:

1. **Check log files** for detailed error information
2. **Review configuration** for incorrect settings
3. **Test with minimal scenario** first
4. **Verify prerequisites** are met

## 📄 License

This project is provided as-is for educational and operational purposes. Use at your own risk and ensure compliance with your organization's security policies.

## 🔄 Version History

- **v1.0.0**: Initial release with basic remediation functionality
- **v1.1.0**: Added comprehensive logging and configuration management
- **v1.2.0**: Added multiple remediation scenarios and validation

---

**⚠️ Important**: Always test this script in a non-production environment before using it on critical systems. Ensure you have proper backups and recovery procedures in place.
