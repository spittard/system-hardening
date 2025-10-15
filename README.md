# System Hardening for AWS Windows Infrastructure

A comprehensive, enterprise-grade system hardening solution designed specifically for Windows Server environments deployed on AWS. This project addresses the critical security challenges of implementing CIS (Center for Internet Security) benchmarks on mature, production-ready codebases while maintaining operational functionality and compliance requirements.

## 🎯 Executive Overview

### Purpose

This repository provides a complete, automated system hardening framework that transforms Windows Server instances into highly secure, compliance-ready infrastructure suitable for enterprise production environments. The solution addresses the complex challenge of applying stringent security controls to existing systems without breaking critical business functionality.

### Key Challenges Addressed

#### 1. **Mature Codebase Integration**
- **Legacy Application Compatibility**: Many enterprise applications were built before modern security standards, making them incompatible with strict CIS controls
- **Dependency Management**: Existing applications often depend on deprecated protocols, weak encryption, or insecure configurations
- **Custom Configuration Requirements**: Production systems have unique configurations that must be preserved during hardening

#### 2. **Operational Continuity**
- **Zero-Downtime Deployment**: Hardening must be applied without disrupting business operations
- **Rollback Capabilities**: Complete rollback procedures for every security control implemented
- **Gradual Implementation**: Phased approach allowing testing and validation at each step

#### 3. **Compliance Complexity**
- **Multi-Framework Support**: Simultaneous compliance with CIS, NIST, OWASP, ISO 27001, PCI DSS, and HIPAA
- **Audit Trail Requirements**: Comprehensive logging and documentation for regulatory compliance
- **Continuous Monitoring**: Real-time compliance monitoring and alerting

#### 4. **AWS-Specific Challenges**
- **AMI-Based Deployment**: Hardening must be integrated into AMI creation and launch processes
- **Cloud Security Integration**: Seamless integration with AWS security services and IAM
- **Scalability Requirements**: Solutions must work across single instances and large-scale deployments

## 🏗️ Architecture Overview

The solution is organized into three specialized hardening modules:

### 1. **CIS Windows Server Hardening** (`cis-windows-server-hardening/`)
- **Purpose**: Core operating system security hardening
- **Scope**: Windows Server 2022 with RDP connectivity maintenance
- **Key Features**: 
  - Automated CIS policy application with RDP-friendly modifications
  - Administrative account management with secure password handling
  - Policy conflict resolution and compatibility fixes

### 2. **CIS IIS Hardening** (`cis-iis-hardening/`)
- **Purpose**: Web server security hardening for IIS
- **Scope**: Internet Information Services (IIS) 10.0+ security configuration
- **Key Features**:
  - SSL/TLS configuration and certificate management
  - Security headers and request filtering
  - Authentication and authorization controls
  - Comprehensive logging and monitoring

### 3. **Sysprep Remediation** (`sysprep-remediation/`)
- **Purpose**: Post-sysprep recovery and hardening
- **Scope**: AWS EC2 instances affected by sysprep operations
- **Key Features**:
  - RDP connectivity restoration
  - AWS Systems Manager Agent recovery
  - Administrator account remediation
  - Automated recovery procedures

## 🚀 AWS Windows Web & Database Server Hardening Workflow

### Phase 1: Pre-Deployment Preparation

#### 1.1 Environment Setup
```powershell
# Clone the hardening repository
git clone https://github.com/spittard/system-hardening.git
cd system-hardening

# Verify prerequisites
.\cis-windows-server-hardening\Tools\Test-Prerequisites.ps1
.\cis-iis-hardening\Tools\Test-Prerequisites.ps1
```

#### 1.2 AMI Preparation
```powershell
# Launch base Windows Server 2022 AMI
# Install required roles and features
Install-WindowsFeature -Name Web-Server, Web-Mgmt-Tools, Web-Scripting-Tools
Install-WindowsFeature -Name IIS-ASPNET45, IIS-NetFxExtensibility45
```

#### 1.3 Security Baseline Configuration
```powershell
# Apply initial security baseline
.\cis-windows-server-hardening\CIS-Hardening-Script.ps1 -CISAdminPassword "SecurePassword123!"
```

### Phase 2: Core System Hardening

#### 2.1 Windows Server Hardening
The Windows Server hardening process applies CIS Level 1 and Level 2 controls while maintaining operational functionality:

**Key Security Controls Applied:**
- **Account Management**: Secure password policies, account lockout policies
- **Audit Policies**: Comprehensive logging for security events
- **User Rights**: Least privilege access controls
- **Security Options**: Advanced security configurations
- **Network Security**: Firewall rules and network access controls

**RDP Connectivity Maintenance:**
- Removes `SeDenyRemoteInteractiveLogonRight` restrictions
- Enables RDP connections (`fDenyTSConnections` = 0)
- Configures proper user rights for Remote Desktop Users
- Maintains administrative access during hardening process

#### 2.2 Administrative Account Management
```powershell
# Automatic CISADMIN account creation with secure password
# Post-reboot rename to Administrator
.\cis-windows-server-hardening\Post-Reboot-Script.ps1
```

### Phase 3: Web Server Hardening

#### 3.1 IIS Security Configuration
```powershell
# Apply IIS hardening policies
.\cis-iis-hardening\IIS-Hardening-Scripts\CIS-IIS-Hardening.ps1 -HardeningLevel Level1

# Apply additional security policies
.\cis-iis-hardening\IIS-Hardening-Scripts\Apply-IIS-Policies.ps1
```

**IIS Security Controls Implemented:**
- **SSL/TLS Configuration**: Enforce TLS 1.2+ with strong cipher suites
- **Security Headers**: HSTS, X-Frame-Options, X-Content-Type-Options
- **Request Filtering**: Block dangerous file extensions and HTTP methods
- **Authentication**: Secure authentication mechanisms
- **Logging**: Enhanced W3C extended logging

#### 3.2 Database Server Integration
For SQL Server hardening (when applicable):
```powershell
# Apply database-specific security controls
.\cis-sqlserver-hardening\Apply-SQLServer-Policies.ps1
```

### Phase 4: AWS-Specific Configuration

#### 4.1 AWS Systems Manager Integration
```powershell
# Ensure SSM Agent is properly configured
.\sysprep-remediation\SysprepRemediation.ps1 -Scenario "SSMOnly"
```

#### 4.2 CloudWatch Integration
- Configure CloudWatch agents for security monitoring
- Set up log aggregation for compliance reporting
- Implement automated alerting for security events

#### 4.3 IAM Role Configuration
- Assign appropriate IAM roles for EC2 instances
- Configure least-privilege access policies
- Enable CloudTrail logging for administrative actions

### Phase 5: Compliance Verification

#### 5.1 Automated Compliance Testing
```powershell
# Run comprehensive compliance checks
.\cis-windows-server-hardening\Tools\Test-Compliance.ps1
.\cis-iis-hardening\Tools\Test-Compliance.ps1
```

#### 5.2 Security Assessment
- Vulnerability scanning with Tenable or similar tools
- Penetration testing of hardened systems
- Compliance reporting for audit requirements

## 📋 Detailed Hardening Process

### Windows Server Hardening Details

#### Core Security Policies Applied

**Account Policies:**
- Password complexity requirements (minimum 14 characters)
- Account lockout threshold (5 failed attempts)
- Password history (24 passwords remembered)
- Maximum password age (60 days)
- Minimum password age (1 day)

**Audit Policies:**
- Audit account logon events (Success, Failure)
- Audit account management (Success, Failure)
- Audit directory service access (Failure)
- Audit logon events (Success, Failure)
- Audit object access (Success, Failure)
- Audit policy change (Success, Failure)
- Audit privilege use (Success, Failure)
- Audit system events (Success, Failure)

**User Rights Assignment:**
- Access this computer from the network (Authenticated Users)
- Allow log on through Remote Desktop Services (Remote Desktop Users)
- Deny access to this computer from the network (Guest, Local account)
- Deny log on through Remote Desktop Services (Guest, Local account)

**Security Options:**
- Interactive logon: Do not display last username (Enabled)
- Interactive logon: Require Domain Controller authentication to unlock workstation (Enabled)
- Interactive logon: Smart card removal behavior (Lock workstation)
- Microsoft network server: Digitally sign communications (Always)
- Network access: Allow anonymous SID/Name translation (Disabled)
- Network access: Do not allow anonymous enumeration of SAM accounts (Enabled)
- Network access: Do not allow anonymous enumeration of SAM accounts and shares (Enabled)
- Network security: Do not store LAN Manager hash value on next password change (Enabled)
- Network security: LAN Manager authentication level (Send NTLMv2 response only. Refuse LM & NTLM)
- Network security: Minimum session security for NTLM SSP based servers (Require NTLMv2 session security, Require 128-bit encryption)

#### RDP Connectivity Maintenance

The hardening process specifically addresses the common issue where CIS policies disable RDP access:

**RDP-Friendly Modifications:**
1. **Remove RDP Deny Policies**: Eliminates `SeDenyRemoteInteractiveLogonRight` restrictions
2. **Enable RDP Service**: Ensures Terminal Services are properly configured
3. **Configure Firewall Rules**: Creates appropriate Windows Firewall rules for RDP
4. **User Rights Management**: Maintains proper group memberships for RDP access

**Administrative Account Strategy:**
1. **CISADMIN Account Creation**: Creates temporary administrative account with secure password
2. **Group Membership**: Adds to Administrators and Remote Desktop Users groups
3. **Post-Reboot Rename**: Renames CISADMIN to Administrator after policy application
4. **Password Management**: Implements secure password policies and rotation

### IIS Hardening Details

#### SSL/TLS Configuration

**Protocol Security:**
- Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1
- Enable only TLS 1.2 and TLS 1.3
- Configure strong cipher suites (AES-256, ChaCha20-Poly1305)
- Implement perfect forward secrecy

**Certificate Management:**
- Enforce certificate validation
- Configure certificate transparency
- Implement certificate pinning where applicable
- Set up automated certificate renewal

#### Security Headers Implementation

**HTTP Security Headers:**
- `Strict-Transport-Security`: Enforce HTTPS with HSTS
- `X-Frame-Options`: Prevent clickjacking attacks
- `X-Content-Type-Options`: Prevent MIME type sniffing
- `X-XSS-Protection`: Enable XSS filtering
- `Referrer-Policy`: Control referrer information
- `Content-Security-Policy`: Implement CSP for XSS protection

#### Request Filtering

**File Extension Filtering:**
- Block executable files (.exe, .bat, .cmd, .com, .pif, .scr)
- Block script files (.asp, .aspx, .php, .jsp, .pl, .py)
- Block configuration files (.config, .ini, .xml, .json)
- Block backup files (.bak, .backup, .old, .tmp)

**HTTP Method Filtering:**
- Allow only GET, POST, HEAD, OPTIONS
- Block dangerous methods (TRACE, DELETE, PUT, PATCH)
- Implement custom method validation

#### Authentication and Authorization

**Authentication Methods:**
- Disable anonymous authentication
- Enable Windows authentication
- Configure forms authentication where needed
- Implement multi-factor authentication

**Authorization Controls:**
- Role-based access control (RBAC)
- Resource-based authorization
- API endpoint protection
- Database access controls

### Sysprep Remediation Details

#### Common Sysprep Issues

**RDP Connectivity Loss:**
- Terminal Services disabled
- RDP firewall rules removed
- User rights assignments reset
- Service configurations reverted

**SSM Agent Issues:**
- Agent service stopped
- Configuration files reset
- IAM role associations lost
- CloudWatch integration broken

**Administrator Account Problems:**
- Account disabled
- Password reset
- Group memberships removed
- Profile corruption

#### Automated Recovery Process

**RDP Recovery:**
```powershell
# Enable Terminal Services
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

# Start RDP service
Start-Service -Name TermService

# Configure firewall
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
```

**SSM Agent Recovery:**
```powershell
# Download and install SSM Agent
$ssmUrl = "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe"
Invoke-WebRequest -Uri $ssmUrl -OutFile "C:\temp\AmazonSSMAgentSetup.exe"
Start-Process -FilePath "C:\temp\AmazonSSMAgentSetup.exe" -ArgumentList "/S" -Wait

# Start SSM Agent service
Start-Service -Name AmazonSSMAgent
```

**Administrator Account Recovery:**
```powershell
# Enable Administrator account
Enable-LocalUser -Name Administrator

# Set secure password
$securePassword = ConvertTo-SecureString "NewSecurePassword123!" -AsPlainText -Force
Set-LocalUser -Name Administrator -Password $securePassword

# Add to required groups
Add-LocalGroupMember -Group "Administrators" -Member "Administrator"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Administrator"
```

## 🔧 Implementation Challenges and Solutions

### Challenge 1: Legacy Application Compatibility

**Problem**: Existing applications may not work with strict security controls.

**Solution**: 
- Gradual implementation with compatibility testing
- Custom policy modifications for specific applications
- Rollback procedures for each security control
- Application-specific configuration adjustments

### Challenge 2: Performance Impact

**Problem**: Security controls may impact system performance.

**Solution**:
- Performance monitoring during implementation
- Optimized security configurations
- Load testing with security controls enabled
- Performance tuning recommendations

### Challenge 3: Compliance Requirements

**Problem**: Multiple compliance frameworks with conflicting requirements.

**Solution**:
- Unified compliance mapping across frameworks
- Automated compliance testing and reporting
- Continuous monitoring and alerting
- Regular compliance reviews and updates

### Challenge 4: Operational Continuity

**Problem**: Hardening must not disrupt business operations.

**Solution**:
- Phased implementation approach
- Comprehensive testing procedures
- Rollback capabilities for all changes
- Change management processes

## 📊 Compliance and Monitoring

### Compliance Frameworks Supported

- **CIS Benchmarks**: Windows Server 2022 and IIS 10.0
- **NIST Cybersecurity Framework**: Complete coverage
- **OWASP Top 10**: Web application security
- **ISO 27001**: Information security management
- **PCI DSS**: Payment card industry compliance
- **HIPAA**: Healthcare data protection

### Monitoring and Alerting

**Real-time Monitoring:**
- Security event logging
- Performance metrics tracking
- Compliance status monitoring
- Anomaly detection

**Automated Alerting:**
- Security policy violations
- Failed authentication attempts
- Unusual network activity
- Compliance drift detection

**Reporting:**
- Executive dashboards
- Technical compliance reports
- Audit documentation
- Trend analysis

## 🚨 Troubleshooting and Support

### Common Issues and Solutions

**RDP Connectivity Issues:**
1. Verify firewall rules are properly configured
2. Check user rights assignments
3. Ensure Terminal Services are running
4. Validate group memberships

**IIS Application Issues:**
1. Review application pool configurations
2. Check file permissions
3. Verify authentication settings
4. Test SSL/TLS configurations

**Compliance Failures:**
1. Run compliance verification scripts
2. Review security policy configurations
3. Check audit log settings
4. Validate user account policies

### Support Resources

- **Documentation**: Comprehensive guides for each module
- **Logging**: Detailed logs for troubleshooting
- **Rollback Procedures**: Complete recovery processes
- **Community Support**: GitHub issues and discussions

## 📈 Best Practices

### Pre-Implementation

1. **Create Complete Backups**: Full system backups before any changes
2. **Test in Non-Production**: Thorough testing in isolated environments
3. **Document Current State**: Baseline configurations and dependencies
4. **Plan Rollback Procedures**: Clear recovery processes for each change

### During Implementation

1. **Phased Approach**: Implement changes gradually
2. **Continuous Testing**: Validate functionality after each change
3. **Monitor Performance**: Track system performance metrics
4. **Document Changes**: Maintain detailed change logs

### Post-Implementation

1. **Compliance Verification**: Regular compliance checks
2. **Performance Monitoring**: Ongoing performance assessment
3. **Security Updates**: Regular security patch management
4. **Audit Preparation**: Maintain audit-ready documentation

## 🔄 Maintenance and Updates

### Regular Maintenance Tasks

- **Weekly**: Security log review and compliance checks
- **Monthly**: Performance analysis and optimization
- **Quarterly**: Comprehensive security assessment
- **Annually**: Full compliance audit and framework updates

### Update Procedures

1. **Test Updates**: Validate in non-production environment
2. **Backup Systems**: Create backups before applying updates
3. **Staged Deployment**: Deploy updates in phases
4. **Monitor Results**: Track performance and security metrics

## 📞 Support and Contributing

### Getting Help

- **Documentation**: Comprehensive guides in each module
- **Issues**: GitHub issues for bug reports and feature requests
- **Discussions**: Community discussions for questions and best practices

### Contributing

- **Code Contributions**: Pull requests welcome
- **Documentation**: Help improve guides and examples
- **Testing**: Report issues and test new features
- **Feedback**: Share experiences and suggestions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

These scripts modify system security settings and should be used with caution. Always test in a non-production environment first and ensure you have proper backups before applying to production systems. The authors are not responsible for any damage or data loss resulting from the use of these scripts.

---

**Note**: This repository is actively maintained and updated to reflect the latest security best practices, CIS benchmark updates, and AWS service changes. Regular updates ensure compatibility with new Windows Server versions and evolving security requirements.