#Requires -Version 3.0

<##############################################################################
Ashley McGlone
Microsoft Premier Field Engineer
April 2013
http://aka.ms/GoateePFE

This script illustrates a nearly touch-free domain controller creation
and removal.  Adjust this template to meet your own needs.

This script requires:
1. Either Windows Server 2012 or Windows 8
2. Active Directory PowerShell module installed

WARNING:  For demonstration purposes this example includes a plain text
password embedded in the script.  In a production environment you should
perhaps use Read-Host to prompt for the password.


LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
 
This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at http://www.microsoft.com/info/cpyright.htm.
##############################################################################>


# Don't run the whole script by accident
break


###############################################################################
# VALIDATION: Random ways to inspect a DC
###############################################################################

Import-Module ActiveDirectory

# Query the current list of domain controllers
Get-ADDomainController -Filter * |
    Format-Table Name, Site, IPv4Address -AutoSize

# Check random services common to DCs
Get-Service adws,kdc,netlogon,dns -ComputerName cvdc1
Get-Service adws,kdc,netlogon,dns -ComputerName member1

# Check for presence of SYSVOL
Test-Path \\cvdc1\SYSVOL
Get-ChildItem \\cvdc1\SYSVOL
Test-Path \\member1\SYSVOL
Get-ChildItem \\member1\SYSVOL



###############################################################################
# Working with the deployment module
###############################################################################

Get-Module a* -ListAvailable
Import-Module ADDSDeployment
Get-Command -Module ADDSDeployment
help Test-ADDSDomainControllerInstallation



###############################################################################
# DCPROMO UP: Create a new DC on a member server in the domain
###############################################################################

# Prompt for credentials to reuse throughout the script
$cred = Get-Credential Cohovineyard\Administrator

# Echo the date for reference in the console output
Get-Date

# Query the current list of domain controllers before the new one
Get-ADDomainController -Filter * |
    Format-Table Name, Site, IPv4Address -AutoSize

# Import the module containing Get-WindowsFeature
Import-Module ServerManager

# List the currently installed features on the remote server
Get-WindowsFeature -ComputerName cvmember1.cohovineyard.com | 
    Where-Object Installed | Format-Table Name

# Install the role for AD-Domain-Services
Install-WindowsFeature –Name AD-Domain-Services `
    –ComputerName cvmember1.cohovineyard.com `
    -IncludeManagementTools

# List the currently installed features on the remote server
# Notice AD-Domain-Services is now in the list
Get-WindowsFeature -ComputerName cvmember1.cohovineyard.com | 
    Where-Object Installed | Format-Table Name

# Promote a new domain controller in the existing domain
# Adjust the parameters to meet your own needs
# Notice we're going to handle the reboot ourselves
#####    BIG THING TO NOTICE    #####
# Notice that the -Credential parameter variable is prefaced with "$using:".
# This is a PS v3 feature, and it is required when passing variables
# into a remote session.  Invoke-Command is based on PowerShell remoting.
# Any other parameters that you turn into variables will need "$using:".
Invoke-Command –ComputerName cvmember1.cohovineyard.com –ScriptBlock {

    Import-Module ADDSDeployment;

    Install-ADDSDomainController `
        -NoGlobalCatalog:$false `
        -CreateDnsDelegation:$false `
        -CriticalReplicationOnly:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainName "CohoVineyard.com" `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$true `
        -ReplicationSourceDC "CVDC1.CohoVineyard.com" `
        -SiteName "Ohio" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true `
        -Credential $using:cred `
        -Confirm:$false `
        -SafeModeAdministratorPassword `
            (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)
}

# We are going to manage the restart ourselves.
Restart-Computer cvmember1.cohovineyard.com `
    -Wait -For PowerShell -Force -Confirm:$false

# Once fully restarted and promoted, query for a fresh list of DCs.
# Notice our new DC in the list.
Get-ADDomainController -Filter * |
    Format-Table Name, Site, IPv4Address -AutoSize

# Echo the date and time for job completion.
Get-Date



###############################################################################
# DCPROMO DOWN: Remove a DC in the domain
###############################################################################

# Prompt for credentials to reuse throughout the script
$cred = Get-Credential Cohovineyard\Administrator

# Echo the date for reference in the console output
Get-Date

# Query the current list of domain controllers before the removal
Get-ADDomainController -Filter * |
    Format-Table Name, Site, IPv4Address -AutoSize

# Reset the error variable
$error.Clear()

# Remove the domain controller in the existing domain
#####    BIG THING TO NOTICE    #####
# Notice that the -Credential parameter variable is prefaced with "$using:".
# This is a PS v3 feature, and it is required when passing variables
# into a remote session.  Invoke-Command is based on PowerShell remoting.
# Any other parameters that you turn into variables will need "$using:".
Invoke-Command –ComputerName cvmember1.cohovineyard.com –ScriptBlock {

    Uninstall-ADDSDomainController -Confirm:$false `
       -LocalAdministratorPassword `
            (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force) `
       -DemoteOperationMasterRole:$true `
       -Credential $using:cred `
       -Force:$true
}

# Exit if the uninstall was unsuccessful
If ($error) {break}

# Give the server time to go down
Start-Sleep -Seconds 5

# The DC removal also removes the host A record in DNS.
# This effectively disables any other remoting until the server reboots.
# Therefore we tell the Uninstall to do the reboot by omitting the
# switch -NoRebootOnCompletion, and then we loop until we can confirm
# the server is reachable again and services are started.
Do    { Start-Sleep -Seconds 1 }
Until (Get-CIMInstance Win32_Bios `
        -ComputerName cvmember1.cohovineyard.com `
        -ErrorAction SilentlyContinue)

# Uninstall the AD DS & DNS roles
Import-Module ServerManager
Uninstall-WindowsFeature `
    –Name AD-Domain-Services, DNS, RSAT-AD-Tools, RSAT-AD-PowerShell `
    –ComputerName cvmember1.cohovineyard.com `
    -IncludeManagementTools `
    -Confirm:$false

# Restart the server and wait for services to come back up
Restart-Computer cvmember1.cohovineyard.com `
    -Wait -For PowerShell -Force -Confirm:$false

# View the roles to verify that AD-Domain-Services is really gone
Get-WindowsFeature -ComputerName cvmember1.cohovineyard.com | 
    Where-Object Installed | Format-Table Name

# Query for a fresh list of DCs.  Confirm it is gone from the list.
Get-ADDomainController -Filter * |
    Format-Table Name, Site, IPv4Address -AutoSize

# Echo the date and time for job completion.
Get-Date



############################################################################sdg