<##############################################################################
Ashley McGlone
Microsoft Premier Field Engineer
January 2014
http://aka.ms/GoateePFE

Sample script to query Active Directory for active XP computer accounts.

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
##########################################################################sdg#>

Import-Module ActiveDirectory

# The basic query for all XP computers in the domain
$XP = Get-ADComputer -Filter {OperatingSystem -like "*XP*"}

# The full-featured query
$XP = Get-ADComputer -Filter {OperatingSystem -like "*XP*"} `
    -Properties Name, DNSHostName, OperatingSystem, `
        OperatingSystemServicePack, OperatingSystemVersion, PasswordLastSet, `
        whenCreated, whenChanged, LastLogonTimestamp, nTSecurityDescriptor, `
        DistinguishedName |
    Select-Object Name, DNSHostName, OperatingSystem, `
        OperatingSystemServicePack, OperatingSystemVersion, PasswordLastSet, `
        whenCreated, whenChanged, `
        @{name='LastLogonTimestampDT';`
            Expression={[datetime]::FromFileTimeUTC($_.LastLogonTimestamp)}}, `
        @{name='Owner';`
            Expression={$_.nTSecurityDescriptor.Owner}}, `
        DistinguishedName

# Get only active XP computers in the last 90 days
$XP = Get-ADComputer -Filter {OperatingSystem -like "*XP*"} `
    -Properties Name, DNSHostName, OperatingSystem, `
        OperatingSystemServicePack, OperatingSystemVersion, PasswordLastSet, `
        whenCreated, whenChanged, LastLogonTimestamp, nTSecurityDescriptor, `
        DistinguishedName |
    Where-Object {$_.whenChanged -gt $((Get-Date).AddDays(-90))} |
    Select-Object Name, DNSHostName, OperatingSystem, `
        OperatingSystemServicePack, OperatingSystemVersion, PasswordLastSet, `
        whenCreated, whenChanged, `
        @{name='LastLogonTimestampDT';`
            Expression={[datetime]::FromFileTimeUTC($_.LastLogonTimestamp)}}, `
        @{name='Owner';`
            Expression={$_.nTSecurityDescriptor.Owner}}, `
        DistinguishedName

# View graphically
$XP | Out-GridView

# Export to CSV
$XP | Export-CSV .\xp.csv -NoTypeInformation

# Count how many computers
($XP | Measure-Object).Count

# Days to Windows XP end-of-life
(New-TimeSpan -End (Get-Date -Day 8 -Month 4 -Year 2014 `
    -Hour 0 -Minute 0 -Second 0)).Days
