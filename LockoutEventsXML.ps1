<#-----------------------------------------------------------------------------
Ashley McGlone
Microsoft Premier Field Engineer

Forensics: Automating Active Directory Account Lockout Search with PowerShell
(an example of deep XML filtering of event logs across multiple servers in parallel)

http://aka.ms/GoateePFE
August 31, 2015
-------------------------------------------------------------------------------
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
-----------------------------------------------------------------------------#>

Function Get-ADAccountLockoutData {
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [switch]$ResolveIP
)

    $LockedOutUsers = (Search-ADAccount -LockedOut).samAccountName

    If ($LockedOutUsers.Count -gt 0) {
        Write-Verbose "Found locked out users [$LockedOutUsers]."

        # Construct a compound user name filter for the event data and the AD query
        # Final results will look like this
        <#
        FilterXML:
            <QueryList><Query Id="0" Path="Security"><Select Path="Security">
            *[System[(EventID=4740 or EventID=4771) and TimeCreated[timediff(@SystemTime) &lt;= 43200000)]]]
            and
            *[EventData[(Data[@Name='TargetUserName'] = 'alice') or (Data[@Name='TargetUserName'] = 'bob') or (Data[@Name='TargetUserName'] = 'charlie')]]
            </Select></Query></QueryList>
        LDAP:
            (|(samAccountName=alice)(samAccountName=bob)(samAccountName=charlie))
        #>
        $UserFilterXML = 'and *[EventData['
        $UserFilterLDAP = '(|'
        ForEach ($User in $LockedOutUsers) {
            $UserFilterXML += "(Data[@Name='TargetUserName'] = '$User') or "
            $UserFilterLDAP += "(samAccountName=$User)"
        }
        $UserFilterXML = $UserFilterXML.Substring(0,$UserFilterXML.Length-4) + ']]'
        $UserFilterLDAP += ')'
    } Else {
        $UserFilterXML = $null
        $UserFilterLDAP = $null
        Write-Warning "No user accounts are currently locked out."
        Break
    }

    $DCs = Get-ADDomainController -Filter *

    $report = @()

    # Find the lockout stats for these users on all DCs
    # This happens serially
    ForEach ($DC in $DCs) {
        Write-Verbose "Querying DC [$($DC.HostName)] for user lockout counts."
        $report += Get-ADUser -LDAPFilter $UserFilterLDAP -Server $DC.HostName -ErrorAction Continue `
            -Properties cn, LockedOut, pwdLastSet, badPwdCount, badPasswordTime, lastLogon, lastLogoff, lastLogonTimeStamp, whenCreated, whenChanged | `
            Select-Object *, @{name='DC';expression={$DC.hostname}}, @{name='DCIP';expression={$DC.IPv4Address}}, @{name='DCSite';expression={$DC.site}}, @{name='PDC';expression={If ($DC.OperationMasterRoles -contains 'PDCEmulator') {'X'} Else {$null}}}
    }

    $ReportOut = $report |
        Select-Object `
            DC, `
            PDC, `
            DCIP, `
            DCSite, `
            cn, `
            LockedOut, `
            pwdLastSet, `
            @{name='pwdLastSetConverted';expression={[datetime]::fromFileTime($_.pwdlastset)}}, `
            badPwdCount,
            badPasswordTime, `
            @{name='badPasswordTimeConverted';expression={[datetime]::fromFileTime($_.badPasswordTime)}}, `
            lastLogon, `
            @{name='lastLogonConverted';expression={[datetime]::fromFileTime($_.lastLogon)}}, `
            lastLogoff, `
            @{name='lastLogoffConverted';expression={[datetime]::fromFileTime($_.lastLogoff)}}, `
            lastLogonTimeStamp, `
            @{name='lastLogonTimestampConverted';expression={[datetime]::fromFileTime($_.lastLogonTimestamp)}}, `
            whenCreated, `
            whenChanged |
        Sort-Object badPasswordTimeConverted
    $ReportOut | Out-GridView -Title 'Lockout Status By Account by DC'
    $ReportOut | Export-Csv -Path .\LockoutEvents_AccountData.csv -NoTypeInformation -Force

    # Only get event logs from the DCs that show a lockout count
    $DCs = $report | Where-Object {$_.badPwdCount -gt 0} | Select-Object -ExpandProperty DC -Unique

    $Milliseconds = $Hours * 3600000
    # Script block for remote event log filter and XML event data extraction
    # Logon audit failure events
    #   Event 4625 is bad password in client log
    #   Event 4771 is bad password in DC log
    #   Event 4740 is lockout in DC log
    $sb = {
[xml]$FilterXML = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">
*[System[(EventID=4740 or EventID=4771) and TimeCreated[timediff(@SystemTime) &lt;= $Using:Milliseconds]]]
$Using:UserFilterXML
</Select></Query></QueryList>
"@

        Try {
            $Events = Get-WinEvent -FilterXml $FilterXML -ErrorAction Stop

            ForEach ($Event in $Events) {
                # Convert the event to XML
                $eventXML = [xml]$Event.ToXml()
                # Iterate through each one of the XML message properties
                For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {
                    # Append these as object properties
                    Add-Member -InputObject $Event -MemberType NoteProperty -Force `
                        -Name  $eventXML.Event.EventData.Data[$i].name `
                        -Value $eventXML.Event.EventData.Data[$i].'#text'
                }
            }

            $Events | Select-Object *
        }
        Catch {
            If ($_.Exception -like "*No events were found that match the specified selection criteria*") {
                Write-Warning "[$(hostname)] No events found"
            } Else {
                $_
            }
        }
    
    }

    # Clear out the local job queue
    Get-Job | Remove-Job

    # Load up the local job queue with event log queries to each DC
    Write-Verbose "Querying lockout events on DCs [$DCs]."
    Invoke-Command -ScriptBlock $sb -ComputerName $DCs -AsJob | Out-Null

    # Loop until all jobs are completed or failed
    Do {
        Start-Sleep -Seconds 1
    } Until ((Get-Job | Where-Object {$_.State -eq 'Running'}).Count -eq 0)

    # Store all of the job output from the DCs into a single reporting variable
    $Output = Get-Job | Receive-Job

    # Clean up the local job queue
    Get-Job | Remove-Job

    If ($Output | Where-Object {$_.Id -eq 4771 -or $_.Id -eq 4771}) {

        If ($ResolveIP) {

            # Save some time on repeated IP lookups by caching results in a hash table
            $IPResults = @{}

            # Resolve IPs to names in the bad password attempt output
            ForEach ($Event in ($Output | Where-Object {$_.Id -eq 4771})) {

                # Does the event data contain an IPv4 address?  (dot instead of colon in IPv6)
                If ($Event.IPAddress.IndexOf('.') -gt 0) {

                    # IP Address parsed out of event data, room for error here
                    # Assuming IPv4 address is listed last in IP event data
                    $IP = $Event.IPAddress.split(':')[-1]

                    If ($IPResults.ContainsKey($IP)) {
                        $NSLookup = $IPResults[$IP]
                    }  Else {
                        # Can return multiple names if reverse zones are not clean, therefore join the strings.
                        Write-Verbose "Resolving IP address [$IP]."
                        $NSLookup = (Resolve-DnsName $IP -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost) -join ','
                        If ($NSLookup) {
                            $IPResults.Add($IP,$NSLookup)
                        } Else {
                            $NSLookup = '*NS_lookup_failed*'
                            $IPResults.Add($IP,$NSLookup)
                        }
                    }

                    Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name  IPtoHostname -Value $NSLookup

                } Else {
                    Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name  IPtoHostname -Value '*No_IPv4_Address*'
                }
            }
        }

        # Display results by event ID, because each event ID has a unique set of columns
        # Optimize column selection for display. Feel free to tweak.
        $ReportOut = $Output | Where-Object {$_.Id -eq 4771} | Select-Object TimeCreated,@{name='DC';expression={$_.PSComputerName}},TargetUserName,IpAddress,IpPort,IPtoHostname,ProviderName,LogName,Id,RecordId,LevelDisplayName,PreAuthType,KeywordDisplayNames,ServiceName,Status,TargetSid,TaskDisplayName,TicketOptions,UserId | Sort-Object TimeCreated
        $ReportOut | Out-GridView -Title 'Bad Password Events'
        $ReportOut | Export-Csv -Path .\LockoutEvents_BadPassword.csv -NoTypeInformation -Force

        $ReportOut = $Output | Where-Object {$_.Id -eq 4740} | Select-Object TimeCreated,@{name='DC';expression={$_.PSComputerName}},TargetUserName,TargetDomainName,ContainerLog,Id,TaskDisplayName,KeywordsDisplayNames,LevelDisplayName,LogName,OpcodeDisplayName,ProviderName,RecordId,SubjectDomainName,SubjectLogonId,SubjectUserName,SubjectUserSid,TargetSid,UserId | Sort-Object TimeCreated
        $ReportOut | Out-GridView -Title 'Lockout Events'
        $ReportOut | Export-Csv -Path .\LockoutEvents_Lockouts.csv -NoTypeInformation -Force

    } Else {
        Write-Warning "No events returned for the specified hours."
    }

    dir LockoutEvents*.csv | ft
}

# Default is events in last 24 hours, no IP to name resolution
Get-ADAccountLockoutData

# Last 12 hours, IP to name resolution for bad password events
# Verbose for progress information
Get-ADAccountLockoutData -ResolveIP -Hours 12 -Verbose
