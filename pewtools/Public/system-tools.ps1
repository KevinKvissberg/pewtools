#region SystemInfo Getters
function Get-LocalDetails {
    <#
    .SYNOPSIS
    Retrieves local system details including hostname, username, uptime, domain, system manufacturer, OS install date, network information, default gateway, DNS servers, internet access, and domain access.
    
    .DESCRIPTION
    The Get-LocalDetails function retrieves various details about the local system and returns them as an object. The function collects information such as the hostname, username, uptime, domain, system manufacturer, OS install date, network information, default gateway, DNS servers, internet access, and domain access.
    
    .PARAMETER None
    This function does not accept any parameters.
    
    .EXAMPLE
    Get-LocalDetails
    
    This example demonstrates how to use the Get-LocalDetails function to retrieve local system details.
    
    .OUTPUTS
    The function returns an object with the following properties:
    - Hostname: The hostname of the local system.
    - Username: The username of the currently logged-in user.
    - UpTime: The uptime of the local system in days, hours, minutes, and seconds.
    - Domain: The domain of the local system.
    - SystemManufacturer: The manufacturer of the local system.
    - OsInstallDate: The installation date of the operating system.
    - netinfo: An array of network interface details, including interface name, IP address, subnet mask, prefix origin, and firewall zone.
    - defaultGateway: The IP address of the default gateway.
    - dnsServers: An array of DNS server IP addresses.
    - InternetAccess: Indicates whether the local system has internet access (True or False).
    - DomainAccess: Indicates whether the local system can access the specified domain (True or False).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param (
        # No parameters for this function
    )

    # Display information message
    Write-Information "Getting local details..." -InformationAction Continue

    # Initialize result object
    $result = "" | Select-Object Hostname, Username, UpTime, Domain, SystemManufacturer, OsInstallDate, netinfo, defaultGateway, dnsServers, InternetAccess, DomainAccess

    # Suppress progress output during execution
    $originalProgressPreference = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"

    # Get system information using Get-ComputerInfo
    $systemInfo = Get-ComputerInfo

    # Restore original progress preference
    $ProgressPreference = $originalProgressPreference

    # Add hostname
    $result.Hostname = HOSTNAME.EXE

    # Add current user
    $result.Username = $systemInfo.CsUserName

    # Calculate system uptime
    $result.UpTime = (Get-Uptime).Readable

    # Add domain, system manufacturer, and OS install date
    $result.Domain = $systemInfo.CsDomain
    $result.SystemManufacturer = $systemInfo.CsManufacturer
    $result.OsInstallDate = $systemInfo.OsInstallDate

    # Collect network information
    $result.netinfo = Get-NetInfo

    # Get default gateway
    $result.defaultGateway = Get-NetInfo -defaultGateway

    # Get DNS server addresses
    $result.dnsServers = Get-NetInfo -dnsServers

    # Check internet access using custom function pingplus
    $result.InternetAccess = pingplus -target 8.8.8.8

    # Check domain access using custom function pingplus
    $result.DomainAccess = pingplus -target $result.Domain

    # Return the populated result object
    return $result
}

Function Get-DiskUsage {
    <#
    .SYNOPSIS
    Gets disk usage information for the local system.
    
    .DESCRIPTION
    This function retrieves disk usage information for the local system, including details such as drive letter, free space, total size, and used percentage.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet','')]
    param (
        # No parameters for this function
    )
    # Check Disk Space
    $diskSpace = Get-WmiObject Win32_LogicalDisk -ComputerName "localhost" | Where-Object { $_.DriveType -eq 3 } | Select-Object DeviceID, FreeSpace, Size, UsedPercentage
    $allDisks = @()
    foreach ($disk in $diskSpace) {
        $disk.FreeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
        $disk.Size = [math]::Round($disk.Size / 1GB, 2)
        $UsedPercentage = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
        $allDisks += $disk

        if ($silent) { continue }
        $disk.UsedPercentage = ("[" + ("#" * $UsedPercentage) + " " * (100 - $UsedPercentage) + "]")
    }
    return $diskSpace
}

function Get-Apps {
    <#
    .SYNOPSIS
    Retrieves information about installed software on a Windows system.
    
    .DESCRIPTION
    This function queries the Windows Registry to gather information about installed software,
    focusing on the "Uninstall" key in the registry.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param (
        # No parameters for this function
    )

    # Query the "Uninstall" key in the Windows Registry to get software information
    $queriedSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

    # Array to store information about installed software
    $InstalledSoftware = @()

    # Loop through each object in the queried software
    foreach ($obj in $queriedSoftware) {
        # Check if DisplayName value is not null
        if ($null -eq $obj.GetValue('DisplayName')) { continue }

        # Create a custom object for each installed software
        $software = [PSCustomObject]@{
            DisplayName    = $obj.GetValue('DisplayName')
            DisplayVersion = $obj.GetValue('DisplayVersion')
            Publisher      = $obj.GetValue('Publisher')
            InstallDate    = Convert-DateFormat -InputDate $obj.GetValue('InstallDate')
            Size           = "$([math]::Round(($obj.GetValue('EstimatedSize')) / 1KB)) MB"
        }

        # Add the software object to the array
        $InstalledSoftware += $software
    }

    # Return the sorted and formatted table of installed software
    return ($InstalledSoftware | Sort-Object DisplayName | Format-Table)
}

function Trace-Eventlog {
    <#
    .SYNOPSIS
    Continuously monitors and retrieves new events from the specified event log with optional filtering.
    
    .DESCRIPTION
    This function continuously monitors and retrieves new events from the specified event log,
    allowing optional filtering by source, message, and entry type.
    
    .PARAMETER LogName
    Specifies the name of the event log to monitor. Default is "Application".
    
    .PARAMETER Source
    Specifies the event source. Default is "*".
    
    .PARAMETER Message
    Specifies a message filter for the events. Default is "*".
    
    .PARAMETER EntryType
    Specifies the entry types to include (e.g., "Error", "Warning", "Information", "SuccessAudit", "FailureAudit").
    #>
    param (
        [Parameter()]
        [ValidateSet("Application", "HardwareEvents", "System", "Security")]
        [string]$LogName = "Application",
        [Parameter()]
        [string]$Source = "*",
        [Parameter()]
        [string]$Message = "*",
        [Parameter()]
        [ValidateSet("Error", "Warning", "Information", "SuccessAudit", "FailureAudit")]
        [String]$EntryType
    )

    # Array to store retrieved events
    $allevents = @()

    # Continuous monitoring loop
    while ($true) {
        try {
            # Retrieve new events based on parameters
            if ($EntryType) {
                $newEvents = Get-EventLog $LogName -Newest 10 -Source $Source -Message "*$Message*" -EntryType $EntryType -ErrorAction Stop | Where-Object { $_.Index -notin $allevents.Index }
            } else {
                $newEvents = Get-EventLog $LogName -Newest 10 -Source $Source -Message "*$Message*" -ErrorAction Stop | Where-Object { $_.Index -notin $allevents.Index }
            }
        }
        catch {
            Write-Error "Error: $_"
            return;
        }

        # If new events are retrieved, add them to the array in reverse order
        if ($null -ne $newEvents) {
            [array]::Reverse($newEvents)
            $allevents += $newEvents
        }

        # Output the new events
        $newEvents

        # Pause for a short interval before checking for new events again
        [System.Threading.Thread]::Sleep(100)
    }
}
#endregion

#region SystemBoot getters
function Get-Uptime {
    <#
    .SYNOPSIS
    Retrieves the system uptime in days, hours, minutes, seconds, and a readable format.

    .DESCRIPTION
    This function calculates and returns the system uptime in various formats, including days, hours, minutes, seconds, and a readable string.
    #>
    param (
        # No parameters for this function
    )
    #TODO support remote targets
    # Create a new PSObject to store the result of system uptime
    $result = New-Object PSObject

    # Calculate the system uptime by subtracting LastBootUpTime from the current date
    $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    # Add properties to the result object for days, hours, minutes, and seconds
    $result | Add-Member -MemberType NoteProperty -Name "Days" -Value $uptime.Days
    $result | Add-Member -MemberType NoteProperty -Name "Hours" -Value $uptime.Hours
    $result | Add-Member -MemberType NoteProperty -Name "Minutes" -Value $uptime.Minutes
    $result | Add-Member -MemberType NoteProperty -Name "Seconds" -Value $uptime.Seconds

    # Add a property for a human-readable format of the uptime
    $result | Add-Member -MemberType NoteProperty -Name "Readable" -Value "$($uptime.Days)d, $($uptime.Hours)h, $($uptime.Minutes)m, $($uptime.Seconds)s"

    # Return the result object
    return $result
}

function Get-BootHistory {
    <#
    .SYNOPSIS
    Retrieves information about system boot history.
    
    .DESCRIPTION
    This function retrieves information about system boot history by querying the System event log for event IDs 1074 and 6005.
    It provides details such as timestamp, user, reason/application for the boot, and the associated action.
    #>
    param (
        # No parameters for this function
    )

    # Array to store the result of boot history information
    $result = @()

    # Array to store power events (shutdown and startup) from the System log
    $powerEvents = @()
    $powerEvents += Get-WinEvent -FilterHashTable @{LogName='System'; ID=1074}
    $powerEvents += Get-WinEvent -FilterHashTable @{LogName='System'; ID=6005}

    # Sort the power events based on TimeCreated
    $powerEvents = $powerEvents | Sort-Object TimeCreated

    # Loop through each power event and create an output object
    foreach ($powerEvent in $powerEvents) {
        $output = "" | Select-Object TimeStamp, User, Reason, Action
        $output.TimeStamp = $powerEvent.TimeCreated

        # Define the regular expression pattern to capture the "on behalf of user" information
        $pattern = "on behalf of user ([^\s]+)"

        # Use the -match operator to find the match in the message property
        if ($powerEvent.message -match $pattern) {
            $onBehalfOfUser = $matches[1]

            # Check if the user is not "NT" (system)
            if ($onBehalfOfUser -ne "NT") {
                $output.User = $onBehalfOfUser
            } else {
                $output.User = "System"
            }
        } else {
            $output.User = "System"
        }

        # Determine the action based on the event ID
        if ($powerEvent.ID -eq 6005) {
            $output.Action = "Startup"
        }
        else {
            $output.Action = $powerEvent.Properties[4].Value
        }

        # For events other than startup, capture the reason property
        if ($powerEvent.ID -ne 6005) {
            $output.Reason = $powerEvent.Properties[0].Value
        }

        # Add the output object to the result array
        $result += $output
    }

    # Return the result array in a formatted table
    return ($result | Format-Table)
}
#endregion

function Get-CertificateExpiry {
    <#
    .SYNOPSIS
    Retrieves information about certificate expiry for the specified target.
    
    .DESCRIPTION
    This function retrieves information about certificate expiry for either the local machine or a remote target.
    It checks the certificates in the "My" store and provides details such as subject, thumbprint, expiration date, and whether it will expire soon.
    
    .PARAMETER target
    Specifies the target machine. If not provided, it checks certificates on the local machine.
    
    .PARAMETER credentials
    Specifies the credentials to be used when checking certificates on a remote machine.
    #>
    param (
        $target,
        [PSCredential]$credentials
    )
    #TODO Accept multiple targets
    # Array to store the result of certificate information
    $result = @()

    # Array to store all certificates
    $allCertificates = @()

    # Check if a target machine is specified
    if ($null -eq $target) {
        # If no target specified, check certificates on the local machine
        $allCertificates += Get-ChildItem -Path Cert:\LocalMachine\My
    }
    else {
        # If a target is specified and credentials are not provided, prompt for credentials
        if ($null -eq $credentials) {
            $credentials = Get-Credential -Message "Enter credentials for $target"
        }

        # Invoke-Command to retrieve certificates on a remote machine
        $allCertificates += Invoke-Command -ComputerName $target -Credential $credentials {
            Get-ChildItem -Path Cert:\LocalMachine\My
        }
    }

    # Loop through each certificate and create an output object
    foreach ($certificate in $allCertificates) {
        $output = "" | Select-Object Subject, Thumbprint, NotAfter, Soon
        $output.Subject = $certificate.Subject
        $output.Thumbprint = $certificate.Thumbprint
        $output.NotAfter = $certificate.NotAfter
        $output.Soon = ($certificate.NotAfter -lt (Get-Date).AddDays(60))  # Check if the certificate will expire soon (within 60 days)

        # Add the output object to the result array
        $result += $output
    }

    # Return the result array
    return $result
}