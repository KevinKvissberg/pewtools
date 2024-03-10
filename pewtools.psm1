<#
.SYNOPSIS
    This function is used to ping or check the accessibility of a target host or IP address.

.DESCRIPTION
    The `pingplus` function allows you to ping a target host or IP address using ICMP or check the accessibility of a specific port using TCP.

.PARAMETER target
    Specifies the target host or IP address to ping or check.

.PARAMETER port
    Specifies the port number to check for accessibility. This parameter is optional.

.PARAMETER timeOut
    Specifies the timeout value in milliseconds for the ping or connection attempt. This parameter is optional and has a default value of 100 milliseconds.

.EXAMPLE
    # Ping a single host
    pingplus -target "www.example.com"

.EXAMPLE
    # Check accessibility of a port on multiple hosts
    pingplus -target 192.168.1.10, 192.168.1.20 -port 80

.OUTPUTS
    If a single target is specified, the function returns a Boolean value indicating the ping or connection result.
    If multiple targets are specified, the function returns an array of custom objects with the following properties:
        - Target: The target host or IP address.
        - Result: The ping or connection result (Boolean).
#>
function pingplus {
    [alias("p", "pp")]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string[]]$target,
        [Parameter(ParameterSetName = 'Port', Position = 1)]
        [int]$port,
        [Parameter(ParameterSetName = 'Port')]
        [int]$timeOut = 100
    )
    # Initialize the result array
    $result = @()

    # Loop through each target
    foreach ($_ in $target) {
        # Check if the target is an DNS name that needs to be resolved
        if (![System.Net.IPAddress]::TryParse($_, [ref]$null)) {
            Write-Verbose "Resolving $_..."
            # Resolve the DNS name
            $dnsResolve = Resolve-DnsName $_ -QuickTimeout -DnsOnly -ErrorAction SilentlyContinue -Verbose:$false
            # If the DNS name cannot be resolved, add a false value to the result array and continue to the next target
            if (!($dnsResolve)) {
                Write-Verbose "Failed to resolve $_"
                $result += $false; continue
            }
            Write-Verbose "Resolved $_ to $($dnsResolve.IPAddress -join ', ')"
        }
        # Check if the port parameter is specified
        if ($PSBoundParameters.ContainsKey('port')) {
            Write-Verbose "Connecting to $_ on port $port with a timeout of $timeOut milliseconds..."

            # Create a new TCP client and attempt to connect to the target on the specified port
            $requestCallback = $state = $null
            $client = New-Object System.Net.Sockets.TcpClient

            # Use the BeginConnect method to connect asynchronously and set the result to true if the connection is successful
            $client.BeginConnect($_, $port, $requestCallback, $state) > $null

            # Wait for the connection to complete or timeout
            Start-Sleep -Milliseconds $timeOut

            # If the client is connected, add a true value to the result array, otherwise add a false value
            if ($client.Connected) { $result += $true } else { $result += $false }
            Write-Verbose "Connection result: $($result[-1])"

            # Close the TCP client
            $client.Close()
        }
        else {
            Write-Verbose "Pinging $_..."

            # Create a new Ping object and send an ICMP echo request to the target
            $client = New-Object System.Net.NetworkInformation.Ping

            # Add a true value to the result array if the ping is successful, otherwise add a false value
            $result += $client.Send($_, $timeOut).Status -eq 'Success'
            Write-Verbose "Ping result: $($result[-1])"
        }
    }
    Write-Verbose "End Result: $($result -join ', ')"
    # Return the result array
    if ($result.Count -eq 1) { return $result[0] }
    else {
        # Create an array of custom objects with the target and result properties
        $output = @()
        foreach ($i in 0..($target.Length - 1)) {
            $obj = "" | Select-Object Target, Result
            $obj.Target = $target[$i]
            $obj.Result = $result[$i]
            $output += $obj
        }
        return $output
    }
}

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
function Get-LocalDetails {
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
    $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    # Calculate system uptime
    $result.UpTime = "$($uptime.Days)d, $($uptime.Hours)h, $($uptime.Minutes)m, $($uptime.Seconds)s"

    # Add domain, system manufacturer, and OS install date
    $result.Domain = $systemInfo.CsDomain
    $result.SystemManufacturer = $systemInfo.CsManufacturer
    $result.OsInstallDate = $systemInfo.OsInstallDate

    # Collect network information
    $netinfo = @()
    Get-NetIPAddress | Where-Object { $_.PrefixOrigin -ne "WellKnown" } | ForEach-Object {
        $details = "" | Select-Object Interface, Address, Mask, PrefixOrigin, FirewallZone
        $details.Interface = $_.InterfaceAlias
        $details.Address = $_.IPAddress
        $details.Mask = $_.PrefixLength
        $details.PrefixOrigin = $_.PrefixOrigin
        # Get firewall zone from network profile
        $netProfile = Get-NetConnectionProfile -InterfaceAlias $_.InterfaceAlias -ErrorAction SilentlyContinue
        if ($netProfile) { $details.FirewallZone = $netProfile.NetworkCategory }
        else { $details.FirewallZone = "Unknown" }

        $netinfo += $details
    }
    $result.netinfo = $netinfo

    # Get default gateway
    $result.defaultGateway = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty "NextHop"

    # Get DNS server addresses
    $result.dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses

    # Check internet access using custom function pingplus
    $result.InternetAccess = pingplus -target 8.8.8.8

    # Check domain access using custom function pingplus
    $result.DomainAccess = pingplus -target $result.Domain

    # Return the populated result object
    return $result
}

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
function Trace-Eventlog {
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


<#
.SYNOPSIS
   Use alias gpu for writing the command gpupdate faster.

.DESCRIPTION
   This function initializes a Group Policy update with optional parameters such as force, target, and boot.

.PARAMETER noForce
   Suppresses the force update if this switch is present.

.PARAMETER target
   Specifies the target for the Group Policy update. Possible values are "Computer", "User", or "Both" (default).

.PARAMETER boot
   Performs a boot-time Group Policy update if this switch is present.
#>
function Initialize-GPUpdate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [alias("gpu")]
    param (
        [Parameter()]
        [switch]$noForce,
        [Parameter()]
        [ValidateSet("Computer", "User", "Both")]
        [Alias("t")]
        [string]$target = "Both",
        [Parameter()]
        [Alias("b")]
        [switch]$boot
    )

    # Array to store attributes for the GPUpdate command
    $attributes = @()

    # Check if the noForce switch is not present
    if ($noForce -eq $false) { $attributes += "/force" }

    # Check if the target is different from the default "Both"
    if ($target -ne "Both") { $attributes += "/target:$target" }

    # Check if the boot switch is present
    if ($boot) { $attributes += "/boot" }

    # Construct and execute the GPUpdate command using Invoke-Expression
    Invoke-Expression "GPUpdate $($attributes -join ' ')"
}


<#
.SYNOPSIS
   Retrieves information about installed software on a Windows system.

.DESCRIPTION
   This function queries the Windows Registry to gather information about installed software,
   focusing on the "Uninstall" key in the registry.
#>
function Get-Apps {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param ()

    # Query the "Uninstall" key in the Windows Registry to get software information
    $queriedSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

    # Function to convert date format from 'yyyyMMdd' to 'yyyy-MM-dd'
    function Convert-DateFormat {
        param (
            [string]$InputDate
        )
        $FormattedDate = if ($InputDate) { [DateTime]::ParseExact($InputDate, 'yyyyMMdd', $null).ToString('yyyy-MM-dd') }
        $FormattedDate
    }

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

<#
.SYNOPSIS
   Tests the health of the server by checking disk usage, gateway ping, internet connectivity, and DNS resolution.

.DESCRIPTION
   This function tests the health of the server by performing various checks such as disk usage, gateway ping, internet connectivity, and DNS resolution.

.NOTES
   File: Test-ServerHealth.ps1
   Author: Your Name
   Version: 1.0
#>
function Test-ServerHealth {
    param (
    )

    # Create a new PSObject to store the health test results
    $output = New-Object PSObject
    
    # Check disk usage
    Write-Output (Get-DiskUsage)

    # Gateway ping Connection
    $output | Add-Member -MemberType NoteProperty -Name "GatewayPing" -value (pingplus -target (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty "NextHop"))

    # Check Network Connectivity
    $output | Add-Member -MemberType NoteProperty -Name "InternetPing" -value ((pingplus 8.8.8.8, 1.1.1.1).result -contains $true)

    # Check DNS
    $output | Add-Member -MemberType NoteProperty -Name "DNS" -value ((pingplus -target "google.com", "github.com").result -contains $true)

    # Return the formatted table of test results
    return ($output | Format-Table)
}


Function Get-DiskUsage {
    param (
        [Parameter()]
        [Alias("s", "q")]
        [switch]$silent
    )
    # Check Disk Space
    $diskSpace = Get-WmiObject Win32_LogicalDisk -ComputerName $ServerName | Where-Object { $_.DriveType -eq 3 } | Select-Object DeviceID, FreeSpace, Size, UsedPercentage
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

export-modulemember -function * -alias *