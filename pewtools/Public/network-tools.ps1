function pingplus {
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

function Get-NetInfo {
    <#
    .SYNOPSIS
    Retrieves information about network interfaces, IP addresses, default gateway, and DNS servers.

    .DESCRIPTION
    This function collects and returns information about network interfaces, IP addresses, default gateway, and DNS servers.
    The user can choose to retrieve the default gateway, DNS servers, or detailed network information.

    .PARAMETER defaultGateway
    Retrieves the default gateway of the system.

    .PARAMETER dnsServers
    Retrieves the DNS servers configured on the system.
    #>
    param (
        [Parameter()]
        [Alias("dg")]
        [switch]$defaultGateway,
        [Parameter()]
        [Alias("dns")]
        [switch]$dnsServers
    )

    # If the user requests the default gateway, return it
    if ($defaultGateway) {
        return (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty "NextHop")
    }
    # If the user requests DNS servers, return them
    elseif ($dnsServers) {
        return (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses
    }

    # Collect detailed network information
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

    # Return the detailed network information
    return $netinfo
}