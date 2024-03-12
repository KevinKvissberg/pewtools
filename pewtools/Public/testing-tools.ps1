#region Broad test functions
function Test-ServerHealth {
    <#
    .SYNOPSIS
    Tests the health of the server by checking disk usage, gateway ping, internet connectivity, and DNS resolution.

    .DESCRIPTION
    This function tests the health of the server by performing various checks such as disk usage, gateway ping, internet connectivity, and DNS resolution.
    #>
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
#end region