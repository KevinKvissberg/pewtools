function Initialize-GPUpdate {
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