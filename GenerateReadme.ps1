<#
.SYNOPSIS
Generate a README.md file for the pewtools module.

.DESCRIPTION
This script generates a README.md file for the pewtools module. It collects all the functions in the module and their descriptions and writes them to the README.md file.
#>

Import-Module .\pewtools\pewtools.psd1 -Force

$output = @"
# pewtools
pewtools is a collection of tools for managing and maintaining a Windows environment.

# Functions
The following functions are availible
"@

$allFunctions = (test-ModuleManifest .\pewtools\pewtools.psd1).ExportedFunctions.Keys
$allFunctions = $allFunctions | Sort-Object
foreach ($function in $allFunctions) {
    $header = $null
    $aliases = $null

    $aliases = (Get-Alias | Where-Object { $_.Definition -eq $function }).name
    $header = "`n`n## $($function)"
    if ($aliases) {
        $header += " ($($aliases -join ', '))"
    }

    $output += $header
    $output += "`n$((get-help $function).description.text)"
}
Set-Content -Path .\README.md -Value $output