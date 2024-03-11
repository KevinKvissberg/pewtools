<#
.SYNOPSIS
PewTools is a collection of PowerShell functions and scripts that I use to make my life easier.
.Description
PewTools is a collection of PowerShell functions and scripts that I use to make my life easier. It is a collection of tools for managing and maintaining a Windows environment.
It uses sub scripts to organize the functions into categories. 
The folder structure is as follows:
- Public
  - Contains exported functions and scripts that are intended to be used by the end user
- Private
  - Contains functions and scripts that are used by the Public functions and scripts
#>
foreach ($module in (Get-ChildItem -Path $PSScriptRoot\Private -Filter *.ps1)) {
    . $module.FullName
}