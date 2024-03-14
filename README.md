# pewtools
pewtools is a collection of tools for managing and maintaining a Windows environment.

# Functions
The following functions are availible

## Find-FileFast (ff, Find-File, Get-File)
This function quickly searches for files in a directory and its subdirectories using a custom C# class.

## Get-Apps
This function queries the Windows Registry to gather information about installed software,
focusing on the "Uninstall" key in the registry.

## Get-BootHistory
This function retrieves information about system boot history by querying the System event log for event IDs 1074 and 6005.
It provides details such as timestamp, user, reason/application for the boot, and the associated action.

## Get-CertificateExpiry
This function retrieves information about certificate expiry for either the local machine or a remote target.
It checks the certificates in the "My" store and provides details such as subject, thumbprint, expiration date, and whether it will expire soon.

## Get-DiskUsage
This function retrieves disk usage information for the local system, including details such as drive letter, free space, total size, and used percentage.

## Get-LocalDetails
The Get-LocalDetails function retrieves various details about the local system and returns them as an object. The function collects information such as the hostname, username, uptime, domain, system manufacturer, OS install date, network information, default gateway, DNS servers, internet access, and domain access.

## Get-NetInfo
This function collects and returns information about network interfaces, IP addresses, default gateway, and DNS servers.
The user can choose to retrieve the default gateway, DNS servers, or detailed network information.

## Get-Uptime
This function calculates and returns the system uptime in various formats, including days, hours, minutes, seconds, and a readable string.

## Initialize-GPUpdate (gpu)
This function initializes a Group Policy update with optional parameters such as force, target, and boot.

## New-Password
Generates a random password with the specified length and constraints.

## New-PasswordUsingWord
Generates a random password using words from a word list.

## pingplus (p, pp)
The pingplus function allows you to ping a target host or IP address using ICMP or check the accessibility of a specific port using TCP.

## Test-ServerHealth
This function tests the health of the server by performing various checks such as disk usage, gateway ping, internet connectivity, and DNS resolution.

## Trace-Eventlog
This function continuously monitors and retrieves new events from the specified event log,
allowing optional filtering by source, message, and entry type.
