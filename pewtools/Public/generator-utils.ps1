Function New-Password {
    <#
    .SYNOPSIS
    Generates a random password

    .DESCRIPTION
    Generates a random password with the specified length and constraints.

    .PARAMETER Length
    The length of the password

    .PARAMETER NoSpecial
    If set, the password will not contain special characters

    .PARAMETER NoNumbers
    If set, the password will not contain numbers

    .PARAMETER OnlyNumbers
    If set, the password will only contain numbers

    .PARAMETER OnlyLowercase
    If set, the password will only contain lowercase letters

    .PARAMETER OnlyUppercase
    If set, the password will only contain uppercase letters

    .PARAMETER AllowSimilarChars
    If set, the password will contain similar characters (e.g. 1, l, I, 0, O, etc.)

    .PARAMETER ListLength
    The number of passwords to generate

    .EXAMPLE
    New-Password -Length 16 -NoSpecial -ListLength 5
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Position = 0)]
        [int]$Length = 12,

        [Parameter()]
        [switch]$NoSpecial,

        [Parameter()]
        [switch]$NoNumbers,

        [Parameter()]
        [switch]$OnlyNumbers,

        [Parameter()]
        [switch]$OnlyLowercase,

        [Parameter()]
        [switch]$OnlyUppercase,

        [Parameter()]
        [switch]$AllowSimilarChars,

        [Parameter()]
        [int]$ListLength = 1
    )

    # Check constraints
    if ($OnlyNumbers -and $NoNumbers) {
        throw "OnlyNumbers and NoNumbers cannot be used together."
    }
    if ($OnlyLowercase -and $OnlyUppercase) {
        throw "OnlyLowercase and OnlyUppercase cannot be used together."
    }

    # Declare variables
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+/.,<>?;:[]{}-="

    # Remove characters based on constraints
    if ($NoSpecial) {
        $chars = $chars -replace "[\W]", ""
        $chars = $chars -replace "[-_]", ""
    }
    if (!$AllowSimilarChars) {
        $chars = $chars -replace "[il1Lo0OvVwW]", ""
    }
    if ($NoNumbers) {
        $chars = $chars -replace "[0-9]", ""
    }
    if ($OnlyNumbers) {
        $chars = "0123456789"
    }
    elseif ($OnlyUppercase) {
        $chars = $chars.ToUpper()
    }
    elseif ($OnlyLowercase) {
        $chars = $chars.ToLower()
    }

    # Loop through the amount of passwords to generate
    for ($i = 0; $i -lt $ListLength; $i++) {
        # Declare variables
        $password = ""

        # Loop through the length of the password
        for ($k = 0; $k -lt $Length; $k++) {
            # Add a random character from the character list to the password
            $password += $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)]
        }

        # Output the password
        if ($PSCmdlet.ShouldProcess("Localhost", "Generate password")) {
            Write-Output $password
        }
    }
}

Function New-PasswordUsingWord {
    <#
    .SYNOPSIS
    Generates a random password using words

    .DESCRIPTION
    Generates a random password using words from a word list.

    .PARAMETER Words
    The number of words to use in the password

    .PARAMETER ListLength
    The number of passwords to generate

    .EXAMPLE
    New-PasswordWords -Length 5 -ListLength 5
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Position = 0)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Words = 3,

        [Parameter()]
        [int]$ListLength = 1,

        [Parameter()]
        [string]$divider = "-"
    )

    # Load word list
    $wordlist = Get-Content -Path "$PSScriptRoot\..\Data\wordlist.txt"

    # Loop through the amount of passwords to generate
    for ($i = 0; $i -lt $ListLength; $i++) {
        # Declare variables
        $password = ""
        $wordsToUse = @()

        # Loop through the amount of words to use
        for ($k = 0; $wordsToUse.count -lt $Words; $k++) {
            # Add a random word from the word list to the array
            $wordsToUse += $wordlist[(Get-Random -Minimum 0 -Maximum $wordlist.Length)]
        }
        # Join the words together with the divider
        $password = $wordsToUse -join $divider

        # Output the password
        if ($PSCmdlet.ShouldProcess("Localhost", "Generate password with words")) {
            Write-Output $password
        }
    }
}