function Convert-DateFormat {
    <#
    .SYNOPSIS
    Converts a date from one format to another.
    
    .DESCRIPTION
    This function converts a date from one format to another. The input date format is 'yyyyMMdd' and the output date format is 'yyyy-MM-dd'.
    
    .PARAMETER InputDate
    The input date in the format 'yyyyMMdd'.
    
    .EXAMPLE
    Convert-DateFormat -InputDate 20210101
    #>
    param (
        [string]$InputDate
    )
    # Convert the input date to the output date format
    $date = if ($InputDate) { [DateTime]::ParseExact($InputDate, 'yyyyMMdd', $null).ToString('yyyy-MM-dd') }
    return $date
}