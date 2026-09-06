function Get-InspectorDiagnosticTimestamp {
    (Get-Date).ToUniversalTime().ToString('o')
}

function ConvertTo-InspectorDiagnosticSafeData {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Data
    )

    if ($null -eq $Data) {
        return $null
    }

    $json = $Data | ConvertTo-Json -Depth 20 -Compress

    if ($json -match '(?i)(secret|token|password|authorization|clientsecret|privatekey|credential)') {
        return '[redacted-sensitive-diagnostic-data]'
    }

    return $Data
}
