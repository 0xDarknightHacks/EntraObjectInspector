function Write-InspectorDiagnosticEvent {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$RunLog,
        [Parameter(Mandatory)][string]$Stage,
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info',
        [Parameter(Mandatory)][string]$EventName,
        [Parameter(Mandatory)][string]$Message,
        [string]$ObjectId,
        [string]$ObjectType,
        [AllowNull()][object]$Exception,
        [AllowNull()][object]$Data
    )

    if ($null -eq $RunLog -or -not $RunLog.DiagnosticLogEnabled) {
        return
    }

    $errorType = $null
    $errorMessage = $null

    if ($null -ne $Exception) {
        $safeException = if ($Exception -is [System.Management.Automation.ErrorRecord]) { $Exception.Exception } else { $Exception }
        $errorType = $safeException.GetType().FullName
        $errorMessage = $safeException.Message
    }

    $event = [PSCustomObject][ordered]@{
        Timestamp    = Get-InspectorDiagnosticTimestamp
        RunId        = $RunLog.RunId
        Stage        = $Stage
        Level        = $Level
        EventName    = $EventName
        Message      = $Message
        ObjectId     = $ObjectId
        ObjectType   = $ObjectType
        ErrorType    = $errorType
        ErrorMessage = $errorMessage
        Data         = ConvertTo-InspectorDiagnosticSafeData -Data $Data
    }

    $event |
        ConvertTo-Json -Depth 20 -Compress |
        Add-Content -LiteralPath $RunLog.DiagnosticsLogPath -Encoding UTF8
}
