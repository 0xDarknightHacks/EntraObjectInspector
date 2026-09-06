function Complete-InspectorRunLog {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$RunLog,
        [string]$Status = 'Success',
        [string]$ReportPath,
        [AllowNull()][object]$RuntimeTelemetry,
        [AllowNull()][object]$OrchestrationTelemetry,
        [AllowNull()][object]$GraphDisconnect,
        [string]$ReportId = '',
        [string]$PackageValidationStatus = 'NotRun',
        [bool]$ReleaseEligible = $false,
        [int]$FailedObjectCount = 0
    )

    if ($null -eq $RunLog) {
        return $null
    }

    $RunLog.CompletedAt = Get-InspectorDiagnosticTimestamp
    $RunLog.Status = $Status
    $RunLog.ReportPath = $ReportPath
    $RunLog.RuntimeTelemetry = $RuntimeTelemetry
    $RunLog |
        Add-Member `
            -NotePropertyName 'OrchestrationTelemetry' `
            -NotePropertyValue $OrchestrationTelemetry `
            -Force
    $RunLog.GraphDisconnect = $GraphDisconnect

    if ($RunLog.DiagnosticLogEnabled) {
        $summary = [PSCustomObject][ordered]@{
            AssessmentName     = $RunLog.AssessmentName
            RunId              = $RunLog.RunId
            StartedAt          = $RunLog.StartedAt
            CompletedAt        = $RunLog.CompletedAt
            Status             = $RunLog.Status
            ReportId           = $ReportId
            PackageValidationStatus = $PackageValidationStatus
            ReleaseEligible    = $ReleaseEligible
            FailedObjectCount  = $FailedObjectCount
            OutputDirectory    = $RunLog.OutputDirectory
            ReportPath         = $RunLog.ReportPath
            StageStatus        = $RunLog.StageStatus
            RuntimeTelemetry   = $RunLog.RuntimeTelemetry
            OrchestrationTelemetry = $RunLog.OrchestrationTelemetry
            GraphDisconnect    = $RunLog.GraphDisconnect
            DiagnosticsLogPath = $RunLog.DiagnosticsLogPath
        }

        $summary |
            ConvertTo-Json -Depth 40 |
            Set-Content -LiteralPath $RunLog.RunSummaryPath -Encoding UTF8 -Force
    }

    return $RunLog
}
