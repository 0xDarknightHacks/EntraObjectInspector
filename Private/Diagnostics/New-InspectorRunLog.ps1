function New-InspectorRunLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$AssessmentName,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [string]$LogDirectory,
        [switch]$Disabled
    )

    $runId = [guid]::NewGuid().ToString()
    $resolvedLogDirectory = $LogDirectory

    if ([string]::IsNullOrWhiteSpace($resolvedLogDirectory)) {
        $resolvedLogDirectory = Join-Path $OutputDirectory 'logs'
    }

    $diagnosticsLogPath = $null
    $summaryPath = $null

    if (-not $Disabled) {
        New-Item -ItemType Directory -Path $resolvedLogDirectory -Force | Out-Null
        $diagnosticsLogPath = Join-Path $resolvedLogDirectory "$runId-diagnostics.jsonl"
        $summaryPath = Join-Path $resolvedLogDirectory "$runId-summary.json"
    }

    [PSCustomObject][ordered]@{
        PSTypeName          = 'EntraObjectInspector.RunLog'
        RunId               = $runId
        AssessmentName      = $AssessmentName
        StartedAt           = Get-InspectorDiagnosticTimestamp
        CompletedAt         = $null
        Status              = 'Running'
        OutputDirectory     = $OutputDirectory
        ReportPath          = $null
        LogDirectory        = $resolvedLogDirectory
        DiagnosticsLogPath  = $diagnosticsLogPath
        RunSummaryPath      = $summaryPath
        StageStatus         = [ordered]@{}
        RuntimeTelemetry    = $null
        OrchestrationTelemetry = $null
        GraphDisconnect     = $null
        DiagnosticLogEnabled = -not [bool]$Disabled
    }
}
