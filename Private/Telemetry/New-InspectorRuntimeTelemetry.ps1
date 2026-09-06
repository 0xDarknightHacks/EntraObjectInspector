function New-InspectorRuntimeTelemetry {
    [CmdletBinding()]
    param ()

    $startedAt = Get-InspectorTelemetryTimestamp
    $memoryStart = Get-InspectorTelemetryMemoryMB

    return [PSCustomObject][ordered]@{
        PSTypeName              = 'EntraObjectInspector.RuntimeTelemetry'
        SchemaVersion           = '1.1.0'
        StartedAt               = $startedAt
        CompletedAt             = $null
        TotalDurationMs         = $null
        StageDurations          = [ordered]@{}
        GraphRequestSummary     = [PSCustomObject][ordered]@{
            TotalRequests        = 0
            SuccessfulRequests   = 0
            FailedRequests       = 0
            RetriedRequests      = 0
            ThrottledRequests    = 0
            RetryAfterSecondsTotal = 0
            RetryAfterSecondsMax = 0
            FirstGraphRequestAt  = $null
            LastGraphRequestAt   = $null
        }
        GraphTransportSummary   = [PSCustomObject][ordered]@{
            TotalHttpRequests      = 0
            SingleHttpRequests     = 0
            BatchHttpRequests      = 0
            BatchSubrequestExecutions   = 0
            FirstHttpRequestAt     = $null
            LastHttpRequestAt      = $null
        }
        GraphRequestsByEndpoint = [ordered]@{}
        GraphStatusCodeSummary  = [ordered]@{}
        RetrySummary            = [PSCustomObject][ordered]@{
            RetriedRequests = 0
            ObjectProcessingRetries = 0
            RetryAfterSecondsTotal = 0
            RetryAfterSecondsMax = 0
        }
        ThrottlingSummary       = [PSCustomObject][ordered]@{
            ThrottledRequests = 0
        }
        ObjectProcessingSummary = [PSCustomObject][ordered]@{
            ObjectsProcessed = 0
            ObjectsSucceeded = 0
            ObjectsFailed    = 0
            ObjectsSkipped   = 0
            RetryAttempts    = 0
            ResumeReplayCount = 0
        }
        ThroughputSummary       = [PSCustomObject][ordered]@{
            ObjectsProcessed = 0
            ObjectsPerSecond = $null
        }
        MemorySummary           = [PSCustomObject][ordered]@{
            ProcessWorkingSetStartMB = $memoryStart
            ProcessWorkingSetEndMB   = $null
            ProcessWorkingSetDeltaMB = $null
            PeakMemoryMB             = $memoryStart
            MemoryTelemetryAvailable = ($null -ne $memoryStart)
        }
        OutputArtifactSummary   = [PSCustomObject][ordered]@{
            ExportDirectory = $null
            ReportPath = $null
            DiagnosticsReportPath = $null
            EvidenceReportPath = $null
            DiagnosticsLogPath = $null
            ArtifactCount = 0
            TotalArtifactSizeBytes = 0
            HtmlReportSizeBytes = 0
        }
        ExternalEndpointSummary = [PSCustomObject][ordered]@{
            ExpectedExternalHosts = @('graph.microsoft.com', 'login.microsoftonline.com')
            ObservedExternalHosts = @()
            UnexpectedExternalHosts = @()
        }
        Limitations             = @()
    }
}
