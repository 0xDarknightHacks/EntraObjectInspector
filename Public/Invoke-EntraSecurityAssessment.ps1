function Invoke-InspectorSecurityAssessmentCore {
    <#
    .SYNOPSIS
        Runs the full Entra Object Inspector assessment workflow.

    .DESCRIPTION
        Orchestrates the read-only workflow for a live tenant, a deterministic
        targeted scope, or a portable offline snapshot. It generates assessment
        intelligence, structured artifacts, and static HTML reporting. When
        SnapshotPath is supplied, authentication and Graph collection are skipped.

        This command does not implement assessment logic directly and does not call
        Microsoft Graph outside snapshot collection.

    .PARAMETER SnapshotPath
        Portable snapshot to re-analyze offline without Graph access.

    .PARAMETER SaveSnapshotPath
        Writes the current snapshot to the versioned portable snapshot contract.

    .PARAMETER TargetFile
        CSV or TXT target specification for genuinely scoped live collection.

    .PARAMETER Target
        Explicit Identity or ObjectType|Identity target entries.

    .PARAMETER CompareToSnapshotPath
        Previous portable snapshot used for deterministic offline drift comparison.

    .PARAMETER RulePackPath
        Constrained declarative JSON rule pack applied to normalized observations.

    .PARAMETER BaselinePath
        Non-destructive assessment baseline for accepted observations and drift keys.
    #>

    [CmdletBinding()]
    param (
        [string]$AssessmentName = 'Entra Object Inspector Assessment',

        [string]$OutputDirectory = '.\EntraObjectInspector-Exports',

        [string]$ReportPath,

        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string[]]$ObjectType = @(
            'Application',
            'ServicePrincipal',
            'User',
            'Group'
        ),

        [int]$MaxObjectsPerType = 0,

        [ValidateRange(1, 500)]
        [int]$BatchSize = 25,

        [ValidateRange(0, 600000)]
        [int]$ThrottleDelayMilliseconds = 0,

        [ValidateRange(0, 10)]
        [int]$MaxRetryCount = 2,

        [string]$CheckpointPath,

        [string]$SnapshotPath,

        [string]$SaveSnapshotPath,

        [string]$TargetFile,

        [string[]]$Target = @(),

        [string]$CompareToSnapshotPath,

        [string]$RulePackPath,

        [string]$BaselinePath,

        [switch]$Resume,

        [switch]$NoProgress,

        [switch]$SkipConnect,

        [switch]$KeepGraphSession,

        [switch]$OpenReport,

        [string]$LogDirectory,

        [switch]$NoDiagnosticLog,

        [string]$ClientName = '',

        [string]$ConsultantName = '',

        [switch]$PassThru
    )

    $commandStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $runLog = $null
    $graphSessionDisconnectAttempted = $false
    $graphSessionDisconnected = $false
    $reportOpened = $false
    $finalStatus = 'Failed'
    $stage = 'Initialize'
    $connectedByCommand = $false
    $stageStatus = [ordered]@{}
    $tenantResult = $null
    $intelligence = $null
    $exportResult = $null
    $reportResult = $null
    $runtimeTelemetry = $null
    $orchestrationTelemetry = $null
    $result = $null
    $reportId = [guid]::NewGuid().ToString()
    $packageValidationStatus = 'NotRun'
    $releaseEligible = $false
    $packageValidationErrors = @()
    $packageValidationWarnings = @()
    $failedObjectCount = 0
    $previousRuntimeTelemetryVariable = Get-Variable -Name 'InspectorCurrentRuntimeTelemetry' -Scope Script -ErrorAction SilentlyContinue
    $hadPreviousRuntimeTelemetry = $null -ne $previousRuntimeTelemetryVariable
    $previousRuntimeTelemetry = if ($hadPreviousRuntimeTelemetry) { $previousRuntimeTelemetryVariable.Value } else { $null }
    $runtimeTelemetry = New-InspectorRuntimeTelemetry
    $script:InspectorCurrentRuntimeTelemetry = $runtimeTelemetry

    function Write-InspectorAssessmentStage {
        param (
            [int]$Step,
            [string]$Name
        )

        $message = "[$Step/7] $Name"

        if (-not $NoProgress -and (Test-InspectorAssessmentInteractiveConsole)) {
            Write-Progress -Activity 'Entra Object Inspector assessment' -Status $message -PercentComplete ([math]::Min(100, [math]::Round(($Step / 7) * 100)))
        }

        Write-Information $message -InformationAction Continue
    }

    function Test-InspectorAssessmentInteractiveConsole {
        if (-not [Environment]::UserInteractive) {
            return $false
        }

        try {
            return -not [Console]::IsOutputRedirected
        }
        catch {
            # Some non-console PowerShell hosts do not expose Console state.
            # In those hosts, retain the normal host-display behavior.
            return $true
        }
    }

    function Test-InspectorAssessmentColorEnabled {
        if (-not (Test-InspectorAssessmentInteractiveConsole)) {
            return $false
        }

        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable('NO_COLOR'))) {
            return $false
        }

        if ([string]::Equals([Environment]::GetEnvironmentVariable('TERM'), 'dumb', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }

        return $true
    }

    function Write-InspectorAssessmentBanner {
        if (-not (Test-InspectorAssessmentInteractiveConsole)) {
            return
        }

        $banner = @'

┌──────────────────────────────────────────────────────────────────────┐
│   ____ ____ ____ ____ ____ _________ ____ ____ ____ ____ ____ ____   │
│  ||E |||n |||t |||r |||a |||       |||O |||b |||j |||e |||c |||t ||  │
│  ||__|||__|||__|||__|||__|||_______|||__|||__|||__|||__|||__|||__||  │
│  |/__\|/__\|/__\|/__\|/__\|/_______\|/__\|/__\|/__\|/__\|/__\|/__\|  │
│           ____ ____ ____ ____ ____ ____ ____ ____ ____               │
│          ||I |||n |||s |||p |||e |||c |||t |||o |||r ||              │
│          ||__|||__|||__|||__|||__|||__|||__|||__|||__||              │
│          |/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|              │
└──────────────────────────────────────────────────────────────────────┘

'@

        $useColor = Test-InspectorAssessmentColorEnabled
        if ($useColor) {
            Write-Host $banner -ForegroundColor Cyan
            Write-Host '  Read-only Microsoft Entra security assessment' -ForegroundColor DarkGray
            Write-Host '  GitHub: https://github.com/0xDarknightHacks' -ForegroundColor DarkGray
            Write-Host ("  Assessment: {0}" -f $AssessmentName) -ForegroundColor DarkGray
        }
        else {
            Write-Host $banner
            Write-Host '  Read-only Microsoft Entra security assessment'
            Write-Host '  GitHub: https://github.com/0xDarknightHacks'
            Write-Host ("  Assessment: {0}" -f $AssessmentName)
        }

        Write-Host ''
    }

    function ConvertTo-InspectorAssessmentDuration {
        param ([AllowNull()][object]$Milliseconds)

        if ($null -eq $Milliseconds) { return 'n/a' }
        $value = [double]$Milliseconds
        if ($value -ge 60000) { return ('{0:N1}m' -f ($value / 60000.0)) }
        if ($value -ge 1000) { return ('{0:N1}s' -f ($value / 1000.0)) }
        return ('{0:N0}ms' -f $value)
    }

    function Write-InspectorAssessmentCompletion {
        param (
            [AllowNull()][object]$AssessmentResult
        )

        if ($null -eq $AssessmentResult -or -not (Test-InspectorAssessmentInteractiveConsole)) {
            return
        }

        $status = [string](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'Status')
        $releaseEligibleValue = Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'ReleaseEligible'
        $releaseEligible = $false
        if ($null -ne $releaseEligibleValue) {
            $releaseEligible = [System.Convert]::ToBoolean($releaseEligibleValue)
        }

        $successful = $status -eq 'Success' -and $releaseEligible
        $marker = if ($successful) { 'OK' } else { '!' }
        $headline = if ($successful) { 'Assessment complete' } else { "Assessment complete with status '$status'" }
        $useColor = Test-InspectorAssessmentColorEnabled

        Write-Host ''
        $executionMode = [string](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'ExecutionMode')
        $targetCount = [int](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'TargetCount')
        $changeCount = [int](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'ChangeCount')
        $acceptedCount = [int](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'AcceptedObservationCount')
        $customCount = [int](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'CustomObservationCount')
        $snapshotSaved = [bool](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'SnapshotSaved')
        $comparisonApplied = [bool](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'ComparisonApplied')
        $rulePackApplied = [bool](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'RulePackApplied')
        $baselineApplied = [bool](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'BaselineApplied')
        $rulePackId = [string](Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'RulePackId')
        $graphRequests = Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'GraphRequestCount'
        $httpRequests = Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'PhysicalHttpRequestCount'
        $graphEfficiency = Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'LogicalRequestsPerHttpRequest'
        $orchestration = Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'OrchestrationTelemetry'
        $snapshotDuration = Get-InspectorObjectInsightProperty -InputObject $orchestration -Name 'SnapshotCollectionDurationMs'
        $offlineDuration = Get-InspectorObjectInsightProperty -InputObject $orchestration -Name 'OfflineProcessingDurationMs'
        $scopeSuffix = if ($targetCount -gt 0) { " | Targets: $targetCount" } else { '' }
        $graphLine = if ($null -ne $httpRequests -and [double]$httpRequests -gt 0) { "Logical/HTTP: $graphRequests/$httpRequests ($graphEfficiency x)" } else { "Graph requests: $graphRequests" }
        $perfLine = "Snapshot: $(ConvertTo-InspectorAssessmentDuration $snapshotDuration) | Offline: $(ConvertTo-InspectorAssessmentDuration $offlineDuration)"
        $featureParts = [System.Collections.Generic.List[string]]::new()
        if ($snapshotSaved) { $featureParts.Add('Snapshot saved') }
        if ($comparisonApplied) { $featureParts.Add("Drift: $changeCount change(s)") }
        if ($rulePackApplied) { $featureParts.Add("Rules: $(if ([string]::IsNullOrWhiteSpace($rulePackId)) { 'applied' } else { $rulePackId }) ($customCount custom)") }
        if ($baselineApplied) { $featureParts.Add("Baseline: applied ($acceptedCount accepted)") }
        $featureLine = $featureParts -join ' | '

        if ($useColor) {
            Write-Host ("[{0}] {1}" -f $marker, $headline) -ForegroundColor $(if ($successful) { 'Green' } else { 'Yellow' })
            Write-Host ("     Mode   : {0}{1}" -f $executionMode, $scopeSuffix) -ForegroundColor DarkGray
            if (-not [string]::IsNullOrWhiteSpace($featureLine)) { Write-Host ("     Features: {0}" -f $featureLine) -ForegroundColor DarkGray }
            Write-Host ("     Perf   : {0}" -f $perfLine) -ForegroundColor DarkGray
            Write-Host ("     Graph  : {0} | After snapshot: {1}" -f $graphLine, (Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'GraphCallsAfterSnapshot')) -ForegroundColor DarkGray
            Write-Host ("     Package: {0} | Release eligible: {1}" -f (Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'PackageValidationStatus'), $releaseEligible) -ForegroundColor DarkGray
            Write-Host ("     Export : {0}" -f (Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'ExportDirectory')) -ForegroundColor DarkGray
            Write-Host ("     Report : {0}" -f (Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'ReportPath')) -ForegroundColor DarkGray
        }
        else {
            Write-Host ("[{0}] {1}" -f $marker, $headline)
            Write-Host ("     Mode   : {0}{1}" -f $executionMode, $scopeSuffix)
            if (-not [string]::IsNullOrWhiteSpace($featureLine)) { Write-Host ("     Features: {0}" -f $featureLine) }
            Write-Host ("     Perf   : {0}" -f $perfLine)
            Write-Host ("     Graph  : {0} | After snapshot: {1}" -f $graphLine, (Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'GraphCallsAfterSnapshot'))
            Write-Host ("     Package: {0} | Release eligible: {1}" -f (Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'PackageValidationStatus'), $releaseEligible)
            Write-Host ("     Export : {0}" -f (Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'ExportDirectory'))
            Write-Host ("     Report : {0}" -f (Get-InspectorObjectInsightProperty -InputObject $AssessmentResult -Name 'ReportPath'))
        }
    }

    function Set-InspectorAssessmentStageStatus {
        param (
            [string]$Name,
            [string]$Status
        )

        $stageStatus[$Name] = $Status
        if ($null -ne $runLog) {
            $runLog.StageStatus[$Name] = $Status
        }
    }

    function Get-InspectorAssessmentStageDurationMs {
        param (
            [AllowNull()][object]$StageDurations,
            [string]$Name
        )

        if ($null -eq $StageDurations -or [string]::IsNullOrWhiteSpace($Name)) {
            return $null
        }

        $stageRecord = $null
        if ($StageDurations -is [System.Collections.IDictionary]) {
            if ($StageDurations.Contains($Name)) {
                $stageRecord = $StageDurations[$Name]
            }
        }
        else {
            $stageRecord = Get-InspectorObjectInsightProperty -InputObject $StageDurations -Name $Name
        }

        return Get-InspectorObjectInsightProperty -InputObject $stageRecord -Name 'DurationMs'
    }

    $offlineAssessment = -not [string]::IsNullOrWhiteSpace($SnapshotPath)

    # CLI decoration is best-effort and must never affect assessment execution.
    try { Write-InspectorAssessmentBanner } catch { }

    try {
        New-Item `
            -ItemType Directory `
            -Path $OutputDirectory `
            -Force |
            Out-Null

        $runLog =
            New-InspectorRunLog `
                -AssessmentName $AssessmentName `
                -OutputDirectory $OutputDirectory `
                -LogDirectory $LogDirectory `
                -Disabled:$NoDiagnosticLog

        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage 'Initialize' -EventName 'AssessmentStarted' -Message 'Assessment orchestration started.'

        if (-not $SkipConnect -and -not $offlineAssessment) {
            $stage = 'Authentication'
            Write-InspectorAssessmentStage -Step 1 -Name 'Authenticating'
            Set-InspectorAssessmentStageStatus -Name $stage -Status 'Running'
            Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'AuthenticationStarted' -Message 'Connecting to Microsoft Graph.'
            Connect-InspectorGraph | Out-Null
            $connectedByCommand = $true
            Set-InspectorAssessmentStageStatus -Name $stage -Status 'Success'
            Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'AuthenticationCompleted' -Message 'Microsoft Graph connection completed.'
        }
        else {
            Set-InspectorAssessmentStageStatus -Name 'Authentication' -Status $(if($offlineAssessment){'SkippedOfflineSnapshot'}else{'Skipped'})
            Write-InspectorDiagnosticEvent -RunLog $runLog -Stage 'Authentication' -EventName 'AuthenticationSkipped' -Message $(if($offlineAssessment){'Graph connection skipped because a portable snapshot was supplied.'}else{'Graph connection skipped; caller-owned session assumed.'})
        }

        # An explicit report path is honored as supplied.  When omitted, defer
        # choosing the path until the structured export directory exists so each
        # assessment run keeps its HTML report and sidecars inside its own package.
        if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
            $reportParent = Split-Path -Path $ReportPath -Parent
            if (-not [string]::IsNullOrWhiteSpace($reportParent)) {
                New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
            }
        }

        $tenantParameters = @{
            ObjectType                 = $ObjectType
            MaxObjectsPerType          = $MaxObjectsPerType
            BatchSize                  = $BatchSize
            ThrottleDelayMilliseconds  = $ThrottleDelayMilliseconds
            MaxRetryCount              = $MaxRetryCount
            Resume                     = $Resume
            NoProgress                 = $NoProgress
        }

        foreach ($optionalParameter in @{ SnapshotPath=$SnapshotPath; SaveSnapshotPath=$SaveSnapshotPath; TargetFile=$TargetFile; CompareToSnapshotPath=$CompareToSnapshotPath; RulePackPath=$RulePackPath; BaselinePath=$BaselinePath }.GetEnumerator()) {
            if (-not [string]::IsNullOrWhiteSpace([string]$optionalParameter.Value)) { $tenantParameters[$optionalParameter.Key] = [string]$optionalParameter.Value }
        }
        if (@($Target).Count -gt 0) { $tenantParameters.Target = @($Target) }

        if (-not [string]::IsNullOrWhiteSpace($CheckpointPath)) {
            $tenantParameters.CheckpointPath = $CheckpointPath
        }

        $stage = 'TenantInspection'
        Write-InspectorAssessmentStage -Step 2 -Name $(if($offlineAssessment){'Loading portable tenant snapshot'}else{'Collecting tenant snapshot'})
        Write-InspectorAssessmentStage -Step 3 -Name 'Processing objects offline'
        Set-InspectorAssessmentStageStatus -Name $stage -Status 'Running'
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'TenantInspectionStarted' -Message 'Tenant snapshot collection and offline object processing started.'
        $tenantInspectionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $script:InspectorCurrentRunLog = $runLog
        $tenantResult =
            Invoke-EntraTenantInspection @tenantParameters
        $script:InspectorCurrentRunLog = $null
        $tenantInspectionStopwatch.Stop()
        $returnedRuntimeTelemetry = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'RuntimeTelemetry'
        if ($null -ne $returnedRuntimeTelemetry -and -not [object]::ReferenceEquals($runtimeTelemetry, $returnedRuntimeTelemetry)) {
            $runtimeTelemetry = $returnedRuntimeTelemetry
            $script:InspectorCurrentRuntimeTelemetry = $runtimeTelemetry
        }
        Set-InspectorAssessmentStageStatus -Name $stage -Status $tenantResult.Status
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'TenantInspectionCompleted' -Message "Tenant inspection completed with status '$($tenantResult.Status)'."
        $failedObjectCount = @(
            Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'FailedObjects'
        ).Count

        $stage = 'AssessmentIntelligence'
        Write-InspectorAssessmentStage -Step 4 -Name 'Building assessment intelligence'
        Set-InspectorAssessmentStageStatus -Name $stage -Status 'Running'
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'AssessmentIntelligenceStarted' -Message 'Assessment intelligence generation started.'
        $assessmentIntelligenceStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $intelligence =
            Invoke-EntraAssessmentIntelligence `
                -InputObject $tenantResult `
                -AssessmentName $AssessmentName
        $assessmentIntelligenceStopwatch.Stop()
        Update-InspectorTelemetryMemorySample -Telemetry $runtimeTelemetry
        Set-InspectorAssessmentStageStatus -Name $stage -Status 'Success'
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'AssessmentIntelligenceCompleted' -Message 'Assessment intelligence generation completed.'

        $stage = 'Export'
        Write-InspectorAssessmentStage -Step 5 -Name 'Exporting structured artifacts'
        Set-InspectorAssessmentStageStatus -Name $stage -Status 'Running'
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'ExportStarted' -Message 'Structured export started.'
        $exportStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $exportResult =
            Export-EntraTenantInspection `
                -InputObject $tenantResult `
                -AssessmentIntelligence $intelligence `
                -OutputDirectory $OutputDirectory `
                -AssessmentName $AssessmentName `
                -RunId $runLog.RunId `
                -ReportId $reportId
        $exportStopwatch.Stop()
        Update-InspectorTelemetryMemorySample -Telemetry $runtimeTelemetry
        Set-InspectorAssessmentStageStatus -Name $stage -Status $exportResult.Status
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'ExportCompleted' -Message "Structured export completed with status '$($exportResult.Status)'."

        if ([string]::IsNullOrWhiteSpace($ReportPath)) {
            $ReportPath = Join-Path -Path $exportResult.ExportDirectory -ChildPath 'entra-object-inspector-report.html'
        }

        $reportParent = Split-Path -Path $ReportPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($reportParent)) {
            New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
        }

        $stage = 'Report'
        Write-InspectorAssessmentStage -Step 6 -Name 'Generating HTML report'
        Set-InspectorAssessmentStageStatus -Name $stage -Status 'Running'
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'ReportStarted' -Message 'HTML report generation started.'
        $stageSummary =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'StageSummary'

        $stageDurations =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'StageDurations'

        $offlineStageDurationValues = @(
            foreach ($offlineStageName in @(
                'OfflineResolution'
                'OfflineRelationshipBuilding'
                'Normalization'
                'PermissionIntelligence'
                'ObservationEngine'
            )) {
                $duration = Get-InspectorAssessmentStageDurationMs -StageDurations $stageDurations -Name $offlineStageName
                if ($null -ne $duration) {
                    [double]$duration
                }
            }
        )

        $offlineStartedAt = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'OfflineProcessingStartedAt'
        $offlineCompletedAt = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'OfflineProcessingCompletedAt'
        $offlineProcessingDurationMs = Get-InspectorAssessmentStageDurationMs -StageDurations $stageDurations -Name 'OfflineProcessing'
        if ($null -eq $offlineProcessingDurationMs) {
            $offlineProcessingDurationMs =
                if ($null -ne $offlineStartedAt -and $null -ne $offlineCompletedAt) {
                    [int](([datetime]$offlineCompletedAt - [datetime]$offlineStartedAt).TotalMilliseconds)
                }
                elseif ($offlineStageDurationValues.Count -gt 0) {
                    [int](($offlineStageDurationValues | Measure-Object -Sum).Sum)
                }
                else {
                    $null
                }
        }

        $snapshotCollectionDurationMs =
            Get-InspectorObjectInsightProperty -InputObject $stageSummary -Name 'TenantSnapshotCollectionDurationMs'
        if ($null -eq $snapshotCollectionDurationMs) {
            $snapshotCollectionDurationMs =
                Get-InspectorAssessmentStageDurationMs -StageDurations $stageDurations -Name 'TenantSnapshotCollection'
        }

        $orchestrationTelemetry = [PSCustomObject][ordered]@{
            PSTypeName                        = 'EntraObjectInspector.OrchestrationTelemetry'
            SchemaVersion                     = '1.1.0'
            RunId                             = $runLog.RunId
            CommandStatus                     = 'Success'
            TenantInspectionStatus            = $tenantResult.Status
            TenantInspectionDurationMs        = $tenantInspectionStopwatch.ElapsedMilliseconds
            SnapshotCollectionDurationMs      = $snapshotCollectionDurationMs
            OfflineProcessingDurationMs       = $(if ($null -ne (Get-InspectorObjectInsightProperty -InputObject $stageSummary -Name 'OfflineProcessingDurationMs')) { Get-InspectorObjectInsightProperty -InputObject $stageSummary -Name 'OfflineProcessingDurationMs' } else { $offlineProcessingDurationMs })
            AssessmentIntelligenceDurationMs  = $assessmentIntelligenceStopwatch.ElapsedMilliseconds
            ExportDurationMs                  = $exportStopwatch.ElapsedMilliseconds
            ExportPerformanceProfile          = Get-InspectorObjectInsightProperty -InputObject $exportResult -Name 'PerformanceProfile'
            ReportGenerationDurationMs        = 0
            ReportPerformanceProfile          = $null
            TotalCommandDurationMs            = $commandStopwatch.ElapsedMilliseconds
            GraphRequestSummary               = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'GraphRequestSummary'
            GraphTransportSummary             = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'GraphTransportSummary'
            ThroughputSummary                 = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'ThroughputSummary'
            MemorySummary                     = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'MemorySummary'
            ExecutionProfile                  = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'ExecutionProfile'
            ScopeSummary                      = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'ScopeSummary'
            RetrySummary                      = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'RetrySummary'
            ThrottlingSummary                 = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'ThrottlingSummary'
            ExternalEndpointSummary           = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'ExternalEndpointSummary'
            OutputArtifactSummary             = [PSCustomObject][ordered]@{
                ExportDirectory = $exportResult.ExportDirectory
                DiagnosticsLogPath = $runLog.DiagnosticsLogPath
            }
        }

        $reportStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $reportResult =
            Export-EntraAssessmentReport `
                -ExportDirectory $exportResult.ExportDirectory `
                -OrchestrationTelemetry $orchestrationTelemetry `
                -AssessmentName $AssessmentName `
                -OutputPath $ReportPath `
                -ClientName $ClientName `
                -ConsultantName $ConsultantName `
                -Force
        $reportStopwatch.Stop()
        Update-InspectorTelemetryMemorySample -Telemetry $runtimeTelemetry
        $orchestrationTelemetry.ReportGenerationDurationMs = $reportStopwatch.ElapsedMilliseconds
        $orchestrationTelemetry.ReportPerformanceProfile =
            Get-InspectorObjectInsightProperty -InputObject $reportResult -Name 'PerformanceProfile'
        Set-InspectorAssessmentStageStatus -Name $stage -Status $reportResult.Status
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -EventName 'ReportCompleted' -Message "HTML report generation completed with status '$($reportResult.Status)'."

        $graphRequestsAtSnapshotCompletion = [int](Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphRequestsAtSnapshotCompletion')
        $graphRequestsAtAssessmentCompletion = [int](Get-InspectorObjectInsightProperty -InputObject (Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'GraphRequestSummary') -Name 'TotalRequests')
        $graphCallsAfterSnapshot = $graphRequestsAtAssessmentCompletion - $graphRequestsAtSnapshotCompletion
        foreach ($telemetryTarget in @($tenantResult, $runtimeTelemetry)) {
            if ($null -ne $telemetryTarget) {
                $telemetryTarget | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $graphRequestsAtSnapshotCompletion -Force
                $telemetryTarget | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $graphRequestsAtAssessmentCompletion -Force
                $telemetryTarget | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $graphCallsAfterSnapshot -Force
            }
        }
        if ($null -ne (Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'Summary')) {
            $tenantResult.Summary | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $graphRequestsAtSnapshotCompletion -Force
            $tenantResult.Summary | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $graphRequestsAtAssessmentCompletion -Force
            $tenantResult.Summary | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $graphCallsAfterSnapshot -Force
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$exportResult.ExportDirectory)) {
            $manifestPath = Join-Path $exportResult.ExportDirectory 'assessment-manifest.json'
            $summaryPath = Join-Path $exportResult.ExportDirectory 'assessment-summary.json'
            if ((Test-Path -LiteralPath $manifestPath -PathType Leaf) -and (Test-Path -LiteralPath $summaryPath -PathType Leaf)) {
            $finalManifest = Read-InspectorReportJsonFile -Path $manifestPath
            $finalSummary = Read-InspectorReportJsonFile -Path $summaryPath
            foreach ($packageObject in @($finalManifest, $finalSummary)) {
                $packageObject | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $graphRequestsAtSnapshotCompletion -Force
                $packageObject | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $graphRequestsAtAssessmentCompletion -Force
                $packageObject | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $graphCallsAfterSnapshot -Force
            }
            Write-InspectorJsonFile -Path $summaryPath -Value $finalSummary
            for ($pass = 0; $pass -lt 3; $pass++) { Update-InspectorExportArtifactSizes -Manifest $finalManifest -BasePath $exportResult.ExportDirectory; Write-InspectorJsonFile -Path $manifestPath -Value $finalManifest }
            $finalReportModel = Get-InspectorReportModelFromDirectory -ExportDirectory $exportResult.ExportDirectory -AssessmentName $AssessmentName -ClientName $ClientName -ConsultantName $ConsultantName
            Write-InspectorJsonFile -Path $summaryPath -Value $finalReportModel.Summary
            for ($pass = 0; $pass -lt 3; $pass++) { Update-InspectorExportArtifactSizes -Manifest $finalReportModel.Manifest -BasePath $exportResult.ExportDirectory; Write-InspectorJsonFile -Path $manifestPath -Value $finalReportModel.Manifest }
            $reportResult | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $finalReportModel.PackageValidationStatus -Force
            $reportResult | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $finalReportModel.ReleaseEligible -Force
            $reportResult | Add-Member -NotePropertyName PackageValidationErrors -NotePropertyValue @($finalReportModel.PackageValidationErrors) -Force
            $reportResult | Add-Member -NotePropertyName PackageValidationWarnings -NotePropertyValue @($finalReportModel.PackageValidationWarnings) -Force
            }
        }

        if ($OpenReport -and $reportResult.Status -eq 'Success' -and -not [string]::IsNullOrWhiteSpace([string]$reportResult.ReportPath)) {
            try {
                if ($IsWindows) {
                    Invoke-Item -LiteralPath $reportResult.ReportPath
                }
                elseif ($IsMacOS) {
                    & open $reportResult.ReportPath
                }
                elseif ($IsLinux) {
                    & xdg-open $reportResult.ReportPath
                }
                else {
                    throw 'Unsupported operating system for automatic report opening.'
                }

                $reportOpened = $true
                Write-InspectorDiagnosticEvent -RunLog $runLog -Stage 'Report' -EventName 'ReportOpened' -Message 'HTML report was opened.'
            }
            catch {
                Write-Warning "Could not open HTML report automatically: $($_.Exception.Message)"
                Write-InspectorDiagnosticEvent -RunLog $runLog -Stage 'Report' -Level 'Warning' -EventName 'ReportOpenFailed' -Message 'Could not open HTML report automatically.' -Exception $_
            }
        }

        $graphSummary =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'GraphRequestSummary'

        Update-InspectorTelemetryDerivedMetrics -Telemetry $runtimeTelemetry
        Update-InspectorTelemetryMemorySample -Telemetry $runtimeTelemetry
        $graphTransportSummary =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'GraphTransportSummary'

        $executionProfile = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'ExecutionProfile'
        $scopeSummary = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'ScopeSummary'
        $tenantSummary = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'Summary'
        $assessmentPolicy = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'AssessmentPolicy'

        $throttlingSummary =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'ThrottlingSummary'

        $retrySummary =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'RetrySummary'

        $throughputSummary =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'ThroughputSummary'

        $memorySummary =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'MemorySummary'

        $externalEndpointSummary =
            Get-InspectorObjectInsightProperty `
                -InputObject $runtimeTelemetry `
                -Name 'ExternalEndpointSummary'

        $totalArtifactSizeBytes = 0
        $exportDirectoryFullPath = ''

        if (
            -not [string]::IsNullOrWhiteSpace([string]$exportResult.ExportDirectory) -and
            (Test-Path -LiteralPath $exportResult.ExportDirectory)
        ) {
            $exportDirectoryFullPath = [System.IO.Path]::GetFullPath([string]$exportResult.ExportDirectory).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            $artifactSizeMeasurement = @(
                Get-ChildItem `
                    -LiteralPath $exportResult.ExportDirectory `
                    -File `
                    -Recurse `
                    -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum
            ) | Select-Object -First 1
            if ($null -ne $artifactSizeMeasurement) {
                $totalArtifactSizeBytes += [long]$artifactSizeMeasurement.Sum
            }
        }

        $diagnosticsReportPath =
            Get-InspectorObjectInsightProperty `
                -InputObject $reportResult `
                -Name 'DiagnosticsReportPath'

        $evidenceReportPath =
            Get-InspectorObjectInsightProperty `
                -InputObject $reportResult `
                -Name 'EvidenceReportPath'

        # Default reports now live inside the run-specific structured export
        # directory.  Count report files separately only when an explicit path
        # placed them outside that directory, avoiding double-counted telemetry.
        foreach ($reportArtifactPath in @($reportResult.ReportPath, $diagnosticsReportPath, $evidenceReportPath)) {
            if (
                [string]::IsNullOrWhiteSpace([string]$reportArtifactPath) -or
                -not (Test-Path -LiteralPath $reportArtifactPath -PathType Leaf)
            ) {
                continue
            }

            $reportArtifactFullPath = [System.IO.Path]::GetFullPath([string]$reportArtifactPath)
            $isInsideExportDirectory =
                -not [string]::IsNullOrWhiteSpace($exportDirectoryFullPath) -and
                $reportArtifactFullPath.StartsWith(
                    $exportDirectoryFullPath + [System.IO.Path]::DirectorySeparatorChar,
                    [System.StringComparison]::OrdinalIgnoreCase
                )

            if (-not $isInsideExportDirectory) {
                $totalArtifactSizeBytes += (Get-Item -LiteralPath $reportArtifactPath).Length
            }
        }

        if ($null -ne $runtimeTelemetry) {
            $runtimeTelemetry.OutputArtifactSummary.ExportDirectory = $exportResult.ExportDirectory
            $runtimeTelemetry.OutputArtifactSummary.ReportPath = $reportResult.ReportPath
            $runtimeTelemetry.OutputArtifactSummary.ArtifactCount = Get-InspectorObjectInsightProperty -InputObject $exportResult -Name 'ArtifactCount'
            $runtimeTelemetry.OutputArtifactSummary.TotalArtifactSizeBytes = $totalArtifactSizeBytes
            $runtimeTelemetry.OutputArtifactSummary.HtmlReportSizeBytes = $reportResult.ReportSizeBytes
            $runtimeTelemetry.OutputArtifactSummary |
                Add-Member -NotePropertyName 'DiagnosticsReportPath' -NotePropertyValue $diagnosticsReportPath -Force

            $runtimeTelemetry.OutputArtifactSummary |
                Add-Member -NotePropertyName 'EvidenceReportPath' -NotePropertyValue $evidenceReportPath -Force

            $runtimeTelemetry.OutputArtifactSummary |
                Add-Member -NotePropertyName 'DiagnosticsLogPath' -NotePropertyValue $runLog.DiagnosticsLogPath -Force
        }

        if ($null -ne $orchestrationTelemetry.OutputArtifactSummary) {
            $orchestrationTelemetry.OutputArtifactSummary |
                Add-Member -NotePropertyName 'ReportPath' -NotePropertyValue $reportResult.ReportPath -Force
            $orchestrationTelemetry.OutputArtifactSummary |
                Add-Member -NotePropertyName 'DiagnosticsReportPath' -NotePropertyValue $diagnosticsReportPath -Force
            $orchestrationTelemetry.OutputArtifactSummary |
                Add-Member -NotePropertyName 'EvidenceReportPath' -NotePropertyValue $evidenceReportPath -Force
        }

        $orchestrationTelemetry.TotalCommandDurationMs = $commandStopwatch.ElapsedMilliseconds
        $finalStatus = $reportResult.Status

        # Package validation fields are additive to the report-result contract.
        # Use the module's safe property accessor so StrictMode does not break
        # orchestration tests, older report DTOs, or callers that mock the
        # pre-validation report shape. Production report results still supply
        # the finalized values.
        $packageValidationStatus =
            [string](Get-InspectorObjectInsightProperty `
                -InputObject $reportResult `
                -Name 'PackageValidationStatus')

        if ([string]::IsNullOrWhiteSpace($packageValidationStatus)) {
            $packageValidationStatus = 'NotRun'
        }

        $releaseEligibleValue =
            Get-InspectorObjectInsightProperty `
                -InputObject $reportResult `
                -Name 'ReleaseEligible'

        $releaseEligible =
            if ($null -eq $releaseEligibleValue) {
                $false
            }
            else {
                [System.Convert]::ToBoolean($releaseEligibleValue)
            }

        $packageValidationErrors = @(
            Get-InspectorObjectInsightProperty `
                -InputObject $reportResult `
                -Name 'PackageValidationErrors' |
            Where-Object {
                $null -ne $_ -and
                -not [string]::IsNullOrWhiteSpace([string](Get-InspectorObjectInsightProperty -InputObject $_ -Name 'ErrorId'))
            }
        )

        $packageValidationWarnings = @(
            Get-InspectorObjectInsightProperty `
                -InputObject $reportResult `
                -Name 'PackageValidationWarnings' |
            Where-Object {
                $null -ne $_ -and
                -not [string]::IsNullOrWhiteSpace([string](Get-InspectorObjectInsightProperty -InputObject $_ -Name 'WarningId'))
            }
        )

        $reportFailedObjectCount =
            Get-InspectorObjectInsightProperty -InputObject $reportResult -Name 'FailedObjectCount'
        if ($null -ne $reportFailedObjectCount) {
            $failedObjectCount = [int]$reportFailedObjectCount
        }

        foreach ($finalizedDto in @($exportResult, $reportResult)) {
            if ($null -ne $finalizedDto) {
                $finalizedDto | Add-Member -NotePropertyName RunId -NotePropertyValue $runLog.RunId -Force
                $finalizedDto | Add-Member -NotePropertyName ReportId -NotePropertyValue $reportId -Force
                $finalizedDto | Add-Member -NotePropertyName FailedObjectCount -NotePropertyValue $failedObjectCount -Force
                $finalizedDto | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidationStatus -Force
                $finalizedDto | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $releaseEligible -Force
            }
        }

        $result = [PSCustomObject][ordered]@{
            PSTypeName                       = 'EntraObjectInspector.SecurityAssessmentResult'
            SchemaVersion                    = '1.1.0'
            Status                           = $reportResult.Status
            AssessmentName                   = $AssessmentName
            RunId                            = $runLog.RunId
            ReportId                         = $reportId
            FailedObjectCount                = $failedObjectCount
            OutputDirectory                  = $OutputDirectory
            ReportPath                       = $reportResult.ReportPath
            DiagnosticsReportPath            = $diagnosticsReportPath
            EvidenceReportPath               = $evidenceReportPath
            ExportDirectory                  = $exportResult.ExportDirectory
            ManifestPath                     = $exportResult.ManifestPath
            TenantInspectionStatus           = $tenantResult.Status
            SnapshotMode                     = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'SnapshotMode'
            ExecutionMode                    = Get-InspectorObjectInsightProperty -InputObject $executionProfile -Name 'Mode'
            CollectionScopeMode              = Get-InspectorObjectInsightProperty -InputObject $scopeSummary -Name 'Mode'
            TargetCount                      = Get-InspectorObjectInsightProperty -InputObject $scopeSummary -Name 'TargetCount'
            PortableSnapshotPath             = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'PortableSnapshotPath'
            SnapshotSaved                    = -not [string]::IsNullOrWhiteSpace($SaveSnapshotPath)
            ComparisonApplied                = $null -ne (Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'SnapshotComparison')
            ChangeCount                      = @((Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'Changes')).Count
            RulePackApplied                  = [bool](Get-InspectorObjectInsightProperty -InputObject $assessmentPolicy -Name 'RulePackApplied')
            RulePackId                       = Get-InspectorObjectInsightProperty -InputObject $assessmentPolicy -Name 'RulePackId'
            BaselineApplied                  = [bool](Get-InspectorObjectInsightProperty -InputObject $assessmentPolicy -Name 'BaselineApplied')
            AcceptedObservationCount         = Get-InspectorObjectInsightProperty -InputObject $tenantSummary -Name 'AcceptedObservationCount'
            CustomObservationCount           = Get-InspectorObjectInsightProperty -InputObject $tenantSummary -Name 'CustomObservationCount'
            SnapshotComparison               = $(if($PassThru){Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'SnapshotComparison'}else{$null})
            ExportStatus                     = $exportResult.Status
            ReportStatus                     = $reportResult.Status
            DiagnosticsLogPath               = $runLog.DiagnosticsLogPath
            RunSummaryPath                   = $runLog.RunSummaryPath
            GraphSessionDisconnected         = $graphSessionDisconnected
            GraphSessionDisconnectAttempted  = $graphSessionDisconnectAttempted
            KeepGraphSession                 = [bool]$KeepGraphSession
            ReportOpened                     = $reportOpened
            # Top-level fields describe the complete assessment command.  The
            # report-only no-side-effect contract is exposed separately below.
            GraphCallsIssued                 = Get-InspectorObjectInsightProperty -InputObject $graphSummary -Name 'TotalRequests'
            IntelligenceAdded                = $null -ne $intelligence
            NewObservationsAdded             = @((Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'SecurityObservations')).Count -gt 0
            ReportGraphCallsIssued           = Get-InspectorObjectInsightProperty -InputObject $reportResult -Name 'GraphCallsIssued'
            ReportIntelligenceAdded          = Get-InspectorObjectInsightProperty -InputObject $reportResult -Name 'IntelligenceAdded'
            ReportNewObservationsAdded       = Get-InspectorObjectInsightProperty -InputObject $reportResult -Name 'NewObservationsAdded'
            RiskScoreProduced                = $reportResult.RiskScoreProduced
            AttackPathsProduced              = $reportResult.AttackPathsProduced
            ClientSideInteractivity          = $reportResult.ClientSideInteractivity
            GroupedObservations              = $reportResult.GroupedObservations
            CrossReferencesEnabled           = $reportResult.CrossReferencesEnabled
            SelfContainedHtml                = $reportResult.SelfContainedHtml
            Printable                        = $reportResult.Printable
            PackageValidationStatus          = $packageValidationStatus
            ReleaseEligible                  = $releaseEligible
            PackageValidationErrors          = $packageValidationErrors
            PackageValidationWarnings        = $packageValidationWarnings
            RuntimeTelemetry                 = $runtimeTelemetry
            OrchestrationTelemetry           = $orchestrationTelemetry
            TotalDurationMs                  = Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'TotalDurationMs'
            TotalCommandDurationMs           = $orchestrationTelemetry.TotalCommandDurationMs
            GraphRequestCount                = Get-InspectorObjectInsightProperty -InputObject $graphSummary -Name 'TotalRequests'
            PhysicalHttpRequestCount          = Get-InspectorObjectInsightProperty -InputObject $graphTransportSummary -Name 'TotalHttpRequests'
            BatchHttpRequestCount             = Get-InspectorObjectInsightProperty -InputObject $graphTransportSummary -Name 'BatchHttpRequests'
            BatchSubrequestExecutions         = Get-InspectorObjectInsightProperty -InputObject $graphTransportSummary -Name 'BatchSubrequestExecutions'
            LogicalRequestsPerHttpRequest     = Get-InspectorObjectInsightProperty -InputObject $graphTransportSummary -Name 'LogicalRequestsPerHttpRequest'
            TransportExecutionsPerHttpRequest = Get-InspectorObjectInsightProperty -InputObject $graphTransportSummary -Name 'TransportExecutionsPerHttpRequest'
            AverageBatchSubrequestsPerRequest = Get-InspectorObjectInsightProperty -InputObject $graphTransportSummary -Name 'AverageBatchSubrequestsPerRequest'
            BatchExecutionSharePercent        = Get-InspectorObjectInsightProperty -InputObject $graphTransportSummary -Name 'BatchExecutionSharePercent'
            GraphRequestsAtSnapshotCompletion = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphRequestsAtSnapshotCompletion'
            GraphRequestsAtAssessmentCompletion = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphRequestsAtAssessmentCompletion'
            GraphCallsAfterSnapshot          = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphCallsAfterSnapshot'
            ThrottledRequests                = Get-InspectorObjectInsightProperty -InputObject $throttlingSummary -Name 'ThrottledRequests'
            RetriedRequests                  = Get-InspectorObjectInsightProperty -InputObject $retrySummary -Name 'RetriedRequests'
            ObjectsProcessed                 = Get-InspectorObjectInsightProperty -InputObject $throughputSummary -Name 'ObjectsProcessed'
            ObjectsPerSecond                 = Get-InspectorObjectInsightProperty -InputObject $throughputSummary -Name 'ObjectsPerSecond'
            PeakMemoryMB                     = Get-InspectorObjectInsightProperty -InputObject $memorySummary -Name 'PeakMemoryMB'
            RunObservedWorkingSetPeakMB       = Get-InspectorObjectInsightProperty -InputObject $memorySummary -Name 'RunObservedWorkingSetPeakMB'
            RunPeakWorkingSetMB               = Get-InspectorObjectInsightProperty -InputObject $memorySummary -Name 'RunPeakWorkingSetMB'
            RunPeakMemoryExact                = Get-InspectorObjectInsightProperty -InputObject $memorySummary -Name 'RunPeakMemoryExact'
            RunPeakMemoryStatus               = Get-InspectorObjectInsightProperty -InputObject $memorySummary -Name 'RunPeakMemoryStatus'
            PeakMemoryScope                  = Get-InspectorObjectInsightProperty -InputObject $memorySummary -Name 'PeakMemoryScope'
            MemoryTelemetryAvailable         = Get-InspectorObjectInsightProperty -InputObject $memorySummary -Name 'MemoryTelemetryAvailable'
            OutputArtifactCount              = Get-InspectorObjectInsightProperty -InputObject $exportResult -Name 'ArtifactCount'
            TotalArtifactSizeBytes           = $totalArtifactSizeBytes
            ExternalHostsContacted           = Get-InspectorObjectInsightProperty -InputObject $externalEndpointSummary -Name 'ObservedExternalHosts'
            UnexpectedExternalHosts          = Get-InspectorObjectInsightProperty -InputObject $externalEndpointSummary -Name 'UnexpectedExternalHosts'
            TenantResult                     = $null
            AssessmentIntelligence           = $null
            ExportResult                     = $null
            ReportResult                     = $null
        }

        if ($PassThru) {
            $result.TenantResult = $tenantResult
            $result.AssessmentIntelligence = $intelligence
            $result.ExportResult = $exportResult
            $result.ReportResult = $reportResult
        }

    }
    catch {
        Set-InspectorAssessmentStageStatus -Name $stage -Status 'Failed'
        Write-InspectorDiagnosticEvent -RunLog $runLog -Stage $stage -Level 'Error' -EventName 'AssessmentFailed' -Message "Assessment failed during stage '$stage'." -Exception $_
        if ($null -ne $runLog -and -not [string]::IsNullOrWhiteSpace($runLog.DiagnosticsLogPath)) {
            Write-Warning "Assessment failed. Diagnostics log: $($runLog.DiagnosticsLogPath)"
        }
        throw
    }
    finally {
        $script:InspectorCurrentRunLog = $null
        Write-InspectorAssessmentStage -Step 7 -Name 'Finalizing and disconnecting'
        $disconnectSummary = [PSCustomObject][ordered]@{
            Attempted        = $false
            Disconnected     = $false
            KeepGraphSession = [bool]$KeepGraphSession
            SkipConnect      = [bool]$SkipConnect
            Message          = 'Disconnect not attempted.'
        }

        if ($connectedByCommand -and -not $KeepGraphSession) {
            $graphSessionDisconnectAttempted = $true
            $disconnectSummary.Attempted = $true
            try {
                Disconnect-MgGraph -ErrorAction Stop | Out-Null
                $graphSessionDisconnected = $true
                $disconnectSummary.Disconnected = $true
                $disconnectSummary.Message = 'Microsoft Graph session disconnected.'
                Write-InspectorDiagnosticEvent -RunLog $runLog -Stage 'Finalize' -EventName 'GraphDisconnected' -Message $disconnectSummary.Message
            }
            catch {
                $disconnectSummary.Message = "Graph disconnect failed: $($_.Exception.Message)"
                Write-Warning $disconnectSummary.Message
                Write-InspectorDiagnosticEvent -RunLog $runLog -Stage 'Finalize' -Level 'Warning' -EventName 'GraphDisconnectFailed' -Message 'Microsoft Graph disconnect failed.' -Exception $_
            }
        }
        elseif ($KeepGraphSession) {
            $disconnectSummary.Message = 'Graph session preserved by -KeepGraphSession.'
        }
        elseif ($SkipConnect) {
            $disconnectSummary.Message = 'Graph disconnect skipped because -SkipConnect was used.'
        }
        elseif (-not $connectedByCommand) {
            $disconnectSummary.Message = 'Graph disconnect skipped because authentication did not establish a command-owned session.'
        }

        # Authoritative lifecycle sentinel: finalization/disconnect is part of the
        # assessment lifecycle. Re-sample the shared run-scoped Graph counter only
        # after that stage has completed, while the outer telemetry context is still
        # active. This prevents a future wrapped Graph request introduced during
        # finalization from escaping the release-integrity invariant.
        if ($null -ne $tenantResult -and $null -ne $runtimeTelemetry) {
            $finalSnapshotCountRaw = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphRequestsAtSnapshotCompletion'
            $finalAssessmentCountRaw = Get-InspectorObjectInsightProperty -InputObject (Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'GraphRequestSummary') -Name 'TotalRequests'
            $isCurrentTenantInspectionResult = @($tenantResult.PSObject.TypeNames) -contains 'EntraObjectInspector.TenantInspectionResult'
            $finalSnapshotCount = [long]0
            $finalAssessmentCount = [long]0
            $finalSnapshotCountValid =
                if ($null -eq $finalSnapshotCountRaw -and -not $isCurrentTenantInspectionResult) {
                    # Preserve compatibility with narrow orchestration mocks/legacy DTOs.
                    # Production TenantInspectionResult objects must always carry the
                    # authoritative snapshot-boundary counter.
                    $true
                }
                else {
                    $null -ne $finalSnapshotCountRaw -and [long]::TryParse([string]$finalSnapshotCountRaw, [ref]$finalSnapshotCount)
                }
            $finalAssessmentCountValid = $null -ne $finalAssessmentCountRaw -and [long]::TryParse([string]$finalAssessmentCountRaw, [ref]$finalAssessmentCount)
            $finalGraphLifecycleValid = $finalSnapshotCountValid -and $finalAssessmentCountValid -and $finalAssessmentCount -ge $finalSnapshotCount
            $finalGraphCallsAfterSnapshot = if ($finalGraphLifecycleValid) { $finalAssessmentCount - $finalSnapshotCount } else { -1 }

            foreach ($telemetryTarget in @($tenantResult, $runtimeTelemetry)) {
                if ($null -ne $telemetryTarget) {
                    $telemetryTarget | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $finalSnapshotCount -Force
                    $telemetryTarget | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $finalAssessmentCount -Force
                    $telemetryTarget | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $finalGraphCallsAfterSnapshot -Force
                }
            }
            if ($null -ne (Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'Summary')) {
                $tenantResult.Summary | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $finalSnapshotCount -Force
                $tenantResult.Summary | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $finalAssessmentCount -Force
                $tenantResult.Summary | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $finalGraphCallsAfterSnapshot -Force
            }

            $finalExportDirectory = [string](Get-InspectorObjectInsightProperty -InputObject $exportResult -Name 'ExportDirectory')
            if (-not [string]::IsNullOrWhiteSpace($finalExportDirectory)) {
                $finalManifestPath = Join-Path $finalExportDirectory 'assessment-manifest.json'
                $finalSummaryPath = Join-Path $finalExportDirectory 'assessment-summary.json'
                if ((Test-Path -LiteralPath $finalManifestPath -PathType Leaf) -and (Test-Path -LiteralPath $finalSummaryPath -PathType Leaf)) {
                    $authoritativeManifest = Read-InspectorReportJsonFile -Path $finalManifestPath
                    $authoritativeSummary = Read-InspectorReportJsonFile -Path $finalSummaryPath
                    foreach ($packageObject in @($authoritativeManifest, $authoritativeSummary)) {
                        $packageObject | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $finalSnapshotCount -Force
                        $packageObject | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $finalAssessmentCount -Force
                        $packageObject | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $finalGraphCallsAfterSnapshot -Force
                    }
                    Write-InspectorJsonFile -Path $finalSummaryPath -Value $authoritativeSummary
                    for ($pass = 0; $pass -lt 3; $pass++) {
                        Update-InspectorExportArtifactSizes -Manifest $authoritativeManifest -BasePath $finalExportDirectory
                        Write-InspectorJsonFile -Path $finalManifestPath -Value $authoritativeManifest
                    }

                    $authoritativeReportModel = Get-InspectorReportModelFromDirectory -ExportDirectory $finalExportDirectory -AssessmentName $AssessmentName -ClientName $ClientName -ConsultantName $ConsultantName
                    Write-InspectorJsonFile -Path $finalSummaryPath -Value $authoritativeReportModel.Summary
                    for ($pass = 0; $pass -lt 3; $pass++) {
                        Update-InspectorExportArtifactSizes -Manifest $authoritativeReportModel.Manifest -BasePath $finalExportDirectory
                        Write-InspectorJsonFile -Path $finalManifestPath -Value $authoritativeReportModel.Manifest
                    }

                    $packageValidationStatus = [string]$authoritativeReportModel.PackageValidationStatus
                    $releaseEligible = [bool]$authoritativeReportModel.ReleaseEligible
                    $packageValidationErrors = @($authoritativeReportModel.PackageValidationErrors)
                    $packageValidationWarnings = @($authoritativeReportModel.PackageValidationWarnings)
                }
            }

            if (-not $finalGraphLifecycleValid -or $finalGraphCallsAfterSnapshot -ne 0) {
                $packageValidationStatus = 'Failed'
                $releaseEligible = $false
                $lifecycleError = [PSCustomObject][ordered]@{
                    ErrorId           = 'PKG-GRAPH-LIFECYCLE-FINAL-001'
                    Message           = $(if ($finalGraphLifecycleValid) { "Graph activity was measured after snapshot completion during the complete assessment lifecycle: $finalGraphCallsAfterSnapshot request(s)." } else { 'Final Graph lifecycle counters were missing, nonnumeric, negative, or inconsistent.' })
                    AffectedInvariant = 'GraphRequestsAtAssessmentCompletion >= GraphRequestsAtSnapshotCompletion and GraphCallsAfterSnapshot == 0 through finalization'
                }
                if (@($packageValidationErrors | Where-Object { [string](Get-InspectorObjectInsightProperty -InputObject $_ -Name 'ErrorId') -eq $lifecycleError.ErrorId }).Count -eq 0) {
                    $packageValidationErrors = @($packageValidationErrors) + @($lifecycleError)
                }
            }

            if ($null -ne $reportResult) {
                $reportResult | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidationStatus -Force
                $reportResult | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $releaseEligible -Force
                $reportResult | Add-Member -NotePropertyName PackageValidationErrors -NotePropertyValue @($packageValidationErrors) -Force
                $reportResult | Add-Member -NotePropertyName PackageValidationWarnings -NotePropertyValue @($packageValidationWarnings) -Force
            }
            if ($null -ne $exportResult) {
                $exportResult | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidationStatus -Force
                $exportResult | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $releaseEligible -Force
            }
        }

        if ($null -ne $runLog) {
            Set-InspectorAssessmentStageStatus -Name 'Finalize' -Status 'Success'
            if ($null -ne $orchestrationTelemetry) {
                $orchestrationTelemetry.TotalCommandDurationMs = $commandStopwatch.ElapsedMilliseconds
            }
            Complete-InspectorRunLog `
                -RunLog $runLog `
                -Status $finalStatus `
                -ReportPath $ReportPath `
                -RuntimeTelemetry $runtimeTelemetry `
                -OrchestrationTelemetry $orchestrationTelemetry `
                -GraphDisconnect $disconnectSummary `
                -ReportId $reportId `
                -PackageValidationStatus $packageValidationStatus `
                -ReleaseEligible $releaseEligible `
                -FailedObjectCount $failedObjectCount |
                Out-Null
        }

        # Terminal drift guard: the shared telemetry context remains active through
        # run-log completion. Re-read the counter immediately before result finalization
        # and telemetry teardown so a future wrapped request introduced anywhere in late
        # finalization cannot occur after the package has been declared releasable.
        if ($null -ne $tenantResult -and $null -ne $runtimeTelemetry) {
            $terminalSnapshotCountRaw = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphRequestsAtSnapshotCompletion'
            $terminalAssessmentCountRaw = Get-InspectorObjectInsightProperty -InputObject (Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'GraphRequestSummary') -Name 'TotalRequests'
            $isCurrentTenantInspectionResult = @($tenantResult.PSObject.TypeNames) -contains 'EntraObjectInspector.TenantInspectionResult'
            $terminalSnapshotCount = [long]0
            $terminalAssessmentCount = [long]0
            $terminalSnapshotCountValid =
                if ($null -eq $terminalSnapshotCountRaw -and -not $isCurrentTenantInspectionResult) {
                    $true
                }
                else {
                    $null -ne $terminalSnapshotCountRaw -and [long]::TryParse([string]$terminalSnapshotCountRaw, [ref]$terminalSnapshotCount)
                }
            $terminalAssessmentCountValid = $null -ne $terminalAssessmentCountRaw -and [long]::TryParse([string]$terminalAssessmentCountRaw, [ref]$terminalAssessmentCount)
            $terminalGraphLifecycleValid = $terminalSnapshotCountValid -and $terminalAssessmentCountValid -and $terminalAssessmentCount -ge $terminalSnapshotCount
            $terminalGraphCallsAfterSnapshot = if ($terminalGraphLifecycleValid) { $terminalAssessmentCount - $terminalSnapshotCount } else { -1 }
            $terminalDriftDetected =
                -not $terminalGraphLifecycleValid -or
                $terminalGraphCallsAfterSnapshot -ne 0 -or
                $terminalAssessmentCount -ne $finalAssessmentCount

            if ($terminalDriftDetected) {
                foreach ($telemetryTarget in @($tenantResult, $runtimeTelemetry)) {
                    if ($null -ne $telemetryTarget) {
                        $telemetryTarget | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $terminalSnapshotCount -Force
                        $telemetryTarget | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $terminalAssessmentCount -Force
                        $telemetryTarget | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $terminalGraphCallsAfterSnapshot -Force
                    }
                }
                if ($null -ne (Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'Summary')) {
                    $tenantResult.Summary | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $terminalSnapshotCount -Force
                    $tenantResult.Summary | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $terminalAssessmentCount -Force
                    $tenantResult.Summary | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $terminalGraphCallsAfterSnapshot -Force
                }

                $packageValidationStatus = 'Failed'
                $releaseEligible = $false
                $terminalLifecycleError = [PSCustomObject][ordered]@{
                    ErrorId           = 'PKG-GRAPH-LIFECYCLE-FINAL-001'
                    Message           = $(if ($terminalGraphLifecycleValid) { "Graph activity was measured after snapshot completion during terminal finalization: $terminalGraphCallsAfterSnapshot request(s)." } else { 'Terminal Graph lifecycle counters were missing, nonnumeric, negative, or inconsistent.' })
                    AffectedInvariant = 'GraphRequestsAtAssessmentCompletion >= GraphRequestsAtSnapshotCompletion and GraphCallsAfterSnapshot == 0 through complete orchestration finalization'
                }
                if (@($packageValidationErrors | Where-Object { [string](Get-InspectorObjectInsightProperty -InputObject $_ -Name 'ErrorId') -eq $terminalLifecycleError.ErrorId }).Count -eq 0) {
                    $packageValidationErrors = @($packageValidationErrors) + @($terminalLifecycleError)
                }

                $terminalExportDirectory = [string](Get-InspectorObjectInsightProperty -InputObject $exportResult -Name 'ExportDirectory')
                if (-not [string]::IsNullOrWhiteSpace($terminalExportDirectory)) {
                    $terminalManifestPath = Join-Path $terminalExportDirectory 'assessment-manifest.json'
                    $terminalSummaryPath = Join-Path $terminalExportDirectory 'assessment-summary.json'
                    if ((Test-Path -LiteralPath $terminalManifestPath -PathType Leaf) -and (Test-Path -LiteralPath $terminalSummaryPath -PathType Leaf)) {
                        $terminalManifest = Read-InspectorReportJsonFile -Path $terminalManifestPath
                        $terminalSummary = Read-InspectorReportJsonFile -Path $terminalSummaryPath
                        foreach ($packageObject in @($terminalManifest, $terminalSummary)) {
                            $packageObject | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $terminalSnapshotCount -Force
                            $packageObject | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $terminalAssessmentCount -Force
                            $packageObject | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $terminalGraphCallsAfterSnapshot -Force
                            $packageObject | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue 'Failed' -Force
                            $packageObject | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $false -Force
                            $packageObject | Add-Member -NotePropertyName ValidationErrors -NotePropertyValue @($packageValidationErrors) -Force

                            $packageValidationEnvelope = Get-InspectorObjectInsightProperty -InputObject $packageObject -Name 'PackageValidation'
                            if ($null -eq $packageValidationEnvelope) {
                                $packageValidationEnvelope = [PSCustomObject][ordered]@{}
                                $packageObject | Add-Member -NotePropertyName PackageValidation -NotePropertyValue $packageValidationEnvelope -Force
                            }
                            $packageValidationEnvelope | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue 'Failed' -Force
                            $packageValidationEnvelope | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $false -Force
                            $packageValidationEnvelope | Add-Member -NotePropertyName ValidationErrors -NotePropertyValue @($packageValidationErrors) -Force
                        }
                        Write-InspectorJsonFile -Path $terminalSummaryPath -Value $terminalSummary
                        for ($pass = 0; $pass -lt 3; $pass++) {
                            Update-InspectorExportArtifactSizes -Manifest $terminalManifest -BasePath $terminalExportDirectory
                            Write-InspectorJsonFile -Path $terminalManifestPath -Value $terminalManifest
                        }
                    }
                }

                if ($null -ne $reportResult) {
                    $reportResult | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidationStatus -Force
                    $reportResult | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $releaseEligible -Force
                    $reportResult | Add-Member -NotePropertyName PackageValidationErrors -NotePropertyValue @($packageValidationErrors) -Force
                }
                if ($null -ne $exportResult) {
                    $exportResult | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidationStatus -Force
                    $exportResult | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $releaseEligible -Force
                }

                if ($null -ne $runLog -and $runLog.DiagnosticLogEnabled -and -not [string]::IsNullOrWhiteSpace([string]$runLog.RunSummaryPath) -and (Test-Path -LiteralPath $runLog.RunSummaryPath -PathType Leaf)) {
                    $terminalRunSummary = Get-Content -LiteralPath $runLog.RunSummaryPath -Raw | ConvertFrom-Json
                    $terminalRunSummary | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidationStatus -Force
                    $terminalRunSummary | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $releaseEligible -Force
                    $terminalRunSummary | Add-Member -NotePropertyName RuntimeTelemetry -NotePropertyValue $runtimeTelemetry -Force
                    $terminalRunSummary | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $runLog.RunSummaryPath -Encoding UTF8 -Force
                }
            }
        }

        if ($null -ne $result) {
            if ($null -ne $orchestrationTelemetry) {
                $result.OrchestrationTelemetry = $orchestrationTelemetry
                $result.TotalCommandDurationMs = $orchestrationTelemetry.TotalCommandDurationMs
            }
            $result.GraphSessionDisconnected = $graphSessionDisconnected
            $result.GraphSessionDisconnectAttempted = $graphSessionDisconnectAttempted
            $result.DiagnosticsLogPath = $runLog.DiagnosticsLogPath
            $result.RunSummaryPath = $runLog.RunSummaryPath
            $result.ReportOpened = $reportOpened
            $result.PackageValidationStatus = $packageValidationStatus
            $result.ReleaseEligible = $releaseEligible
            $result.PackageValidationErrors = @($packageValidationErrors)
            $result.PackageValidationWarnings = @($packageValidationWarnings)
            if ($null -ne $tenantResult) {
                $result.GraphRequestsAtSnapshotCompletion = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphRequestsAtSnapshotCompletion'
                $result.GraphRequestsAtAssessmentCompletion = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphRequestsAtAssessmentCompletion'
                $result.GraphCallsAfterSnapshot = Get-InspectorObjectInsightProperty -InputObject $tenantResult -Name 'GraphCallsAfterSnapshot'
            }
            $result.GraphRequestCount = Get-InspectorObjectInsightProperty -InputObject (Get-InspectorObjectInsightProperty -InputObject $runtimeTelemetry -Name 'GraphRequestSummary') -Name 'TotalRequests'
            $result.GraphCallsIssued = $result.GraphRequestCount
        }

        if ($hadPreviousRuntimeTelemetry) { $script:InspectorCurrentRuntimeTelemetry = $previousRuntimeTelemetry } else { Remove-Variable -Name 'InspectorCurrentRuntimeTelemetry' -Scope Script -ErrorAction SilentlyContinue }

        if (-not $NoProgress -and (Test-InspectorAssessmentInteractiveConsole)) {
            Write-Progress -Activity 'Entra Object Inspector assessment' -Completed
        }
    }

    if ($null -ne $result) {
        # Keep host-only presentation outside the structured pipeline contract.
        try { Write-InspectorAssessmentCompletion -AssessmentResult $result } catch { }
        return $result
    }
}

function Invoke-EntraSecurityAssessment {
    <#
    .SYNOPSIS
        Runs a complete read-only Entra Object Inspector assessment.

    .DESCRIPTION
        Runs the normal Entra Object Inspector workflow with a compact command
        surface. Use the default Live parameter set for tenant-wide or targeted
        Microsoft Graph collection. Use -SnapshotPath for portable offline
        re-analysis without authentication or Graph collection.

        Advanced transport, checkpoint, logging, session, and report metadata
        controls remain available through -AdvancedOptions so the common syntax
        stays short. Run Get-Help Invoke-EntraSecurityAssessment -Examples for
        copy/paste examples.

    .PARAMETER AssessmentName
        Friendly name used in exported assessment artifacts and reports.

    .PARAMETER OutputDirectory
        Parent directory for timestamped assessment export packages.

    .PARAMETER SnapshotPath
        Portable tenant snapshot to analyze offline. Supplying this parameter
        selects PortableOffline mode and skips authentication and Graph collection.

    .PARAMETER SaveSnapshotPath
        Saves the snapshot collected during a live assessment for later offline use.

    .PARAMETER Target
        One or more explicit targets in Identity or ObjectType|Identity form.
        This performs a targeted live assessment instead of tenant-wide collection.

    .PARAMETER TargetFile
        TXT or CSV target specification for a targeted live assessment.

    .PARAMETER CompareToSnapshotPath
        Previous portable snapshot used for deterministic drift comparison.

    .PARAMETER RulePackPath
        Constrained declarative JSON rule pack applied to normalized observations.

    .PARAMETER BaselinePath
        Assessment baseline used to mark accepted observations without deleting them.

    .PARAMETER OpenReport
        Opens the generated main HTML report after successful completion.

    .PARAMETER PassThru
        Includes the full tenant, intelligence, export, and report result objects in
        the returned assessment result.

    .PARAMETER AdvancedOptions
        Optional hashtable for infrequently used operational controls. Supported
        keys are ReportPath, ObjectType, MaxObjectsPerType, BatchSize,
        ThrottleDelayMilliseconds, MaxRetryCount, CheckpointPath, Resume,
        NoProgress, SkipConnect, KeepGraphSession, LogDirectory, NoDiagnosticLog,
        ClientName, and ConsultantName. Values are validated by the internal
        orchestration command before execution.

    .EXAMPLE
        Invoke-EntraSecurityAssessment -AssessmentName "Contoso Entra Assessment"

        Runs a normal tenant-wide live assessment and writes a timestamped export
        package under .\EntraObjectInspector-Exports.

    .EXAMPLE
        Invoke-EntraSecurityAssessment `
            -AssessmentName "Contoso Live Assessment" `
            -SaveSnapshotPath ".\snapshots\contoso.json"

        Runs a live assessment and saves the collected portable snapshot for reuse.

    .EXAMPLE
        Invoke-EntraSecurityAssessment `
            -AssessmentName "Contoso Offline Review" `
            -SnapshotPath ".\snapshots\contoso.json"

        Re-analyzes an existing snapshot completely offline with zero Graph requests.

    .EXAMPLE
        Invoke-EntraSecurityAssessment `
            -AssessmentName "Targeted App Review" `
            -Target "Application|<object-id>","ServicePrincipal|<object-id>"

        Performs a targeted live assessment for the supplied objects.

    .EXAMPLE
        Invoke-EntraSecurityAssessment `
            -AssessmentName "Snapshot Drift Review" `
            -SnapshotPath ".\snapshots\current.json" `
            -CompareToSnapshotPath ".\snapshots\previous.json"

        Compares the current portable snapshot with an earlier snapshot while
        remaining fully offline.

    .EXAMPLE
        Invoke-EntraSecurityAssessment `
            -AssessmentName "Policy Review" `
            -SnapshotPath ".\snapshots\current.json" `
            -RulePackPath ".\policy\rules.json" `
            -BaselinePath ".\policy\baseline.json"

        Applies a rule pack and baseline to a portable snapshot offline.

    .EXAMPLE
        Invoke-EntraSecurityAssessment `
            -AssessmentName "Consulting Assessment" `
            -AdvancedOptions @{
                ClientName = "Contoso"
                ConsultantName = "Security Team"
                BatchSize = 50
            }

        Uses optional advanced controls without expanding the normal command syntax.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Live', PositionalBinding = $false)]
    param (
        [Parameter(ParameterSetName = 'Live')]
        [Parameter(ParameterSetName = 'Offline')]
        [string]$AssessmentName = 'Entra Object Inspector Assessment',

        [Parameter(ParameterSetName = 'Live')]
        [Parameter(ParameterSetName = 'Offline')]
        [string]$OutputDirectory = '.\EntraObjectInspector-Exports',

        [Parameter(Mandatory, ParameterSetName = 'Offline')]
        [string]$SnapshotPath,

        [Parameter(ParameterSetName = 'Live')]
        [string]$SaveSnapshotPath,

        [Parameter(ParameterSetName = 'Live')]
        [string[]]$Target = @(),

        [Parameter(ParameterSetName = 'Live')]
        [string]$TargetFile,

        [Parameter(ParameterSetName = 'Live')]
        [Parameter(ParameterSetName = 'Offline')]
        [string]$CompareToSnapshotPath,

        [Parameter(ParameterSetName = 'Live')]
        [Parameter(ParameterSetName = 'Offline')]
        [string]$RulePackPath,

        [Parameter(ParameterSetName = 'Live')]
        [Parameter(ParameterSetName = 'Offline')]
        [string]$BaselinePath,

        [Parameter(ParameterSetName = 'Live')]
        [Parameter(ParameterSetName = 'Offline')]
        [switch]$OpenReport,

        [Parameter(ParameterSetName = 'Live')]
        [Parameter(ParameterSetName = 'Offline')]
        [switch]$PassThru,

        [Parameter(ParameterSetName = 'Live')]
        [Parameter(ParameterSetName = 'Offline')]
        [hashtable]$AdvancedOptions = @{}
    )

    $allowedAdvancedOptions = @(
        'ReportPath',
        'ObjectType',
        'MaxObjectsPerType',
        'BatchSize',
        'ThrottleDelayMilliseconds',
        'MaxRetryCount',
        'CheckpointPath',
        'Resume',
        'NoProgress',
        'SkipConnect',
        'KeepGraphSession',
        'LogDirectory',
        'NoDiagnosticLog',
        'ClientName',
        'ConsultantName'
    )

    $unknownAdvancedOptions = @(
        $AdvancedOptions.Keys |
            Where-Object { $allowedAdvancedOptions -notcontains [string]$_ }
    )

    if ($unknownAdvancedOptions.Count -gt 0) {
        throw "Unsupported AdvancedOptions key(s): $($unknownAdvancedOptions -join ', '). Supported keys: $($allowedAdvancedOptions -join ', ')."
    }

    $coreParameters = @{
        AssessmentName  = $AssessmentName
        OutputDirectory = $OutputDirectory
    }

    foreach ($name in @(
        'SnapshotPath',
        'SaveSnapshotPath',
        'Target',
        'TargetFile',
        'CompareToSnapshotPath',
        'RulePackPath',
        'BaselinePath'
    )) {
        if ($PSBoundParameters.ContainsKey($name)) {
            $coreParameters[$name] = $PSBoundParameters[$name]
        }
    }

    if ($OpenReport) {
        $coreParameters.OpenReport = $true
    }
    if ($PassThru) {
        $coreParameters.PassThru = $true
    }

    foreach ($name in $AdvancedOptions.Keys) {
        $coreParameters[[string]$name] = $AdvancedOptions[$name]
    }

    return Invoke-InspectorSecurityAssessmentCore @coreParameters
}
