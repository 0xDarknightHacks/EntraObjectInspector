function Export-EntraAssessmentReport {
    <#
    .SYNOPSIS
        Generates a static HTML assessment report.

    .DESCRIPTION
        HTML assessment report generator.

        This command consumes either an in-memory tenant inspection result or an
        assessment export directory and writes a static, searchable,
        self-contained HTML report. It is a read-only presentation layer. It
        does not call Microsoft Graph, does not create new observations, does
        not generate intelligence, and does not calculate risk or attack paths.
        The HTML report is intentionally lightweight; detailed evidence remains
        in the structured JSON/CSV export artifacts.
        Report search is local to the file and supports prefilled `?q=` or
        `?object=` values plus copy buttons for available identifiers.
        Recommendations and findings may include static authoritative reference
        links for transparency.

    .PARAMETER ClientName
        Optional client name rendered in the report metadata block.

    .PARAMETER ConsultantName
        Optional consultant name rendered in the report metadata block.
    #>

    [CmdletBinding(DefaultParameterSetName = 'InputObject')]
    param (
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ParameterSetName = 'InputObject'
        )]
        [object]$InputObject,

        [Parameter(
            Mandatory,
            ParameterSetName = 'ExportDirectory'
        )]
        [string]$ExportDirectory,

        [Parameter(ParameterSetName = 'InputObject')]
        [AllowNull()]
        [object]$AssessmentIntelligence,

        [AllowNull()]
        [object]$OrchestrationTelemetry,

        [string]$AssessmentName = 'Entra Object Inspector Assessment',

        [string]$OutputPath,

        [string]$OutputDirectory = '.\reports',

        [string]$ClientName = '',

        [string]$ConsultantName = '',

        [switch]$Force
    )

    process {
        $reportStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $workingSetSamples = [System.Collections.Generic.List[double]]::new()
        $workingSetStartMB = Get-InspectorExportWorkingSetMB
        if ($null -ne $workingSetStartMB) {
            $workingSetSamples.Add([double]$workingSetStartMB)
        }

        Write-Verbose 'Starting report model conversion.'

        if ($PSCmdlet.ParameterSetName -eq 'ExportDirectory') {
            $reportModel =
                Get-InspectorReportModelFromDirectory `
                    -ExportDirectory $ExportDirectory `
                    -AssessmentName $AssessmentName `
                    -ClientName $ClientName `
                    -ConsultantName $ConsultantName

            if ($null -ne $OrchestrationTelemetry) {
                $reportModel |
                    Add-Member -NotePropertyName 'OrchestrationTelemetry' -NotePropertyValue $OrchestrationTelemetry -Force

                $orchestrationRunId =
                    Get-InspectorReportProperty `
                        -InputObject $OrchestrationTelemetry `
                        -Name 'RunId'

                if (-not [string]::IsNullOrWhiteSpace([string]$orchestrationRunId)) {
                    $reportModel |
                        Add-Member -NotePropertyName 'RunId' -NotePropertyValue ([string]$orchestrationRunId) -Force
                }
            }
        }
        else {
            $reportModel =
                ConvertTo-InspectorReportModel `
                    -InputObject $InputObject `
                    -AssessmentIntelligence $AssessmentIntelligence `
                    -AssessmentName $AssessmentName `
                    -OrchestrationTelemetry $OrchestrationTelemetry `
                    -ClientName $ClientName `
                    -ConsultantName $ConsultantName `
                    -SourceKind 'InMemoryObject'
        }

        $modelConversionElapsedMs = $phaseStopwatch.ElapsedMilliseconds
        $workingSetAfterModelMB = Get-InspectorExportWorkingSetMB
        if ($null -ne $workingSetAfterModelMB) {
            $workingSetSamples.Add([double]$workingSetAfterModelMB)
        }
        Write-Verbose "Report model conversion completed in $modelConversionElapsedMs ms."

        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            New-Item `
                -ItemType Directory `
                -Path $OutputDirectory `
                -Force |
                Out-Null

            $safeName =
                ConvertTo-InspectorReportSafeFileName `
                    -Name $AssessmentName

            $timestamp =
                (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')

            $OutputPath =
                Join-Path `
                    -Path $OutputDirectory `
                    -ChildPath "$safeName-$timestamp.html"
        }
        else {
            $parent =
                Split-Path `
                    -Path $OutputPath `
                    -Parent

            if (-not [string]::IsNullOrWhiteSpace($parent)) {
                New-Item `
                    -ItemType Directory `
                    -Path $parent `
                    -Force |
                    Out-Null
            }
        }

        if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
            throw "Report already exists: $OutputPath. Use -Force or choose another OutputPath."
        }

        $reportDirectory = Split-Path -Path $OutputPath -Parent
        $reportLeaf = Split-Path -Path $OutputPath -Leaf
        $reportBase = [System.IO.Path]::GetFileNameWithoutExtension($reportLeaf)
        $diagnosticsPath = Join-Path -Path $reportDirectory -ChildPath "$reportBase-diagnostics.html"
        $evidencePath = Join-Path -Path $reportDirectory -ChildPath "$reportBase-evidence.html"
        $reportModel.ReportFileName = $reportLeaf
        $reportModel.DiagnosticsReportFileName = Split-Path -Path $diagnosticsPath -Leaf
        $reportModel.EvidenceReportFileName = Split-Path -Path $evidencePath -Leaf

        if ($reportModel.SourceKind -eq 'ExportDirectory' -and -not [string]::IsNullOrWhiteSpace([string]$reportModel.SourcePath)) {
            $manifestPath = Join-Path -Path $reportModel.SourcePath -ChildPath 'assessment-manifest.json'
            $summaryPath = Join-Path -Path $reportModel.SourcePath -ChildPath 'assessment-summary.json'
            $intelligencePath = Join-Path -Path $reportModel.SourcePath -ChildPath 'assessment-intelligence.json'
            $tenantPosturePath = Join-Path -Path $reportModel.SourcePath -ChildPath 'tenant-posture.json'
            $markdownPath = Join-Path -Path $reportModel.SourcePath -ChildPath 'assessment-summary.md'

            if (Test-Path -LiteralPath $manifestPath) {
                Write-InspectorJsonFile -Path $manifestPath -Value $reportModel.Manifest
            }

            if (Test-Path -LiteralPath $summaryPath) {
                Write-InspectorJsonFile -Path $summaryPath -Value $reportModel.Summary
            }

            if ((Test-Path -LiteralPath $intelligencePath) -and $null -ne $reportModel.AssessmentIntelligence) {
                Write-InspectorJsonFile -Path $intelligencePath -Value $reportModel.AssessmentIntelligence -Depth 40
            }

            if ((Test-Path -LiteralPath $tenantPosturePath) -and $null -ne $reportModel.TenantPosture) {
                Write-InspectorJsonFile -Path $tenantPosturePath -Value $reportModel.TenantPosture
            }

            if (Test-Path -LiteralPath $markdownPath) {
                $markdownFindingRows =
                    @(
                        @($reportModel.AssessmentFindings) |
                        Where-Object { $null -ne $_ } |
                        ForEach-Object {
                            ConvertTo-InspectorFlatAssessmentFinding `
                                -Finding $_
                        }
                    )

                $markdownRecommendationRows =
                    @(
                        @($reportModel.AssessmentRecommendations) |
                        Where-Object { $null -ne $_ } |
                        ForEach-Object {
                            ConvertTo-InspectorFlatAssessmentRecommendation `
                                -Recommendation $_
                        }
                    )

                $markdownCorrelationRows =
                    @(
                        @($reportModel.AssessmentCorrelations) |
                        Where-Object { $null -ne $_ } |
                        ForEach-Object {
                            ConvertTo-InspectorFlatAssessmentCorrelation `
                                -Correlation $_
                        }
                    )

                New-InspectorAssessmentMarkdown `
                    -ExportModel ([PSCustomObject]@{
                        Manifest = $reportModel.Manifest
                        Summary = $reportModel.Summary
                        TenantPosture = $reportModel.TenantPosture
                        AssessmentFindingRows = @($markdownFindingRows)
                        AssessmentRecommendationRows = @($markdownRecommendationRows)
                        AssessmentCorrelationRows = @($markdownCorrelationRows)
                        AssessmentLimitations = @($reportModel.AssessmentLimitations)
                    }) |
                    Set-Content -LiteralPath $markdownPath -Encoding UTF8 -Force
            }

            # Report-model conversion finalizes RunId/ReportId, package validation,
            # release eligibility, and summary content. Refresh the manifest artifact
            # inventory after those rewrites so SizeBytes represents the final files
            # rather than their pre-report export state. A few passes let the manifest's
            # self-referential SizeBytes stabilize without external state.
            for ($artifactRefreshPass = 0; $artifactRefreshPass -lt 3; $artifactRefreshPass++) {
                Update-InspectorExportArtifactSizes -Manifest $reportModel.Manifest -BasePath $reportModel.SourcePath
                Write-InspectorJsonFile -Path $manifestPath -Value $reportModel.Manifest
            }
        }

        if (((Test-Path -LiteralPath $diagnosticsPath) -or (Test-Path -LiteralPath $evidencePath)) -and -not $Force) {
            throw "Sidecar report already exists next to: $OutputPath. Use -Force or choose another OutputPath."
        }

        $phaseStopwatch.Restart()
        Write-Verbose 'Starting HTML report rendering.'

        $html =
            New-InspectorHtmlReport `
                -ReportModel $reportModel

        $evidenceHtml =
            New-InspectorEvidenceHtmlReport `
                -ReportModel $reportModel

        $htmlRenderElapsedMs = $phaseStopwatch.ElapsedMilliseconds
        $workingSetAfterHtmlRenderMB = Get-InspectorExportWorkingSetMB
        if ($null -ne $workingSetAfterHtmlRenderMB) {
            $workingSetSamples.Add([double]$workingSetAfterHtmlRenderMB)
        }
        if ($null -ne $reportModel.OrchestrationTelemetry) {
            $reportModel.OrchestrationTelemetry |
                Add-Member -NotePropertyName 'ReportGenerationDurationMs' -NotePropertyValue $htmlRenderElapsedMs -Force
        }

        $diagnosticsHtml =
            New-InspectorDiagnosticsHtmlReport `
                -ReportModel $reportModel

        Write-Verbose "HTML report rendering completed in $htmlRenderElapsedMs ms."

        $phaseStopwatch.Restart()
        Write-Verbose "Starting HTML report write to '$OutputPath'."

        $html |
            Set-Content `
                -LiteralPath $OutputPath `
                -Encoding UTF8 `
                -Force

        $diagnosticsHtml |
            Set-Content `
                -LiteralPath $diagnosticsPath `
                -Encoding UTF8 `
                -Force

        $evidenceHtml |
            Set-Content `
                -LiteralPath $evidencePath `
                -Encoding UTF8 `
                -Force

        $fileWriteElapsedMs = $phaseStopwatch.ElapsedMilliseconds
        $workingSetEndMB = Get-InspectorExportWorkingSetMB
        if ($null -ne $workingSetEndMB) {
            $workingSetSamples.Add([double]$workingSetEndMB)
        }
        $reportStopwatch.Stop()

        $peakObservedWorkingSetMB =
            if ($workingSetSamples.Count -gt 0) {
                [math]::Round(
                    [double](($workingSetSamples | Measure-Object -Maximum).Maximum),
                    2
                )
            }
            else {
                $null
            }

        $reportPerformanceProfile = [PSCustomObject][ordered]@{
            SchemaVersion                 = '1.0.0'
            TotalDurationMs               = $reportStopwatch.ElapsedMilliseconds
            ModelConversionDurationMs     = $modelConversionElapsedMs
            HtmlRenderDurationMs          = $htmlRenderElapsedMs
            FileWriteDurationMs           = $fileWriteElapsedMs
            WorkingSetStartMB             = $workingSetStartMB
            WorkingSetAfterModelMB        = $workingSetAfterModelMB
            WorkingSetAfterHtmlRenderMB   = $workingSetAfterHtmlRenderMB
            WorkingSetEndMB               = $workingSetEndMB
            PeakObservedWorkingSetMB      = $peakObservedWorkingSetMB
        }

        Write-Verbose "HTML report write completed in $fileWriteElapsedMs ms."
        Write-Verbose "Assessment report export completed in $($reportStopwatch.ElapsedMilliseconds) ms."

        $fileInfo =
            Get-Item `
                -LiteralPath $OutputPath `
                -ErrorAction Stop

        return [PSCustomObject][ordered]@{
            PSTypeName              = 'EntraObjectInspector.AssessmentReportResult'
            SchemaVersion           = '0.12.0'
            Status                  = 'Success'
            AssessmentName          = $AssessmentName
            RunId                   = $reportModel.RunId
            ReportId                = $reportModel.ReportId
            FailedObjectCount       = $reportModel.FailedObjectCount
            ReportPath              = $fileInfo.FullName
            DiagnosticsReportPath   = (Get-Item -LiteralPath $diagnosticsPath -ErrorAction Stop).FullName
            EvidenceReportPath      = (Get-Item -LiteralPath $evidencePath -ErrorAction Stop).FullName
            ReportSizeBytes         = $fileInfo.Length
            SourceKind              = $reportModel.SourceKind
            GraphCallsIssued        = 0
            IntelligenceAdded       = $false
            NewObservationsAdded    = $false
            RiskScoreProduced       = $false
            ExposureScoreProduced   = $false
            AttackPathsProduced     = $false
            ClientSideInteractivity = $true
            GroupedObservations     = $true
            CrossReferencesEnabled  = $true
            SelfContainedHtml       = $true
            Printable               = $true
            PerformanceProfile      = $reportPerformanceProfile
            PackageValidationStatus = $reportModel.PackageValidationStatus
            ReleaseEligible         = $reportModel.ReleaseEligible
            PackageValidation       = $reportModel.PackageValidation
            PackageValidationErrors = @($reportModel.PackageValidationErrors)
            PackageValidationWarnings = @($reportModel.PackageValidationWarnings)
            ModelConversionMs       = $modelConversionElapsedMs
            HtmlRenderMs            = $htmlRenderElapsedMs
            FileWriteMs             = $fileWriteElapsedMs
            TotalExportMs           = $reportStopwatch.ElapsedMilliseconds
        }
    }
}
