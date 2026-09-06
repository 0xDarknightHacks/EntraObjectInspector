$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Invoke-EntraSecurityAssessment' {

    It 'is exported by the module' {
        $module = Get-Module EntraObjectInspector

        $module.ExportedFunctions.Keys |
            Should -Contain 'Invoke-EntraSecurityAssessment'
    }

    InModuleScope EntraObjectInspector {

        BeforeEach {
            $script:callOrder = [System.Collections.Generic.List[string]]::new()

            Mock Connect-InspectorGraph {
                $script:callOrder.Add('Connect-InspectorGraph')
            }

            Mock Invoke-EntraTenantInspection {
                $script:callOrder.Add('Invoke-EntraTenantInspection')

                [PSCustomObject]@{
                    Status = 'Success'
                    ObjectInsights = @()
                    SecurityObservations = @()
                    FailedObjects = @()
                    Summary = [PSCustomObject]@{
                        ObjectInsightCount = 0
                        SecurityObservationCount = 0
                    }
                }
            }

            Mock Invoke-EntraAssessmentIntelligence {
                $script:callOrder.Add('Invoke-EntraAssessmentIntelligence')

                [PSCustomObject]@{
                    TenantPosture = $null
                    AssessmentFindings = @()
                    AssessmentRecommendations = @()
                    Correlations = @()
                    Limitations = @()
                }
            }

            Mock Export-EntraTenantInspection {
                $script:callOrder.Add('Export-EntraTenantInspection')

                [PSCustomObject]@{
                    Status = 'Success'
                    ExportDirectory = Join-Path $OutputDirectory 'mock-export'
                    ManifestPath = Join-Path $OutputDirectory 'mock-export\assessment-manifest.json'
                    GraphCallsIssued = 0
                    IntelligenceAdded = $false
                }
            }

            Mock Export-EntraAssessmentReport {
                $script:callOrder.Add('Export-EntraAssessmentReport')

                [PSCustomObject]@{
                    Status = 'Success'
                    ReportPath = $OutputPath
                    ReportSizeBytes = 123
                    GraphCallsIssued = 0
                    IntelligenceAdded = $false
                    NewObservationsAdded = $false
                    RiskScoreProduced = $false
                    AttackPathsProduced = $false
                    ClientSideInteractivity = $true
                    GroupedObservations = $true
                    CrossReferencesEnabled = $true
                    SelfContainedHtml = $true
                    Printable = $true
                }
            }

            Mock Disconnect-MgGraph {}

            Mock Invoke-Item {}

        }

        It 'calls the existing public commands in workflow order' {
            Invoke-EntraSecurityAssessment `
                -AssessmentName 'Orchestration Test' `
                -OutputDirectory (Join-Path $TestDrive 'exports') |
                Out-Null

            @($script:callOrder) |
                Should -Be @(
                    'Connect-InspectorGraph',
                    'Invoke-EntraTenantInspection',
                    'Invoke-EntraAssessmentIntelligence',
                    'Export-EntraTenantInspection',
                    'Export-EntraAssessmentReport'
                )
        }

        It 'supports SkipConnect without calling Connect-InspectorGraph' {
            Invoke-EntraSecurityAssessment `
                -AssessmentName 'Skip Connect Test' `
                -OutputDirectory (Join-Path $TestDrive 'exports') `
                -SkipConnect |
                Out-Null

            Should -Invoke Connect-InspectorGraph -Times 0 -Exactly
            @($script:callOrder) |
                Should -Be @(
                    'Invoke-EntraTenantInspection',
                    'Invoke-EntraAssessmentIntelligence',
                    'Export-EntraTenantInspection',
                    'Export-EntraAssessmentReport'
                )
        }

        It 'uses the default report path under the output directory' {
            $outputDirectory = Join-Path $TestDrive 'assessment-output'

            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Default Report Path Test' `
                    -OutputDirectory $outputDirectory `
                    -SkipConnect

            $result.ReportPath |
                Should -Be (Join-Path $outputDirectory 'entra-object-inspector-report.html')

            Should -Invoke Export-EntraAssessmentReport `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $OutputPath -eq (Join-Path $outputDirectory 'entra-object-inspector-report.html')
                }
        }

        It 'uses an explicit report path when supplied' {
            $reportPath = Join-Path $TestDrive 'reports\custom-report.html'

            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Explicit Report Path Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -ReportPath $reportPath `
                    -SkipConnect

            $result.ReportPath | Should -Be $reportPath

            Should -Invoke Export-EntraAssessmentReport `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $OutputPath -eq $reportPath
                }
        }

        It 'returns a structured summary object with report and export invariants' {
            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Invariant Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -SkipConnect

            $result.PSTypeNames[0] | Should -Be 'EntraObjectInspector.SecurityAssessmentResult'
            $result.SchemaVersion | Should -Be '1.0.0'
            $result.Status | Should -Be 'Success'
            $result.TenantInspectionStatus | Should -Be 'Success'
            $result.ExportStatus | Should -Be 'Success'
            $result.ReportStatus | Should -Be 'Success'
            $result.GraphCallsIssued | Should -Be 0
            $result.IntelligenceAdded | Should -BeFalse
            $result.NewObservationsAdded | Should -BeFalse
            $result.RiskScoreProduced | Should -BeFalse
            $result.AttackPathsProduced | Should -BeFalse
            $result.ClientSideInteractivity | Should -BeTrue
            $result.GroupedObservations | Should -BeTrue
            $result.CrossReferencesEnabled | Should -BeTrue
            $result.SelfContainedHtml | Should -BeTrue
            $result.Printable | Should -BeTrue
            $result.DiagnosticsLogPath | Should -Not -BeNullOrEmpty
            $result.RunSummaryPath | Should -Not -BeNullOrEmpty
            $result.RunId | Should -Not -BeNullOrEmpty
            $result.ReportId | Should -Not -BeNullOrEmpty
            $result.FailedObjectCount | Should -Be 0
            $result.GraphSessionDisconnectAttempted | Should -BeFalse
            $result.GraphSessionDisconnected | Should -BeFalse
            $result.KeepGraphSession | Should -BeFalse
            $result.ReportOpened | Should -BeFalse
        }

        It 'does not expand nested result objects unless PassThru is supplied' {
            $summary =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Summary Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -SkipConnect

            $summary.TenantResult | Should -BeNullOrEmpty
            $summary.AssessmentIntelligence | Should -BeNullOrEmpty
            $summary.ExportResult | Should -BeNullOrEmpty
            $summary.ReportResult | Should -BeNullOrEmpty

            $expanded =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'PassThru Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports-expanded') `
                    -SkipConnect `
                    -PassThru

            $expanded.TenantResult.Status | Should -Be 'Success'
            $expanded.AssessmentIntelligence | Should -Not -BeNullOrEmpty
            $expanded.ExportResult.Status | Should -Be 'Success'
            $expanded.ReportResult.Status | Should -Be 'Success'
        }

        It 'does not call Invoke-InspectorGraphRequest directly' {
            Mock Invoke-InspectorGraphRequest {
                throw 'The orchestration command must not call Graph directly.'
            }

            Invoke-EntraSecurityAssessment `
                -AssessmentName 'Graph Boundary Test' `
                -OutputDirectory (Join-Path $TestDrive 'exports') `
                -SkipConnect |
                Out-Null

            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'exposes operational readiness parameters' {
            $parameters = (Get-Command Invoke-EntraSecurityAssessment).Parameters.Keys

            $parameters | Should -Contain 'KeepGraphSession'
            $parameters | Should -Contain 'OpenReport'
            $parameters | Should -Contain 'LogDirectory'
            $parameters | Should -Contain 'NoDiagnosticLog'
            $parameters | Should -Contain 'ClientName'
            $parameters | Should -Contain 'ConsultantName'
        }

        It 'returns orchestration telemetry and passes report metadata through' {
            Mock Invoke-EntraTenantInspection {
                $script:callOrder.Add('Invoke-EntraTenantInspection')

                [PSCustomObject]@{
                    Status = 'Success'
                    ObjectInsights = @()
                    SecurityObservations = @()
                    FailedObjects = @()
                    OfflineProcessingStartedAt = '2026-09-03T11:08:23Z'
                    OfflineProcessingCompletedAt = '2026-09-03T11:08:58Z'
                    Summary = [PSCustomObject]@{ ObjectInsightCount = 0; SecurityObservationCount = 0 }
                    RuntimeTelemetry = [PSCustomObject]@{
                        TotalDurationMs = 350
                        StageDurations = [ordered]@{
                            TenantSnapshotCollection = [PSCustomObject]@{ DurationMs = 200 }
                            OfflineResolution = [PSCustomObject]@{ DurationMs = 10 }
                            OfflineRelationshipBuilding = [PSCustomObject]@{ DurationMs = 20 }
                            Normalization = [PSCustomObject]@{ DurationMs = 30 }
                            PermissionIntelligence = [PSCustomObject]@{ DurationMs = 40 }
                            ObservationEngine = [PSCustomObject]@{ DurationMs = 50 }
                        }
                        GraphRequestSummary = [PSCustomObject]@{ TotalRequests = 7 }
                        RetrySummary = [PSCustomObject]@{ RetriedRequests = 0 }
                        ThrottlingSummary = [PSCustomObject]@{ ThrottledRequests = 0 }
                        ThroughputSummary = [PSCustomObject]@{ ObjectsProcessed = 0; ObjectsPerSecond = 0 }
                        MemorySummary = [PSCustomObject]@{ PeakMemoryMB = 1; MemoryTelemetryAvailable = $true }
                        ExternalEndpointSummary = [PSCustomObject]@{ HostsContacted = @('graph.microsoft.com'); UnexpectedExternalHosts = @() }
                        OutputArtifactSummary = [PSCustomObject]@{
                            ExportDirectory = ''
                            ReportPath = ''
                            ArtifactCount = 0
                            TotalArtifactSizeBytes = 0
                            HtmlReportSizeBytes = 0
                        }
                    }
                }
            }

            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Telemetry Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -ClientName 'Client Test' `
                    -ConsultantName 'Consultant Test' `
                    -SkipConnect

            $result.OrchestrationTelemetry | Should -Not -BeNullOrEmpty
            $result.OrchestrationTelemetry.TenantInspectionDurationMs | Should -Not -BeNullOrEmpty
            $result.OrchestrationTelemetry.SnapshotCollectionDurationMs | Should -Be 200
            $result.OrchestrationTelemetry.OfflineProcessingDurationMs | Should -Be 35000
            $result.OrchestrationTelemetry.AssessmentIntelligenceDurationMs | Should -Not -BeNullOrEmpty
            $result.OrchestrationTelemetry.ExportDurationMs | Should -Not -BeNullOrEmpty
            $result.OrchestrationTelemetry.ReportGenerationDurationMs | Should -Not -BeNullOrEmpty
            $result.OrchestrationTelemetry.TotalCommandDurationMs | Should -Not -BeNullOrEmpty
            $result.TotalCommandDurationMs | Should -Be $result.OrchestrationTelemetry.TotalCommandDurationMs

            Should -Invoke Export-EntraAssessmentReport `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $ClientName -eq 'Client Test' -and
                    $ConsultantName -eq 'Consultant Test' -and
                    $null -ne $OrchestrationTelemetry
                }
        }

        It 'attempts Graph disconnect when it created the session' {
            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Disconnect Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports')

            Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
            $result.GraphSessionDisconnectAttempted | Should -BeTrue
            $result.GraphSessionDisconnected | Should -BeTrue
        }

        It 'does not attempt Graph disconnect when authentication fails before a session is established' {
            Mock Connect-InspectorGraph {
                throw 'authentication failed for test'
            }

            {
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Authentication Failure Disconnect Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -NoProgress
            } | Should -Throw '*authentication failed for test*'

            Should -Invoke Disconnect-MgGraph -Times 0 -Exactly
            Should -Invoke Invoke-EntraTenantInspection -Times 0 -Exactly
        }

        It 'fails release integrity when the real Graph request boundary is invoked during finalization' {
            Mock Get-MgContext {
                [PSCustomObject]@{ TenantId = 'tenant-1'; ClientId = 'client-1'; AuthType = 'AppOnly' }
            }

            Mock Invoke-EntraTenantInspection {
                $script:callOrder.Add('Invoke-EntraTenantInspection')
                $activeTelemetry = $script:InspectorCurrentRuntimeTelemetry
                $activeTelemetry | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue 0 -Force

                [PSCustomObject]@{
                    Status = 'Success'
                    ObjectInsights = @()
                    SecurityObservations = @()
                    FailedObjects = @()
                    GraphRequestsAtSnapshotCompletion = 0
                    GraphRequestsAtAssessmentCompletion = 0
                    GraphCallsAfterSnapshot = 0
                    Summary = [PSCustomObject]@{ ObjectInsightCount = 0; SecurityObservationCount = 0; GraphRequestsAtSnapshotCompletion = 0; GraphRequestsAtAssessmentCompletion = 0; GraphCallsAfterSnapshot = 0 }
                    RuntimeTelemetry = $activeTelemetry
                }
            }

            Mock Invoke-MgGraphRequest {
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
                $response.Content = [System.Net.Http.StringContent]::new('{"value":[]}')
                $response
            }

            Mock Complete-InspectorRunLog {
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications?$top=1' `
                    -RequiredPermission 'Application.Read.All' `
                    -RuntimeTelemetry $script:InspectorCurrentRuntimeTelemetry |
                    Out-Null
                $RunLog
            }

            $result = Invoke-EntraSecurityAssessment `
                -AssessmentName 'Finalization Graph Sentinel Test' `
                -OutputDirectory (Join-Path $TestDrive 'exports')

            $result.GraphRequestsAtSnapshotCompletion | Should -Be 0
            $result.GraphRequestsAtAssessmentCompletion | Should -BeGreaterThan 0
            $result.GraphCallsAfterSnapshot | Should -BeGreaterThan 0
            $result.PackageValidationStatus | Should -Not -Be 'Success'
            $result.ReleaseEligible | Should -BeFalse
            @($result.PackageValidationErrors | Where-Object { [string](Get-InspectorObjectInsightProperty -InputObject $_ -Name 'ErrorId') -eq 'PKG-GRAPH-LIFECYCLE-FINAL-001' }).Count | Should -Be 1
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
        }

        It 'skips Graph disconnect when KeepGraphSession is supplied' {
            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Keep Session Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -KeepGraphSession

            Should -Invoke Disconnect-MgGraph -Times 0 -Exactly
            $result.GraphSessionDisconnectAttempted | Should -BeFalse
            $result.GraphSessionDisconnected | Should -BeFalse
            $result.KeepGraphSession | Should -BeTrue
        }

        It 'skips Graph disconnect by default when SkipConnect is used' {
            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Caller Owned Session Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -SkipConnect

            Should -Invoke Disconnect-MgGraph -Times 0 -Exactly
            $result.GraphSessionDisconnectAttempted | Should -BeFalse
            $result.GraphSessionDisconnected | Should -BeFalse
        }

        It 'logs disconnect failures as warnings without masking success' {
            Mock Disconnect-MgGraph { throw 'disconnect failed for test' }

            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Disconnect Warning Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports')

            $result.Status | Should -Be 'Success'
            $result.GraphSessionDisconnectAttempted | Should -BeTrue
            $result.GraphSessionDisconnected | Should -BeFalse
            Get-Content -LiteralPath $result.DiagnosticsLogPath -Raw | Should -Match 'GraphDisconnectFailed'
        }

        It 'creates diagnostics summary and JSONL events without obvious secrets' {
            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Diagnostics Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -SkipConnect

            Test-Path -LiteralPath $result.DiagnosticsLogPath | Should -BeTrue
            Test-Path -LiteralPath $result.RunSummaryPath | Should -BeTrue
            $logContent = Get-Content -LiteralPath $result.DiagnosticsLogPath -Raw
            $logContent | Should -Match 'AssessmentStarted'
            $logContent | Should -Not -Match '(?i)(access_token|refresh_token|client_secret|authorization|password)'
        }

        It 'logs fatal orchestration failures before rethrowing' {
            Mock Invoke-EntraTenantInspection { throw 'snapshot collection failed for test' }

            $outputDirectory = Join-Path $TestDrive 'exports'

            {
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Failure Logging Test' `
                    -OutputDirectory $outputDirectory
            } | Should -Throw

            $diagnosticLog =
                Get-ChildItem `
                    -LiteralPath (Join-Path $outputDirectory 'logs') `
                    -Filter '*-diagnostics.jsonl' |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1

            $diagnosticLog | Should -Not -BeNullOrEmpty
            Get-Content -LiteralPath $diagnosticLog.FullName -Raw | Should -Match 'AssessmentFailed'
            Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
        }

        It 'opens the report only after successful report generation when requested' {
            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Open Report Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -OpenReport `
                    -SkipConnect

            Should -Invoke Invoke-Item -Times 1 -Exactly
            $result.ReportOpened | Should -BeTrue
        }

        It 'logs report open failures as warnings' {
            Mock Invoke-Item { throw 'open failed for test' }

            $result =
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Open Report Failure Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -OpenReport `
                    -SkipConnect

            $result.ReportOpened | Should -BeFalse
            Get-Content -LiteralPath $result.DiagnosticsLogPath -Raw | Should -Match 'ReportOpenFailed'
        }

        It 'emits high-level orchestration progress messages' {
            $messages = @(
                Invoke-EntraSecurityAssessment `
                    -AssessmentName 'Progress Test' `
                    -OutputDirectory (Join-Path $TestDrive 'exports') `
                    -SkipConnect `
                    6>&1
            )

            ($messages | Out-String) | Should -Match '\[2/7\] Collecting tenant snapshot'
            ($messages | Out-String) | Should -Match '\[7/7\] Finalizing and disconnecting'
        }
    }
}
