$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Runtime telemetry' {

    InModuleScope EntraObjectInspector {

        It 'records stage durations and Graph request summaries locally' {
            $telemetry = New-InspectorRuntimeTelemetry

            Start-InspectorTelemetryStage -Telemetry $telemetry -Name 'TenantSnapshotCollection'
            Stop-InspectorTelemetryStage -Telemetry $telemetry -Name 'TenantSnapshotCollection'
            Start-InspectorTelemetryStage -Telemetry $telemetry -Name 'TenantSnapshotCollection'
            Stop-InspectorTelemetryStage -Telemetry $telemetry -Name 'TenantSnapshotCollection'
            Add-InspectorGraphTelemetryRecord `
                -Telemetry $telemetry `
                -GraphResult ([PSCustomObject]@{
                    SourceEndpoint = 'https://graph.microsoft.com/v1.0/applications?$select=id'
                    Status = 'Success'
                })

            $telemetry.SchemaVersion | Should -Be '1.1.0'
            $telemetry.StageDurations.TenantSnapshotCollection.Status | Should -Be 'Completed'
            $telemetry.StageDurations.TenantSnapshotCollection.DurationMs | Should -Not -BeNullOrEmpty
            $telemetry.StageDurations.TenantSnapshotCollection.InvocationCount | Should -Be 2
            $telemetry.StageDurations.TenantSnapshotCollection.FailedInvocationCount | Should -Be 0
            $telemetry.GraphRequestSummary.TotalRequests | Should -Be 1
            $telemetry.GraphRequestSummary.SuccessfulRequests | Should -Be 1
            $telemetry.GraphRequestsByEndpoint['/v1.0/applications'] | Should -Be 1
            $telemetry.ExternalEndpointSummary.ObservedExternalHosts | Should -Contain 'graph.microsoft.com'
            $telemetry.ExternalEndpointSummary.UnexpectedExternalHosts.Count | Should -Be 0
            ($telemetry | ConvertTo-Json -Depth 10) | Should -Not -Match 'secret|token|authorization|raw response'
        }

        It 'flags unexpected external hosts if observable' {
            $telemetry = New-InspectorRuntimeTelemetry

            Add-InspectorGraphTelemetryRecord `
                -Telemetry $telemetry `
                -GraphResult ([PSCustomObject]@{
                    SourceEndpoint = 'https://example.invalid/data'
                    Status = 'Failed'
                })

            $telemetry.ExternalEndpointSummary.UnexpectedExternalHosts | Should -Contain 'example.invalid'
        }

        It 'counts a real post-snapshot Graph boundary call and makes the package release-ineligible' {
            $telemetry = New-InspectorRuntimeTelemetry
            $script:InspectorCurrentRuntimeTelemetry = $telemetry
            try {
                Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'tenant-test' } }
                Mock Invoke-MgGraphRequest {
                    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
                    $response.Content = [System.Net.Http.StringContent]::new('{"value":[]}')
                    return $response
                }

                $graphRequestsAtSnapshotCompletion = [int]$telemetry.GraphRequestSummary.TotalRequests
                $graphResult = Invoke-InspectorGraphRequest -Uri 'https://graph.microsoft.com/v1.0/applications' -RequiredPermission 'Application.Read.All'
                $graphRequestsAtAssessmentCompletion = [int]$telemetry.GraphRequestSummary.TotalRequests
                $graphCallsAfterSnapshot = $graphRequestsAtAssessmentCompletion - $graphRequestsAtSnapshotCompletion

                $graphResult.Status | Should -Be 'Success'
                $graphCallsAfterSnapshot | Should -BeGreaterThan 0
                $telemetry.GraphTransportSummary.TotalHttpRequests | Should -Be 1
                $telemetry.GraphTransportSummary.SingleHttpRequests | Should -Be 1
                $telemetry.GraphTransportSummary.BatchHttpRequests | Should -Be 0

                $scope = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @(); AssessmentCoverageCompleteness = 'Complete' }
                $coverage = [PSCustomObject]@{ Status = 'Success'; Completeness = 'Complete'; EvidencePlanMatches = $true; ExpectedEvidenceCount = 0; ActualRequiredEvidenceCount = 0; ExpectedQueries = @() }
                $summary = [PSCustomObject]@{ SchemaVersion = '0.10.0'; Status = 'Success'; FailedCount = 0; ScopeInventory = $scope; AssessmentCoverage = $coverage; GraphCallsAfterSnapshot = $graphCallsAfterSnapshot }
                $manifest = [PSCustomObject]@{ SchemaVersion = '0.10.0'; SourceStatus = 'Success'; FailedObjectCount = 0; ScopeInventory = $scope; AssessmentCoverage = $coverage; GraphCallsAfterSnapshot = $graphCallsAfterSnapshot; PackageValidationStatus = 'NotRun'; ReleaseEligible = $false; Artifacts = @() }
                $validation = Test-InspectorReportPackageConsistency -Summary $summary -Manifest $manifest

                $validation.Status | Should -Not -Be 'Success'
                $validation.ReleaseEligible | Should -BeFalse
                @($validation.Errors).ErrorId | Should -Contain 'PKG-GRAPH-POSTSNAPSHOT-001'
            }
            finally {
                Remove-Variable -Name 'InspectorCurrentRuntimeTelemetry' -Scope Script -ErrorAction SilentlyContinue
            }
        }

        It 'finds no unexpected outbound HTTP commands outside the approved Graph/auth path' {
            $root = Resolve-Path (Join-Path $PSScriptRoot '..')
            $hits =
                @(
                    Get-ChildItem -Path $root -Recurse -File -Include *.ps1,*.psm1 |
                    Where-Object { $_.Name -ne 'RuntimeTelemetry.Tests.ps1' } |
                    Select-String -Pattern 'Invoke-WebRequest|Invoke-RestMethod|System\.Net\.Http\.HttpClient|WebClient|curl|wget|Start-BitsTransfer'
                )

            $hits | Should -BeNullOrEmpty
        }
    }
}
