$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Invoke-EntraTenantInspection' {

    InModuleScope EntraObjectInspector {

        BeforeEach {
            $script:snapshotBuilt = $false

            Mock New-InspectorTenantSnapshot {
                $script:snapshotBuilt = $true
                Add-InspectorGraphTelemetryRecord `
                    -Telemetry $RuntimeTelemetry `
                    -GraphResult ([PSCustomObject]@{
                        Status = 'Success'
                        SourceEndpoint = 'https://graph.microsoft.com/v1.0/applications'
                    })

                [PSCustomObject]@{
                    SchemaVersion = '1.0.0'
                    SnapshotId = 'snapshot-1'
                    CreatedAt = (Get-Date).ToUniversalTime().ToString('o')
                    Collections = [PSCustomObject]@{}
                    Indexes = [PSCustomObject]@{}
                    Evidence = @()
                    Limitations = @()
                }
            }

            Mock ConvertFrom-InspectorTenantSnapshot {
                [PSCustomObject]@{
                    Status = 'Success'
                    TotalCount = 1
                    DiscoveredObjects = @(
                        [PSCustomObject]@{
                            ObjectType = 'Application'
                            ObjectId = 'app-1'
                            InspectionIdentity = 'app-1'
                            ObjectKey = 'Application:app-1'
                        }
                    )
                    Evidence = @()
                    Limitations = @()
                    Logs = @()
                }
            }

            Mock Resolve-EntraObjectFromSnapshot {
                if (-not $script:snapshotBuilt) {
                    throw 'Resolution ran before snapshot collection.'
                }

                [PSCustomObject]@{
                    Status = 'Resolved'
                    ResolutionType = 'Application'
                    PrimaryObject = [PSCustomObject]@{
                        ObjectType = 'Application'
                        Identifiers = [PSCustomObject]@{ ObjectId = 'app-1'; AppId = 'client-1' }
                    }
                    DirectMatches = @(
                        [PSCustomObject]@{
                            ObjectType = 'Application'
                            Identifiers = [PSCustomObject]@{ ObjectId = 'app-1'; AppId = 'client-1' }
                        }
                    )
                    RelatedObjects = @()
                    Relationships = @()
                    Evidence = @()
                    Limitations = @()
                }
            }

            Mock Get-InspectorSnapshotRelationships {
                if (-not $script:snapshotBuilt) {
                    throw 'Relationship building ran before snapshot collection.'
                }

                [PSCustomObject]@{
                    Status = 'Success'
                    Completeness = 'Complete'
                    CollectorResults = @()
                    Relationships = @()
                    Artifacts = @()
                    Evidence = @()
                    Limitations = @()
                }
            }

            Mock Add-InspectorPermissionIntelligence { $ObjectInsight }
            Mock Invoke-InspectorRules { @() }
            Mock Invoke-InspectorObservationEngine {
                [PSCustomObject]@{ Observations = @() }
            }

            Mock Invoke-MgGraphRequest {
                throw 'Tenant inspection must not call Graph directly.'
            }
            Mock Connect-MgGraph {
                throw 'Tenant inspection must not authenticate after snapshot collection.'
            }
        }

        It 'builds a tenant snapshot first and returns tenant inspection metadata' {
            $checkpointPath = Join-Path $TestDrive 'tenant-resume.json'
            $checkpointState = New-InspectorCheckpointState
            Add-InspectorCheckpointObject -State $checkpointState -ObjectKey 'Application:app-1'
            Write-InspectorCheckpointState -Path $checkpointPath -State $checkpointState

            $result =
                Invoke-EntraTenantInspection `
                    -ObjectType @('Application') `
                    -MaxObjectsPerType 1 `
                    -BatchSize 1 `
                    -CheckpointPath $checkpointPath `
                    -Resume `
                    -NoProgress

            $result.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.TenantInspectionResult'
            $result.Status | Should -Be 'Success'
            $result.SnapshotMode | Should -Be 'InMemory'
            $result.SnapshotSchemaVersion | Should -Be '1.0.0'
            $result.SnapshotId | Should -Be 'snapshot-1'
            $result.GraphCallsAfterSnapshot | Should -Be 0
            $result.GraphRequestsAtSnapshotCompletion | Should -Be 1
            $result.GraphRequestsAtInspectionCompletion | Should -Be 1
            $result.RuntimeTelemetry.GraphCallsAfterSnapshot | Should -Be 0
            $result.Summary.DiscoveredCount | Should -Be 1
            $result.Summary.ProcessedCount | Should -Be 1
            $result.Summary.ObjectInsightCount | Should -Be 1
            $result.Summary.SkippedCount | Should -Be 0
            $result.Summary.ResumeReplayCount | Should -Be 1
            $result.Pipeline.Resume | Should -BeTrue
            $result.Pipeline.ResumeReplayCount | Should -Be 1
            $result.Limitations -join ' ' | Should -Match 'replayed from the current snapshot'
            $result.RuntimeTelemetry | Should -Not -BeNullOrEmpty

            Should -Invoke New-InspectorTenantSnapshot -Times 1 -Exactly
            Should -Invoke ConvertFrom-InspectorTenantSnapshot -Times 1 -Exactly
            Should -Invoke Resolve-EntraObjectFromSnapshot -Times 1 -Exactly
            Should -Invoke Get-InspectorSnapshotRelationships -Times 1 -Exactly
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
            Should -Invoke Connect-MgGraph -Times 0 -Exactly
        }

        It 'measures an actual central Graph request after the snapshot boundary instead of hard-coding zero' {
            Mock Get-MgContext {
                [PSCustomObject]@{ AuthType = 'AppOnly' }
            }
            Mock Invoke-MgGraphRequest {
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
                $response.Content = [System.Net.Http.StringContent]::new('{"id":"post-snapshot"}')
                $response
            }
            Mock Stop-InspectorTelemetryStage {
                if ($Name -eq 'OfflineResolution') {
                    Invoke-InspectorGraphRequest `
                        -Uri 'https://graph.microsoft.com/v1.0/users/post-snapshot' `
                        -RequiredPermission 'User.Read.All' |
                        Out-Null
                }
            }

            $result =
                Invoke-EntraTenantInspection `
                    -ObjectType @('Application') `
                    -MaxObjectsPerType 1 `
                    -BatchSize 1 `
                    -NoProgress

            $result.GraphRequestsAtSnapshotCompletion | Should -Be 1
            $result.GraphRequestsAtInspectionCompletion | Should -Be 2
            $result.GraphCallsAfterSnapshot | Should -Be 1
            $result.RuntimeTelemetry.GraphCallsAfterSnapshot | Should -Be 1
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
        }

        It 'propagates partial status from offline object processing failures' {
            Mock ConvertFrom-InspectorTenantSnapshot {
                [PSCustomObject]@{
                    Status = 'Success'
                    TotalCount = 2
                    DiscoveredObjects = @(
                        [PSCustomObject]@{
                            ObjectType = 'Application'
                            ObjectId = 'app-1'
                            InspectionIdentity = 'app-1'
                            ObjectKey = 'Application:app-1'
                        },
                        [PSCustomObject]@{
                            ObjectType = 'Application'
                            ObjectId = 'app-2'
                            InspectionIdentity = 'app-2'
                            ObjectKey = 'Application:app-2'
                        }
                    )
                    Evidence = @()
                    Limitations = @()
                    Logs = @()
                }
            }

            $script:app2Attempts = 0
            Mock Resolve-EntraObjectFromSnapshot {
                if ($Identity -eq 'app-2') {
                    $script:app2Attempts++
                    throw 'offline failure'
                }

                [PSCustomObject]@{
                    Status = 'Resolved'
                    ResolutionType = 'Application'
                    PrimaryObject = [PSCustomObject]@{
                        ObjectType = 'Application'
                        Identifiers = [PSCustomObject]@{ ObjectId = 'app-1'; AppId = 'client-1' }
                    }
                    DirectMatches = @()
                    RelatedObjects = @()
                    Relationships = @()
                    Evidence = @()
                    Limitations = @()
                }
            }

            $result =
                Invoke-EntraTenantInspection `
                    -ObjectType @('Application') `
                    -BatchSize 1 `
                    -MaxRetryCount 1 `
                    -NoProgress

            $result.Status | Should -Be 'Partial'
            $result.Summary.FailedCount | Should -Be 1
            $result.Pipeline.RetryAttemptCount | Should -Be 1
            $result.FailedObjects[0].Attempts | Should -Be 2
            $script:app2Attempts | Should -Be 2
            $result.GraphCallsAfterSnapshot | Should -Be 0
            Should -Invoke Resolve-EntraObjectFromSnapshot -Times 3 -Exactly
        }
    }
}
