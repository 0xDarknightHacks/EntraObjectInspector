$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'observation integration' {

    InModuleScope EntraObjectInspector {

        It 'adds SecurityObservations to Get-EntraObjectInsight output' {
            $resolution = [PSCustomObject]@{
                Input = 'app-id'
                NormalizedInput = 'app-id'
                InputShape = 'Guid'
                Status = 'Resolved'
                ResolutionType = 'Application'
                PrimaryObject = [PSCustomObject]@{
                    ObjectType = 'Application'
                    Identifiers = [PSCustomObject]@{
                        ObjectId = 'app-1'
                        AppId = 'client-id'
                    }
                }
                DirectMatches = @(
                    [PSCustomObject]@{
                        ObjectType = 'Application'
                        Identifiers = [PSCustomObject]@{
                            ObjectId = 'app-1'
                            AppId = 'client-id'
                        }
                    }
                )
                RelatedObjects = @()
                Relationships = @()
                Evidence = @()
                Limitations = @()
            }

            $collection = [PSCustomObject]@{
                Status = 'Success'
                Completeness = 'Complete'
                CollectorResults = @(
                    [PSCustomObject]@{
                        CollectorName = 'ApplicationRelationships'
                        SourceObjectType = 'Application'
                        SourceObjectId = 'app-1'
                        Status = 'Success'
                        Properties = [PSCustomObject]@{
                            DisplayName = 'App'
                        }
                    }
                )
                Relationships = @()
                Artifacts = @()
                Evidence = @()
                Limitations = @()
            }

            Mock Resolve-EntraObject { $resolution }
            Mock Invoke-InspectorRelationshipCollection { $collection }

            $result = Get-EntraObjectInsight -Identity 'app-id'

            $result.ObservationEngine.GraphCallsIssued | Should -Be 0
            $result.SecurityObservations.Count | Should -BeGreaterThan 0
            $result.Summary.SecurityObservationCount | Should -Be $result.SecurityObservations.Count
        }

        It 'aggregates SecurityObservations in tenant inspection output' {
            Mock New-InspectorTenantSnapshot {
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
                            ObjectId = '11111111-1111-1111-1111-111111111111'
                            InspectionIdentity = '11111111-1111-1111-1111-111111111111'
                            ObjectKey = 'Application:11111111-1111-1111-1111-111111111111'
                        }
                    )
                    Evidence = @()
                    Limitations = @()
                    Logs = @()
                }
            }

            Mock Resolve-EntraObjectFromSnapshot {
                [PSCustomObject]@{
                    Status = 'Resolved'
                    ResolutionType = 'Application'
                    PrimaryObject = [PSCustomObject]@{
                        ObjectType = 'Application'
                        Identifiers = [PSCustomObject]@{
                            ObjectId = '11111111-1111-1111-1111-111111111111'
                            AppId = '22222222-2222-2222-2222-222222222222'
                        }
                    }
                    DirectMatches = @(
                        [PSCustomObject]@{
                            ObjectType = 'Application'
                            Identifiers = [PSCustomObject]@{
                                ObjectId = '11111111-1111-1111-1111-111111111111'
                                AppId = '22222222-2222-2222-2222-222222222222'
                            }
                        }
                    )
                    RelatedObjects = @()
                    Relationships = @()
                    Evidence = @()
                    Limitations = @()
                }
            }

            Mock Get-InspectorSnapshotRelationships {
                [PSCustomObject]@{
                    Status = 'Success'
                    Completeness = 'Complete'
                    CollectorResults = @(
                        [PSCustomObject]@{
                            CollectorName = 'ApplicationRelationships'
                            SourceObjectType = 'Application'
                            SourceObjectId = '11111111-1111-1111-1111-111111111111'
                            Status = 'Success'
                            Properties = [PSCustomObject]@{
                                DisplayName = 'App'
                            }
                        }
                    )
                    Relationships = @()
                    Artifacts = @()
                    Evidence = @()
                    Limitations = @()
                }
            }

            Mock Invoke-InspectorObservationEngine {
                [PSCustomObject]@{
                    Observations = @(
                        [PSCustomObject]@{
                            ObservationId = 'OBS-1'
                            Title = 'Observation'
                        }
                    )
                }
            }

            Mock Invoke-InspectorGraphRequest {
                throw 'Tenant inspection must not call Graph after snapshot collection.'
            }

            Mock Invoke-MgGraphRequest {
                throw 'Tenant inspection must not call Graph directly.'
            }

            Mock Add-InspectorPermissionIntelligence { $ObjectInsight }
            Mock Invoke-InspectorRules { @() }

            $result =
                Invoke-EntraTenantInspection `
                    -ObjectType Application `
                    -NoProgress

            $result.SchemaVersion | Should -Be '0.7.0'
            $result.SecurityObservations.Count | Should -Be 1
            $result.Summary.SecurityObservationCount | Should -Be 1
        }
    }
}

