$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Get-EntraObjectInsight' {

    InModuleScope EntraObjectInspector {

        It 'reports Disconnected when no Graph context exists' {
            Mock Get-MgContext { $null }

            $result = Get-EntraObjectInsight

            $result.SchemaVersion | Should -Be '0.7.0'
            $result.Status | Should -Be 'Disconnected'
            $result.ReadOnly | Should -BeTrue
        }

        It 'reports Ready for AppOnly authentication' {
            Mock Get-MgContext {
                [PSCustomObject]@{
                    AuthType = 'AppOnly'
                    TenantId = '11111111-1111-1111-1111-111111111111'
                    ClientId = '22222222-2222-2222-2222-222222222222'
                }
            }

            $result = Get-EntraObjectInsight

            $result.SchemaVersion | Should -Be '0.7.0'
            $result.Status | Should -Be 'Ready'
        }

        It 'returns normalized ObjectInsight with Security observations and rule results' {
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
                Relationships = @(
                    [PSCustomObject]@{
                        RelationshipType = 'GrantedAppRole'
                        SourceObjectId = 'sp-1'
                        SourceObjectType = 'ServicePrincipal'
                        TargetObjectId = 'graph-sp'
                        TargetDisplayName = 'Microsoft Graph'
                        EvidenceId = 'ev-permission'
                        Metadata = [PSCustomObject]@{
                            AppRoleId = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'
                        }
                    }
                )
                Artifacts = @()
                Evidence = @()
                Limitations = @()
            }

            Mock Resolve-EntraObject { $resolution }
            Mock Invoke-InspectorRelationshipCollection { $collection }

            $result = Get-EntraObjectInsight -Identity 'app-id'

            $result.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.ObjectInsight'
            $result.Status | Should -Be 'Resolved'
            $result.RelationshipCollection.Status | Should -Be 'Success'
            $result.PermissionIntelligence.GraphCallsIssued | Should -Be 0
            $result.PermissionInsights.Count | Should -Be 1
            $result.PermissionInsights[0].PermissionName | Should -Be 'Directory.ReadWrite.All'
            $result.RuleResults.RuleId | Should -Contain 'PERM-GRAPH-HIGH-001'
            $result.ObservationEngine.GraphCallsIssued | Should -Be 0
            $result.SecurityObservations.Count | Should -BeGreaterThan 0
            $result.Findings.Count | Should -Be $result.RuleResults.Count
            $result.Summary.FindingCount | Should -Be $result.RuleResults.Count
            $result.Summary.PermissionInsightCount | Should -Be 1
            $result.Summary.SecurityObservationCount | Should -Be $result.SecurityObservations.Count

            Should-Invoke Resolve-EntraObject -Times 1 -Exactly
            Should-Invoke Invoke-InspectorRelationshipCollection -Times 1 -Exactly
        }
    }
}

