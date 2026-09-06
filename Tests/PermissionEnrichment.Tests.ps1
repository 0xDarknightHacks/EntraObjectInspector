$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'permission intelligence enrichment' {

    InModuleScope EntraObjectInspector {

        It 'converts a GrantedAppRole relationship into a resolved permission insight' {
            $relationship = [PSCustomObject]@{
                RelationshipType = 'GrantedAppRole'
                SourceObjectId = 'client-sp'
                SourceObjectType = 'ServicePrincipal'
                TargetObjectId = 'graph-sp'
                TargetDisplayName = 'Microsoft Graph'
                EvidenceId = 'ev-graph-permission'
                Metadata = [PSCustomObject]@{
                    AppRoleId = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'
                }
            }

            $insight =
                ConvertTo-InspectorPermissionInsight `
                    -Relationship $relationship

            $insight.CatalogStatus | Should -Be 'Resolved'
            $insight.PermissionName | Should -Be 'Directory.ReadWrite.All'
            $insight.PermissionType | Should -Be 'Application'
            $insight.IsHighImpact | Should -BeTrue
            $insight.RelationshipEvidenceId | Should -Be 'ev-graph-permission'
        }

        It 'adds PermissionInsights and enriches relationship metadata without Graph calls' {
            Mock Invoke-InspectorGraphRequest {
                throw 'Permission intelligence must not call Graph.'
            }

            $objectInsight = [PSCustomObject]@{
                Relationships = @(
                    [PSCustomObject]@{
                        RelationshipType = 'GrantedAppRole'
                        SourceObjectId = 'client-sp'
                        SourceObjectType = 'ServicePrincipal'
                        TargetObjectId = 'graph-sp'
                        TargetDisplayName = 'Microsoft Graph'
                        EvidenceId = 'ev-graph-permission'
                        Metadata = [PSCustomObject]@{
                            AppRoleId = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'
                        }
                    }
                )
                Limitations = @()
                Summary = [PSCustomObject]@{}
            }

            $result =
                Add-InspectorPermissionIntelligence `
                    -ObjectInsight $objectInsight

            $result.PermissionIntelligence.GraphCallsIssued | Should -Be 0
            $result.PermissionInsights.Count | Should -Be 1
            $result.PermissionInsights[0].PermissionName | Should -Be 'Directory.ReadWrite.All'
            $result.Relationships[0].Metadata.PermissionName | Should -Be 'Directory.ReadWrite.All'
            $result.Summary.PermissionInsightCount | Should -Be 1

            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'keeps unresolved permissions visible as limitations instead of guessing' {
            $objectInsight = [PSCustomObject]@{
                Relationships = @(
                    [PSCustomObject]@{
                        RelationshipType = 'GrantedAppRole'
                        SourceObjectId = 'client-sp'
                        SourceObjectType = 'ServicePrincipal'
                        TargetObjectId = 'graph-sp'
                        TargetDisplayName = 'Microsoft Graph'
                        EvidenceId = 'ev-unknown-permission'
                        Metadata = [PSCustomObject]@{
                            AppRoleId = '00000000-0000-0000-0000-000000000123'
                        }
                    }
                )
                Limitations = @()
                Summary = [PSCustomObject]@{}
            }

            $result =
                Add-InspectorPermissionIntelligence `
                    -ObjectInsight $objectInsight

            $result.PermissionInsights[0].CatalogStatus | Should -Be 'Unknown'
            $result.PermissionInsights[0].PermissionName | Should -BeNullOrEmpty
            $result.Limitations.Count | Should -BeGreaterThan 0
        }

        It 'allows the rule engine to classify enriched high-impact Graph permissions' {
            $objectInsight = [PSCustomObject]@{
                SourceObjects = @()
                Relationships = @(
                    [PSCustomObject]@{
                        RelationshipType = 'GrantedAppRole'
                        SourceObjectId = 'client-sp'
                        SourceObjectType = 'ServicePrincipal'
                        TargetObjectId = 'graph-sp'
                        TargetDisplayName = 'Microsoft Graph'
                        EvidenceId = 'ev-graph-permission'
                        Metadata = [PSCustomObject]@{
                            AppRoleId = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'
                        }
                    }
                )
                Artifacts = @()
                ApplicationIdentity = $null
                Limitations = @()
                Summary = [PSCustomObject]@{}
            }

            $objectInsight =
                Add-InspectorPermissionIntelligence `
                    -ObjectInsight $objectInsight

            $rules =
                Invoke-InspectorRules `
                    -ObjectInsight $objectInsight

            $highImpactRule =
                $rules |
                Where-Object { $_.RuleId -eq 'PERM-GRAPH-HIGH-001' }

            $highImpactRule | Should -Not -BeNullOrEmpty
            $highImpactRule.Metadata.PermissionName | Should -Be 'Directory.ReadWrite.All'
            $highImpactRule.Severity | Should -Be 'High'
        }
    }
}

