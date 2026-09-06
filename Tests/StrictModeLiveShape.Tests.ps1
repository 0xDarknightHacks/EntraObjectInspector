$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'StrictMode live-shape regression coverage' {

    InModuleScope EntraObjectInspector {

        It 'rule relationship filtering ignores non-relationship or partial-shape objects' {
            $objectInsight = [PSCustomObject]@{
                SourceObjects = @(
                    [PSCustomObject]@{
                        ObjectType = 'Application'
                        ObjectId = 'app-1'
                        Properties = [PSCustomObject]@{
                            DisplayName = 'Application One'
                        }
                    }
                )
                Relationships = @(
                    [PSCustomObject]@{
                        RelationshipType = 'OwnedBy'
                        SourceObjectId = 'app-1'
                        TargetObjectId = 'owner-1'
                        TargetObjectType = 'User'
                        TargetDisplayName = 'Owner One'
                        EvidenceId = 'ev-owner'
                    },
                    [PSCustomObject]@{
                        RelationshipType = 'PartialShapeWithoutSourceObjectId'
                        EvidenceId = 'ev-partial'
                    }
                )
                Artifacts = @()
                PermissionInsights = @()
                ApplicationIdentity = $null
            }

            {
                $results = Invoke-InspectorRules -ObjectInsight $objectInsight
                $results.RuleId | Should -Contain 'APP-OWNER-002'
            } | Should -Not -Throw
        }

        It 'observation relationship filtering ignores non-relationship or partial-shape objects' {
            $objectInsight = [PSCustomObject]@{
                Input = 'app-1'
                SourceObjects = @(
                    [PSCustomObject]@{
                        ObjectType = 'Application'
                        ObjectId = 'app-1'
                        Properties = [PSCustomObject]@{
                            DisplayName = 'Application One'
                        }
                    }
                )
                Relationships = @(
                    [PSCustomObject]@{
                        RelationshipType = 'OwnedBy'
                        SourceObjectId = 'app-1'
                        TargetObjectId = 'owner-1'
                        TargetObjectType = 'User'
                        TargetDisplayName = 'Owner One'
                        EvidenceId = 'ev-owner'
                    },
                    [PSCustomObject]@{
                        RelationshipType = 'PartialShapeWithoutSourceObjectId'
                        EvidenceId = 'ev-partial'
                    }
                )
                Artifacts = @()
                PermissionInsights = @()
                RuleResults = @()
                ApplicationIdentity = $null
            }

            {
                $result = Invoke-InspectorObservationEngine -ObjectInsight $objectInsight
                $result.GraphCallsIssued | Should -Be 0
                $result.Observations.Title | Should -Contain 'Application has a single owner'
            } | Should -Not -Throw
        }
    }
}
