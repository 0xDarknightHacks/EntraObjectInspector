$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'ConvertTo-InspectorObjectInsight' {

    InModuleScope EntraObjectInspector {

        It 'combines resolution, relationship collection, artifacts, evidence, and limitations' {
            $app = [PSCustomObject]@{
                ObjectType = 'Application'
                Identifiers = [PSCustomObject]@{
                    ObjectId = 'app-object-id'
                    AppId = 'client-id'
                }
            }

            $sp = [PSCustomObject]@{
                ObjectType = 'ServicePrincipal'
                Identifiers = [PSCustomObject]@{
                    ObjectId = 'sp-object-id'
                    AppId = 'client-id'
                }
            }

            $resolution = [PSCustomObject]@{
                Input = 'client-id'
                NormalizedInput = 'client-id'
                InputShape = 'Guid'
                Status = 'Resolved'
                ResolutionType = 'ApplicationIdentity'
                PrimaryObject = $app
                DirectMatches = @($app, $sp)
                RelatedObjects = @()
                Relationships = @(
                    [PSCustomObject]@{
                        RelationshipType = 'ApplicationToServicePrincipal'
                        EvidenceId = 'resolution-evidence'
                    }
                )
                Evidence = @(
                    [PSCustomObject]@{ EvidenceId = 'resolution-evidence' }
                )
                Limitations = @('Resolution limitation')
            }

            $collection = [PSCustomObject]@{
                Status = 'Success'
                Completeness = 'Complete'
                CollectorResults = @(
                    [PSCustomObject]@{
                        CollectorName = 'ApplicationRelationships'
                        SourceObjectType = 'Application'
                        SourceObjectId = 'app-object-id'
                        Status = 'Success'
                        Properties = [PSCustomObject]@{
                            DisplayName = 'App'
                        }
                    }
                )
                Relationships = @(
                    [PSCustomObject]@{
                        RelationshipType = 'OwnedBy'
                        SourceObjectId = 'app-object-id'
                        EvidenceId = 'owner-evidence'
                    }
                )
                Artifacts = @(
                    [PSCustomObject]@{
                        ArtifactType = 'CredentialMetadata'
                        EvidenceId = 'credential-evidence'
                    }
                )
                Evidence = @(
                    [PSCustomObject]@{ EvidenceId = 'owner-evidence' }
                )
                Limitations = @('Collection limitation')
            }

            $insight =
                ConvertTo-InspectorObjectInsight `
                    -Resolution $resolution `
                    -RelationshipCollection $collection

            $insight.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.ObjectInsight'
            $insight.SchemaVersion | Should -Be '0.4.0'
            $insight.Status | Should -Be 'Resolved'
            $insight.ResolutionType | Should -Be 'ApplicationIdentity'
            $insight.ApplicationIdentity.AppId | Should -Be 'client-id'
            $insight.ApplicationIdentity.ApplicationObjectId | Should -Be 'app-object-id'
            $insight.ApplicationIdentity.ServicePrincipalObjectId | Should -Be 'sp-object-id'
            $insight.Relationships.Count | Should -Be 2
            $insight.Artifacts.Count | Should -Be 1
            $insight.Evidence.Count | Should -Be 2
            $insight.Limitations | Should -Contain 'Resolution limitation'
            $insight.Limitations | Should -Contain 'Collection limitation'
            $insight.RuleResults.Count | Should -Be 0
            $insight.Summary.RelationshipCount | Should -Be 2
        }
    }
}
