$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Invoke-InspectorRules' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestObjectInsight {
                param (
                    [object[]]$SourceObjects = @(),
                    [object[]]$Relationships = @(),
                    [object[]]$Artifacts = @(),
                    [object]$ApplicationIdentity = $null
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.ObjectInsight'
                    SourceObjects = @($SourceObjects)
                    Relationships = @($Relationships)
                    Artifacts = @($Artifacts)
                    ApplicationIdentity = $ApplicationIdentity
                }
            }
        }

        It 'flags application and service principal objects with no owner' {
            $insight = New-TestObjectInsight -SourceObjects @(
                [PSCustomObject]@{
                    ObjectType = 'Application'
                    ObjectId = 'app-1'
                    Properties = [PSCustomObject]@{
                        DisplayName = 'Ownerless App'
                    }
                }
            )

            $results = Invoke-InspectorRules -ObjectInsight $insight

            $results.RuleId | Should -Contain 'APP-OWNER-001'
            ($results | Where-Object RuleId -eq 'APP-OWNER-001').Severity |
                Should -Be 'High'
        }

        It 'flags application and service principal objects with exactly one owner' {
            $insight = New-TestObjectInsight `
                -SourceObjects @(
                    [PSCustomObject]@{
                        ObjectType = 'Application'
                        ObjectId = 'app-1'
                        Properties = [PSCustomObject]@{
                            DisplayName = 'Single Owner App'
                        }
                    }
                ) `
                -Relationships @(
                    [PSCustomObject]@{
                        RelationshipType = 'OwnedBy'
                        SourceObjectId = 'app-1'
                        TargetObjectId = 'owner-1'
                        EvidenceId = 'ev-owner'
                    }
                )

            $results = Invoke-InspectorRules -ObjectInsight $insight

            $rule = $results | Where-Object RuleId -eq 'APP-OWNER-002'

            $rule | Should -Not -BeNullOrEmpty
            $rule.Severity | Should -Be 'Medium'
            $rule.EvidenceIds | Should -Contain 'ev-owner'
        }

        It 'flags expiring and expired credentials' {
            $expiredDate = (Get-Date).ToUniversalTime().AddDays(-1)
            $expiringDate = (Get-Date).ToUniversalTime().AddDays(10)

            $insight = New-TestObjectInsight -Artifacts @(
                [PSCustomObject]@{
                    ArtifactType = 'CredentialMetadata'
                    CredentialType = 'Password'
                    SourceObjectType = 'Application'
                    SourceObjectId = 'app-1'
                    KeyId = 'expired-key'
                    DisplayName = 'expired'
                    EndDateTime = $expiredDate
                    EvidenceId = 'ev-expired'
                },
                [PSCustomObject]@{
                    ArtifactType = 'CredentialMetadata'
                    CredentialType = 'Certificate'
                    SourceObjectType = 'Application'
                    SourceObjectId = 'app-1'
                    KeyId = 'expiring-key'
                    DisplayName = 'expiring'
                    EndDateTime = $expiringDate
                    EvidenceId = 'ev-expiring'
                }
            )

            $results = Invoke-InspectorRules `
                -ObjectInsight $insight `
                -CredentialExpiryWarningDays 30

            $results.RuleId | Should -Contain 'CRED-001'
            $results.RuleId | Should -Contain 'CRED-002'
        }

        It 'flags application permissions without classifying them as high impact by default' {
            $insight = New-TestObjectInsight -Relationships @(
                [PSCustomObject]@{
                    RelationshipType = 'GrantedAppRole'
                    SourceObjectId = 'sp-1'
                    TargetObjectId = 'graph-sp'
                    TargetDisplayName = 'Microsoft Graph'
                    EvidenceId = 'ev-perm'
                    Metadata = [PSCustomObject]@{
                        AppRoleId = 'role-id'
                    }
                }
            )

            $results = Invoke-InspectorRules -ObjectInsight $insight

            $results.RuleId | Should -Contain 'PERM-APP-001'
            $results.RuleId | Should -Not -Contain 'PERM-GRAPH-HIGH-001'
        }

        It 'flags high-impact Microsoft Graph permissions when permission name metadata exists' {
            $insight = New-TestObjectInsight -Relationships @(
                [PSCustomObject]@{
                    RelationshipType = 'GrantedAppRole'
                    SourceObjectId = 'sp-1'
                    TargetObjectId = 'graph-sp'
                    TargetDisplayName = 'Microsoft Graph'
                    EvidenceId = 'ev-high'
                    Metadata = [PSCustomObject]@{
                        AppRoleId = 'role-id'
                        PermissionName = 'Directory.ReadWrite.All'
                    }
                }
            )

            $results = Invoke-InspectorRules -ObjectInsight $insight

            $results.RuleId | Should -Contain 'PERM-GRAPH-HIGH-001'

            $rule = $results |
                Where-Object RuleId -eq 'PERM-GRAPH-HIGH-001'

            $rule.Severity | Should -Be 'High'
            $rule.Confidence | Should -Be 'Medium'
        }

        It 'flags application and service principal ownership mismatch' {
            $insight = New-TestObjectInsight `
                -ApplicationIdentity ([PSCustomObject]@{
                    AppId = 'client-id'
                    ApplicationObjectId = 'app-1'
                    ServicePrincipalObjectId = 'sp-1'
                }) `
                -Relationships @(
                    [PSCustomObject]@{
                        RelationshipType = 'OwnedBy'
                        SourceObjectId = 'app-1'
                        TargetObjectId = 'owner-a'
                        EvidenceId = 'ev-app-owner'
                    },
                    [PSCustomObject]@{
                        RelationshipType = 'OwnedBy'
                        SourceObjectId = 'sp-1'
                        TargetObjectId = 'owner-b'
                        EvidenceId = 'ev-sp-owner'
                    }
                )

            $results = Invoke-InspectorRules -ObjectInsight $insight

            $rule = $results |
                Where-Object RuleId -eq 'APP-OWNERSHIP-001'

            $rule | Should -Not -BeNullOrEmpty
            $rule.Severity | Should -Be 'Low'
            $rule.EvidenceIds | Should -Contain 'ev-app-owner'
            $rule.EvidenceIds | Should -Contain 'ev-sp-owner'
        }

        It 'adds service principal state observations' {
            $insight = New-TestObjectInsight -SourceObjects @(
                [PSCustomObject]@{
                    ObjectType = 'ServicePrincipal'
                    ObjectId = 'sp-1'
                    Properties = [PSCustomObject]@{
                        DisplayName = 'SP'
                        AccountEnabled = $false
                        AppRoleAssignmentRequired = $true
                    }
                }
            )

            $results = Invoke-InspectorRules -ObjectInsight $insight

            $results.RuleId | Should -Contain 'SP-STATE-001'
            $results.RuleId | Should -Contain 'SP-STATE-002'

            ($results | Where-Object RuleId -eq 'SP-STATE-001').Severity |
                Should -Be 'Informational'
        }

        It 'returns every rule result with the required contract fields' {
            $insight = New-TestObjectInsight -SourceObjects @(
                [PSCustomObject]@{
                    ObjectType = 'Application'
                    ObjectId = 'app-1'
                    Properties = [PSCustomObject]@{
                        DisplayName = 'Ownerless App'
                    }
                }
            )

            $result =
                Invoke-InspectorRules -ObjectInsight $insight |
                Select-Object -First 1

            $result.PSObject.Properties.Name | Should -Contain 'RuleId'
            $result.PSObject.Properties.Name | Should -Contain 'Title'
            $result.PSObject.Properties.Name | Should -Contain 'Severity'
            $result.PSObject.Properties.Name | Should -Contain 'EvidenceIds'
            $result.PSObject.Properties.Name | Should -Contain 'Source'
            $result.PSObject.Properties.Name | Should -Contain 'Confidence'
            $result.PSObject.Properties.Name | Should -Contain 'Limitations'
        }
    }
}
