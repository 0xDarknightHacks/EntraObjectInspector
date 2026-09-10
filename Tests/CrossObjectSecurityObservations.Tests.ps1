$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Cross-object security observations' {
    InModuleScope EntraObjectInspector {
        BeforeAll {
            function New-CrossSourceObject {
                param (
                    [string]$ObjectType,
                    [string]$ObjectId,
                    [hashtable]$Properties = @{}
                )

                [PSCustomObject]@{
                    ObjectType = $ObjectType
                    ObjectId = $ObjectId
                    Properties = [PSCustomObject]$Properties
                }
            }

            function New-CrossRelationship {
                param (
                    [string]$RelationshipType,
                    [string]$SourceObjectId,
                    [string]$SourceObjectType,
                    [string]$TargetObjectId,
                    [string]$TargetObjectType,
                    [string]$EvidenceId,
                    [hashtable]$Metadata = @{}
                )

                [PSCustomObject]@{
                    RelationshipType = $RelationshipType
                    SourceObjectId = $SourceObjectId
                    SourceObjectType = $SourceObjectType
                    TargetObjectId = $TargetObjectId
                    TargetObjectType = $TargetObjectType
                    TargetDisplayName = $TargetObjectId
                    EvidenceId = $EvidenceId
                    Metadata = [PSCustomObject]$Metadata
                }
            }

            function New-CrossRiskArtifact {
                param (
                    [string]$UserId,
                    [string]$RiskLevel = 'high',
                    [string]$RiskState = 'atRisk',
                    [string]$EvidenceId = 'ev-risk'
                )

                [PSCustomObject]@{
                    ArtifactType = 'RiskyUserContext'
                    SourceObjectType = 'User'
                    SourceObjectId = $UserId
                    RiskLevel = $RiskLevel
                    RiskState = $RiskState
                    EvidenceId = $EvidenceId
                }
            }

            function New-CrossInsight {
                param (
                    [object[]]$SourceObjects = @(),
                    [object[]]$Relationships = @(),
                    [object[]]$PermissionInsights = @(),
                    [object[]]$Artifacts = @(),
                    [object]$ApplicationIdentity = $null
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.ObjectInsight'
                    SourceObjects = @($SourceObjects)
                    Relationships = @($Relationships)
                    PermissionInsights = @($PermissionInsights)
                    Artifacts = @($Artifacts)
                    ApplicationIdentity = $ApplicationIdentity
                }
            }

            function Get-CrossObservation {
                param ([object[]]$Observations, [string]$Title)
                @($Observations | Where-Object Title -eq $Title)[0]
            }
        }

        BeforeEach {
            Mock Invoke-InspectorGraphRequest { throw 'Cross-object correlation must remain offline.' }
        }

        It 'correlates user ownership with a privileged application identity' {
            $app = New-CrossSourceObject -ObjectType 'Application' -ObjectId 'app-1' -Properties @{ DisplayName='Privileged App'; AppId='client-1' }
            $sp = New-CrossSourceObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1' -Properties @{ DisplayName='Privileged SP'; AppId='client-1' }
            $owner = New-CrossSourceObject -ObjectType 'User' -ObjectId 'user-1' -Properties @{ DisplayName='App Owner'; UserPrincipalName='owner@contoso.com' }
            $ownership = New-CrossRelationship -RelationshipType 'OwnedBy' -SourceObjectId 'app-1' -SourceObjectType 'Application' -TargetObjectId 'user-1' -TargetObjectType 'User' -EvidenceId 'ev-owner' -Metadata @{ EvidenceIds=@('ev-owner','ev-owner-reconciled') }
            $permission = [PSCustomObject]@{ SourceObjectId='sp-1'; AppRoleId='role-1'; PermissionName='RoleManagement.ReadWrite.Directory'; ResourceDisplayName='Microsoft Graph'; ResourceAppId='00000003-0000-0000-c000-000000000000'; IsHighImpact=$true; RelationshipEvidenceId='ev-perm' }
            $identity = [PSCustomObject]@{ ApplicationObjectId='app-1'; ServicePrincipalObjectId='sp-1' }
            $insight = New-CrossInsight -SourceObjects @($app,$sp,$owner) -Relationships @($ownership) -PermissionInsights @($permission) -ApplicationIdentity $identity

            $observations = @(Get-InspectorCrossObjectSecurityObservations -ObjectInsights @($insight))
            $observation = Get-CrossObservation -Observations $observations -Title 'Privileged application identity has user owner'

            $observation | Should -Not -BeNullOrEmpty
            $observation.Severity | Should -Be 'Low'
            $observation.Metadata.RelatedPrincipalId | Should -Be 'user-1'
            $observation.Metadata.RelatedServicePrincipalId | Should -Be 'sp-1'
            @($observation.EvidenceIds) | Should -Contain 'ev-owner-reconciled'
            @($observation.EvidenceIds) | Should -Contain 'ev-perm'
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'raises risky ownership when the privileged application owner has current unresolved risk' {
            $app = New-CrossSourceObject -ObjectType 'Application' -ObjectId 'app-risk' -Properties @{ DisplayName='Risk-Owned App'; AppId='client-risk' }
            $sp = New-CrossSourceObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-risk' -Properties @{ DisplayName='Risk-Owned SP'; AppId='client-risk' }
            $owner = New-CrossSourceObject -ObjectType 'User' -ObjectId 'user-risk-owner' -Properties @{ DisplayName='Risky Owner' }
            $ownership = New-CrossRelationship -RelationshipType 'OwnedBy' -SourceObjectId 'app-risk' -SourceObjectType 'Application' -TargetObjectId 'user-risk-owner' -TargetObjectType 'User' -EvidenceId 'ev-risk-owner'
            $permission = [PSCustomObject]@{ SourceObjectId='sp-risk'; AppRoleId='role-risk'; PermissionName='AppRoleAssignment.ReadWrite.All'; ResourceDisplayName='Microsoft Graph'; ResourceAppId='00000003-0000-0000-c000-000000000000'; IsHighImpact=$true; RelationshipEvidenceId='ev-risk-perm' }
            $risk = New-CrossRiskArtifact -UserId 'user-risk-owner' -RiskLevel 'high' -EvidenceId 'ev-current-risk'
            $identity = [PSCustomObject]@{ ApplicationObjectId='app-risk'; ServicePrincipalObjectId='sp-risk' }
            $insight = New-CrossInsight -SourceObjects @($app,$sp,$owner) -Relationships @($ownership) -PermissionInsights @($permission) -Artifacts @($risk) -ApplicationIdentity $identity

            $observations = @(Get-InspectorCrossObjectSecurityObservations -ObjectInsights @($insight))
            $observation = Get-CrossObservation -Observations $observations -Title 'Risky user owns privileged application identity'

            $observation | Should -Not -BeNullOrEmpty
            $observation.Severity | Should -Be 'High'
            $observation.AffectedObject.ObjectId | Should -Be 'user-risk-owner'
            @($observation.EvidenceIds) | Should -Contain 'ev-current-risk'
            @($observation.EvidenceIds) | Should -Contain 'ev-risk-perm'
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'correlates risky group membership with active directory privilege' {
            $user = New-CrossSourceObject -ObjectType 'User' -ObjectId 'user-active-group' -Properties @{ DisplayName='Risky Member' }
            $group = New-CrossSourceObject -ObjectType 'Group' -ObjectId 'group-active' -Properties @{ DisplayName='Active Privileged Group' }
            $membership = New-CrossRelationship -RelationshipType 'MemberOfGroup' -SourceObjectId 'user-active-group' -SourceObjectType 'User' -TargetObjectId 'group-active' -TargetObjectType 'Group' -EvidenceId 'ev-membership' -Metadata @{ EvidenceIds=@('ev-membership','ev-membership-reconciled') }
            $role = New-CrossRelationship -RelationshipType 'AssignedDirectoryRole' -SourceObjectId 'group-active' -SourceObjectType 'Group' -TargetObjectId 'role-active' -TargetObjectType 'DirectoryRoleDefinition' -EvidenceId 'ev-group-role' -Metadata @{ RoleDefinitionId='role-active'; RoleDisplayName='Privileged Role'; ScopeType='Tenant'; EvidenceIds=@('ev-group-role','ev-group-role-reconciled') }
            $risk = New-CrossRiskArtifact -UserId 'user-active-group' -RiskLevel 'high' -EvidenceId 'ev-risk-active-group'
            $insight = New-CrossInsight -SourceObjects @($user,$group) -Relationships @($membership,$role) -Artifacts @($risk)

            $observations = @(Get-InspectorCrossObjectSecurityObservations -ObjectInsights @($insight))
            $observation = Get-CrossObservation -Observations $observations -Title 'Risky user inherits active directory privilege through group'

            $observation | Should -Not -BeNullOrEmpty
            $observation.Severity | Should -Be 'High'
            $observation.Metadata.RelatedGroupId | Should -Be 'group-active'
            $observation.Metadata.PrivilegeState | Should -Be 'Active'
            @($observation.EvidenceIds) | Should -Contain 'ev-membership-reconciled'
            @($observation.EvidenceIds) | Should -Contain 'ev-group-role-reconciled'
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'keeps risky group-based PIM eligibility distinct from active privilege' {
            $user = New-CrossSourceObject -ObjectType 'User' -ObjectId 'user-eligible-group' -Properties @{ DisplayName='Eligible Risk Member' }
            $group = New-CrossSourceObject -ObjectType 'Group' -ObjectId 'group-eligible' -Properties @{ DisplayName='Eligible Privileged Group' }
            $membership = New-CrossRelationship -RelationshipType 'MemberOfGroup' -SourceObjectId 'user-eligible-group' -SourceObjectType 'User' -TargetObjectId 'group-eligible' -TargetObjectType 'Group' -EvidenceId 'ev-membership-eligible'
            $eligible = New-CrossRelationship -RelationshipType 'EligibleDirectoryRoleScheduleInstance' -SourceObjectId 'group-eligible' -SourceObjectType 'Group' -TargetObjectId 'role-eligible' -TargetObjectType 'DirectoryRoleDefinition' -EvidenceId 'ev-group-eligible' -Metadata @{ RoleDefinitionId='role-eligible'; RoleDisplayName='Privileged Role'; ScopeType='Tenant'; EvidenceIds=@('ev-group-eligible','ev-group-eligible-reconciled') }
            $risk = New-CrossRiskArtifact -UserId 'user-eligible-group' -RiskLevel 'high' -EvidenceId 'ev-risk-eligible-group'
            $insight = New-CrossInsight -SourceObjects @($user,$group) -Relationships @($membership,$eligible) -Artifacts @($risk)

            $observations = @(Get-InspectorCrossObjectSecurityObservations -ObjectInsights @($insight))
            $observation = Get-CrossObservation -Observations $observations -Title 'Risky user is eligible for directory privilege through group'

            $observation | Should -Not -BeNullOrEmpty
            $observation.Severity | Should -Be 'Medium'
            $observation.Metadata.PrivilegeState | Should -Be 'Eligible'
            @($observations | Where-Object Title -eq 'Risky user inherits active directory privilege through group').Count | Should -Be 0
            @($observation.EvidenceIds) | Should -Contain 'ev-group-eligible-reconciled'
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'correlates current user risk with ownership of a privileged group' {
            $user = New-CrossSourceObject -ObjectType 'User' -ObjectId 'user-group-owner' -Properties @{ DisplayName='Risky Group Owner' }
            $group = New-CrossSourceObject -ObjectType 'Group' -ObjectId 'group-owned' -Properties @{ DisplayName='Owned Privileged Group' }
            $ownership = New-CrossRelationship -RelationshipType 'OwnedBy' -SourceObjectId 'group-owned' -SourceObjectType 'Group' -TargetObjectId 'user-group-owner' -TargetObjectType 'User' -EvidenceId 'ev-group-owner' -Metadata @{ EvidenceIds=@('ev-group-owner','ev-group-owner-reconciled') }
            $role = New-CrossRelationship -RelationshipType 'AssignedDirectoryRole' -SourceObjectId 'group-owned' -SourceObjectType 'Group' -TargetObjectId 'role-owned' -TargetObjectType 'DirectoryRoleDefinition' -EvidenceId 'ev-owned-role' -Metadata @{ RoleDefinitionId='role-owned'; RoleDisplayName='Privileged Role'; ScopeType='Tenant'; EvidenceIds=@('ev-owned-role','ev-owned-role-reconciled') }
            $risk = New-CrossRiskArtifact -UserId 'user-group-owner' -RiskLevel 'high' -EvidenceId 'ev-risk-group-owner'
            $insight = New-CrossInsight -SourceObjects @($user,$group) -Relationships @($ownership,$role) -Artifacts @($risk)

            $observations = @(Get-InspectorCrossObjectSecurityObservations -ObjectInsights @($insight))
            $observation = Get-CrossObservation -Observations $observations -Title 'Risky user owns privileged group'

            $observation | Should -Not -BeNullOrEmpty
            $observation.Severity | Should -Be 'High'
            $observation.Metadata.PrivilegeState | Should -Be 'Active'
            @($observation.EvidenceIds) | Should -Contain 'ev-group-owner-reconciled'
            @($observation.EvidenceIds) | Should -Contain 'ev-owned-role-reconciled'
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }
    }
}
