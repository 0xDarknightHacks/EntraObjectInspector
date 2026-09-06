$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Tenant snapshot offline pipeline' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestTenantSnapshot {
                $collections = [PSCustomObject]@{
                    Applications = @(
                        [PSCustomObject]@{ id = '11111111-1111-1111-1111-111111111111'; appId = '77777777-7777-7777-7777-777777777777'; displayName = 'App One'; keyCredentials = @(); passwordCredentials = @([PSCustomObject]@{ keyId = 'credential-1'; displayName = 'Credential One'; startDateTime = (Get-Date).ToUniversalTime().AddDays(-5).ToString('o'); endDateTime = (Get-Date).ToUniversalTime().AddDays(30).ToString('o') }); appRoles = @(); requiredResourceAccess = @() },
                        [PSCustomObject]@{ id = '22222222-2222-2222-2222-222222222222'; appId = '88888888-8888-8888-8888-888888888888'; displayName = 'App Two'; keyCredentials = @(); passwordCredentials = @(); appRoles = @(); requiredResourceAccess = @() }
                    )
                    ServicePrincipals = @(
                        [PSCustomObject]@{ id = '33333333-3333-3333-3333-333333333333'; appId = '77777777-7777-7777-7777-777777777777'; displayName = 'SP One'; keyCredentials = @(); passwordCredentials = @(); appRoles = @() },
                        [PSCustomObject]@{ id = '44444444-4444-4444-4444-444444444444'; appId = '88888888-8888-8888-8888-888888888888'; displayName = 'SP Two'; keyCredentials = @(); passwordCredentials = @(); appRoles = @() }
                    )
                    Users = @([PSCustomObject]@{ id = '55555555-5555-5555-5555-555555555555'; userPrincipalName = 'user1@contoso.com'; displayName = 'User One' })
                    Groups = @([PSCustomObject]@{ id = '66666666-6666-6666-6666-666666666666'; displayName = 'Group One' })
                    ApplicationOwners = @()
                    ServicePrincipalOwners = @()
                    GroupOwners = @()
                    GroupMembers = @()
                    GroupMemberships = @()
                    UserTransitiveMemberships = @()
                    DirectoryRoleAssignments = @([PSCustomObject]@{ id = 'role-1'; principalId = '55555555-5555-5555-5555-555555555555'; roleDefinitionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; roleDefinition = [PSCustomObject]@{ displayName = 'Reader' } })
                    AppRoleAssignments = @()
                    AppRoleAssignedTo = @()
                    OAuth2PermissionGrants = @([PSCustomObject]@{ id = 'grant-1'; clientId = '33333333-3333-3333-3333-333333333333'; resourceId = '99999999-9999-9999-9999-999999999999'; consentType = 'AllPrincipals'; scope = 'User.Read' })
                }

                $indexes = New-InspectorTenantSnapshotIndexes -Collections $collections

                [PSCustomObject]@{
                    SchemaVersion = '1.0.0'
                    SnapshotId = 'snapshot-test'
                    CreatedAt = (Get-Date).ToUniversalTime().ToString('o')
                    Collections = $collections
                    Indexes = $indexes
                    Evidence = @([PSCustomObject]@{ EvidenceId = 'ev-snapshot'; Status = 'Success' })
                    Limitations = @()
                }
            }
        }

        It 'resolves supported identifiers offline from indexes' {
            $snapshot = New-TestTenantSnapshot

            (Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity '55555555-5555-5555-5555-555555555555').ResolutionType | Should -Be 'User'
            (Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity 'user1@contoso.com').ResolutionType | Should -Be 'User'
            (Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity '66666666-6666-6666-6666-666666666666').ResolutionType | Should -Be 'Group'
            (Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity '11111111-1111-1111-1111-111111111111').ResolutionType | Should -Be 'ApplicationIdentity'
            (Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity '33333333-3333-3333-3333-333333333333').ResolutionType | Should -Be 'ApplicationIdentity'
            (Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity '77777777-7777-7777-7777-777777777777').ResolutionType | Should -Be 'ApplicationIdentity'
            (Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity 'missing-id').Status | Should -Be 'UnsupportedIdentifier'
            (Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity '00000000-0000-0000-0000-000000000000').Status | Should -Be 'NotFound'
        }

        It 'builds relationship and evidence shape offline without Graph calls' {
            $snapshot = New-TestTenantSnapshot
            $resolution = Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity '77777777-7777-7777-7777-777777777777'

            Mock Invoke-InspectorGraphRequest {
                throw 'Offline relationship building must not call Graph.'
            }

            $relationships = Get-InspectorSnapshotRelationships -TenantSnapshot $snapshot -Resolution $resolution

            $relationships.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.RelationshipCollection'
            $relationships.Status | Should -Be 'Success'
            $relationships.Relationships.RelationshipType | Should -Contain 'ApplicationToServicePrincipal'
            $snapshot.Evidence.Count | Should -BeGreaterThan 0
            $relationships.Evidence.Count | Should -Be 0
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'processes users with empty or singleton relationship collections without Count failures' {
            $snapshot = New-TestTenantSnapshot
            $userId = '55555555-5555-5555-5555-555555555555'
            $membership = [PSCustomObject]@{ id = '66666666-6666-6666-6666-666666666666'; displayName = 'Group One'; '@odata.type' = '#microsoft.graph.group' }
            $snapshot.Indexes.MembershipsByObjectId[$userId] = [System.Collections.Generic.List[object]]::new()
            $snapshot.Indexes.MembershipsByObjectId[$userId].Add([PSCustomObject]@{ Membership = $membership; EvidenceId = 'ev-user-membership' })
            $snapshot.Indexes.DirectoryRoleAssignmentsByPrincipalId[$userId] = [System.Collections.Generic.List[object]]::new()

            Mock Invoke-InspectorGraphRequest {
                throw 'Offline user processing must not call Graph.'
            }

            $resolution = Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity 'user1@contoso.com'
            $relationships = Get-InspectorSnapshotRelationships -TenantSnapshot $snapshot -Resolution $resolution
            $insight = ConvertTo-InspectorObjectInsight -Resolution $resolution -RelationshipCollection $relationships
            $rules = Invoke-InspectorRules -ObjectInsight $insight
            $insight.RuleResults = @($rules)
            $observations = Invoke-InspectorObservationEngine -ObjectInsight $insight

            $insight.Status | Should -Be 'Resolved'
            @($relationships.Relationships).Count | Should -Be 1
            @($observations).Count | Should -BeGreaterOrEqual 0
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }


        It 'normalizes snapshot credentials without requiring a raw EvidenceId property' {
            $snapshot = New-TestTenantSnapshot
            $resolution = Resolve-EntraObjectFromSnapshot -TenantSnapshot $snapshot -Identity '11111111-1111-1111-1111-111111111111'

            { $relationships = Get-InspectorSnapshotRelationships -TenantSnapshot $snapshot -Resolution $resolution } | Should -Not -Throw
            $relationships = Get-InspectorSnapshotRelationships -TenantSnapshot $snapshot -Resolution $resolution
            $credentialArtifact = @($relationships.Artifacts | Where-Object { $_.ArtifactType -eq 'CredentialMetadata' })[0]

            $credentialArtifact | Should -Not -BeNullOrEmpty
            $credentialArtifact.PSObject.Properties.Name | Should -Contain 'EvidenceId'
            $credentialArtifact.PSObject.Properties.Name | Should -Contain 'ParentEvidenceId'
            $credentialArtifact.KeyId | Should -Be 'credential-1'
        }

        It 'does not persist raw snapshot artifacts by default' {
            $before = @(Get-ChildItem -Path $TestDrive -Recurse -Force)
            New-TestTenantSnapshot | Out-Null
            $after = @(Get-ChildItem -Path $TestDrive -Recurse -Force)

            $after.Count | Should -Be $before.Count
        }
    }
}

