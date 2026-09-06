$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'relationship collectors' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-RelationshipCollectorGraphResult {
                param(
                    [string]$Uri,
                    [string]$RequiredPermission,
                    [string]$Status = 'Success',
                    [object[]]$ObservedValue = @(),
                    [string[]]$Limitations = @()
                )

                [PSCustomObject]@{
                    SourceEndpoint     = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime     = '2026-08-29T21:00:00.0000000Z'
                    Status             = $Status
                    ObservedValue      = $ObservedValue
                    Limitations        = $Limitations
                }
            }

            function New-RelationshipCollectorCandidate {
                param(
                    [string]$ObjectType,
                    [string]$ObjectId,
                    [string]$AppId = $null
                )

                $ids = [ordered]@{
                    ObjectId = $ObjectId
                }

                if ($null -ne $AppId) {
                    $ids.AppId = $AppId
                }

                [PSCustomObject]@{
                    ObjectType  = $ObjectType
                    DisplayName = "$ObjectType Test"
                    Identifiers = [PSCustomObject]$ids
                    MatchBasis  = @('ObjectId')
                    IsDirectMatch = $true
                }
            }
        }

        BeforeEach {
            $script:relationshipCollectorHandler = $null

            Mock Invoke-InspectorGraphRequest {
                param($Uri, $RequiredPermission)

                if ($null -ne $script:relationshipCollectorHandler) {
                    return & $script:relationshipCollectorHandler $Uri $RequiredPermission
                }

                return New-RelationshipCollectorGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $RequiredPermission `
                    -Status 'Success' `
                    -ObservedValue @()
            }
        }

        It 'returns NotApplicable when the application collector receives a User' {
            $candidate = New-RelationshipCollectorCandidate `
                -ObjectType 'User' `
                -ObjectId '11111111-1111-1111-1111-111111111111'

            $result = Get-InspectorApplicationRelationships -Candidate $candidate

            $result.Status | Should -Be 'NotApplicable'
            $result.Evidence[0].Status | Should -Be 'NotApplicable'
            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'collects application owners, credentials, app roles, requested access, and counterpart' {
            $appObjectId = '11111111-1111-1111-1111-111111111111'
            $appId = '22222222-2222-2222-2222-222222222222'
            $spId = '33333333-3333-3333-3333-333333333333'
            $ownerId = '44444444-4444-4444-4444-444444444444'

            $candidate = New-RelationshipCollectorCandidate `
                -ObjectType 'Application' `
                -ObjectId $appObjectId `
                -AppId $appId

            $script:relationshipCollectorHandler = {
                param($Uri, $Permission)

                if ($Uri -eq "https://graph.microsoft.com/v1.0/applications/$appObjectId") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = $appObjectId
                            appId = $appId
                            displayName = 'Test App'
                            signInAudience = 'AzureADMyOrg'
                            publisherDomain = 'contoso.com'
                            verifiedPublisher = [PSCustomObject]@{ displayName = 'Contoso' }
                            appRoles = @([PSCustomObject]@{ id = 'role-1'; value = 'Reader' })
                            requiredResourceAccess = @([PSCustomObject]@{ resourceAppId = 'resource-app' })
                            keyCredentials = @(
                                [PSCustomObject]@{
                                    keyId = 'key-1'
                                    displayName = 'cert'
                                    startDateTime = '2026-01-01T00:00:00Z'
                                    endDateTime = '2027-01-01T00:00:00Z'
                                    type = 'AsymmetricX509Cert'
                                    usage = 'Verify'
                                }
                            )
                            passwordCredentials = @()
                        }
                    )
                }

                if ($Uri -like "*/applications/$appObjectId/owners*") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            '@odata.type' = '#microsoft.graph.user'
                            id = $ownerId
                            displayName = 'Owner One'
                        }
                    )
                }

                if ($Uri -like "*servicePrincipals(appId='$appId')*") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = $spId
                            appId = $appId
                            displayName = 'Test App Enterprise'
                            servicePrincipalType = 'Application'
                        }
                    )
                }

                return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission
            }

            $result = Get-InspectorApplicationRelationships -Candidate $candidate

            $result.Status | Should -Be 'Success'
            $result.Properties.AppId | Should -Be $appId
            $result.Artifacts.Count | Should -Be 1
            $result.Relationships.RelationshipType | Should -Contain 'OwnedBy'
            $result.Relationships.RelationshipType | Should -Contain 'ApplicationToServicePrincipal'
            $result.Properties.AppRoles.Count | Should -Be 1
            $result.Properties.RequiredResourceAccess.Count | Should -Be 1
        }

        It 'collects service principal app-role, consent, ownership, counterpart, and role relationships' {
            $spId = '11111111-1111-1111-1111-111111111111'
            $appId = '22222222-2222-2222-2222-222222222222'
            $appObjectId = '33333333-3333-3333-3333-333333333333'
            $resourceId = '44444444-4444-4444-4444-444444444444'
            $principalId = '55555555-5555-5555-5555-555555555555'
            $roleDefinitionId = '66666666-6666-6666-6666-666666666666'

            $candidate = New-RelationshipCollectorCandidate `
                -ObjectType 'ServicePrincipal' `
                -ObjectId $spId `
                -AppId $appId

            $script:relationshipCollectorHandler = {
                param($Uri, $Permission)

                if ($Uri -eq "https://graph.microsoft.com/v1.0/servicePrincipals/$spId") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = $spId
                            appId = $appId
                            displayName = 'SP'
                            accountEnabled = $true
                            appRoleAssignmentRequired = $true
                            servicePrincipalType = 'Application'
                            appRoles = @()
                            tags = @('WindowsAzureActiveDirectoryIntegratedApp')
                            keyCredentials = @()
                            passwordCredentials = @()
                        }
                    )
                }

                if ($Uri -like "*/servicePrincipals/$spId/owners*") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @()
                }

                if ($Uri -like "*applications(appId='$appId')*") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = $appObjectId
                            appId = $appId
                            displayName = 'App'
                        }
                    )
                }

                if ($Uri -like "*/servicePrincipals/$spId/appRoleAssignments") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'assignment-out'
                            appRoleId = 'app-role-id'
                            resourceId = $resourceId
                            resourceDisplayName = 'Microsoft Graph'
                        }
                    )
                }

                if ($Uri -like "*/servicePrincipals/$spId/appRoleAssignedTo") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'assignment-in'
                            appRoleId = 'role-in'
                            principalId = $principalId
                            principalType = 'User'
                            principalDisplayName = 'Assigned User'
                        }
                    )
                }

                if ($Uri -like '*oauth2PermissionGrants*') {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'grant-1'
                            clientId = $spId
                            resourceId = $resourceId
                            consentType = 'AllPrincipals'
                            principalId = $null
                            scope = 'User.Read'
                        }
                    )
                }

                if ($Uri -like '*roleManagement/directory/roleAssignments*') {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'role-assignment'
                            principalId = $spId
                            roleDefinitionId = $roleDefinitionId
                            directoryScopeId = '/'
                            roleDefinition = [PSCustomObject]@{
                                id = $roleDefinitionId
                                displayName = 'Directory Readers'
                            }
                        }
                    )
                }

                return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission
            }

            $result = Get-InspectorServicePrincipalRelationships -Candidate $candidate

            $result.Status | Should -Be 'Success'
            $result.Properties.AppRoleAssignmentRequired | Should -BeTrue
            $result.Relationships.RelationshipType | Should -Contain 'ServicePrincipalToApplication'
            $result.Relationships.RelationshipType | Should -Contain 'GrantedAppRole'
            $result.Relationships.RelationshipType | Should -Contain 'AssignedToAppRole'
            $result.Relationships.RelationshipType | Should -Contain 'DelegatedPermissionGrant'
            $result.Relationships.RelationshipType | Should -Contain 'AssignedDirectoryRole'
        }

        It 'marks the service principal collector InsufficientPermission when delegated grant access is denied' {
            $spId = '11111111-1111-1111-1111-111111111111'
            $candidate = New-RelationshipCollectorCandidate -ObjectType 'ServicePrincipal' -ObjectId $spId -AppId '22222222-2222-2222-2222-222222222222'

            $script:relationshipCollectorHandler = {
                param($Uri, $Permission)

                if ($Uri -eq "https://graph.microsoft.com/v1.0/servicePrincipals/$spId") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = $spId
                            appId = '22222222-2222-2222-2222-222222222222'
                            displayName = 'SP'
                            keyCredentials = @()
                            passwordCredentials = @()
                            appRoles = @()
                            tags = @()
                        }
                    )
                }

                if ($Uri -like '*oauth2PermissionGrants*') {
                    return New-RelationshipCollectorGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'InsufficientPermission' `
                        -Limitations @('Synthetic 403')
                }

                return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission
            }

            $result = Get-InspectorServicePrincipalRelationships -Candidate $candidate

            $result.Status | Should -Be 'InsufficientPermission'
            $result.Completeness | Should -Be 'Partial'
            $result.Limitations.Count | Should -BeGreaterThan 0
        }

        It 'collects user transitive memberships and direct directory-role assignments while documenting ownedObjects limitation' {
            $userId = '11111111-1111-1111-1111-111111111111'
            $groupId = '22222222-2222-2222-2222-222222222222'
            $roleDefinitionId = '33333333-3333-3333-3333-333333333333'

            $candidate = New-RelationshipCollectorCandidate -ObjectType 'User' -ObjectId $userId

            $script:relationshipCollectorHandler = {
                param($Uri, $Permission)

                if ($Uri -like "*/users/$userId/transitiveMemberOf*") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            '@odata.type' = '#microsoft.graph.group'
                            id = $groupId
                            displayName = 'Security Group'
                        }
                    )
                }

                if ($Uri -like '*roleManagement/directory/roleAssignments*') {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'assignment-1'
                            roleDefinitionId = $roleDefinitionId
                            directoryScopeId = '/'
                            roleDefinition = [PSCustomObject]@{
                                displayName = 'Global Reader'
                            }
                        }
                    )
                }

                return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission
            }

            $result = Get-InspectorUserRelationships -Candidate $candidate

            $result.Status | Should -Be 'Success'
            $result.Completeness | Should -Be 'Complete'
            $result.Relationships.RelationshipType | Should -Contain 'MemberOfGroup'
            $result.Relationships.RelationshipType | Should -Contain 'AssignedDirectoryRole'
            $result.Evidence.Status | Should -Contain 'NotApplicable'
            $result.Limitations.Count | Should -BeGreaterThan 0
        }

        It 'returns InsufficientPermission when user directory-role assignments cannot be read' {
            $userId = '11111111-1111-1111-1111-111111111111'
            $candidate = New-RelationshipCollectorCandidate -ObjectType 'User' -ObjectId $userId

            $script:relationshipCollectorHandler = {
                param($Uri, $Permission)

                if ($Uri -like '*roleManagement/directory/roleAssignments*') {
                    return New-RelationshipCollectorGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'InsufficientPermission'
                }

                return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission
            }

            $result = Get-InspectorUserRelationships -Candidate $candidate

            $result.Status | Should -Be 'InsufficientPermission'
        }

        It 'collects group owners, members, parent memberships, and directory-role assignments' {
            $groupId = '11111111-1111-1111-1111-111111111111'
            $ownerId = '22222222-2222-2222-2222-222222222222'
            $memberId = '33333333-3333-3333-3333-333333333333'
            $parentId = '44444444-4444-4444-4444-444444444444'
            $roleDefinitionId = '55555555-5555-5555-5555-555555555555'

            $candidate = New-RelationshipCollectorCandidate -ObjectType 'Group' -ObjectId $groupId

            $script:relationshipCollectorHandler = {
                param($Uri, $Permission)

                if ($Uri -eq "https://graph.microsoft.com/v1.0/groups/$groupId") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = $groupId
                            displayName = 'Role Group'
                            groupTypes = @()
                            securityEnabled = $true
                            mailEnabled = $false
                            isAssignableToRole = $true
                            visibility = 'Private'
                        }
                    )
                }

                if ($Uri -like "*/groups/$groupId/owners*") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            '@odata.type' = '#microsoft.graph.user'
                            id = $ownerId
                            displayName = 'Owner'
                        }
                    )
                }

                if ($Uri -like "*/groups/$groupId/members*") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            '@odata.type' = '#microsoft.graph.user'
                            id = $memberId
                            displayName = 'Member'
                        }
                    )
                }

                if ($Uri -like "*/groups/$groupId/memberOf*") {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            '@odata.type' = '#microsoft.graph.group'
                            id = $parentId
                            displayName = 'Parent Group'
                        }
                    )
                }

                if ($Uri -like '*roleManagement/directory/roleAssignments*') {
                    return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'role-assignment'
                            roleDefinitionId = $roleDefinitionId
                            directoryScopeId = '/'
                            roleDefinition = [PSCustomObject]@{
                                displayName = 'Privileged Role Administrator'
                            }
                        }
                    )
                }

                return New-RelationshipCollectorGraphResult -Uri $Uri -RequiredPermission $Permission
            }

            $result = Get-InspectorGroupRelationships -Candidate $candidate

            $result.Status | Should -Be 'Success'
            $result.Properties.IsAssignableToRole | Should -BeTrue
            $result.Relationships.RelationshipType | Should -Contain 'OwnedBy'
            $result.Relationships.RelationshipType | Should -Contain 'HasMember'
            $result.Relationships.RelationshipType | Should -Contain 'MemberOf'
            $result.Relationships.RelationshipType | Should -Contain 'AssignedDirectoryRole'
        }

        It 'preserves the common evidence envelope for collector queries' {
            $candidate = New-RelationshipCollectorCandidate `
                -ObjectType 'Group' `
                -ObjectId '11111111-1111-1111-1111-111111111111'

            $result = Get-InspectorGroupRelationships -Candidate $candidate

            $record = $result.Evidence[0]

            $record.EvidenceId | Should -Not -BeNullOrEmpty
            $record.CollectorName | Should -Be 'GroupRelationships'
            $record.QueryName | Should -Be 'GroupMetadata'
            $record.Endpoint | Should -Not -BeNullOrEmpty
            $record.RequiredPermission | Should -Be 'GroupMember.Read.All'
            $record.CollectionTime | Should -Not -BeNullOrEmpty
            $record.PSObject.Properties.Name | Should -Contain 'Status'
            $record.PSObject.Properties.Name | Should -Contain 'Result'
            $record.PSObject.Properties.Name | Should -Contain 'Limitations'
        }

        It 'maps object-specific relationship evidence to the inspected subject' {
            $objectId = '11111111-1111-1111-1111-111111111111'
            $candidate = New-RelationshipCollectorCandidate `
                -ObjectType 'Group' `
                -ObjectId $objectId

            $result = Get-InspectorGroupRelationships -Candidate $candidate
            $membersEvidence = $result.Evidence | Where-Object QueryName -eq 'GroupMembers' | Select-Object -First 1

            $membersEvidence.EvidenceScope | Should -Be 'ObjectRelationship'
            $membersEvidence.SubjectObjectType | Should -Be 'Group'
            $membersEvidence.SubjectObjectId | Should -Be $objectId
        }
    }
}

