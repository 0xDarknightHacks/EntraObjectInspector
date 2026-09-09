$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Tenant snapshot collection' {

    InModuleScope EntraObjectInspector {

        BeforeEach {
            Mock Get-MgContext {
                [PSCustomObject]@{
                    TenantId = 'tenant-1'
                    ClientId = 'client-1'
                    Scopes = @('GroupMember.Read.All','Application.Read.All','Member.Read.Hidden')
                }
            }

            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/applications?*' {
                        @([PSCustomObject]@{ id = 'app-1'; appId = 'shared-app-id'; displayName = 'App'; keyCredentials = @(); passwordCredentials = @(); appRoles = @(); requiredResourceAccess = @() })
                    }
                    '*/servicePrincipals?*' {
                        @([PSCustomObject]@{ id = 'sp-1'; appId = 'shared-app-id'; displayName = 'SP'; keyCredentials = @(); passwordCredentials = @(); appRoles = @() })
                    }
                    '*/users?*' {
                        @([PSCustomObject]@{ id = 'user-1'; userPrincipalName = 'user1@contoso.com'; displayName = 'User One' })
                    }
                    '*/organization?*' {
                        @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @([PSCustomObject]@{ name = 'tenant.onmicrosoft.com'; isDefault = $true; isInitial = $true }) })
                    }
                    '*/groups?*' {
                        @([PSCustomObject]@{ id = 'group-1'; displayName = 'Group One' })
                    }
                    '*/oauth2PermissionGrants?*' {
                        @([PSCustomObject]@{ id = 'grant-1'; clientId = 'sp-1'; resourceId = 'graph-sp'; consentType = 'AllPrincipals'; scope = 'User.Read' })
                    }
                    '*/roleManagement/directory/roleAssignmentScheduleInstances*' {
                        @(); break
                    }
                    '*/roleManagement/directory/roleEligibilityScheduleInstances*' {
                        @(); break
                    }
                    '*/roleManagement/directory/roleAssignments?*' {
                        @([PSCustomObject]@{ id = 'role-1'; principalId = 'user-1'; roleDefinitionId = 'role-def-1'; roleDefinition = [PSCustomObject]@{ displayName = 'Reader' } }); break
                    }
                    default { @() }
                }

                $mockResult = [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
                Add-InspectorGraphTelemetryRecord -Telemetry $RuntimeTelemetry -GraphResult $mockResult
                $mockResult
            }

            # Snapshot tests keep their existing URI-specific Graph mocks while the
            # production snapshot routes high-volume relationship GETs through the
            # real batch transport. This passthrough preserves the logical request
            # behavior for focused snapshot assertions; GraphBatch.Tests.ps1 covers
            # the physical JSON batch transport itself.
            Mock Invoke-InspectorGraphBatchRequest {
                @(
                    foreach ($request in @($Requests)) {
                        Invoke-InspectorGraphRequest `
                            -Uri ([string](Get-InspectorSnapshotProperty -InputObject $request -Name 'Uri')) `
                            -RequiredPermission ([string](Get-InspectorSnapshotProperty -InputObject $request -Name 'RequiredPermission')) `
                            -RuntimeTelemetry $RuntimeTelemetry
                    }
                )
            }
        }

        It 'returns the expected in-memory snapshot schema and indexes' {
            $telemetry = New-InspectorRuntimeTelemetry
            $snapshot = New-InspectorTenantSnapshot -RuntimeTelemetry $telemetry

            $snapshot.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.TenantSnapshot'
            $snapshot.SchemaVersion | Should -Be '1.1.0'
            $snapshot.CollectionMode | Should -Be 'GraphIngestionOnly'
            $snapshot.PersistenceMode | Should -Be 'PortableCapable'
            $snapshot.GraphCallsAllowedAfterSnapshot | Should -BeFalse
            $snapshot.Collections.Applications.Count | Should -Be 1
            $snapshot.Collections.ServicePrincipals.Count | Should -Be 1
            $snapshot.Collections.Users.Count | Should -Be 1
            $snapshot.Collections.Groups.Count | Should -Be 1
            $snapshot.Indexes.ApplicationByObjectId['app-1'].Count | Should -Be 1
            $snapshot.Indexes.ApplicationByAppId['shared-app-id'].Count | Should -Be 1
            $snapshot.Indexes.ServicePrincipalByObjectId['sp-1'].Count | Should -Be 1
            $snapshot.Indexes.ServicePrincipalByAppId['shared-app-id'].Count | Should -Be 1
            $snapshot.Indexes.UserByObjectId['user-1'].Count | Should -Be 1
            $snapshot.Indexes.UserByUserPrincipalName['user1@contoso.com'].Count | Should -Be 1
            $snapshot.Indexes.GroupByObjectId['group-1'].Count | Should -Be 1
            $snapshot.Indexes.OAuth2PermissionGrantsByClientId['sp-1'].Count | Should -Be 1
            $snapshot.Indexes.DirectoryRoleAssignmentsByPrincipalId['user-1'].Count | Should -Be 1
            $snapshot.Collections.DirectoryRoleDefinitions.Count | Should -Be 0
            $snapshot.Collections.RoleAssignmentScheduleInstances.Count | Should -Be 0
            $snapshot.Collections.RoleEligibilityScheduleInstances.Count | Should -Be 0
            $snapshot.Collections.AdministrativeUnits.Count | Should -Be 0
            $snapshot.Collections.RiskyUsers.Count | Should -Be 0
            $snapshot.TenantMetadata.TenantId | Should -Be 'tenant-1'
            $snapshot.TenantMetadata.TenantDisplayName | Should -Be 'Tenant One'
            $snapshot.RuntimeTelemetry.GraphRequestSummary.TotalRequests | Should -BeGreaterThan 0
            $snapshot.AssessmentCoverage.EvidencePlanMatches | Should -BeTrue
            $snapshot.AssessmentCoverage.ExpectedEvidenceCount | Should -Be $snapshot.AssessmentCoverage.ActualRequiredEvidenceCount
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'Applications'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'DirectoryRoleDefinitions'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'RoleAssignmentScheduleInstances'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'RoleEligibilityScheduleInstances'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'AdministrativeUnits'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'RiskyUsers'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'ApplicationOwners:app-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'ServicePrincipalOwners:sp-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'ServicePrincipalOwnedObjects:sp-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'AppRoleAssignments:sp-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'AppRoleAssignedTo:sp-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'ServicePrincipalGroupMemberships:sp-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'GroupOwners:group-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'GroupMembers:group-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'GroupMemberships:group-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'UserTransitiveMemberships:user-1'

            Should -Invoke Invoke-InspectorGraphBatchRequest -Times 2 -Exactly
            Should -Invoke Invoke-InspectorGraphBatchRequest -ParameterFilter {
                @($Requests).Count -eq 1 -and
                [string](Get-InspectorSnapshotProperty -InputObject @($Requests)[0] -Name 'Name') -eq 'ApplicationOwners:app-1'
            } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphBatchRequest -ParameterFilter {
                @($Requests).Count -eq 5 -and
                @($Requests | ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'Name') }) -contains 'ServicePrincipalGroupMemberships:sp-1'
            } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals/sp-1/memberOf' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals/sp-1/ownedObjects*' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,tags,appRoles,appOwnerOrganizationId,publisherName,verifiedPublisher,keyCredentials,passwordCredentials&$top=100' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/appRoleAssignedTo' } -Times 1 -Exactly
        }

        It 'collects privileged identity context domains and AU dependencies with complete evidence' {
            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/applications?*' { @(); break }
                    '*/servicePrincipals?*' { @(); break }
                    '*/users?*' { @([PSCustomObject]@{ id = 'user-1'; userPrincipalName = 'user1@contoso.com'; displayName = 'User One' }); break }
                    '*/groups?*' { @(); break }
                    '*/organization?*' { @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @() }); break }
                    '*/oauth2PermissionGrants?*' { @(); break }
                    '*/roleManagement/directory/roleDefinitions' { @([PSCustomObject]@{ id = 'role-def-1'; displayName = 'Privileged Role'; isBuiltIn = $true; templateId = 'role-def-1' }); break }
                    '*/roleManagement/directory/roleAssignments?*' { @([PSCustomObject]@{ id = 'assignment-1'; principalId = 'user-1'; roleDefinitionId = 'role-def-1'; directoryScopeId = '/administrativeUnits/au-1'; roleDefinition = [PSCustomObject]@{ displayName = 'Privileged Role' } }); break }
                    '*/roleManagement/directory/roleAssignmentScheduleInstances*' { @([PSCustomObject]@{ id = 'active-1'; principalId = 'user-1'; roleDefinitionId = 'role-def-1'; directoryScopeId = '/'; memberType = 'Direct'; assignmentType = 'Assigned'; roleAssignmentOriginId = 'assignment-1'; roleAssignmentScheduleId = 'schedule-1'; startDateTime = '2026-01-01T00:00:00Z'; endDateTime = $null }); break }
                    '*/roleManagement/directory/roleEligibilityScheduleInstances*' { @([PSCustomObject]@{ id = 'eligible-1'; principalId = 'user-1'; roleDefinitionId = 'role-def-1'; directoryScopeId = '/'; memberType = 'Direct'; startDateTime = '2026-01-01T00:00:00Z'; endDateTime = '2026-12-31T00:00:00Z' }); break }
                    '*/directory/administrativeUnits/au-1/members?*' { @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'user-1'; displayName = 'User One'; userPrincipalName = 'user1@contoso.com' }); break }
                    '*/directory/administrativeUnits?*' { @([PSCustomObject]@{ id = 'au-1'; displayName = 'Privileged AU'; visibility = 'Public'; isMemberManagementRestricted = $true }); break }
                    '*/identityProtection/riskyUsers?*' { @([PSCustomObject]@{ id = 'user-1'; userPrincipalName = 'user1@contoso.com'; riskLevel = 'high'; riskState = 'atRisk'; riskDetail = 'adminConfirmedUserCompromised'; riskLastUpdatedDateTime = '2026-01-02T00:00:00Z' }); break }
                    default { @(); break }
                }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry)

            $snapshot.Collections.DirectoryRoleDefinitions.Count | Should -Be 1
            $snapshot.Collections.RoleAssignmentScheduleInstances.Count | Should -Be 1
            $snapshot.Collections.RoleEligibilityScheduleInstances.Count | Should -Be 1
            $snapshot.Collections.AdministrativeUnits.Count | Should -Be 1
            $snapshot.Collections.AdministrativeUnitMembers.Count | Should -Be 1
            $snapshot.Collections.AdministrativeUnitScopedRoleMembers.Count | Should -Be 0
            $snapshot.Collections.RiskyUsers.Count | Should -Be 1
            $snapshot.Indexes.DirectoryRoleDefinitionsById['role-def-1'].Count | Should -Be 1
            $snapshot.Indexes.RoleAssignmentScheduleInstancesByPrincipalId['user-1'].Count | Should -Be 1
            $snapshot.Indexes.RoleEligibilityScheduleInstancesByPrincipalId['user-1'].Count | Should -Be 1
            $snapshot.Indexes.AdministrativeUnitById['au-1'].Count | Should -Be 1
            $snapshot.Indexes.AdministrativeUnitMembersByMemberId['user-1'].Count | Should -Be 1
            $snapshot.Indexes.RiskyUsersByUserId['user-1'].Count | Should -Be 1
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'AdministrativeUnitMembers:au-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Not -Contain 'AdministrativeUnitScopedRoleMembers:au-1'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Complete'
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/roleManagement/directory/roleDefinitions?*' } -Times 0 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/roleManagement/directory/roleAssignments*$top=999*' } -Times 0 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/roleManagement/directory/roleAssignmentScheduleInstances*$top=999*' } -Times 0 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/roleManagement/directory/roleEligibilityScheduleInstances*$top=999*' } -Times 0 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName,description,visibility,isMemberManagementRestricted,membershipType,membershipRule,membershipRuleProcessingState' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/directory/administrativeUnits/au-1/members?$top=999' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/directory/administrativeUnits/au-1/scopedRoleMembers*' } -Times 0 -Exactly
        }

        It 'fails closed for hidden administrative-unit membership when Member.Read.Hidden is absent' {
            Mock Get-MgContext {
                [PSCustomObject]@{
                    TenantId = 'tenant-1'
                    ClientId = 'client-1'
                    Scopes = @('AdministrativeUnit.Read.All','RoleManagement.Read.Directory')
                }
            }

            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/directory/administrativeUnits?*' { @([PSCustomObject]@{ id = 'au-hidden'; displayName = 'Hidden AU'; visibility = 'HiddenMembership' }); break }
                    '*/organization?*' { @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @() }); break }
                    default { @(); break }
                }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $memberEvidence = @($snapshot.Evidence | Where-Object QueryName -eq 'AdministrativeUnitMembers:au-hidden')

            $memberEvidence.Count | Should -Be 1
            $memberEvidence[0].Status | Should -Be 'InsufficientPermission'
            $memberEvidence[0].Completeness | Should -Be 'Partial'
            $memberEvidence[0].RequiredPermission | Should -Match 'Member.Read.Hidden'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Partial'
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/directory/administrativeUnits/au-hidden/members*' } -Times 0 -Exactly
        }

        It 'merges direct user owners with service-principal group owners reconstructed from ownedObjects evidence' {
            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/servicePrincipals/sp-owner/ownedObjects*' {
                        @(
                            [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'group-target'; displayName = 'Target Group' }
                        )
                        break
                    }
                    '*/servicePrincipals/sp-owner/memberOf' { @(); break }
                    '*/applications?*' { @() }
                    '*/servicePrincipals?*' { @([PSCustomObject]@{ id = 'sp-owner'; appId = 'app-sp-owner'; displayName = 'Automation Owner SP'; servicePrincipalType = 'Application'; keyCredentials = @(); passwordCredentials = @(); appRoles = @() }) }
                    '*/users?*' { @() }
                    '*/organization?*' { @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @() }) }
                    '*/groups/group-target/owners?*' { @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'user-owner'; displayName = 'User Owner' }); break }
                    '*/groups?*' { @([PSCustomObject]@{ id = 'group-target'; displayName = 'Target Group'; visibility = 'Private'; securityEnabled = $true; mailEnabled = $false }) }
                    default { @() }
                }

                $mockResult = [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
                Add-InspectorGraphTelemetryRecord -Telemetry $RuntimeTelemetry -GraphResult $mockResult
                $mockResult
            }

            $snapshot = New-InspectorTenantSnapshot -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $ownerRows = @($snapshot.Collections.GroupOwners | Where-Object { $_.SourceObjectId -eq 'group-target' } | Sort-Object { $_.Owner.id })

            $ownerRows.Count | Should -Be 2
            @($ownerRows.Owner.id) | Should -Be @('sp-owner','user-owner')
            ($ownerRows | Where-Object { $_.Owner.id -eq 'sp-owner' }).EvidenceId | Should -Be (
                @($snapshot.Evidence | Where-Object QueryName -eq 'ServicePrincipalOwnedObjects:sp-owner')[0].EvidenceId
            )
            @($snapshot.Collections.GroupOwners | Where-Object { $_.Owner.id -eq 'sp-owner' }).Count | Should -Be 1
            $snapshot.CollectionSummary.GroupOwners.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.GroupOwners.Completeness | Should -Be 'Complete'
        }

        It 'fails closed for group-owner completeness when service-principal ownedObjects evidence is unavailable' {
            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/servicePrincipals?*' { @([PSCustomObject]@{ id = 'sp-1'; appId = 'app-sp-1'; displayName = 'SP'; keyCredentials = @(); passwordCredentials = @(); appRoles = @() }) }
                    '*/groups?*' { @([PSCustomObject]@{ id = 'group-1'; displayName = 'Group One'; visibility = 'Private'; securityEnabled = $true; mailEnabled = $false }) }
                    '*/organization?*' { @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @() }) }
                    default { @() }
                }

                $status = if ($Uri -like '*/servicePrincipals/sp-1/ownedObjects*') { 'InsufficientPermission' } else { 'Success' }
                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = $status
                    ObservedValue = $items
                    Limitations = if ($status -eq 'Success') { @() } else { @('ownedObjects denied') }
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType ServicePrincipal,Group -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $ownerEvidence = @($snapshot.Evidence | Where-Object QueryName -eq 'GroupOwners:group-1')

            $ownerEvidence.Count | Should -Be 1
            $ownerEvidence[0].Status | Should -Be 'Partial'
            $ownerEvidence[0].Completeness | Should -Be 'Partial'
            @($ownerEvidence[0].Limitations) -join ' ' | Should -Match 'ownedObjects corpus'
            $snapshot.CollectionSummary.GroupOwners.Completeness | Should -Be 'Partial'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Partial'
        }

        It 'fails closed for mail-enabled security-group owner completeness' {
            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/servicePrincipals?*' { @() }
                    '*/groups?*' {
                        @([PSCustomObject]@{
                            id = 'mail-security-group-1'
                            displayName = 'Mail Security Group'
                            visibility = 'Private'
                            securityEnabled = $true
                            mailEnabled = $true
                            groupTypes = @()
                            onPremisesSyncEnabled = $false
                        })
                    }
                    '*/organization?*' { @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @() }) }
                    default { @() }
                }

                $mockResult = [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
                Add-InspectorGraphTelemetryRecord -Telemetry $RuntimeTelemetry -GraphResult $mockResult
                $mockResult
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType ServicePrincipal,Group -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $ownerEvidence = @($snapshot.Evidence | Where-Object QueryName -eq 'GroupOwners:mail-security-group-1')

            $ownerEvidence.Count | Should -Be 1
            $ownerEvidence[0].Status | Should -Be 'Partial'
            $ownerEvidence[0].Completeness | Should -Be 'Partial'
            @($ownerEvidence[0].Limitations) -join ' ' | Should -Match 'mail-enabled security group'
            $snapshot.CollectionSummary.GroupOwners.Completeness | Should -Be 'Partial'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Partial'
        }

        It 'reconstructs direct service-principal group members through stable v1.0 reverse membership evidence' {
            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/servicePrincipals/sp-member/memberOf' { @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'group-target'; displayName = 'Target Group' }); break }
                    '*/servicePrincipals/sp-member/ownedObjects*' { @(); break }
                    '*/applications?*' { @() }
                    '*/servicePrincipals?*' { @([PSCustomObject]@{ id = 'sp-member'; appId = 'app-sp-member'; displayName = 'Automation SP'; servicePrincipalType = 'Application'; keyCredentials = @(); passwordCredentials = @(); appRoles = @() }) }
                    '*/users?*' { @() }
                    '*/organization?*' { @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @() }) }
                    '*/groups/*/members?*' { @(); break }
                    '*/groups?*' { @([PSCustomObject]@{ id = 'group-target'; displayName = 'Target Group'; visibility = 'Private' }) }
                    default { @() }
                }

                $mockResult = [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
                Add-InspectorGraphTelemetryRecord -Telemetry $RuntimeTelemetry -GraphResult $mockResult
                $mockResult
            }

            $snapshot = New-InspectorTenantSnapshot -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $memberRows = @($snapshot.Collections.GroupMembers | Where-Object { $_.SourceObjectId -eq 'group-target' })

            $memberRows.Count | Should -Be 1
            $memberRows[0].Member.id | Should -Be 'sp-member'
            $memberRows[0].Member.'@odata.type' | Should -Be '#microsoft.graph.servicePrincipal'
            $spMembershipEvidence = @($snapshot.Evidence | Where-Object { $_.QueryName -eq 'ServicePrincipalGroupMemberships:sp-member' })
            $spMembershipEvidence.Count | Should -Be 1
            $spMembershipEvidence[0].Status | Should -Be 'Success'
            $spMembershipEvidence[0].Completeness | Should -Be 'Complete'
            $snapshot.AssessmentCoverage.Status | Should -Be 'Success'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Complete'
            $snapshot.AssessmentCoverage.EvidencePlanMatches | Should -BeTrue
        }

        It 'fails closed for group-member completeness when service-principal assessment scope is unavailable' {
            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/groups?*' { @([PSCustomObject]@{ id = 'group-only'; displayName = 'Group Only'; visibility = 'Private' }) }
                    '*/organization?*' { @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @() }) }
                    default { @() }
                }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType Group -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $memberEvidence = @($snapshot.Evidence | Where-Object { $_.QueryName -eq 'GroupMembers:group-only' })

            $memberEvidence.Count | Should -Be 1
            $memberEvidence[0].Status | Should -Be 'Partial'
            $memberEvidence[0].Completeness | Should -Be 'Partial'
            @($memberEvidence[0].Limitations) -join ' ' | Should -Match 'ServicePrincipals tenant collection'
            $snapshot.CollectionSummary.GroupMembers.Completeness | Should -Be 'Partial'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Partial'
            $snapshot.ScopeInventory.CollectionCompleteness | Should -Be 'Partial'
        }

        It 'fails closed for HiddenMembership group members when Member.Read.Hidden is absent' {
            Mock Get-MgContext {
                [PSCustomObject]@{
                    TenantId = 'tenant-1'
                    ClientId = 'client-1'
                    Scopes = @('GroupMember.Read.All','Application.Read.All')
                }
            }

            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/groups?*' { @([PSCustomObject]@{ id = 'hidden-group'; displayName = 'Hidden Group'; visibility = 'HiddenMembership' }) }
                    '*/organization?*' { @([PSCustomObject]@{ id = 'tenant-1'; displayName = 'Tenant One'; verifiedDomains = @() }) }
                    default { @() }
                }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType Group -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $memberEvidence = @($snapshot.Evidence | Where-Object { $_.QueryName -eq 'GroupMembers:hidden-group' })

            $memberEvidence.Count | Should -Be 1
            $memberEvidence[0].Status | Should -Be 'InsufficientPermission'
            $memberEvidence[0].Completeness | Should -Be 'Partial'
            $memberEvidence[0].RequiredPermission | Should -Match 'Member.Read.Hidden'
            $snapshot.CollectionSummary.GroupMembers.Completeness | Should -Be 'Partial'
            $snapshot.AssessmentCoverage.Status | Should -Be 'Partial'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Partial'
            $snapshot.ScopeInventory.CollectionCompleteness | Should -Be 'Partial'
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/groups/hidden-group/members?*' } -Times 0 -Exactly
        }

        It 'uses only basic user properties in the default user snapshot query' {
            $script:userSnapshotUri = $null

            Mock Invoke-InspectorGraphRequest {
                if ($Uri -like '*/users?*') {
                    $script:userSnapshotUri = $Uri
                }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = @()
                    Limitations = @()
                }
            }

            New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry) | Out-Null

            $script:userSnapshotUri | Should -Not -BeNullOrEmpty
            $script:userSnapshotUri | Should -Match '\$select=id,userPrincipalName,displayName,userType,accountEnabled'
            $script:userSnapshotUri | Should -Not -Match 'signInActivity'
        }

        It 'propagates bounded and required-evidence failures into assessment coverage and relationship completeness' {
            Mock Invoke-InspectorGraphRequest {
                $observed =
                    if ($Uri -like '*/applications?*') {
                        @(
                            [PSCustomObject]@{ id = 'app-1'; appId = 'client-1'; displayName = 'One'; keyCredentials = @(); passwordCredentials = @(); appRoles = @(); requiredResourceAccess = @() },
                            [PSCustomObject]@{ id = 'app-2'; appId = 'client-2'; displayName = 'Two'; keyCredentials = @(); passwordCredentials = @(); appRoles = @(); requiredResourceAccess = @() }
                        )
                    }
                    elseif ($Uri -like '*/servicePrincipals?*') {
                        @(
                            [PSCustomObject]@{ id = 'sp-1'; appId = 'client-sp-1'; displayName = 'Service Principal One'; servicePrincipalType = 'Application'; accountEnabled = $true; appRoleAssignmentRequired = $false; tags = @(); appRoles = @(); appOwnerOrganizationId = 'external-tenant'; publisherName = 'Contoso'; verifiedPublisher = $null; keyCredentials = @(); passwordCredentials = @() }
                        )
                    }
                    else {
                        @()
                    }

                $status =
                    if ($Uri -like '*oauth2PermissionGrants*') { 'InsufficientPermission' }
                    elseif ($Uri -like '*roleManagement/directory/roleAssignments*') { 'Failed' }
                    elseif ($Uri -like '*/servicePrincipals/sp-1/owners*') { 'InsufficientPermission' }
                    elseif ($Uri -like '*/servicePrincipals/sp-1/appRoleAssignments*') { 'ServiceUnavailable' }
                    else { 'Success' }

                $limitations =
                    switch ($status) {
                        'InsufficientPermission' { @('permission denied') }
                        'Failed' { @('directory role collection failed') }
                        'ServiceUnavailable' { @('app-role assignment service unavailable') }
                        default { @() }
                    }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = $status
                    ObservedValue = $observed
                    Limitations = $limitations
                }
            }

            $snapshot = New-InspectorTenantSnapshot -MaxObjectsPerType 1 -RuntimeTelemetry (New-InspectorRuntimeTelemetry)

            $snapshot.CollectionSummary.OAuth2PermissionGrants.Status | Should -Be 'InsufficientPermission'
            $snapshot.CollectionSummary.DirectoryRoleAssignments.Status | Should -Be 'Failed'
            $snapshot.CollectionSummary.ServicePrincipalOwners.Status | Should -Be 'InsufficientPermission'
            $snapshot.CollectionSummary.ServicePrincipalOwners.Completeness | Should -Be 'Partial'
            $snapshot.CollectionSummary.AppRoleAssignments.Status | Should -Be 'ServiceUnavailable'
            $snapshot.CollectionSummary.AppRoleAssignments.Completeness | Should -Be 'Partial'
            $snapshot.Limitations | Should -Contain 'permission denied'
            $snapshot.Limitations | Should -Contain 'directory role collection failed'
            $snapshot.Limitations | Should -Contain 'app-role assignment service unavailable'

            $snapshot.CollectionSummary.Applications.Status | Should -Be 'Partial'
            $snapshot.CollectionSummary.Applications.Completeness | Should -Be 'Truncated'
            $snapshot.CollectionSummary.Applications.Truncated | Should -BeTrue
            $snapshot.CollectionSummary.Applications.SourceResultCount | Should -Be 2
            $snapshot.Collections.Applications.Count | Should -Be 1
            $snapshot.ScopeInventory.BoundedRun | Should -BeTrue
            $snapshot.ScopeInventory.CollectionCompleteness | Should -Be 'Partial'
            $snapshot.ScopeInventory.AssessmentCoverageStatus | Should -Be 'Failed'
            $snapshot.ScopeInventory.AssessmentCoverageCompleteness | Should -Be 'Partial'
            $snapshot.ScopeInventory.IncompleteRequiredEvidenceCount | Should -BeGreaterThan 0
            $snapshot.ScopeInventory.TruncatedCollections | Should -Contain 'Applications'

            foreach ($requiredIncompleteQuery in @(
                'Applications',
                'OAuth2PermissionGrants',
                'DirectoryRoleAssignments',
                'ServicePrincipalOwners:sp-1',
                'AppRoleAssignments:sp-1'
            )) {
                $snapshot.AssessmentCoverage.IncompleteQueries | Should -Contain $requiredIncompleteQuery
            }

            $applicationEvidence = @($snapshot.Evidence | Where-Object QueryName -eq 'Applications')[0]
            $applicationEvidence.Status | Should -Be 'Partial'
            $applicationEvidence.Completeness | Should -Be 'Truncated'
            $applicationEvidence.ResultCount | Should -Be 1
            $applicationEvidence.SourceResultCount | Should -Be 2
            (Test-InspectorObservationTenantCollectionEvidenceSucceeded -ObjectInsight ([PSCustomObject]@{ Evidence = @($snapshot.Evidence) }) -QueryName @('Applications')) | Should -BeFalse

            $discovery = ConvertFrom-InspectorTenantSnapshot -TenantSnapshot $snapshot -ObjectType @('Application', 'ServicePrincipal')
            $discovery.Status | Should -Be 'Failed'
            $discovery.Completeness | Should -Be 'Partial'
            $discovery.AssessmentCoverage.Status | Should -Be 'Failed'

            $spCandidate = @($discovery.DiscoveredObjects | Where-Object ObjectType -eq 'ServicePrincipal')[0]
            $resolution = [PSCustomObject]@{ DirectMatches = @($spCandidate); RelatedObjects = @() }
            $relationshipCollection = Get-InspectorSnapshotRelationships -Resolution $resolution -TenantSnapshot $snapshot
            $relationshipCollection.Status | Should -Be 'Failed'
            $relationshipCollection.Completeness | Should -Be 'Partial'
            @($relationshipCollection.Evidence).QueryName | Should -Contain 'ServicePrincipalOwners:sp-1'
            @($relationshipCollection.Evidence).QueryName | Should -Contain 'AppRoleAssignments:sp-1'

            # A silently omitted query must be detected independently of the
            # statuses on the evidence rows that remain.
            $omittedQuery = 'AppRoleAssignedTo:sp-1'
            $coverageWithMissingEvidence =
                Get-InspectorSnapshotAssessmentCoverage `
                    -Evidence @($snapshot.Evidence | Where-Object QueryName -ne $omittedQuery) `
                    -ExpectedQueries @($snapshot.AssessmentCoverage.ExpectedQueries)

            $coverageWithMissingEvidence.Status | Should -Be 'Failed'
            $coverageWithMissingEvidence.Completeness | Should -Be 'Partial'
            $coverageWithMissingEvidence.EvidencePlanMatches | Should -BeFalse
            $coverageWithMissingEvidence.MissingExpectedEvidenceCount | Should -BeGreaterThan 0
            $coverageWithMissingEvidence.MissingExpectedQueries | Should -Contain $omittedQuery
        }

        It 'marks PIM and risky-user evidence license-unavailable for a P1-only tenant without calling licensed feature APIs' {
            Mock Invoke-InspectorGraphRequest {
                $items =
                    if ($Uri -like '*/subscribedSkus?*') {
                        @(
                            [PSCustomObject]@{
                                id = 'sku-business-premium'
                                skuId = '00000000-0000-0000-0000-000000000001'
                                skuPartNumber = 'SPB'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{
                                        servicePlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'
                                        servicePlanName = 'AAD_PREMIUM'
                                        provisioningStatus = 'Success'
                                    }
                                )
                            }
                        )
                    }
                    else {
                        @()
                    }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $license = $snapshot.TenantMetadata.LicenseValidation
            $skuEvidence = @($snapshot.Evidence | Where-Object QueryName -eq 'SubscribedSkus')[0]

            $license.ValidationStatus | Should -Be 'LimitedByLicense'
            $license.DetectedPlans.EntraIdP1 | Should -BeTrue
            $license.DetectedPlans.EntraIdP2 | Should -BeFalse
            $license.PrivilegedIdentityManagement.Status | Should -Be 'NotLicensed'
            $license.IdentityProtectionRiskyUsers.Status | Should -Be 'NotLicensed'
            $snapshot.CollectionSummary.RoleAssignmentScheduleInstances.Status | Should -Be 'LicenseUnavailable'
            $snapshot.CollectionSummary.RoleEligibilityScheduleInstances.Status | Should -Be 'LicenseUnavailable'
            $snapshot.CollectionSummary.RiskyUsers.Status | Should -Be 'LicenseUnavailable'
            $snapshot.AssessmentCoverage.Status | Should -Be 'Partial'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Partial'
            $snapshot.AssessmentCoverage.IncompleteQueries | Should -Contain 'RoleAssignmentScheduleInstances'
            $snapshot.AssessmentCoverage.IncompleteQueries | Should -Contain 'RoleEligibilityScheduleInstances'
            $snapshot.AssessmentCoverage.IncompleteQueries | Should -Contain 'RiskyUsers'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Not -Contain 'SubscribedSkus'
            $skuEvidence.RequiredForCoverage | Should -BeFalse
            $snapshot.ScopeInventory.PimLicenseCapability | Should -Be 'NotLicensed'
            $snapshot.ScopeInventory.IdentityProtectionLicenseCapability | Should -Be 'NotLicensed'
            @($snapshot.Limitations | Where-Object { $_ -like '*Required licensing:*' }).Count | Should -Be 3

            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' } -Times 0 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' } -Times 0 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/identityProtection/riskyUsers?*' } -Times 0 -Exactly
        }

        It 'accepts Entra ID Governance plus its P1 prerequisite for PIM without granting Identity Protection capability' {
            Mock Invoke-InspectorGraphRequest {
                $items =
                    if ($Uri -like '*/subscribedSkus?*') {
                        @(
                            [PSCustomObject]@{
                                id = 'sku-p1'
                                skuPartNumber = 'AAD_PREMIUM'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'; servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success' }
                                )
                            },
                            [PSCustomObject]@{
                                id = 'sku-governance'
                                skuPartNumber = 'Microsoft_Entra_ID_Governance'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = 'e866a266-3cff-43a3-acca-0c90a7e00c8b'; servicePlanName = 'Entra_Identity_Governance'; provisioningStatus = 'Success' }
                                )
                            }
                        )
                    }
                    else {
                        @()
                    }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $license = $snapshot.TenantMetadata.LicenseValidation

            $license.ValidationStatus | Should -Be 'Mixed'
            $license.DetectedPlans.EntraIdentityGovernance | Should -BeTrue
            $license.PrivilegedIdentityManagement.Status | Should -Be 'Available'
            $license.IdentityProtectionRiskyUsers.Status | Should -Be 'NotLicensed'
            $snapshot.CollectionSummary.RoleAssignmentScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RoleEligibilityScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RiskyUsers.Status | Should -Be 'LicenseUnavailable'
            $snapshot.AssessmentCoverage.Status | Should -Be 'Partial'

            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/identityProtection/riskyUsers?*' } -Times 0 -Exactly
        }

        It 'accepts Microsoft Entra ID P2 for both PIM and Identity Protection capability' {
            Mock Invoke-InspectorGraphRequest {
                $items =
                    if ($Uri -like '*/subscribedSkus?*') {
                        @(
                            [PSCustomObject]@{
                                id = 'sku-p2'
                                skuPartNumber = 'AAD_PREMIUM_P2'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'; servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success' },
                                    [PSCustomObject]@{ servicePlanId = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'; servicePlanName = 'AAD_PREMIUM_P2'; provisioningStatus = 'Success' }
                                )
                            }
                        )
                    }
                    else {
                        @()
                    }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $license = $snapshot.TenantMetadata.LicenseValidation

            $license.ValidationStatus | Should -Be 'Available'
            $license.DetectedPlans.EntraIdP2 | Should -BeTrue
            $license.PrivilegedIdentityManagement.Status | Should -Be 'Available'
            $license.IdentityProtectionRiskyUsers.Status | Should -Be 'Available'
            $snapshot.CollectionSummary.RoleAssignmentScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RoleEligibilityScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RiskyUsers.Status | Should -Be 'Success'
            $snapshot.AssessmentCoverage.Status | Should -Be 'Success'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Complete'
        }

        It 'accepts Microsoft Entra Suite entitlement for both PIM and Identity Protection capability' {
            Mock Invoke-InspectorGraphRequest {
                $items =
                    if ($Uri -like '*/subscribedSkus?*') {
                        @(
                            [PSCustomObject]@{
                                id = 'sku-p1'
                                skuPartNumber = 'AAD_PREMIUM'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'; servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success' }
                                )
                            },
                            [PSCustomObject]@{
                                id = 'sku-suite'
                                skuPartNumber = 'Microsoft_Entra_Suite'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = 'e866a266-3cff-43a3-acca-0c90a7e00c8b'; servicePlanName = 'Entra_Identity_Governance'; provisioningStatus = 'Success' },
                                    [PSCustomObject]@{ servicePlanId = '8d23cb83-ab07-418f-8517-d7aca77307dc'; servicePlanName = 'Entra_Premium_Internet_Access'; provisioningStatus = 'Success' },
                                    [PSCustomObject]@{ servicePlanId = 'f057aab1-b184-49b2-85c0-881b02a405c5'; servicePlanName = 'Entra_Premium_Private_Access'; provisioningStatus = 'Success' }
                                )
                            }
                        )
                    }
                    else {
                        @()
                    }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $license = $snapshot.TenantMetadata.LicenseValidation

            $license.ValidationStatus | Should -Be 'Available'
            $license.DetectedPlans.EntraSuite | Should -BeTrue
            $license.PrivilegedIdentityManagement.Status | Should -Be 'Available'
            $license.IdentityProtectionRiskyUsers.Status | Should -Be 'Available'
            $snapshot.CollectionSummary.RoleAssignmentScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RoleEligibilityScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RiskyUsers.Status | Should -Be 'Success'
            $snapshot.AssessmentCoverage.Status | Should -Be 'Success'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Complete'

            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/identityProtection/riskyUsers?*' } -Times 1 -Exactly
        }

        It 'does not infer Entra Suite or Identity Protection from separately licensed Governance, Internet Access, and Private Access plans' {
            Mock Invoke-InspectorGraphRequest {
                $items =
                    if ($Uri -like '*/subscribedSkus?*') {
                        @(
                            [PSCustomObject]@{
                                id = 'sku-p1'
                                skuPartNumber = 'AAD_PREMIUM'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'; servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success' }
                                )
                            },
                            [PSCustomObject]@{
                                id = 'sku-governance'
                                skuPartNumber = 'Microsoft_Entra_ID_Governance'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = 'e866a266-3cff-43a3-acca-0c90a7e00c8b'; servicePlanName = 'Entra_Identity_Governance'; provisioningStatus = 'Success' }
                                )
                            },
                            [PSCustomObject]@{
                                id = 'sku-internet'
                                skuPartNumber = 'Microsoft_Entra_Internet_Access'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = '8d23cb83-ab07-418f-8517-d7aca77307dc'; servicePlanName = 'Entra_Premium_Internet_Access'; provisioningStatus = 'Success' }
                                )
                            },
                            [PSCustomObject]@{
                                id = 'sku-private'
                                skuPartNumber = 'Microsoft_Entra_Private_Access'
                                capabilityStatus = 'Enabled'
                                servicePlans = @(
                                    [PSCustomObject]@{ servicePlanId = 'f057aab1-b184-49b2-85c0-881b02a405c5'; servicePlanName = 'Entra_Premium_Private_Access'; provisioningStatus = 'Success' }
                                )
                            }
                        )
                    }
                    else {
                        @()
                    }

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = 'Success'
                    ObservedValue = $items
                    Limitations = @()
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $license = $snapshot.TenantMetadata.LicenseValidation

            $license.DetectedPlans.EntraIdentityGovernance | Should -BeTrue
            $license.DetectedPlans.EntraSuite | Should -BeFalse
            $license.PrivilegedIdentityManagement.Status | Should -Be 'Available'
            $license.IdentityProtectionRiskyUsers.Status | Should -Be 'NotLicensed'
            $snapshot.CollectionSummary.RoleAssignmentScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RoleEligibilityScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RiskyUsers.Status | Should -Be 'LicenseUnavailable'
            $snapshot.AssessmentCoverage.Status | Should -Be 'Partial'

            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/identityProtection/riskyUsers?*' } -Times 0 -Exactly
        }

        It 'keeps license inventory optional and uses feature endpoint evidence when subscribedSkus cannot be read' {
            Mock Invoke-InspectorGraphRequest {
                $isLicenseInventory = $Uri -like '*/subscribedSkus?*'

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = (Get-Date).ToUniversalTime().ToString('o')
                    Status = $(if ($isLicenseInventory) { 'InsufficientPermission' } else { 'Success' })
                    ObservedValue = @()
                    Limitations = $(if ($isLicenseInventory) { @('license inventory permission denied') } else { @() })
                }
            }

            $snapshot = New-InspectorTenantSnapshot -ObjectType User -RuntimeTelemetry (New-InspectorRuntimeTelemetry)
            $license = $snapshot.TenantMetadata.LicenseValidation
            $skuEvidence = @($snapshot.Evidence | Where-Object QueryName -eq 'SubscribedSkus')[0]

            $license.ValidationStatus | Should -Be 'Unknown'
            $license.InventoryStatus | Should -Be 'InsufficientPermission'
            $license.PrivilegedIdentityManagement.Status | Should -Be 'Unknown'
            $license.IdentityProtectionRiskyUsers.Status | Should -Be 'Unknown'
            $skuEvidence.RequiredForCoverage | Should -BeFalse
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Not -Contain 'SubscribedSkus'
            $snapshot.AssessmentCoverage.Status | Should -Be 'Success'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Complete'
            $snapshot.CollectionSummary.RoleAssignmentScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RoleEligibilityScheduleInstances.Status | Should -Be 'Success'
            $snapshot.CollectionSummary.RiskyUsers.Status | Should -Be 'Success'
            $snapshot.Limitations | Should -Contain 'Tenant license capability inventory from /subscribedSkus was unavailable. PIM and Identity Protection license prevalidation is therefore unknown; their feature endpoint evidence remains authoritative.'

            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/identityProtection/riskyUsers?*' } -Times 1 -Exactly
        }

        It 'normalizes singleton index values used by user processing' {
            $index = @{}
            $first = [PSCustomObject]@{ id = 'group-1' }
            $second = [PSCustomObject]@{ id = 'role-1' }

            Add-InspectorSnapshotIndexValue -Index $index -Key 'user-1' -Value $first
            Add-InspectorSnapshotIndexValue -Index $index -Key 'user-1' -Value $second

            $values = @(Get-InspectorSnapshotIndexSingle -Index $index -Key 'user-1')

            $values.Count | Should -Be 2
            $values[0].id | Should -Be 'group-1'
            $values[1].id | Should -Be 'role-1'
        }
    }
}
