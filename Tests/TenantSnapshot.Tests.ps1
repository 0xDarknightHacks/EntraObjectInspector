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
                    '*/roleManagement/directory/roleAssignments?*' {
                        @([PSCustomObject]@{ id = 'role-1'; principalId = 'user-1'; roleDefinitionId = 'role-def-1'; roleDefinition = [PSCustomObject]@{ displayName = 'Reader' } })
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
            $snapshot.SchemaVersion | Should -Be '1.0.0'
            $snapshot.CollectionMode | Should -Be 'GraphIngestionOnly'
            $snapshot.PersistenceMode | Should -Be 'InMemoryTemporary'
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
            $snapshot.TenantMetadata.TenantId | Should -Be 'tenant-1'
            $snapshot.TenantMetadata.TenantDisplayName | Should -Be 'Tenant One'
            $snapshot.RuntimeTelemetry.GraphRequestSummary.TotalRequests | Should -BeGreaterThan 0
            $snapshot.AssessmentCoverage.EvidencePlanMatches | Should -BeTrue
            $snapshot.AssessmentCoverage.ExpectedEvidenceCount | Should -Be $snapshot.AssessmentCoverage.ActualRequiredEvidenceCount
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'Applications'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'ApplicationOwners:app-1'
            $snapshot.AssessmentCoverage.ExpectedQueries | Should -Contain 'ServicePrincipalOwners:sp-1'
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
                @($Requests).Count -eq 4 -and
                @($Requests | ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'Name') }) -contains 'ServicePrincipalGroupMemberships:sp-1'
            } -Times 1 -Exactly
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals/sp-1/memberOf' } -Times 1 -Exactly
        }

        It 'reconstructs direct service-principal group members through stable v1.0 reverse membership evidence' {
            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/servicePrincipals/sp-member/memberOf' { @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'group-target'; displayName = 'Target Group' }) }
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
