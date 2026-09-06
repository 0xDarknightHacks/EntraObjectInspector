$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Graph batch request transport' {
    InModuleScope EntraObjectInspector {
        BeforeEach {
            Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'tenant' } }
        }

        It 'splits logical GETs into small batches while preserving logical telemetry' {
            $script:batchBodies = [System.Collections.Generic.List[object]]::new()

            Mock Invoke-MgGraphRequest {
                $payload = $Body | ConvertFrom-Json
                $script:batchBodies.Add($payload)

                [PSCustomObject]@{
                    responses = @(
                        foreach ($request in @($payload.requests)) {
                            [PSCustomObject]@{
                                id = [string]$request.id
                                status = 200
                                headers = @{}
                                body = [PSCustomObject]@{
                                    value = @([PSCustomObject]@{ id = "result-$($request.id)" })
                                }
                            }
                        }
                    )
                }
            }

            $requests = 1..23 | ForEach-Object {
                [PSCustomObject]@{
                    Uri = "https://graph.microsoft.com/v1.0/servicePrincipals/00000000-0000-0000-0000-$($_.ToString('000000000000'))/owners"
                    RequiredPermission = 'Application.Read.All'
                }
            }

            $telemetry = New-InspectorRuntimeTelemetry
            $result = Invoke-InspectorGraphBatchRequest -Requests $requests -BatchSize 10 -RuntimeTelemetry $telemetry

            $result.Count | Should -Be 23
            @($result | Where-Object Status -ne 'Success').Count | Should -Be 0
            $telemetry.GraphRequestSummary.TotalRequests | Should -Be 23
            $telemetry.GraphRequestSummary.SuccessfulRequests | Should -Be 23
            $telemetry.GraphTransportSummary.TotalHttpRequests | Should -Be 3
            $telemetry.GraphTransportSummary.BatchHttpRequests | Should -Be 3
            $telemetry.GraphTransportSummary.SingleHttpRequests | Should -Be 0
            $telemetry.GraphTransportSummary.BatchSubrequestExecutions | Should -Be 23
            $script:batchBodies.Count | Should -Be 3
            @($script:batchBodies[0].requests).Count | Should -Be 10
            @($script:batchBodies[1].requests).Count | Should -Be 10
            @($script:batchBodies[2].requests).Count | Should -Be 3

            foreach ($payload in @($script:batchBodies)) {
                foreach ($request in @($payload.requests)) {
                    $request.method | Should -Be 'GET'
                    $request.url | Should -Match '^/servicePrincipals/'
                    $request.url | Should -Not -Match '^https?://'
                }
            }

            Should -Invoke Invoke-MgGraphRequest -ParameterFilter {
                $Method -eq 'POST' -and $Uri -eq 'https://graph.microsoft.com/v1.0/$batch'
            } -Times 3 -Exactly
        }

        It 'correlates out-of-order mixed subresponses back to the original logical requests' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{
                    responses = @(
                        [PSCustomObject]@{ id = '3'; status = 404; headers = @{}; body = [PSCustomObject]@{} }
                        [PSCustomObject]@{ id = '1'; status = 200; headers = @{}; body = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'owner-1' }) } }
                        [PSCustomObject]@{ id = '2'; status = 403; headers = @{}; body = [PSCustomObject]@{} }
                    )
                }
            }

            $requests = @(
                [PSCustomObject]@{ Uri = 'https://graph.microsoft.com/v1.0/applications/00000000-0000-0000-0000-000000000001/owners'; RequiredPermission = 'Application.Read.All' }
                [PSCustomObject]@{ Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/00000000-0000-0000-0000-000000000002/owners'; RequiredPermission = 'Application.Read.All' }
                [PSCustomObject]@{ Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/00000000-0000-0000-0000-000000000003/appRoleAssignments'; RequiredPermission = 'Application.Read.All' }
            )

            $telemetry = New-InspectorRuntimeTelemetry
            $result = Invoke-InspectorGraphBatchRequest -Requests $requests -RuntimeTelemetry $telemetry

            $result.Count | Should -Be 3
            $result[0].SourceEndpoint | Should -Be $requests[0].Uri
            $result[0].Status | Should -Be 'Success'
            @($result[0].ObservedValue).Count | Should -Be 1
            $result[1].SourceEndpoint | Should -Be $requests[1].Uri
            $result[1].Status | Should -Be 'InsufficientPermission'
            $result[2].SourceEndpoint | Should -Be $requests[2].Uri
            $result[2].Status | Should -Be 'NotFound'
            $telemetry.GraphRequestSummary.TotalRequests | Should -Be 3
            $telemetry.GraphRequestsByEndpoint['/v1.0/applications/{id}/owners'] | Should -Be 1
            $telemetry.GraphRequestsByEndpoint['/v1.0/servicePrincipals/{id}/owners'] | Should -Be 1
            $telemetry.GraphRequestsByEndpoint['/v1.0/servicePrincipals/{id}/appRoleAssignments'] | Should -Be 1
        }

        It 'normalizes dictionary-shaped non-empty relationship items to the single-request object shape' {
            Mock Invoke-MgGraphRequest {
                @{
                    responses = @(
                        @{
                            id = '1'
                            status = 200
                            headers = @{}
                            body = @{
                                value = @(
                                    @{
                                        '@odata.type' = '#microsoft.graph.user'
                                        id = 'owner-1'
                                        displayName = 'Owner One'
                                    }
                                )
                            }
                        },
                        @{
                            id = '2'
                            status = 200
                            headers = @{}
                            body = @{
                                value = @(
                                    @{
                                        id = 'assignment-1'
                                        principalId = 'sp-1'
                                        resourceId = 'resource-sp'
                                        resourceDisplayName = 'Resource SP'
                                        appRoleId = 'role-1'
                                    }
                                )
                            }
                        },
                        @{
                            id = '3'
                            status = 200
                            headers = @{}
                            body = @{
                                value = @(
                                    @{
                                        '@odata.type' = '#microsoft.graph.group'
                                        id = 'group-1'
                                        displayName = 'Group One'
                                    }
                                )
                            }
                        }
                    )
                }
            }

            $result = Invoke-InspectorGraphBatchRequest -Requests @(
                [PSCustomObject]@{
                    Uri = 'https://graph.microsoft.com/v1.0/applications/app-1/owners'
                    RequiredPermission = 'Application.Read.All'
                }
                [PSCustomObject]@{
                    Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/appRoleAssignments'
                    RequiredPermission = 'Application.Read.All'
                }
                [PSCustomObject]@{
                    Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/memberOf'
                    RequiredPermission = 'Application.Read.All'
                }
            ) -RuntimeTelemetry (New-InspectorRuntimeTelemetry)

            $owner = @($result[0].ObservedValue)[0]
            $assignment = @($result[1].ObservedValue)[0]
            $membership = @($result[2].ObservedValue)[0]

            ($owner -is [PSCustomObject]) | Should -BeTrue
            $owner.PSObject.Properties['id'].Value | Should -Be 'owner-1'
            $owner.PSObject.Properties['@odata.type'].Value | Should -Be '#microsoft.graph.user'

            ($assignment -is [PSCustomObject]) | Should -BeTrue
            $assignment.PSObject.Properties['principalId'].Value | Should -Be 'sp-1'
            $assignment.PSObject.Properties['resourceId'].Value | Should -Be 'resource-sp'

            ($membership -is [PSCustomObject]) | Should -BeTrue
            $membership.PSObject.Properties['id'].Value | Should -Be 'group-1'
            $membership.PSObject.Properties['@odata.type'].Value | Should -Be '#microsoft.graph.group'
        }

        It 'follows each subrequest nextLink without creating extra logical evidence operations' {
            $script:batchCall = 0

            Mock Invoke-MgGraphRequest {
                $script:batchCall++
                if ($script:batchCall -eq 1) {
                    return [PSCustomObject]@{
                        responses = @(
                            [PSCustomObject]@{
                                id = '1'
                                status = 200
                                headers = @{}
                                body = [PSCustomObject]@{
                                    value = @([PSCustomObject]@{ id = 'page-1' })
                                    '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/memberOf?$skiptoken=next'
                                }
                            }
                        )
                    }
                }

                [PSCustomObject]@{
                    responses = @(
                        [PSCustomObject]@{
                            id = '1'
                            status = 200
                            headers = @{}
                            body = [PSCustomObject]@{
                                value = @([PSCustomObject]@{ id = 'page-2' })
                            }
                        }
                    )
                }
            }

            $telemetry = New-InspectorRuntimeTelemetry
            $result = Invoke-InspectorGraphBatchRequest -Requests @(
                [PSCustomObject]@{
                    Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/memberOf'
                    RequiredPermission = 'Application.Read.All'
                }
            ) -RuntimeTelemetry $telemetry

            $result.Count | Should -Be 1
            $result[0].Status | Should -Be 'Success'
            $pagedValues = @($result[0].ObservedValue)
            $pagedValues.Count | Should -Be 2
            $pagedValues[0].id | Should -Be 'page-1'
            $pagedValues[1].id | Should -Be 'page-2'
            $telemetry.GraphRequestSummary.TotalRequests | Should -Be 1
            $telemetry.GraphTransportSummary.TotalHttpRequests | Should -Be 2
            $telemetry.GraphTransportSummary.BatchHttpRequests | Should -Be 2
            Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly
        }

        It 'retries throttled subrequests using Retry-After and keeps one logical telemetry record' {
            $script:attempt = 0
            Mock Start-Sleep {}
            Mock Invoke-MgGraphRequest {
                $script:attempt++
                if ($script:attempt -eq 1) {
                    return [PSCustomObject]@{
                        responses = @(
                            [PSCustomObject]@{
                                id = '1'
                                status = 429
                                headers = @{ 'Retry-After' = '2' }
                                body = [PSCustomObject]@{}
                            }
                        )
                    }
                }

                [PSCustomObject]@{
                    responses = @(
                        [PSCustomObject]@{
                            id = '1'
                            status = 200
                            headers = @{}
                            body = [PSCustomObject]@{ value = @() }
                        }
                    )
                }
            }

            $telemetry = New-InspectorRuntimeTelemetry
            $result = Invoke-InspectorGraphBatchRequest -Requests @(
                [PSCustomObject]@{
                    Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/owners'
                    RequiredPermission = 'Application.Read.All'
                }
            ) -RuntimeTelemetry $telemetry

            $result[0].Status | Should -Be 'Success'
            $telemetry.GraphRequestSummary.TotalRequests | Should -Be 1
            $telemetry.GraphTransportSummary.TotalHttpRequests | Should -Be 2
            Should -Invoke Start-Sleep -ParameterFilter { $Seconds -eq 2 } -Times 1 -Exactly
            Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly
        }

        It 'fails a missing correlated subresponse closed instead of silently treating it as empty' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ responses = @() }
            }

            $result = Invoke-InspectorGraphBatchRequest -Requests @(
                [PSCustomObject]@{
                    Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/owners'
                    RequiredPermission = 'Application.Read.All'
                }
            ) -RuntimeTelemetry (New-InspectorRuntimeTelemetry)

            $result.Count | Should -Be 1
            $result[0].Status | Should -Be 'Failed'
            @($result[0].Limitations) -join ' ' | Should -Match 'correlated subresponse'
        }

        It 'rejects non-v1.0 or non-Graph subrequests before any batch transport call' {
            Mock Invoke-MgGraphRequest {
                throw 'Batch transport must not be called for ineligible subrequests.'
            }

            $telemetry = New-InspectorRuntimeTelemetry

            $result = Invoke-InspectorGraphBatchRequest -Requests @(
                [PSCustomObject]@{ Uri = 'https://graph.microsoft.com/beta/servicePrincipals/sp-1/memberOf'; RequiredPermission = 'Application.Read.All' }
                [PSCustomObject]@{ Uri = 'https://example.invalid/v1.0/users'; RequiredPermission = 'User.Read.All' }
            ) -RuntimeTelemetry $telemetry

            $result.Count | Should -Be 2
            @($result | Where-Object Status -ne 'Failed').Count | Should -Be 0
            $telemetry.GraphRequestSummary.TotalRequests | Should -Be 2
            $telemetry.GraphTransportSummary.TotalHttpRequests | Should -Be 0
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
    }
}

Describe 'Graph batch snapshot integration' {
    InModuleScope EntraObjectInspector {
        BeforeEach {
            Mock Get-MgContext {
                [PSCustomObject]@{
                    TenantId = 'tenant-1'
                    ClientId = 'client-1'
                    Scopes = @('Application.Read.All','GroupMember.Read.All','Member.Read.Hidden')
                }
            }

            Mock Invoke-InspectorGraphRequest {
                $items = switch -Wildcard ($Uri) {
                    '*/applications?*' {
                        @([PSCustomObject]@{
                            id = 'app-1'
                            appId = 'app-id-1'
                            displayName = 'Application One'
                            keyCredentials = @()
                            passwordCredentials = @()
                            appRoles = @()
                            requiredResourceAccess = @()
                        })
                        break
                    }
                    '*/servicePrincipals?*' {
                        @([PSCustomObject]@{
                            id = 'sp-1'
                            appId = 'app-id-1'
                            displayName = 'Service Principal One'
                            servicePrincipalType = 'Application'
                            appOwnerOrganizationId = 'tenant-1'
                            keyCredentials = @()
                            passwordCredentials = @()
                            appRoles = @()
                        })
                        break
                    }
                    '*/organization?*' {
                        @([PSCustomObject]@{
                            id = 'tenant-1'
                            displayName = 'Tenant One'
                            verifiedDomains = @()
                        })
                        break
                    }
                    '*/groups/*/owners?*' { @(); break }
                    '*/groups/*/members?*' { @(); break }
                    '*/groups/*/memberOf?*' { @(); break }
                    '*/groups?*' {
                        @([PSCustomObject]@{
                            id = 'group-1'
                            displayName = 'Group One'
                            visibility = 'Private'
                        })
                        break
                    }
                    '*/oauth2PermissionGrants?*' { @(); break }
                    '*/roleManagement/directory/roleAssignments?*' { @(); break }
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

            Mock Invoke-MgGraphRequest {
                $payload = $Body | ConvertFrom-Json
                $responses = @(
                    foreach ($request in @($payload.requests)) {
                        $value = switch -Wildcard ([string]$request.url) {
                            '/applications/app-1/owners*' {
                                @(
                                    @{
                                        '@odata.type' = '#microsoft.graph.user'
                                        id = 'owner-app'
                                        displayName = 'Application Owner'
                                    }
                                )
                                break
                            }
                            '/servicePrincipals/sp-1/owners*' {
                                @(
                                    @{
                                        '@odata.type' = '#microsoft.graph.user'
                                        id = 'owner-sp'
                                        displayName = 'Service Principal Owner'
                                    }
                                )
                                break
                            }
                            '/servicePrincipals/sp-1/appRoleAssignments*' {
                                @(
                                    @{
                                        id = 'assignment-out'
                                        principalId = 'sp-1'
                                        resourceId = 'resource-sp'
                                        resourceDisplayName = 'Resource Service Principal'
                                        appRoleId = 'role-out'
                                    }
                                )
                                break
                            }
                            '/servicePrincipals/sp-1/appRoleAssignedTo*' {
                                @(
                                    @{
                                        id = 'assignment-in'
                                        principalId = 'principal-sp'
                                        principalType = 'ServicePrincipal'
                                        principalDisplayName = 'Principal Service Principal'
                                        resourceId = 'sp-1'
                                        appRoleId = 'role-in'
                                    }
                                )
                                break
                            }
                            '/servicePrincipals/sp-1/memberOf*' {
                                @(
                                    @{
                                        '@odata.type' = '#microsoft.graph.group'
                                        id = 'group-1'
                                        displayName = 'Group One'
                                    }
                                )
                                break
                            }
                            default { @() }
                        }

                        @{
                            id = [string]$request.id
                            status = 200
                            headers = @{}
                            body = @{ value = $value }
                        }
                    }
                )

                @{ responses = $responses }
            }
        }

        It 'preserves non-empty dictionary relationship data through batch snapshot indexing and relationship projection' {
            $telemetry = New-InspectorRuntimeTelemetry
            $snapshot = New-InspectorTenantSnapshot `
                -ObjectType @('Application','ServicePrincipal','Group') `
                -RuntimeTelemetry $telemetry

            $snapshot.AssessmentCoverage.Status | Should -Be 'Success'
            $snapshot.AssessmentCoverage.Completeness | Should -Be 'Complete'
            $snapshot.AssessmentCoverage.EvidencePlanMatches | Should -BeTrue

            @($snapshot.Collections.ApplicationOwners).Count | Should -Be 1
            @($snapshot.Collections.ServicePrincipalOwners).Count | Should -Be 1
            @($snapshot.Collections.AppRoleAssignments).Count | Should -Be 1
            @($snapshot.Collections.AppRoleAssignedTo).Count | Should -Be 1
            @($snapshot.Collections.ServicePrincipalGroupMemberships).Count | Should -Be 1

            $applicationOwner = $snapshot.Collections.ApplicationOwners[0].Owner
            $applicationOwner.PSObject.Properties['id'].Value | Should -Be 'owner-app'
            $applicationOwner.PSObject.Properties['@odata.type'].Value | Should -Be '#microsoft.graph.user'

            $outboundAssignment = $snapshot.Collections.AppRoleAssignments[0].Assignment
            $outboundAssignment.PSObject.Properties['principalId'].Value | Should -Be 'sp-1'
            $outboundAssignment.PSObject.Properties['resourceId'].Value | Should -Be 'resource-sp'

            $membership = $snapshot.Collections.ServicePrincipalGroupMemberships[0].Membership
            $membership.PSObject.Properties['id'].Value | Should -Be 'group-1'
            $membership.PSObject.Properties['@odata.type'].Value | Should -Be '#microsoft.graph.group'

            $reconstructedMember = @(
                $snapshot.Collections.GroupMembers |
                    Where-Object SourceObjectId -eq 'group-1' |
                    ForEach-Object Member |
                    Where-Object id -eq 'sp-1'
            )
            $reconstructedMember.Count | Should -Be 1
            $reconstructedMember[0].PSObject.Properties['@odata.type'].Value | Should -Be '#microsoft.graph.servicePrincipal'

            $discovery = ConvertFrom-InspectorTenantSnapshot `
                -TenantSnapshot $snapshot `
                -ObjectType @('Application','ServicePrincipal','Group')
            $resolution = [PSCustomObject]@{
                DirectMatches = @($discovery.DiscoveredObjects)
                RelatedObjects = @()
            }

            $relationshipResult = Get-InspectorSnapshotRelationships `
                -Resolution $resolution `
                -TenantSnapshot $snapshot

            $relationshipResult.Status | Should -Be 'Success'
            $relationshipResult.Completeness | Should -Be 'Complete'

            @($relationshipResult.Relationships | Where-Object {
                $_.RelationshipType -eq 'OwnedBy' -and
                $_.SourceObjectId -eq 'app-1' -and
                $_.TargetObjectId -eq 'owner-app' -and
                $_.TargetObjectType -eq 'user'
            }).Count | Should -Be 1

            @($relationshipResult.Relationships | Where-Object {
                $_.RelationshipType -eq 'GrantedAppRole' -and
                $_.SourceObjectId -eq 'sp-1' -and
                $_.TargetObjectId -eq 'resource-sp'
            }).Count | Should -Be 1

            @($relationshipResult.Relationships | Where-Object {
                $_.RelationshipType -eq 'AssignedToAppRole' -and
                $_.SourceObjectId -eq 'principal-sp' -and
                $_.TargetObjectId -eq 'sp-1'
            }).Count | Should -Be 1

            @($relationshipResult.Relationships | Where-Object {
                $_.RelationshipType -eq 'HasMember' -and
                $_.SourceObjectId -eq 'group-1' -and
                $_.TargetObjectId -eq 'sp-1' -and
                $_.TargetObjectType -eq 'servicePrincipal'
            }).Count | Should -Be 1

            $telemetry.GraphRequestSummary.TotalRequests | Should -BeGreaterThan 0
            $telemetry.GraphTransportSummary.BatchHttpRequests | Should -Be 2
            Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly
        }
    }
}
