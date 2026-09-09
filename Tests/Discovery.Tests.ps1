$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'tenant discovery' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-DiscoveryGraphResult {
                param (
                    [string]$Uri,
                    [string]$RequiredPermission,
                    [string]$Status = 'Success',
                    [object[]]$ObservedValue = @(),
                    [string[]]$Limitations = @()
                )

                [PSCustomObject]@{
                    SourceEndpoint = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime = '2026-08-30T10:00:00.0000000Z'
                    Status = $Status
                    ObservedValue = $ObservedValue
                    Limitations = $Limitations
                }
            }
        }

        BeforeEach {
            Mock Invoke-InspectorGraphRequest {
                param($Uri, $RequiredPermission)

                if ($Uri -like '*applications*') {
                    return New-DiscoveryGraphResult -Uri $Uri -RequiredPermission $RequiredPermission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'app-object-1'
                            appId = 'client-id-1'
                            displayName = 'App One'
                        }
                    )
                }

                if ($Uri -like '*servicePrincipals*') {
                    return New-DiscoveryGraphResult -Uri $Uri -RequiredPermission $RequiredPermission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'sp-object-1'
                            appId = 'client-id-1'
                            displayName = 'SP One'
                            servicePrincipalType = 'Application'
                        }
                    )
                }

                if ($Uri -like '*users*') {
                    return New-DiscoveryGraphResult -Uri $Uri -RequiredPermission $RequiredPermission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'user-object-1'
                            userPrincipalName = 'user1@contoso.com'
                            displayName = 'User One'
                        }
                    )
                }

                if ($Uri -like '*groups*') {
                    return New-DiscoveryGraphResult -Uri $Uri -RequiredPermission $RequiredPermission -ObservedValue @(
                        [PSCustomObject]@{
                            id = 'group-object-1'
                            displayName = 'Group One'
                        }
                    )
                }

                return New-DiscoveryGraphResult -Uri $Uri -RequiredPermission $RequiredPermission
            }
        }

        It 'discovers applications with stable inspection identities' {
            $result = Get-InspectorDiscoveredApplications

            $result.Status | Should -Be 'Success'
            $result.ObjectType | Should -Be 'Application'
            $result.DiscoveredObjects.Count | Should -Be 1
            $result.DiscoveredObjects[0].ObjectKey | Should -Be 'Application:app-object-1'
            $result.DiscoveredObjects[0].InspectionIdentity | Should -Be 'app-object-1'
            $result.Evidence[0].RequiredPermission | Should -Be 'Application.Read.All'
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName&$top=999' } -Times 1 -Exactly
        }

        It 'discovers users using UPN as inspection identity when available' {
            $result = Get-InspectorDiscoveredUsers

            $result.Status | Should -Be 'Success'
            $result.DiscoveredObjects[0].ObjectKey | Should -Be 'User:user-object-1'
            $result.DiscoveredObjects[0].InspectionIdentity | Should -Be 'user1@contoso.com'
            $result.Evidence[0].RequiredPermission | Should -Be 'User.Read.All'
        }

        It 'discovers all requested object types deterministically' {
            $result =
                Invoke-InspectorDiscovery `
                    -ObjectType @('User', 'Application', 'Group', 'ServicePrincipal')

            $result.Status | Should -Be 'Success'
            $result.TotalCount | Should -Be 4
            $result.CountsByType.Application | Should -Be 1
            $result.CountsByType.ServicePrincipal | Should -Be 1
            $result.CountsByType.User | Should -Be 1
            $result.CountsByType.Group | Should -Be 1
            $result.DiscoveredObjects.ObjectType | Should -Be @(
                'Application',
                'Group',
                'ServicePrincipal',
                'User'
            )
            Should -Invoke Invoke-InspectorGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType&$top=100' } -Times 1 -Exactly
        }

        It 'respects MaxObjectsPerType' {
            Mock Invoke-InspectorGraphRequest {
                param($Uri, $RequiredPermission)

                return New-DiscoveryGraphResult -Uri $Uri -RequiredPermission $RequiredPermission -ObservedValue @(
                    [PSCustomObject]@{ id = 'app-1'; appId = 'client-1'; displayName = 'One' },
                    [PSCustomObject]@{ id = 'app-2'; appId = 'client-2'; displayName = 'Two' }
                )
            }

            $result =
                Invoke-InspectorDiscovery `
                    -ObjectType @('Application') `
                    -MaxObjectsPerType 1

            $result.TotalCount | Should -Be 1
        }

        It 'surfaces discovery permission failures without throwing' {
            Mock Invoke-InspectorGraphRequest {
                param($Uri, $RequiredPermission)

                return New-DiscoveryGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $RequiredPermission `
                    -Status 'InsufficientPermission' `
                    -Limitations @('Synthetic 403')
            }

            $result =
                Invoke-InspectorDiscovery `
                    -ObjectType @('Application')

            $result.Status | Should -Be 'Partial'
            $result.TotalCount | Should -Be 0
            $result.Evidence[0].Status | Should -Be 'InsufficientPermission'
            $result.Limitations | Should -Contain 'Synthetic 403'
        }
    }
}

