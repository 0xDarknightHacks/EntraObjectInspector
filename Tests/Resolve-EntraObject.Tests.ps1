$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Resolve-EntraObject' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestResolverGraphResult {
                param (
                    [Parameter(Mandatory)]
                    [string]$Uri,

                    [Parameter(Mandatory)]
                    [string]$RequiredPermission,

                    [Parameter(Mandatory)]
                    [string]$Status,

                    [object[]]$ObservedValue = @(),

                    [string[]]$Limitations = @()
                )

                [PSCustomObject]@{
                    SourceEndpoint     = $Uri
                    RequiredPermission = $RequiredPermission
                    CollectionTime     = '2026-08-29T20:00:00.0000000Z'
                    Status             = $Status
                    ObservedValue      = $ObservedValue
                    Limitations        = $Limitations
                }
            }
        }

        BeforeEach {
            $script:resolverHandler = $null

            Mock Invoke-InspectorGraphRequest {
                param(
                    $Uri,
                    $RequiredPermission
                )

                if ($null -ne $script:resolverHandler) {
                    return & $script:resolverHandler `
                        $Uri `
                        $RequiredPermission
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $RequiredPermission `
                    -Status 'NotFound'
            }
        }

        It 'returns UnsupportedIdentifier without querying Graph for unsupported input' {

            $result = Resolve-EntraObject `
                -Identity 'not-an-entra-identifier'

            $result.Status |
                Should -Be 'UnsupportedIdentifier'

            $result.InputShape |
                Should -Be 'Unsupported'

            $result.Evidence.Count |
                Should -Be 0

            Should-Invoke `
                Invoke-InspectorGraphRequest `
                -Times 0
        }

        It 'resolves a UPN-like input as a User' {

            $script:resolverHandler = {
                param($Uri, $Permission)

                if ($Uri -like '*/users/*') {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = '11111111-1111-1111-1111-111111111111'
                                displayName = 'Alice Example'
                                userPrincipalName = 'alice@contoso.com'
                            }
                        )
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'NotFound'
            }

            $result = Resolve-EntraObject `
                -Identity 'alice@contoso.com'

            $result.Status |
                Should -Be 'Resolved'

            $result.InputShape |
                Should -Be 'UpnLike'

            $result.ResolutionType |
                Should -Be 'User'

            $result.PrimaryObject.ObjectType |
                Should -Be 'User'

            $result.Evidence.Count |
                Should -Be 1

            $result.Evidence[0].Status |
                Should -Be 'Success'
        }

        It 'returns NotFound for a UPN that Graph cannot resolve' {

            $result = Resolve-EntraObject `
                -Identity 'missing@contoso.com'

            $result.Status |
                Should -Be 'NotFound'

            $result.Evidence.Count |
                Should -Be 1
        }

        It 'returns InsufficientPermission when the UPN query returns 403' {

            $script:resolverHandler = {
                param($Uri, $Permission)

                New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'InsufficientPermission'
            }

            $result = Resolve-EntraObject `
                -Identity 'alice@contoso.com'

            $result.Status |
                Should -Be 'InsufficientPermission'
        }

        It 'resolves a GUID as a User object ID only after probing supported meanings' {

            $guid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

            $script:resolverHandler = {
                param($Uri, $Permission)

                if ($Uri -like "*/users/$guid*") {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = $guid
                                displayName = 'GUID User'
                                userPrincipalName = 'guid.user@contoso.com'
                            }
                        )
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'NotFound'
            }

            $result = Resolve-EntraObject -Identity $guid

            $result.Status |
                Should -Be 'Resolved'

            $result.ResolutionType |
                Should -Be 'User'

            $result.PrimaryObject.MatchBasis |
                Should -Contain 'ObjectId'

            $result.Evidence.Count |
                Should -Be 6

            Should-Invoke `
                Invoke-InspectorGraphRequest `
                -Times 6 `
                -Exactly
        }

        It 'resolves an Application object ID and discovers its related Service Principal' {

            $objectId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            $appId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            $spId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'

            $script:resolverHandler = {
                param($Uri, $Permission)

                if ($Uri -like "*/applications/$objectId*") {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = $objectId
                                appId = $appId
                                displayName = 'Application A'
                            }
                        )
                }

                if ($Uri -like "*servicePrincipals(appId='$appId')*") {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = $spId
                                appId = $appId
                                displayName = 'Application A Enterprise App'
                            }
                        )
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'NotFound'
            }

            $result = Resolve-EntraObject -Identity $objectId

            $result.Status |
                Should -Be 'Resolved'

            $result.ResolutionType |
                Should -Be 'Application'

            $result.PrimaryObject.ObjectType |
                Should -Be 'Application'

            $result.RelatedObjects.Count |
                Should -Be 1

            $result.RelatedObjects[0].ObjectType |
                Should -Be 'ServicePrincipal'

            $result.Relationships.Count |
                Should -Be 1

            $result.Relationships[0].RelationshipType |
                Should -Be 'ApplicationToServicePrincipal'

            $result.Evidence.Count |
                Should -Be 7
        }

        It 'resolves a Client ID to the Application and Service Principal as one logical identity' {

            $appId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            $applicationObjectId =
                'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            $servicePrincipalObjectId =
                'cccccccc-cccc-cccc-cccc-cccccccccccc'

            $script:resolverHandler = {
                param($Uri, $Permission)

                if ($Uri -like "*applications(appId='$appId')*") {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = $applicationObjectId
                                appId = $appId
                                displayName = 'Client ID App'
                            }
                        )
                }

                if ($Uri -like "*servicePrincipals(appId='$appId')*") {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = $servicePrincipalObjectId
                                appId = $appId
                                displayName = 'Client ID Enterprise App'
                            }
                        )
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'NotFound'
            }

            $result = Resolve-EntraObject -Identity $appId

            $result.Status |
                Should -Be 'Resolved'

            $result.ResolutionType |
                Should -Be 'ApplicationIdentity'

            $result.DirectMatches.Count |
                Should -Be 2

            $result.PrimaryObject.ObjectType |
                Should -Be 'Application'

            $result.Relationships.Count |
                Should -Be 1

            $result.Evidence.Count |
                Should -Be 6
        }

        It 'can resolve a Client ID when only the local Service Principal exists' {

            $appId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            $servicePrincipalObjectId =
                'cccccccc-cccc-cccc-cccc-cccccccccccc'

            $script:resolverHandler = {
                param($Uri, $Permission)

                if ($Uri -like "*servicePrincipals(appId='$appId')*") {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = $servicePrincipalObjectId
                                appId = $appId
                                displayName = 'External Application'
                            }
                        )
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'NotFound'
            }

            $result = Resolve-EntraObject -Identity $appId

            $result.Status |
                Should -Be 'Resolved'

            $result.ResolutionType |
                Should -Be 'ApplicationIdentity'

            $result.PrimaryObject.ObjectType |
                Should -Be 'ServicePrincipal'

            $result.DirectMatches.Count |
                Should -Be 1
        }

        It 'returns Ambiguous when a GUID is both an unrelated object ID and an appId' {

            $guid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            $applicationObjectId =
                'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'

            $script:resolverHandler = {
                param($Uri, $Permission)

                if ($Uri -like "*/users/$guid*") {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = $guid
                                displayName = 'Collision User'
                                userPrincipalName = 'collision@contoso.com'
                            }
                        )
                }

                if ($Uri -like "*applications(appId='$guid')*") {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Success' `
                        -ObservedValue @(
                            [PSCustomObject]@{
                                id = $applicationObjectId
                                appId = $guid
                                displayName = 'Collision Application'
                            }
                        )
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'NotFound'
            }

            $result = Resolve-EntraObject -Identity $guid

            $result.Status |
                Should -Be 'Ambiguous'

            $result.PrimaryObject |
                Should -BeNullOrEmpty

            $result.DirectMatches.Count |
                Should -Be 2
        }

        It 'returns InsufficientPermission if any required GUID probe is forbidden' {

            $guid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

            $script:resolverHandler = {
                param($Uri, $Permission)

                if ($Uri -like '*/applications/*') {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'InsufficientPermission'
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'NotFound'
            }

            $result = Resolve-EntraObject -Identity $guid

            $result.Status |
                Should -Be 'InsufficientPermission'

            $result.Evidence.Count |
                Should -Be 6
        }

        It 'returns Indeterminate instead of guessing when a required GUID probe fails unexpectedly' {

            $guid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

            $script:resolverHandler = {
                param($Uri, $Permission)

                if ($Uri -like '*/groups/*') {
                    return New-TestResolverGraphResult `
                        -Uri $Uri `
                        -RequiredPermission $Permission `
                        -Status 'Failed' `
                        -Limitations @(
                            'Synthetic transport failure.'
                        )
                }

                return New-TestResolverGraphResult `
                    -Uri $Uri `
                    -RequiredPermission $Permission `
                    -Status 'NotFound'
            }

            $result = Resolve-EntraObject -Identity $guid

            $result.Status |
                Should -Be 'Indeterminate'

            $result.Limitations.Count |
                Should -BeGreaterThan 0
        }

        It 'preserves endpoint, timestamp, status, result, permission, and limitations for every Graph query' {

            $result = Resolve-EntraObject `
                -Identity 'missing@contoso.com'

            $result.Evidence.Count |
                Should -Be 1

            $record = $result.Evidence[0]

            $record.Endpoint |
                Should -Not -BeNullOrEmpty

            $record.CollectionTime |
                Should -Not -BeNullOrEmpty

            $record.Status |
                Should -Be 'NotFound'

            $record.RequiredPermission |
                Should -Be 'User.Read.All'

            $record.PSObject.Properties.Name |
                Should -Contain 'Result'

            $record.PSObject.Properties.Name |
                Should -Contain 'Limitations'
        }
    }
}
