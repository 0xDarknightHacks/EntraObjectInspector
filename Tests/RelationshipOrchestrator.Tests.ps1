$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Invoke-InspectorRelationshipCollection' {

    InModuleScope EntraObjectInspector {

        It 'returns NotApplicable for an unresolved object' {
            $resolution = [PSCustomObject]@{
                Status = 'NotFound'
                DirectMatches = @()
                RelatedObjects = @()
                PrimaryObject = $null
            }

            $result = Invoke-InspectorRelationshipCollection -Resolution $resolution

            $result.Status | Should -Be 'NotApplicable'
            $result.CollectorResults.Count | Should -Be 0
        }

        It 'selects both Application and ServicePrincipal collectors for an application identity' {
            $app = [PSCustomObject]@{
                ObjectType = 'Application'
                Identifiers = [PSCustomObject]@{
                    ObjectId = '11111111-1111-1111-1111-111111111111'
                    AppId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                }
            }

            $sp = [PSCustomObject]@{
                ObjectType = 'ServicePrincipal'
                Identifiers = [PSCustomObject]@{
                    ObjectId = '22222222-2222-2222-2222-222222222222'
                    AppId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                }
            }

            $resolution = [PSCustomObject]@{
                Status = 'Resolved'
                DirectMatches = @($app, $sp)
                RelatedObjects = @()
                PrimaryObject = $app
            }

            Mock Get-InspectorApplicationRelationships {
                [PSCustomObject]@{
                    Status = 'Success'
                    Completeness = 'Complete'
                    Relationships = @()
                    Artifacts = @()
                    Evidence = @()
                    Limitations = @()
                }
            }

            Mock Get-InspectorServicePrincipalRelationships {
                [PSCustomObject]@{
                    Status = 'Success'
                    Completeness = 'Complete'
                    Relationships = @()
                    Artifacts = @()
                    Evidence = @()
                    Limitations = @()
                }
            }

            $result = Invoke-InspectorRelationshipCollection -Resolution $resolution

            $result.Status | Should -Be 'Success'
            $result.CollectorResults.Count | Should -Be 2

            Should-Invoke Get-InspectorApplicationRelationships -Times 1 -Exactly
            Should-Invoke Get-InspectorServicePrincipalRelationships -Times 1 -Exactly
        }

        It 'propagates InsufficientPermission when any collector is permission-limited' {
            $user = [PSCustomObject]@{
                ObjectType = 'User'
                Identifiers = [PSCustomObject]@{
                    ObjectId = '11111111-1111-1111-1111-111111111111'
                }
            }

            $resolution = [PSCustomObject]@{
                Status = 'Resolved'
                DirectMatches = @($user)
                RelatedObjects = @()
                PrimaryObject = $user
            }

            Mock Get-InspectorUserRelationships {
                [PSCustomObject]@{
                    Status = 'InsufficientPermission'
                    Completeness = 'Partial'
                    Relationships = @()
                    Artifacts = @()
                    Evidence = @()
                    Limitations = @('Missing permission')
                }
            }

            $result = Invoke-InspectorRelationshipCollection -Resolution $resolution

            $result.Status | Should -Be 'InsufficientPermission'
            $result.Completeness | Should -Be 'Partial'
            $result.Limitations | Should -Contain 'Missing permission'
        }
    }
}
