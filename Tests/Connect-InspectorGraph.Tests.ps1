$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Connect-InspectorGraph' {

    InModuleScope EntraObjectInspector {

        BeforeEach {

            $script:testClientId =
                '11111111-1111-1111-1111-111111111111'

            $script:testTenantId =
                '22222222-2222-2222-2222-222222222222'

            $script:testSecret =
                ConvertTo-SecureString `
                    'unit-test-secret' `
                    -AsPlainText `
                    -Force
        }

        It 'fails when configuration does not exist' {

            Mock Test-Path {
                $false
            }

            {
                Connect-InspectorGraph
            } | Should -Throw
        }

        It 'fails when the secret is unavailable' {

            Mock Test-Path {
                $true
            }

            Mock Get-Content {
                @{
                    TenantId = $script:testTenantId
                    ClientId = $script:testClientId
                } |
                ConvertTo-Json
            }

            Mock Get-Secret {
                $null
            }

            {
                Connect-InspectorGraph
            } | Should -Throw
        }

        It 'constructs client-secret authentication with the Client ID as username' {

            Mock Test-Path {
                $true
            }

            Mock Get-Content {
                @{
                    TenantId = $script:testTenantId
                    ClientId = $script:testClientId
                } |
                ConvertTo-Json
            }

            Mock Get-Secret {
                $script:testSecret
            }

            Mock Connect-MgGraph {}

            Mock Get-MgContext {
                [PSCustomObject]@{
                    AuthType = 'AppOnly'
                    TenantId = $script:testTenantId
                    ClientId = $script:testClientId
                }
            }

            $result = Connect-InspectorGraph

            $result.AuthType |
                Should -Be 'AppOnly'

            Should-Invoke `
                Connect-MgGraph `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $TenantId -eq $script:testTenantId -and
                    $ClientSecretCredential.UserName -eq
                        $script:testClientId
                }
        }

        It 'retries SecretStore password failures up to three attempts and then connects' {

            Mock Test-Path {
                $true
            }

            Mock Get-Content {
                @{
                    TenantId = $script:testTenantId
                    ClientId = $script:testClientId
                } |
                ConvertTo-Json
            }

            $script:secretStoreAttempts = 0
            Mock Get-Secret {
                $script:secretStoreAttempts++
                if ($script:secretStoreAttempts -lt 3) {
                    throw 'A valid password is required to access the Microsoft.PowerShell.SecretStore vault.'
                }

                $script:testSecret
            }

            Mock Connect-MgGraph {}

            Mock Get-MgContext {
                [PSCustomObject]@{
                    AuthType = 'AppOnly'
                    TenantId = $script:testTenantId
                    ClientId = $script:testClientId
                }
            }

            $result = Connect-InspectorGraph -WarningAction SilentlyContinue

            $result.AuthType | Should -Be 'AppOnly'
            Should-Invoke Get-Secret -Times 3 -Exactly
            Should-Invoke Connect-MgGraph -Times 1 -Exactly
        }

        It 'fails cleanly after three SecretStore password attempts' {

            Mock Test-Path {
                $true
            }

            Mock Get-Content {
                @{
                    TenantId = $script:testTenantId
                    ClientId = $script:testClientId
                } |
                ConvertTo-Json
            }

            Mock Get-Secret {
                throw 'A valid password is required to access the Microsoft.PowerShell.SecretStore vault.'
            }

            Mock Connect-MgGraph {}

            {
                Connect-InspectorGraph -WarningAction SilentlyContinue
            } | Should -Throw '*after 3 password attempts*'

            Should-Invoke Get-Secret -Times 3 -Exactly
            Should-Invoke Connect-MgGraph -Times 0 -Exactly
        }

        It 'rejects a non-AppOnly resulting context' {

            Mock Test-Path {
                $true
            }

            Mock Get-Content {
                @{
                    TenantId = $script:testTenantId
                    ClientId = $script:testClientId
                } |
                ConvertTo-Json
            }

            Mock Get-Secret {
                $script:testSecret
            }

            Mock Connect-MgGraph {}

            Mock Get-MgContext {
                [PSCustomObject]@{
                    AuthType = 'Delegated'
                }
            }

            {
                Connect-InspectorGraph
            } | Should -Throw
        }
    }
}
