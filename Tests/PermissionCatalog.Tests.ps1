$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'permission catalog' {

    InModuleScope EntraObjectInspector {

        It 'returns Microsoft Graph permission catalog entries' {
            $catalog = Get-InspectorPermissionCatalog

            $catalog.Count | Should -BeGreaterThan 5
            $catalog.PermissionName | Should -Contain 'Application.Read.All'
            $catalog.PermissionName | Should -Contain 'Directory.ReadWrite.All'
            $catalog.PermissionName | Should -Contain 'AppRoleAssignment.ReadWrite.All'
            $catalog.PermissionName | Should -Contain 'RoleManagement.ReadWrite.Directory'
        }

        It 'resolves a known Microsoft Graph appRoleId' {
            $entry =
                Resolve-InspectorPermissionMetadata `
                    -AppRoleId '19dbc75e-c2e2-444c-a770-ec69d8559fc7' `
                    -ResourceDisplayName 'Microsoft Graph'

            $entry.CatalogStatus | Should -Be 'Resolved'
            $entry.PermissionName | Should -Be 'Directory.ReadWrite.All'
            $entry.IsHighImpact | Should -BeTrue
            $entry.Confidence | Should -Be 'High'
        }

        It 'returns Unknown for an appRoleId not in the local catalog' {
            $entry =
                Resolve-InspectorPermissionMetadata `
                    -AppRoleId '00000000-0000-0000-0000-000000000123' `
                    -ResourceDisplayName 'Microsoft Graph'

            $entry.CatalogStatus | Should -Be 'Unknown'
            $entry.PermissionName | Should -BeNullOrEmpty
            $entry.Confidence | Should -Be 'Low'
        }
    }
}

