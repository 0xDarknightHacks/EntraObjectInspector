BeforeAll {
    $modulePath =
        Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'
}

Describe 'EntraObjectInspector module' {

    It 'has a valid module manifest' {
        {
            Test-ModuleManifest `
                -Path $modulePath `
                -ErrorAction Stop
        } | Should -Not -Throw
    }

    It 'imports successfully' {
        {
            Import-Module `
                $modulePath `
                -Force `
                -ErrorAction Stop
        } | Should -Not -Throw
    }

    It 'exports only the public authentication, inspection, intelligence, export, and report commands' {
        Import-Module $modulePath -Force

        $module = Get-Module EntraObjectInspector

        @($module.ExportedFunctions.Keys).Count | Should -Be 7
        $module.ExportedFunctions.Keys | Should -Contain 'Connect-InspectorGraph'
        $module.ExportedFunctions.Keys | Should -Contain 'Get-EntraObjectInsight'
        $module.ExportedFunctions.Keys | Should -Contain 'Invoke-EntraTenantInspection'
        $module.ExportedFunctions.Keys | Should -Contain 'Export-EntraTenantInspection'
        $module.ExportedFunctions.Keys | Should -Contain 'Invoke-EntraAssessmentIntelligence'
        $module.ExportedFunctions.Keys | Should -Contain 'Export-EntraAssessmentReport'
        $module.ExportedFunctions.Keys | Should -Contain 'Invoke-EntraSecurityAssessment'
    }
}
