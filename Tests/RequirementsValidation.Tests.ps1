Describe 'Requirements validation helper' {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot '..\Scripts\Test-EntraObjectInspectorRequirements.ps1'
        $modulePath = Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'
    }

    It 'exists under Scripts' {
        Test-Path -LiteralPath $scriptPath | Should -BeTrue
    }

    It 'exposes operational validation parameters' {
        $command = Get-Command $scriptPath

        $command.Parameters.Keys | Should -Contain 'RunTests'
        $command.Parameters.Keys | Should -Contain 'TestOutputPath'
        $command.Parameters.Keys | Should -Contain 'LogDirectory'
        $command.Parameters.Keys | Should -Contain 'AsJson'
    }

    It 'validates module import and expected public command surface' {
        $output = pwsh -NoProfile -ExecutionPolicy Bypass -File $scriptPath -NonInteractive -SkipGalleryReachability -AsJson
        $result = $output | ConvertFrom-Json

        $result.ModuleImportSucceeded | Should -BeTrue
        $result.ExpectedPublicCommands.Count | Should -Be 7
        $result.ActualPublicCommands.Count | Should -Be 7
        $result.MissingPublicCommands.Count | Should -Be 0
        $result.UnexpectedPublicCommands.Count | Should -Be 0
        $result.PesterSummary.Ran | Should -BeFalse
    }

    It 'keeps the public module command count at seven' {
        Import-Module $modulePath -Force
        $module = Get-Module EntraObjectInspector

        @($module.ExportedFunctions.Keys).Count | Should -Be 7
    }

    It 'declares PowerShell 7.6 as the production runtime baseline' {
        $manifest = Import-PowerShellDataFile -LiteralPath $modulePath
        $scriptContent = Get-Content -LiteralPath $scriptPath -Raw

        [version]$manifest.ModuleVersion | Should -Be ([version]'1.0.2')
        [version]$manifest.PowerShellVersion | Should -Be ([version]'7.6')
        $scriptContent | Should -Match "\[Version\]'7\.6'"

        $required = @($manifest.RequiredModules)
        ($required | Where-Object ModuleName -eq 'Microsoft.Graph.Authentication').ModuleVersion | Should -Be '2.39.0'
        ($required | Where-Object ModuleName -eq 'Microsoft.PowerShell.SecretManagement').ModuleVersion | Should -Be '1.1.2'
        ($required | Where-Object ModuleName -eq 'Microsoft.PowerShell.SecretStore').ModuleVersion | Should -Be '1.0.6'
        $scriptContent | Should -Match 'MinimumVersion'
        $scriptContent | Should -Match 'SatisfiesRequirement'
    }

    It 'contains concise Pester summary support for RunTests' {
        $content = Get-Content -LiteralPath $scriptPath -Raw

        $content | Should -Match 'Invoke-Pester'
        $content | Should -Match 'Pester summary: Passed='
        $content | Should -Match 'Detailed output'
    }

    It 'has a CI release-validation workflow for import, tests, and source-output exclusion' {
        $workflowPath = Join-Path $PSScriptRoot '..\.github\workflows\release-validation.yml'
        $content = Get-Content -LiteralPath $workflowPath -Raw

        $content | Should -Match 'Release validation'
        $content | Should -Match '7\.6'
        $content | Should -Match 'Import-Module ./EntraObjectInspector\.psd1 -Force'
        $content | Should -Match '\$commands\.Count -ne 7'
        $content | Should -Match 'Invoke-Pester -Path ./Tests'
        $content | Should -Match 'Microsoft.Graph.Authentication -RequiredVersion 2\.39\.0'
        $content | Should -Match 'Microsoft.PowerShell.SecretManagement -RequiredVersion 1\.1\.2'
        $content | Should -Match 'Microsoft.PowerShell.SecretStore -RequiredVersion 1\.0\.6'
        $content | Should -Match 'Pester -RequiredVersion 6\.1\.0'
        $content | Should -Match 'EntraObjectInspector-Exports'
        $content | Should -Match 'EntraObjectInspector-Reports'
        $content | Should -Match "'snapshots'"
        $content | Should -Match "'logs'"
        $content | Should -Match "'TestResults'"
        $content | Should -Match "'coverage'"
        $content | Should -Match '\.zip'
        $content | Should -Match 'release-repro-inventory\*\.txt'
        $content | Should -Match '\*tenant-snapshot\*\.json'
        $content | Should -Match '\*snapshot\*\.portable\.json'
    }
}
