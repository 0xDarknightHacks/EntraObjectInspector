@{
    RootModule = 'EntraObjectInspector.psm1'

    ModuleVersion = '1.0.1'

    GUID = '3c8c54d6-218b-4a51-a3c7-41f908e6fd79'

    Author = 'Entra Object Inspector'

    Description = @'
Read-only Microsoft Entra investigation module that provides
evidence-backed object inspection through Microsoft Graph.
'@

    PowerShellVersion = '7.6'

    CompatiblePSEditions = @(
        'Core'
    )

    RequiredModules = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication';        ModuleVersion = '2.39.0' },
        @{ ModuleName = 'Microsoft.PowerShell.SecretManagement'; ModuleVersion = '1.1.2' },
        @{ ModuleName = 'Microsoft.PowerShell.SecretStore';      ModuleVersion = '1.0.6' }
    )

    FunctionsToExport = @(
        'Connect-InspectorGraph',
        'Get-EntraObjectInsight',
        'Invoke-EntraTenantInspection',
        'Export-EntraTenantInspection',
        'Invoke-EntraAssessmentIntelligence',
        'Export-EntraAssessmentReport',
        'Invoke-EntraSecurityAssessment'
    )

    CmdletsToExport = @()

    VariablesToExport = @()

    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @(
                'MicrosoftGraph',
                'EntraID',
                'Security',
                'ReadOnly'
            )
        }
    }
}
