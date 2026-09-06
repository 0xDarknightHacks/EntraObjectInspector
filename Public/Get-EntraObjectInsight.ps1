function Get-EntraObjectInsight {
    <#
    .SYNOPSIS
        Public entry point for Entra Object Inspector.

    .DESCRIPTION
        Without -Identity, returns the current Inspector runtime status.

        With -Identity:
        1. Deterministically resolves the supported Entra object.
        2. Runs object-specific relationship collectors.
        3. Normalizes the result into ObjectInsight.
        4. Adds permission intelligence from a local catalog.
        5. Evaluates baseline rules over the enriched object insight.

        The enrichment and rule layers never call Microsoft Graph and do not
        produce a numerical risk score.
    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [Alias(
            'Id',
            'ObjectId',
            'AppId',
            'UserPrincipalName'
        )]
        [string]$Identity,

        [ValidateRange(1, 365)]
        [int]$CredentialExpiryWarningDays = 30
    )

    process {
        if ([string]::IsNullOrWhiteSpace($Identity)) {
            $context = Get-MgContext

            if (-not $context) {
                return [PSCustomObject][ordered]@{
                    PSTypeName     = 'EntraObjectInspector.FoundationStatus'
                    SchemaVersion  = '0.7.0'
                    Status         = 'Disconnected'
                    AuthType       = $null
                    TenantId       = $null
                    ClientId       = $null
                    ReadOnly       = $true
                    Message        = 'Run Connect-InspectorGraph before using the Inspector.'
                }
            }

            $status =
                if ($context.AuthType -eq 'AppOnly') {
                    'Ready'
                }
                else {
                    'InvalidAuthenticationMode'
                }

            return [PSCustomObject][ordered]@{
                PSTypeName     = 'EntraObjectInspector.FoundationStatus'
                SchemaVersion  = '0.7.0'
                Status         = $status
                AuthType       = $context.AuthType
                TenantId       = $context.TenantId
                ClientId       = $context.ClientId
                ReadOnly       = $true
                Message    =
                    if ($status -eq 'Ready') {
                        'Permission intelligence is available.'
                    }
                    else {
                        'Inspector requires an AppOnly Microsoft Graph context.'
                    }
            }
        }

        $resolution = Resolve-EntraObject -Identity $Identity
        $relationshipCollection =
            Invoke-InspectorRelationshipCollection -Resolution $resolution

        $objectInsight =
            ConvertTo-InspectorObjectInsight `
                -Resolution $resolution `
                -RelationshipCollection $relationshipCollection

        $objectInsight =
            Add-InspectorPermissionIntelligence `
                -ObjectInsight $objectInsight

        $ruleResults =
            Invoke-InspectorRules `
                -ObjectInsight $objectInsight `
                -CredentialExpiryWarningDays $CredentialExpiryWarningDays

        $objectInsight.RuleResults = @($ruleResults)
        $objectInsight.Findings = @($ruleResults)
        $objectInsight.Summary.FindingCount = @($ruleResults).Count

        $observationResult =
            Invoke-InspectorObservationEngine `
                -ObjectInsight $objectInsight `
                -CredentialExpiryWarningDays $CredentialExpiryWarningDays

        $objectInsight |
            Add-Member `
                -NotePropertyName 'ObservationEngine' `
                -NotePropertyValue $observationResult `
                -Force

        $objectInsight |
            Add-Member `
                -NotePropertyName 'SecurityObservations' `
                -NotePropertyValue @($observationResult.Observations) `
                -Force

        $objectInsight.Summary |
            Add-Member `
                -NotePropertyName 'SecurityObservationCount' `
                -NotePropertyValue @($observationResult.Observations).Count `
                -Force

        return $objectInsight
    }
}

