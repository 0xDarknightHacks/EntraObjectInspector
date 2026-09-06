function Invoke-EntraAssessmentIntelligence {
    <#
    .SYNOPSIS
        Builds assessment intelligence from existing inspection results.

    .DESCRIPTION
        Consumes an existing TenantInspectionResult or ObjectInsight and
        generates deterministic assessment intelligence, summaries,
        correlations, and recommendations.

        This command does not call Microsoft Graph, does not rerun discovery,
        does not invoke collectors, does not score risk, and does not build
        attack paths.

    .PARAMETER InputObject
        TenantInspectionResult returned by Invoke-EntraTenantInspection, or a
        single ObjectInsight returned by Get-EntraObjectInsight.

    .PARAMETER AssessmentName
        Human-readable name included in the intelligence result.

    .PARAMETER PassThru
        Adds AssessmentIntelligence to the input object and returns the input.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [string]$AssessmentName = 'Entra Object Inspector Assessment',

        [switch]$PassThru
    )

    process {
        $intelligence =
            Invoke-InspectorAssessmentIntelligence `
                -InputObject $InputObject `
                -AssessmentName $AssessmentName

        if ($PassThru) {
            $InputObject |
                Add-Member `
                    -NotePropertyName 'AssessmentIntelligence' `
                    -NotePropertyValue $intelligence `
                    -Force

            return $InputObject
        }

        return $intelligence
    }
}

