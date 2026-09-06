function Add-InspectorPermissionIntelligence {
    <#
    .SYNOPSIS
        Adds permission intelligence to ObjectInsight.

    .DESCRIPTION
        Enriches already-collected GrantedAppRole relationships with local
        permission-catalog metadata and adds a PermissionInsights collection
        to the ObjectInsight model.

        This function never calls Microsoft Graph.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight
    )

    $relationships = @(
        (Get-InspectorPermissionProperty `
            -InputObject $ObjectInsight `
            -Name 'Relationships') |
        Where-Object { $null -ne $_ }
    )

    $permissionInsights = [System.Collections.Generic.List[object]]::new()

    foreach ($relationship in $relationships) {
        $relationshipType =
            [string](Get-InspectorPermissionProperty `
                -InputObject $relationship `
                -Name 'RelationshipType')

        if ($relationshipType -ne 'GrantedAppRole') {
            continue
        }

        $insight =
            ConvertTo-InspectorPermissionInsight `
                -Relationship $relationship

        if ($null -eq $insight) {
            continue
        }

        $permissionInsights.Add($insight)

        $metadata =
            Get-InspectorPermissionProperty `
                -InputObject $relationship `
                -Name 'Metadata'

        if ($null -eq $metadata) {
            $metadata = [PSCustomObject]@{}
            Set-InspectorPermissionProperty `
                -InputObject $relationship `
                -Name 'Metadata' `
                -Value $metadata
        }

        if ($insight.CatalogStatus -eq 'Resolved') {
            Set-InspectorPermissionProperty -InputObject $metadata -Name 'PermissionName' -Value $insight.PermissionName
            Set-InspectorPermissionProperty -InputObject $metadata -Name 'PermissionType' -Value $insight.PermissionType
            Set-InspectorPermissionProperty -InputObject $metadata -Name 'PermissionCategory' -Value $insight.PermissionCategory
            Set-InspectorPermissionProperty -InputObject $metadata -Name 'ImpactLevel' -Value $insight.ImpactLevel
            Set-InspectorPermissionProperty -InputObject $metadata -Name 'IsHighImpact' -Value $insight.IsHighImpact
            Set-InspectorPermissionProperty -InputObject $metadata -Name 'AdministrativeImpact' -Value $insight.AdministrativeImpact
            Set-InspectorPermissionProperty -InputObject $metadata -Name 'PermissionCatalogStatus' -Value $insight.CatalogStatus
        }
        else {
            Set-InspectorPermissionProperty -InputObject $metadata -Name 'PermissionCatalogStatus' -Value $insight.CatalogStatus
        }
    }

    Set-InspectorPermissionProperty `
        -InputObject $ObjectInsight `
        -Name 'PermissionInsights' `
        -Value @($permissionInsights)

    Set-InspectorPermissionProperty `
        -InputObject $ObjectInsight `
        -Name 'PermissionCatalog' `
        -Value @(
            Get-InspectorPermissionCatalog
        )

    Set-InspectorPermissionProperty `
        -InputObject $ObjectInsight `
        -Name 'PermissionIntelligence' `
        -Value ([PSCustomObject][ordered]@{
            SchemaVersion          = '0.5.0'
            GeneratedAt            = (Get-Date).ToUniversalTime().ToString('o')
            CatalogVersion         = '0.5.0'
            PermissionInsightCount = @($permissionInsights).Count
            CatalogEntryCount      = @(Get-InspectorPermissionCatalog).Count
            EnrichmentMode         = 'LocalCatalogOnly'
            GraphCallsIssued       = 0
        })

    $unknownCount = @(
        $permissionInsights |
        Where-Object { $_.CatalogStatus -ne 'Resolved' }
    ).Count

    if ($unknownCount -gt 0) {
        $currentLimitations = @(
            Get-InspectorPermissionProperty `
                -InputObject $ObjectInsight `
                -Name 'Limitations'
        ) | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        }

        $currentLimitations +=
            "The local permission catalog could not resolve $unknownCount app role assignment(s) in the local permission catalog."

        Set-InspectorPermissionProperty `
            -InputObject $ObjectInsight `
            -Name 'Limitations' `
            -Value @($currentLimitations | Select-Object -Unique)
    }

    $summary =
        Get-InspectorPermissionProperty `
            -InputObject $ObjectInsight `
            -Name 'Summary'

    if ($null -ne $summary) {
        Set-InspectorPermissionProperty `
            -InputObject $summary `
            -Name 'PermissionInsightCount' `
            -Value @($permissionInsights).Count
    }

    return $ObjectInsight
}

