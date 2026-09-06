function Get-InspectorPublisherMetadataProperty {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Test-InspectorVerifiedPublisherMetadata {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$VerifiedPublisher
    )

    if ($null -eq $VerifiedPublisher) {
        return $false
    }

    $verifiedPublisherId =
        [string](Get-InspectorPublisherMetadataProperty -InputObject $VerifiedPublisher -Name 'verifiedPublisherId')

    $displayName =
        [string](Get-InspectorPublisherMetadataProperty -InputObject $VerifiedPublisher -Name 'displayName')

    return (
        -not [string]::IsNullOrWhiteSpace($verifiedPublisherId) -or
        -not [string]::IsNullOrWhiteSpace($displayName)
    )
}

function Test-InspectorMicrosoftPublishedAppId {
    <#
    .SYNOPSIS
        Tests an application ID against the local Microsoft-documented first-party catalog.

    .DESCRIPTION
        This is a deliberately narrow fallback for Microsoft-published applications
        whose service-principal owner-tenant metadata is absent or inconsistent in a
        collected tenant shape.  The catalog must contain only exact AppIds published
        by Microsoft documentation; display names are never used as classification
        proof.
    #>

    [CmdletBinding()]
    param (
        [string]$AppId
    )

    if ([string]::IsNullOrWhiteSpace($AppId)) {
        return $false
    }

    # Microsoft Learn: "Verify first-party Microsoft applications in sign-in reports"
    # (Application IDs of Microsoft tenant-owned applications, tenant
    # 72f988bf-86f1-41af-91ab-2d7cd011db47). Keep this list intentionally small
    # and expand it only from authoritative Microsoft documentation.
    $microsoftDocumentedAppIds = @(
        'de8bc8b5-d9f9-48b1-a8ad-b748da725064', # Graph Explorer
        '14d82eec-204b-4c2f-b7e8-296a70dab67e'  # Microsoft Graph Command Line Tools
    )

    return $AppId.ToLowerInvariant() -in $microsoftDocumentedAppIds
}

function Get-InspectorPublisherClassification {
    <#
    .SYNOPSIS
        Classifies application/service-principal publisher ownership from collected metadata.

    .DESCRIPTION
        Central classification policy used by snapshot discovery and ObjectInsight
        normalization. Microsoft-published service principals are identified primarily
        by Microsoft owner-tenant metadata.  A narrow exact-AppId fallback is used only
        for application IDs explicitly documented by Microsoft as Microsoft tenant-owned.
        External verification requires Graph verifiedPublisher metadata; publisherName
        by itself is not proof of publisher verification.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string]$ObjectType,

        [string]$ServicePrincipalType = '',

        [string]$AppId = '',

        [string]$AppOwnerOrganizationId = '',

        [AllowNull()]
        [object]$VerifiedPublisher,

        [string]$InspectorTenantId = '',

        [switch]$HasTenantApplicationCounterpart
    )

    if ($ObjectType -eq 'Application') {
        return 'TenantOwned'
    }

    if ($ObjectType -ne 'ServicePrincipal') {
        return 'Unknown'
    }

    if ($ServicePrincipalType -eq 'ManagedIdentity') {
        return 'ManagedIdentity'
    }

    $microsoftOwnerTenantIds = @(
        # Microsoft Services tenant.
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
        # Microsoft tenant that owns applications including Graph Explorer and
        # Microsoft Graph Command Line Tools.
        '72f988bf-86f1-41af-91ab-2d7cd011db47'
    )

    # Preferred general proof: the application owner tenant collected from Graph.
    if ($AppOwnerOrganizationId -in $microsoftOwnerTenantIds) {
        return 'MicrosoftPublished'
    }

    # Narrow fallback: exact AppIds explicitly documented by Microsoft. This is
    # intentionally evaluated before generic tenant/external classification so a
    # missing or stale owner-tenant field cannot turn a documented Microsoft app
    # into an actionable external/tenant-owned signal.
    if (Test-InspectorMicrosoftPublishedAppId -AppId $AppId) {
        return 'MicrosoftPublished'
    }

    if (
        -not [string]::IsNullOrWhiteSpace($InspectorTenantId) -and
        $AppOwnerOrganizationId -eq $InspectorTenantId
    ) {
        return 'TenantOwned'
    }

    if ($HasTenantApplicationCounterpart) {
        return 'TenantOwned'
    }

    if (Test-InspectorVerifiedPublisherMetadata -VerifiedPublisher $VerifiedPublisher) {
        return 'ExternalVerified'
    }

    return 'ExternalUnverified'
}
