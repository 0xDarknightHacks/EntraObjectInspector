function Get-InspectorSnapshotProperty {
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

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function New-InspectorSnapshotEvidence {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$QueryName,

        [Parameter(Mandatory)]
        [object]$GraphResult,

        [string]$EvidenceScope = 'TenantCollection',

        [string]$SubjectObjectType = '',

        [string]$SubjectObjectId = ''
    )

    return [PSCustomObject][ordered]@{
        PSTypeName         = 'EntraObjectInspector.SnapshotEvidence'
        EvidenceId         = [guid]::NewGuid().ToString()
        QueryName          = $QueryName
        Endpoint           = $GraphResult.SourceEndpoint
        RequiredPermission = $GraphResult.RequiredPermission
        CollectionTime     = $GraphResult.CollectionTime
        Status             = $GraphResult.Status
        ResultCount        = @($GraphResult.ObservedValue).Count
        Limitations        = @($GraphResult.Limitations)
        CollectorName      = $QueryName
        EvidenceScope      = $EvidenceScope
        SubjectObjectType  = $SubjectObjectType
        SubjectObjectId    = $SubjectObjectId
    }
}

function New-InspectorSnapshotCollectionResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$RequiredPermission,

        [string]$EvidenceScope = 'TenantCollection',

        [string]$SubjectObjectType = '',

        [string]$SubjectObjectId = '',

        [AllowNull()]
        [object]$RuntimeTelemetry
    )

    $graphResult =
        Invoke-InspectorGraphRequest `
            -Uri $Uri `
            -RequiredPermission $RequiredPermission `
            -RuntimeTelemetry $RuntimeTelemetry

    $evidence =
        New-InspectorSnapshotEvidence `
            -QueryName $Name `
            -GraphResult $graphResult `
            -EvidenceScope $EvidenceScope `
            -SubjectObjectType $SubjectObjectType `
            -SubjectObjectId $SubjectObjectId

    $evidence | Add-Member -NotePropertyName 'Completeness' -NotePropertyValue $(if ($graphResult.Status -eq 'Success') { 'Complete' } else { 'Partial' }) -Force
    $evidence | Add-Member -NotePropertyName 'SourceResultCount' -NotePropertyValue @($graphResult.ObservedValue).Count -Force

    return [PSCustomObject][ordered]@{
        Name        = $Name
        Status      = $graphResult.Status
        Items       = @(
            if ($graphResult.Status -eq 'Success') {
                @($graphResult.ObservedValue)
            }
        )
        Evidence    = $evidence
        Limitations = @($graphResult.Limitations)
    }
}


function Get-InspectorTenantLicenseCapabilityProfile {
    [CmdletBinding()]
    param (
        [object[]]$SubscribedSkus = @(),

        [string]$InventoryStatus = 'NotRun',

        [string[]]$InventoryLimitations = @(),

        [switch]$Evaluated
    )

    # Microsoft-published service-plan identifiers. Use service plans rather than
    # product display names so bundles such as Microsoft 365 E5 and Business
    # Premium resolve consistently through /subscribedSkus.
    $entraP1PlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'
    $entraP2PlanId = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'
    $entraGovernancePlanId = 'e866a266-3cff-43a3-acca-0c90a7e00c8b'

    $skuRows = @($SubscribedSkus | Where-Object { $null -ne $_ })
    $activeSkus = [System.Collections.Generic.List[object]]::new()
    $activePlanIds = @{}

    foreach ($sku in $skuRows) {
        $capabilityStatus = [string](Get-InspectorSnapshotProperty -InputObject $sku -Name 'capabilityStatus')
        if ($capabilityStatus -notin @('Enabled', 'Warning')) {
            continue
        }

        $activeSkus.Add($sku)

        foreach ($servicePlan in @(Get-InspectorSnapshotProperty -InputObject $sku -Name 'servicePlans')) {
            if ($null -eq $servicePlan) { continue }

            $provisioningStatus = [string](Get-InspectorSnapshotProperty -InputObject $servicePlan -Name 'provisioningStatus')
            if ($provisioningStatus -ne 'Success') {
                continue
            }

            $servicePlanId = [string](Get-InspectorSnapshotProperty -InputObject $servicePlan -Name 'servicePlanId')
            if (-not [string]::IsNullOrWhiteSpace($servicePlanId)) {
                $activePlanIds[$servicePlanId.ToLowerInvariant()] = $true
            }
        }
    }

    $hasEntraP1 = $activePlanIds.ContainsKey($entraP1PlanId)
    $hasEntraP2 = $activePlanIds.ContainsKey($entraP2PlanId)
    $hasEntraGovernance = $activePlanIds.ContainsKey($entraGovernancePlanId)
    $suiteSkuDetected = @(
        $activeSkus |
            Where-Object {
                [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'skuPartNumber') -like 'Microsoft_Entra_Suite*'
            }
    ).Count -gt 0

    # Do not infer Suite ownership merely because Governance, Internet Access,
    # and Private Access service plans are all present: those products can be
    # licensed separately and that combination does not prove ID Protection
    # entitlement. An explicit active Suite SKU (or P2 independently) is the
    # fail-closed signal used for Identity Protection capability.
    $hasEntraSuite = $suiteSkuDetected

    $hasGovernanceEntitlement = $hasEntraGovernance -and ($hasEntraP1 -or $hasEntraP2)
    $hasSuiteEntitlement = $hasEntraSuite -and ($hasEntraP1 -or $hasEntraP2)

    $inventoryAvailable = $Evaluated -and $InventoryStatus -eq 'Success'
    # A successful but completely empty inventory is kept inconclusive. This
    # avoids turning unusual/trial/free-tenant inventory behavior into a false
    # licensing conclusion; the feature endpoint remains authoritative.
    $inventoryConclusive = $inventoryAvailable -and $skuRows.Count -gt 0

    $pimStatus =
        if (-not $Evaluated) { 'Unknown' }
        elseif (-not $inventoryConclusive) { 'Unknown' }
        elseif ($hasEntraP2 -or $hasGovernanceEntitlement) { 'Available' }
        else { 'NotLicensed' }

    $identityProtectionStatus =
        if (-not $Evaluated) { 'Unknown' }
        elseif (-not $inventoryConclusive) { 'Unknown' }
        elseif ($hasEntraP2 -or $hasSuiteEntitlement) { 'Available' }
        else { 'NotLicensed' }

    $validationStatus =
        if (-not $Evaluated) { 'Unknown' }
        elseif (-not $inventoryConclusive) { 'Unknown' }
        elseif ($pimStatus -eq 'Available' -and $identityProtectionStatus -eq 'Available') { 'Available' }
        elseif ($pimStatus -eq 'NotLicensed' -and $identityProtectionStatus -eq 'NotLicensed') { 'LimitedByLicense' }
        else { 'Mixed' }

    $activeSkuPartNumbers = @(
        $activeSkus |
            ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'skuPartNumber') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    return [PSCustomObject][ordered]@{
        PSTypeName              = 'EntraObjectInspector.TenantLicenseCapabilityProfile'
        ValidationStatus        = $validationStatus
        InventoryStatus         = $InventoryStatus
        InventoryPermission     = 'LicenseAssignment.Read.All (least privileged), Directory.Read.All, or Organization.Read.All'
        InventoryLimitations    = @($InventoryLimitations)
        ActiveSkuCount          = @($activeSkus).Count
        ActiveSkuPartNumbers    = @($activeSkuPartNumbers)
        DetectedPlans           = [PSCustomObject][ordered]@{
            EntraIdP1             = [bool]$hasEntraP1
            EntraIdP2             = [bool]$hasEntraP2
            EntraIdentityGovernance = [bool]$hasEntraGovernance
            EntraSuite            = [bool]$hasEntraSuite
        }
        PrivilegedIdentityManagement = [PSCustomObject][ordered]@{
            Status      = $pimStatus
            Requirement = 'Microsoft Entra ID P2 or Microsoft Entra ID Governance. Microsoft Entra Suite includes Microsoft Entra ID Governance.'
            Basis        = 'Tenant subscribed SKU capability/service-plan inventory; feature endpoint evidence remains authoritative when inventory is unavailable or inconclusive.'
        }
        IdentityProtectionRiskyUsers = [PSCustomObject][ordered]@{
            Status      = $identityProtectionStatus
            Requirement = 'Microsoft Entra ID P2 or Microsoft Entra Suite for full Microsoft Entra ID Protection risky-user access.'
            Basis        = 'Tenant subscribed SKU capability/service-plan inventory; feature endpoint evidence remains authoritative when inventory is unavailable or inconclusive.'
        }
        ComplianceScope = 'Capability-level tenant entitlement signal only. This does not validate per-user seat assignment, license quantity, or Microsoft licensing compliance.'
    }
}

function Resolve-InspectorTenantCapabilities {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Alias('TenantSnapshot','InputObject')]
        [object]$Snapshot
    )

    # Portable snapshots created after tenant-license capability validation was
    # introduced already carry the computed profile. Preserve that serialized
    # result verbatim so offline replay cannot reinterpret licensing differently
    # from the live collection run.
    $tenantMetadata = Get-InspectorSnapshotProperty -InputObject $Snapshot -Name 'TenantMetadata'
    $existingProfile = Get-InspectorSnapshotProperty -InputObject $tenantMetadata -Name 'LicenseValidation'
    if ($null -ne $existingProfile) {
        return $existingProfile
    }

    # Historical snapshots do not contain TenantMetadata.LicenseValidation.
    # Reconstruct only from evidence already present in the portable payload;
    # never call Graph during import. Missing legacy inventory remains Unknown,
    # not NotLicensed, so older snapshots fail closed without inventing a tenant
    # entitlement conclusion.
    $collections = Get-InspectorSnapshotProperty -InputObject $Snapshot -Name 'Collections'
    $collectionSummary = Get-InspectorSnapshotProperty -InputObject $Snapshot -Name 'CollectionSummary'
    $subscribedSkus = @(
        Get-InspectorSnapshotProperty -InputObject $collections -Name 'SubscribedSkus' |
            Where-Object { $null -ne $_ }
    )

    $skuSummary = Get-InspectorSnapshotProperty -InputObject $collectionSummary -Name 'SubscribedSkus'
    $inventoryStatus = [string](Get-InspectorSnapshotProperty -InputObject $skuSummary -Name 'Status')
    $inventoryLimitations = @(
        Get-InspectorSnapshotProperty -InputObject $skuSummary -Name 'Limitations' |
            Where-Object { $null -ne $_ } |
            ForEach-Object { [string]$_ }
    )

    $evaluated = $false
    if (-not [string]::IsNullOrWhiteSpace($inventoryStatus) -and $inventoryStatus -ne 'NotRun') {
        $evaluated = $true
    }
    elseif ($subscribedSkus.Count -gt 0) {
        # A historical/custom snapshot may contain SKU rows without a summary.
        # Treat the inventory as successfully available in that narrow case.
        $inventoryStatus = 'Success'
        $evaluated = $true
    }
    else {
        $inventoryStatus = 'NotRun'
    }

    return Get-InspectorTenantLicenseCapabilityProfile `
        -SubscribedSkus @($subscribedSkus) `
        -InventoryStatus $inventoryStatus `
        -InventoryLimitations @($inventoryLimitations) `
        -Evaluated:$evaluated
}

function New-InspectorSnapshotLicenseUnavailableCollectionResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$RequiredPermission,

        [Parameter(Mandatory)]
        [string]$CapabilityName,

        [Parameter(Mandatory)]
        [string]$LicenseRequirement
    )

    $limitation =
        "Tenant collection '$Name' was not attempted because license capability validation found no active qualifying tenant subscription for $CapabilityName. Required licensing: $LicenseRequirement The assessment remains fail-closed for this capability; this tenant-level check does not validate per-user licensing compliance."

    $graphResult = [PSCustomObject][ordered]@{
        SourceEndpoint      = $Uri
        RequiredPermission  = $RequiredPermission
        CollectionTime      = (Get-Date).ToUniversalTime().ToString('o')
        Status              = 'LicenseUnavailable'
        ObservedValue       = @()
        Limitations         = @($limitation)
    }

    $evidence =
        New-InspectorSnapshotEvidence `
            -QueryName $Name `
            -GraphResult $graphResult

    $evidence | Add-Member -NotePropertyName 'Completeness' -NotePropertyValue 'Partial' -Force
    $evidence | Add-Member -NotePropertyName 'SourceResultCount' -NotePropertyValue 0 -Force
    $evidence | Add-Member -NotePropertyName 'LimitationCategory' -NotePropertyValue 'Licensing' -Force
    $evidence | Add-Member -NotePropertyName 'LicenseRequirement' -NotePropertyValue $LicenseRequirement -Force

    return [PSCustomObject][ordered]@{
        Name        = $Name
        Status      = 'LicenseUnavailable'
        Items       = @()
        Evidence    = $evidence
        Limitations = @($limitation)
    }
}

function New-InspectorSnapshotBatchCollectionResults {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object[]]$Requests,

        [ValidateRange(1, 20)]
        [int]$BatchSize = 10,

        [AllowNull()]
        [object]$RuntimeTelemetry
    )

    $requestList = @($Requests | Where-Object { $null -ne $_ })
    if ($requestList.Count -eq 0) {
        return @()
    }

    $graphResults = @(
        Invoke-InspectorGraphBatchRequest `
            -Requests $requestList `
            -BatchSize $BatchSize `
            -RuntimeTelemetry $RuntimeTelemetry
    )

    if ($graphResults.Count -ne $requestList.Count) {
        throw "Graph batch result count mismatch. Expected $($requestList.Count), received $($graphResults.Count)."
    }

    $results = @(
        for ($index = 0; $index -lt $requestList.Count; $index++) {
            $request = $requestList[$index]
            $graphResult = $graphResults[$index]
            $name = [string](Get-InspectorSnapshotProperty -InputObject $request -Name 'Name')
            $evidenceScope = [string](Get-InspectorSnapshotProperty -InputObject $request -Name 'EvidenceScope')
            $subjectObjectType = [string](Get-InspectorSnapshotProperty -InputObject $request -Name 'SubjectObjectType')
            $subjectObjectId = [string](Get-InspectorSnapshotProperty -InputObject $request -Name 'SubjectObjectId')

            if ([string]::IsNullOrWhiteSpace($evidenceScope)) {
                $evidenceScope = 'ObjectRelationship'
            }

            $evidence =
                New-InspectorSnapshotEvidence `
                    -QueryName $name `
                    -GraphResult $graphResult `
                    -EvidenceScope $evidenceScope `
                    -SubjectObjectType $subjectObjectType `
                    -SubjectObjectId $subjectObjectId

            $evidence | Add-Member -NotePropertyName 'Completeness' -NotePropertyValue $(if ($graphResult.Status -eq 'Success') { 'Complete' } else { 'Partial' }) -Force
            $evidence | Add-Member -NotePropertyName 'SourceResultCount' -NotePropertyValue @($graphResult.ObservedValue).Count -Force

            [PSCustomObject][ordered]@{
                Name        = $name
                Status      = $graphResult.Status
                Items       = @(
                    if ($graphResult.Status -eq 'Success') {
                        @($graphResult.ObservedValue)
                    }
                )
                Evidence    = $evidence
                Limitations = @($graphResult.Limitations)
                Request     = $request
            }
        }
    )

    return @($results)
}

function Add-InspectorSnapshotIndexValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Index,

        [string]$Key,

        [AllowNull()]
        [object]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Key) -or $null -eq $Value) {
        return
    }

    if (-not $Index.ContainsKey($Key)) {
        $Index[$Key] = [System.Collections.Generic.List[object]]::new()
    }

    $Index[$Key].Add($Value)
}

function Get-InspectorSnapshotIndexSingle {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [hashtable]$Index,

        [string]$Key
    )

    if ($null -eq $Index -or [string]::IsNullOrWhiteSpace($Key) -or -not $Index.ContainsKey($Key)) {
        return @()
    }

    return @(
        foreach ($item in @($Index[$Key])) {
            if ($null -eq $item) {
                continue
            }

            if ($item -is [System.Collections.IEnumerable] -and $item -isnot [string] -and $item -isnot [System.Collections.IDictionary]) {
                foreach ($inner in $item) {
                    if ($null -ne $inner) {
                        $inner
                    }
                }
            }
            else {
                $item
            }
        }
    )
}

function ConvertTo-InspectorSnapshotCandidate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string]$ObjectType,

        [Parameter(Mandatory)]
        [object]$RawObject,

        [Parameter(Mandatory)]
        [string]$MatchBasis,

        [bool]$IsDirectMatch = $true
    )

    $id = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'id')
    $identifiers = [ordered]@{ ObjectId = $id }

    $appId = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'appId')
    if ($ObjectType -in @('Application', 'ServicePrincipal') -and -not [string]::IsNullOrWhiteSpace($appId)) {
        $identifiers.AppId = $appId
    }

    $upn = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'userPrincipalName')
    if ($ObjectType -eq 'User' -and -not [string]::IsNullOrWhiteSpace($upn)) {
        $identifiers.UserPrincipalName = $upn
    }

    return [PSCustomObject][ordered]@{
        PSTypeName    = 'EntraObjectInspector.ResolutionCandidate'
        ObjectType    = $ObjectType
        DisplayName   = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'displayName')
        Identifiers   = [PSCustomObject]$identifiers
        MatchBasis    = @($MatchBasis)
        IsDirectMatch = $IsDirectMatch
        EvidenceId    = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'EvidenceId')
        RawObject     = $RawObject
    }
}

function ConvertTo-InspectorSnapshotDiscoveredObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string]$ObjectType,

        [Parameter(Mandatory)]
        [object]$RawObject,

        [string]$EvidenceId
    )

    $appId = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'appId')
    $appOwnerOrganizationId = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'appOwnerOrganizationId')
    $publisherName = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'publisherName')
    $verifiedPublisher = Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'verifiedPublisher'
    $inspectorTenantId = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'InspectorTenantId')
    $servicePrincipalType = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'servicePrincipalType')
    $publisherClassification =
        Get-InspectorPublisherClassification `
            -ObjectType $ObjectType `
            -ServicePrincipalType $servicePrincipalType `
            -AppId $appId `
            -AppOwnerOrganizationId $appOwnerOrganizationId `
            -VerifiedPublisher $verifiedPublisher `
            -InspectorTenantId $inspectorTenantId

    New-InspectorDiscoveredObject `
        -ObjectType $ObjectType `
        -ObjectId ([string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'id')) `
        -DisplayName ([string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'displayName')) `
        -AppId $appId `
        -UserPrincipalName ([string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'userPrincipalName')) `
        -DiscoverySource 'TenantSnapshot' `
        -EvidenceId $EvidenceId `
        -Metadata @{
            ServicePrincipalType = $servicePrincipalType
            AppOwnerOrganizationId = $appOwnerOrganizationId
            PublisherName = $publisherName
            VerifiedPublisher = $verifiedPublisher
            PublisherDomain = [string](Get-InspectorSnapshotProperty -InputObject $RawObject -Name 'publisherDomain')
            PublisherClassification = $publisherClassification
            TenantOwnershipClassification = $publisherClassification
            ClassificationConfidence = 'ConservativeMetadata'
            ClassificationMethod = 'Central publisher classification using owner-tenant metadata, Microsoft-documented exact AppId fallback, verifiedPublisher, managed-identity, and tenant-ownership metadata.'
        }
}

function Get-InspectorSnapshotAggregateState {
    [CmdletBinding()]
    param (
        [object[]]$Evidence = @(),

        [string]$FallbackStatus = 'Success',

        [int]$Count = 0,

        [switch]$Truncated
    )

    $rows = @($Evidence | Where-Object { $null -ne $_ })
    $statuses = @(
        $rows |
            ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'Status') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    $status = $FallbackStatus

    if ($statuses.Count -gt 0) {
        if ('Failed' -in $statuses) {
            $status = 'Failed'
        }
        elseif ('Throttled' -in $statuses) {
            $status = 'Throttled'
        }
        elseif ('ServiceUnavailable' -in $statuses) {
            $status = 'ServiceUnavailable'
        }
        elseif ('InsufficientPermission' -in $statuses) {
            $status = 'InsufficientPermission'
        }
        elseif ('Partial' -in $statuses) {
            $status = 'Partial'
        }
        elseif (@($statuses | Where-Object { $_ -ne 'Success' }).Count -gt 0) {
            $status = 'Partial'
        }
        else {
            $status = 'Success'
        }
    }

    $completeness =
        if ($Truncated) {
            'Truncated'
        }
        elseif ($status -eq 'Success') {
            'Complete'
        }
        else {
            'Partial'
        }

    return [PSCustomObject][ordered]@{
        Status            = $status
        Count             = $Count
        Completeness      = $completeness
        QueryCount        = $rows.Count
        IncompleteQueries = @(
            $rows |
                Where-Object {
                    [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'Status') -ne 'Success' -or
                    [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'Completeness') -in @('Partial', 'Truncated')
                } |
                ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'QueryName') } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )
        Statuses          = @($statuses)
    }
}

function Test-InspectorSnapshotRequiredEvidence {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Evidence
    )

    if ($null -eq $Evidence) {
        return $false
    }

    $queryName = [string](Get-InspectorSnapshotProperty -InputObject $Evidence -Name 'QueryName')

    if ([string]::IsNullOrWhiteSpace($queryName)) {
        return $false
    }

    $requiredForCoverage = Get-InspectorSnapshotProperty -InputObject $Evidence -Name 'RequiredForCoverage'
    if ($null -ne $requiredForCoverage -and -not [System.Convert]::ToBoolean($requiredForCoverage)) {
        return $false
    }

    # /organization is report metadata support. Other evidence explicitly
    # marked RequiredForCoverage=$false (for example /subscribedSkus license
    # prevalidation) is advisory. All remaining executed snapshot collections
    # feed assessment semantics or prove negative-state completeness and are
    # therefore release-required evidence.
    return $queryName -ne 'Organization'
}

function Get-InspectorSnapshotExpectedEvidencePlan {
    <#
    .SYNOPSIS
        Builds the required snapshot evidence plan from the collected scope.

    .DESCRIPTION
        The plan is derived independently from evidence rows. This allows the
        release validator to detect a silently omitted collection query instead
        of shrinking the evidence denominator and incorrectly reporting complete
        coverage.
    #>

    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Collections,

        [AllowNull()]
        [object]$CollectionSummary
    )

    $expected = [System.Collections.Generic.List[string]]::new()
    $seen = @{}

    function Add-ExpectedEvidenceQuery {
        param ([string]$QueryName)

        if ([string]::IsNullOrWhiteSpace($QueryName) -or $seen.ContainsKey($QueryName)) {
            return
        }

        $seen[$QueryName] = $true
        $expected.Add($QueryName)
    }

    foreach ($baseQuery in @(
        'Applications',
        'ServicePrincipals',
        'Users',
        'Groups',
        'OAuth2PermissionGrants',
        'DirectoryRoleDefinitions',
        'DirectoryRoleAssignments',
        'RoleAssignmentScheduleInstances',
        'RoleEligibilityScheduleInstances',
        'AdministrativeUnits',
        'RiskyUsers'
    )) {
        $summaryRow = Get-InspectorSnapshotProperty -InputObject $CollectionSummary -Name $baseQuery
        $status = [string](Get-InspectorSnapshotProperty -InputObject $summaryRow -Name 'Status')

        # Object collections intentionally excluded by -ObjectType are NotRun
        # and are not part of that run's declared scope. Targeted collection
        # supplies the exact probe/filter query names through ExpectedQueries so
        # the evidence denominator remains independently constructed.
        if ($status -ne 'NotRun') {
            $declaredExpectedQueries = @(
                Get-InspectorSnapshotProperty -InputObject $summaryRow -Name 'ExpectedQueries' |
                    ForEach-Object { [string]$_ } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
            if ($declaredExpectedQueries.Count -gt 0) {
                foreach ($declaredQuery in $declaredExpectedQueries) { Add-ExpectedEvidenceQuery -QueryName $declaredQuery }
            }
            else {
                Add-ExpectedEvidenceQuery -QueryName $baseQuery
            }
        }
    }

    foreach ($id in @(
        (Get-InspectorSnapshotProperty -InputObject $Collections -Name 'Applications') |
            ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'id') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )) {
        Add-ExpectedEvidenceQuery -QueryName "ApplicationOwners:$id"
    }

    $groupIds = @(
        (Get-InspectorSnapshotProperty -InputObject $Collections -Name 'Groups') |
            ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'id') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    foreach ($id in @(
        (Get-InspectorSnapshotProperty -InputObject $Collections -Name 'ServicePrincipals') |
            ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'id') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )) {
        $servicePrincipalPrefixes = @('ServicePrincipalOwners','ServicePrincipalOwnedObjects','AppRoleAssignments','AppRoleAssignedTo')
        if ($groupIds.Count -gt 0) {
            # Microsoft Graph v1.0 /groups/{id}/members has a documented service-principal
            # omission. The stable v1.0 servicePrincipal/memberOf relationship is collected
            # independently so direct service-principal group membership can be reconstructed
            # without a beta dependency.
            $servicePrincipalPrefixes += 'ServicePrincipalGroupMemberships'
        }

        foreach ($prefix in @($servicePrincipalPrefixes)) {
            Add-ExpectedEvidenceQuery -QueryName "${prefix}:$id"
        }
    }

    foreach ($id in $groupIds) {
        foreach ($prefix in @('GroupOwners','GroupMembers','GroupMemberships')) {
            Add-ExpectedEvidenceQuery -QueryName "${prefix}:$id"
        }
    }

    foreach ($id in @(
        (Get-InspectorSnapshotProperty -InputObject $Collections -Name 'Users') |
            ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'id') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )) {
        Add-ExpectedEvidenceQuery -QueryName "UserTransitiveMemberships:$id"
    }

    foreach ($id in @(
        (Get-InspectorSnapshotProperty -InputObject $Collections -Name 'AdministrativeUnits') |
            ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'id') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )) {
        Add-ExpectedEvidenceQuery -QueryName "AdministrativeUnitMembers:$id"
    }

    return [PSCustomObject][ordered]@{
        PSTypeName             = 'EntraObjectInspector.ExpectedEvidencePlan'
        ExpectedEvidenceCount  = $expected.Count
        ExpectedQueries        = @($expected)
        Basis                  = 'Required tenant collections plus one ApplicationOwners query per collected application; ServicePrincipalOwners, ServicePrincipalOwnedObjects, AppRoleAssignments, and AppRoleAssignedTo per collected service principal; ServicePrincipalGroupMemberships per collected service principal whenever groups are in scope; GroupOwners, GroupMembers, and GroupMemberships per collected group; and UserTransitiveMemberships per collected user. Group owner and member completeness combines stable v1.0 forward collections with reverse service-principal evidence.'
    }
}

function Get-InspectorSnapshotAssessmentCoverage {
    [CmdletBinding()]
    param (
        [object[]]$Evidence = @(),

        [string[]]$ExpectedQueries = @()
    )

    $requiredEvidence = @(
        $Evidence |
            Where-Object { Test-InspectorSnapshotRequiredEvidence -Evidence $_ }
    )

    $expectedQueryList = @(
        @($ExpectedQueries) |
            ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    # Backward-compatible fallback for legacy snapshot shapes that predate an
    # explicit expected plan. Current snapshots always supply ExpectedQueries.
    if ($expectedQueryList.Count -eq 0) {
        $expectedQueryList = @(
            $requiredEvidence |
                ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'QueryName') } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )
    }

    $expectedSet = @{}
    foreach ($queryName in $expectedQueryList) { $expectedSet[$queryName] = $true }

    $actualByQuery = @{}
    foreach ($row in $requiredEvidence) {
        $queryName = [string](Get-InspectorSnapshotProperty -InputObject $row -Name 'QueryName')
        if ([string]::IsNullOrWhiteSpace($queryName)) { continue }
        if (-not $actualByQuery.ContainsKey($queryName)) {
            $actualByQuery[$queryName] = [System.Collections.Generic.List[object]]::new()
        }
        $actualByQuery[$queryName].Add($row)
    }

    $missingQueries = @(
        $expectedQueryList |
            Where-Object { -not $actualByQuery.ContainsKey($_) }
    )

    $unexpectedQueries = @(
        $actualByQuery.Keys |
            Where-Object { -not $expectedSet.ContainsKey([string]$_) } |
            Sort-Object
    )

    $duplicateQueries = @(
        $actualByQuery.GetEnumerator() |
            Where-Object { @($_.Value).Count -gt 1 } |
            ForEach-Object { [string]$_.Key } |
            Sort-Object
    )

    $incompleteDetails = [System.Collections.Generic.List[object]]::new()
    $successfulExpectedCount = 0
    $problemStatuses = [System.Collections.Generic.List[string]]::new()

    foreach ($queryName in $expectedQueryList) {
        if (-not $actualByQuery.ContainsKey($queryName)) {
            $incompleteDetails.Add([PSCustomObject][ordered]@{
                QueryName = $queryName
                Status = 'Missing'
                Completeness = 'Missing'
                Issue = 'MissingExpectedEvidence'
            })
            continue
        }

        $rows = @($actualByQuery[$queryName])
        if ($rows.Count -ne 1) {
            $incompleteDetails.Add([PSCustomObject][ordered]@{
                QueryName = $queryName
                Status = 'Duplicate'
                Completeness = 'Partial'
                Issue = 'DuplicateRequiredEvidence'
            })
            continue
        }

        $status = [string](Get-InspectorSnapshotProperty -InputObject $rows[0] -Name 'Status')
        $completeness = [string](Get-InspectorSnapshotProperty -InputObject $rows[0] -Name 'Completeness')
        if ([string]::IsNullOrWhiteSpace($completeness)) {
            $completeness = $(if ($status -eq 'Success') { 'Complete' } else { 'Partial' })
        }

        if ($status -eq 'Success' -and $completeness -eq 'Complete') {
            $successfulExpectedCount++
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($status) -and -not $problemStatuses.Contains($status)) {
            $problemStatuses.Add($status)
        }

        $incompleteDetails.Add([PSCustomObject][ordered]@{
            QueryName = $queryName
            Status = $status
            Completeness = $completeness
            Issue = 'IncompleteRequiredEvidence'
        })
    }

    foreach ($queryName in $unexpectedQueries) {
        $rows = @($actualByQuery[$queryName])
        $status = if ($rows.Count -gt 0) { [string](Get-InspectorSnapshotProperty -InputObject $rows[0] -Name 'Status') } else { 'Unknown' }
        $completeness = if ($rows.Count -gt 0) { [string](Get-InspectorSnapshotProperty -InputObject $rows[0] -Name 'Completeness') } else { 'Unknown' }
        $incompleteDetails.Add([PSCustomObject][ordered]@{
            QueryName = $queryName
            Status = $status
            Completeness = $completeness
            Issue = 'UnexpectedRequiredEvidence'
        })
    }

    $planMatches =
        $missingQueries.Count -eq 0 -and
        $unexpectedQueries.Count -eq 0 -and
        $duplicateQueries.Count -eq 0 -and
        $requiredEvidence.Count -eq $expectedQueryList.Count

    $hasHardFailure = @(
        $incompleteDetails |
            Where-Object { $_.Status -in @('Failed','Throttled','ServiceUnavailable') }
    ).Count -gt 0

    $coverageComplete =
        $planMatches -and
        $successfulExpectedCount -eq $expectedQueryList.Count

    $status =
        if ($hasHardFailure) { 'Failed' }
        elseif (-not $coverageComplete) { 'Partial' }
        else { 'Success' }

    $incompleteQueries = @(
        $incompleteDetails |
            ForEach-Object { [string]$_.QueryName } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    $incompleteEvidenceIds = @(
        $requiredEvidence |
            Where-Object {
                $queryName = [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'QueryName')
                $queryName -in $incompleteQueries
            } |
            ForEach-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'EvidenceId') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    return [PSCustomObject][ordered]@{
        PSTypeName                       = 'EntraObjectInspector.AssessmentCoverage'
        Status                           = $status
        Completeness                     = $(if ($coverageComplete) { 'Complete' } else { 'Partial' })
        EvidencePlanMatches              = [bool]$planMatches
        ExpectedEvidenceCount            = $expectedQueryList.Count
        ActualRequiredEvidenceCount      = $requiredEvidence.Count
        RequiredEvidenceCount            = $expectedQueryList.Count
        SuccessfulRequiredEvidenceCount  = $successfulExpectedCount
        IncompleteRequiredEvidenceCount  = $expectedQueryList.Count - $successfulExpectedCount
        MissingExpectedEvidenceCount     = $missingQueries.Count
        UnexpectedRequiredEvidenceCount  = $unexpectedQueries.Count
        DuplicateRequiredEvidenceCount   = $duplicateQueries.Count
        ExpectedQueries                  = @($expectedQueryList)
        MissingExpectedQueries           = @($missingQueries)
        UnexpectedRequiredQueries        = @($unexpectedQueries)
        DuplicateRequiredQueries         = @($duplicateQueries)
        IncompleteEvidenceIds            = @($incompleteEvidenceIds)
        IncompleteQueries                = @($incompleteQueries)
        IncompleteStatuses               = @($problemStatuses)
        IncompleteQueryDetails           = @($incompleteDetails)
        CoverageBasis                    = 'Expected evidence is generated independently from the collected scope and must exactly match the assessment-required evidence rows. Every expected query must occur exactly once and complete with Status=Success and Completeness=Complete. Organization metadata is intentionally non-required.'
    }
}
