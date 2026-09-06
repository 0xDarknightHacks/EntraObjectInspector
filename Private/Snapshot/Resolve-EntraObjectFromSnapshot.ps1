function Resolve-EntraObjectFromSnapshot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [object]$TenantSnapshot
    )

    $inputValue = $Identity.Trim()
    $guidValue = [guid]::Empty
    $inputShape = $null
    $normalizedInput = $inputValue

    if ([guid]::TryParse($inputValue, [ref]$guidValue)) {
        $inputShape = 'Guid'
        $normalizedInput = $guidValue.ToString()
    }
    elseif ($inputValue -match '^[^@\s]+@[^@\s]+$') {
        $inputShape = 'UpnLike'
    }
    else {
        return [PSCustomObject][ordered]@{
            PSTypeName      = 'EntraObjectInspector.ResolutionResult'
            Input           = $inputValue
            NormalizedInput = $inputValue
            InputShape      = 'Unsupported'
            Status          = 'UnsupportedIdentifier'
            ResolutionType  = $null
            PrimaryObject   = $null
            DirectMatches   = @()
            RelatedObjects  = @()
            Relationships   = @()
            Evidence        = @()
            Limitations     = @('Input is neither a supported UPN-like value nor a GUID.')
        }
    }

    $directMatches = [System.Collections.Generic.List[object]]::new()

    if ($inputShape -eq 'UpnLike') {
        foreach ($user in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.UserByUserPrincipalName -Key $inputValue.ToLowerInvariant())) {
            $directMatches.Add((ConvertTo-InspectorSnapshotCandidate -ObjectType 'User' -RawObject $user -MatchBasis 'UserPrincipalName'))
        }
    }
    else {
        foreach ($user in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.UserByObjectId -Key $normalizedInput)) {
            $directMatches.Add((ConvertTo-InspectorSnapshotCandidate -ObjectType 'User' -RawObject $user -MatchBasis 'ObjectId'))
        }
        foreach ($group in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.GroupByObjectId -Key $normalizedInput)) {
            $directMatches.Add((ConvertTo-InspectorSnapshotCandidate -ObjectType 'Group' -RawObject $group -MatchBasis 'ObjectId'))
        }
        foreach ($application in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ApplicationByObjectId -Key $normalizedInput)) {
            $directMatches.Add((ConvertTo-InspectorSnapshotCandidate -ObjectType 'Application' -RawObject $application -MatchBasis 'ObjectId'))
        }
        foreach ($servicePrincipal in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ServicePrincipalByObjectId -Key $normalizedInput)) {
            $directMatches.Add((ConvertTo-InspectorSnapshotCandidate -ObjectType 'ServicePrincipal' -RawObject $servicePrincipal -MatchBasis 'ObjectId'))
        }
        foreach ($application in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ApplicationByAppId -Key $normalizedInput)) {
            $directMatches.Add((ConvertTo-InspectorSnapshotCandidate -ObjectType 'Application' -RawObject $application -MatchBasis 'AppId'))
        }
        foreach ($servicePrincipal in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ServicePrincipalByAppId -Key $normalizedInput)) {
            $directMatches.Add((ConvertTo-InspectorSnapshotCandidate -ObjectType 'ServicePrincipal' -RawObject $servicePrincipal -MatchBasis 'AppId'))
        }
    }

    $unique = @($directMatches | Sort-Object ObjectType, { $_.Identifiers.ObjectId } -Unique)
    if ($unique.Count -eq 0) {
        return [PSCustomObject][ordered]@{
            PSTypeName      = 'EntraObjectInspector.ResolutionResult'
            Input           = $inputValue
            NormalizedInput = $normalizedInput
            InputShape      = $inputShape
            Status          = 'NotFound'
            ResolutionType  = $null
            PrimaryObject   = $null
            DirectMatches   = @()
            RelatedObjects  = @()
            Relationships   = @()
            Evidence        = @($TenantSnapshot.Evidence)
            Limitations     = @()
        }
    }

    $apps = @($unique | Where-Object ObjectType -eq 'Application')
    $sps = @($unique | Where-Object ObjectType -eq 'ServicePrincipal')
    $nonApps = @($unique | Where-Object ObjectType -notin @('Application', 'ServicePrincipal'))
    $related = [System.Collections.Generic.List[object]]::new()
    $relationships = [System.Collections.Generic.List[object]]::new()

    if ($nonApps.Count -gt 1 -or ($nonApps.Count -eq 1 -and ($apps.Count + $sps.Count) -gt 0)) {
        return [PSCustomObject][ordered]@{
            PSTypeName      = 'EntraObjectInspector.ResolutionResult'
            Input           = $inputValue
            NormalizedInput = $normalizedInput
            InputShape      = $inputShape
            Status          = 'Ambiguous'
            ResolutionType  = $null
            PrimaryObject   = $null
            DirectMatches   = @($unique)
            RelatedObjects  = @()
            Relationships   = @()
            Evidence        = @($TenantSnapshot.Evidence)
            Limitations     = @('The identifier matched more than one logical identity in the tenant snapshot.')
        }
    }

    foreach ($application in $apps) {
        $appId = [string]$application.Identifiers.AppId
        foreach ($servicePrincipalRaw in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ServicePrincipalByAppId -Key $appId)) {
            $candidate = ConvertTo-InspectorSnapshotCandidate -ObjectType 'ServicePrincipal' -RawObject $servicePrincipalRaw -MatchBasis 'RelatedByAppId' -IsDirectMatch:$false
            if ($candidate.Identifiers.ObjectId -notin @($unique | ForEach-Object { $_.Identifiers.ObjectId })) {
                $related.Add($candidate)
            }
        }
    }

    foreach ($servicePrincipal in $sps) {
        $appId = [string]$servicePrincipal.Identifiers.AppId
        foreach ($applicationRaw in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ApplicationByAppId -Key $appId)) {
            $candidate = ConvertTo-InspectorSnapshotCandidate -ObjectType 'Application' -RawObject $applicationRaw -MatchBasis 'RelatedByAppId' -IsDirectMatch:$false
            if ($candidate.Identifiers.ObjectId -notin @($unique | ForEach-Object { $_.Identifiers.ObjectId })) {
                $related.Add($candidate)
            }
        }
    }

    $all = @($unique + @($related))
    foreach ($application in @($all | Where-Object ObjectType -eq 'Application')) {
        foreach ($servicePrincipal in @($all | Where-Object ObjectType -eq 'ServicePrincipal')) {
            if ([string]$application.Identifiers.AppId -eq [string]$servicePrincipal.Identifiers.AppId) {
                $relationships.Add([PSCustomObject][ordered]@{
                    PSTypeName               = 'EntraObjectInspector.ResolutionRelationship'
                    RelationshipType         = 'ApplicationToServicePrincipal'
                    AppId                    = [string]$application.Identifiers.AppId
                    ApplicationObjectId      = $application.Identifiers.ObjectId
                    ServicePrincipalObjectId = $servicePrincipal.Identifiers.ObjectId
                    Basis                    = 'SharedAppId'
                })
            }
        }
    }

    $resolutionType =
        if (($apps.Count + $sps.Count) -gt 0) {
            'ApplicationIdentity'
        }
        else {
            $unique[0].ObjectType
        }

    return [PSCustomObject][ordered]@{
        PSTypeName      = 'EntraObjectInspector.ResolutionResult'
        Input           = $inputValue
        NormalizedInput = $normalizedInput
        InputShape      = $inputShape
        Status          = 'Resolved'
        ResolutionType  = $resolutionType
        PrimaryObject   = $unique[0]
        DirectMatches   = @($unique)
        RelatedObjects  = @($related)
        Relationships   = @($relationships)
        Evidence        = @($TenantSnapshot.Evidence)
        Limitations     = @()
    }
}
