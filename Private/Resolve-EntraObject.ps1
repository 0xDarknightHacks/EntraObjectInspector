function Get-InspectorPropertyValue {
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

function Invoke-InspectorResolverProbe {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$RequiredPermission,

        [Parameter(Mandatory)]
        [string]$QueryName,

        [Parameter(Mandatory)]
        [ValidateSet('User', 'Group', 'Application', 'ServicePrincipal')]
        [string]$ObjectType,

        [Parameter(Mandatory)]
        [ValidateSet('UserPrincipalName', 'ObjectId', 'AppId', 'RelatedByAppId')]
        [string]$MatchBasis,

        [Parameter(Mandatory)]
        [bool]$IsDirectMatchQuery
    )

    $graphResult = Invoke-InspectorGraphRequest `
        -Uri $Uri `
        -RequiredPermission $RequiredPermission

    $evidence = [PSCustomObject][ordered]@{
        PSTypeName         = 'EntraObjectInspector.ResolutionEvidence'
        QueryName          = $QueryName
        ObjectTypeProbe    = $ObjectType
        MatchBasis         = $MatchBasis
        IsDirectMatchQuery = $IsDirectMatchQuery
        Endpoint           = $graphResult.SourceEndpoint
        RequiredPermission = $graphResult.RequiredPermission
        CollectionTime     = $graphResult.CollectionTime
        Status             = $graphResult.Status
        Result             = $graphResult.ObservedValue
        Limitations        = @($graphResult.Limitations)
    }

    $candidates = [System.Collections.Generic.List[object]]::new()

    if ($graphResult.Status -eq 'Success') {
        foreach ($item in @($graphResult.ObservedValue)) {
            if ($null -eq $item) {
                continue
            }

            $objectId = [string](Get-InspectorPropertyValue `
                -InputObject $item `
                -Name 'id')

            if ([string]::IsNullOrWhiteSpace($objectId)) {
                continue
            }

            $identifiers = [ordered]@{
                ObjectId = $objectId
            }

            if ($ObjectType -in @('Application', 'ServicePrincipal')) {
                $appId = [string](Get-InspectorPropertyValue `
                    -InputObject $item `
                    -Name 'appId')

                if (-not [string]::IsNullOrWhiteSpace($appId)) {
                    $identifiers.AppId = $appId
                }
            }

            if ($ObjectType -eq 'User') {
                $upn = [string](Get-InspectorPropertyValue `
                    -InputObject $item `
                    -Name 'userPrincipalName')

                if (-not [string]::IsNullOrWhiteSpace($upn)) {
                    $identifiers.UserPrincipalName = $upn
                }
            }

            $candidate = [PSCustomObject][ordered]@{
                PSTypeName    = 'EntraObjectInspector.ResolutionCandidate'
                ObjectType    = $ObjectType
                DisplayName   = [string](Get-InspectorPropertyValue `
                    -InputObject $item `
                    -Name 'displayName')
                Identifiers   = [PSCustomObject]$identifiers
                MatchBasis    = @($MatchBasis)
                IsDirectMatch = $IsDirectMatchQuery
                RawObject     = $item
            }

            $candidates.Add($candidate)
        }
    }

    return [PSCustomObject][ordered]@{
        Evidence   = $evidence
        Candidates = @($candidates)
    }
}

function Resolve-EntraObject {
    <#
    .SYNOPSIS
        Deterministically resolves a supported Microsoft Entra identifier.

    .DESCRIPTION
        Classifies only the input shape first, then uses Microsoft Graph evidence
        to determine what the identifier represents.

        A GUID is never assumed to represent a specific Entra object type.

        Supported V1 resolver object types:
        - User
        - Group
        - Application
        - Service Principal

        Supported input shapes:
        - UPN-like value
        - GUID

        A GUID is probed as:
        - User object ID
        - Group object ID
        - Application object ID
        - Service Principal object ID
        - Application appId / Client ID
        - Service Principal appId / Client ID

        Application and Service Principal objects that share the same appId are
        represented as one logical application identity while preserving their
        distinct directory object IDs.

    .PARAMETER Identity
        Arbitrary identifier to resolve.

    .OUTPUTS
        EntraObjectInspector.ResolutionResult
    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
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
        [ValidateNotNullOrEmpty()]
        [string]$Identity
    )

    process {
        $inputValue = $Identity.Trim()

        $evidence = [System.Collections.Generic.List[object]]::new()
        $limitations = [System.Collections.Generic.List[string]]::new()
        $candidateMap = [ordered]@{}
        $queriedUris = @{}

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
                Limitations     = @(
                    'Input is neither a supported UPN-like value nor a GUID.'
                )
            }
        }

        $graphBaseUri = 'https://graph.microsoft.com/v1.0'

        $mergeProbe = {
            param (
                [Parameter(Mandatory)]
                [string]$Uri,

                [Parameter(Mandatory)]
                [string]$RequiredPermission,

                [Parameter(Mandatory)]
                [string]$QueryName,

                [Parameter(Mandatory)]
                [string]$ObjectType,

                [Parameter(Mandatory)]
                [string]$MatchBasis,

                [Parameter(Mandatory)]
                [bool]$IsDirectMatchQuery
            )

            if ($queriedUris.ContainsKey($Uri)) {
                return
            }

            $queriedUris[$Uri] = $true

            $probe = Invoke-InspectorResolverProbe `
                -Uri $Uri `
                -RequiredPermission $RequiredPermission `
                -QueryName $QueryName `
                -ObjectType $ObjectType `
                -MatchBasis $MatchBasis `
                -IsDirectMatchQuery $IsDirectMatchQuery

            $evidence.Add($probe.Evidence)

            foreach ($candidate in @($probe.Candidates)) {
                $objectId = [string]$candidate.Identifiers.ObjectId
                $candidateKey = "$($candidate.ObjectType)|$objectId"

                if ($candidateMap.Contains($candidateKey)) {
                    $existing = $candidateMap[$candidateKey]

                    $existing.MatchBasis = @(
                        @($existing.MatchBasis) +
                        @($candidate.MatchBasis) |
                        Select-Object -Unique
                    )

                    if ($candidate.IsDirectMatch) {
                        $existing.IsDirectMatch = $true
                    }
                }
                else {
                    $candidateMap[$candidateKey] = $candidate
                }
            }
        }

        if ($inputShape -eq 'UpnLike') {
            if ($inputValue.StartsWith('$')) {
                $odataLiteral = $inputValue.Replace("'", "''")
                $userUri =
                    "$graphBaseUri/users('$odataLiteral')?`$select=id,displayName,userPrincipalName"
            }
            else {
                $encodedUpn = [uri]::EscapeDataString($inputValue)
                $userUri =
                    "$graphBaseUri/users/${encodedUpn}?`$select=id,displayName,userPrincipalName"
            }

            & $mergeProbe `
                -Uri $userUri `
                -RequiredPermission 'User.Read.All' `
                -QueryName 'UserByUserPrincipalName' `
                -ObjectType 'User' `
                -MatchBasis 'UserPrincipalName' `
                -IsDirectMatchQuery $true

            $directEvidence = @(
                $evidence |
                Where-Object { $_.IsDirectMatchQuery }
            )

            $directMatches = @(
                $candidateMap.Values |
                Where-Object { $_.IsDirectMatch }
            )

            $status = $null

            if ($directMatches.Count -eq 1) {
                $status = 'Resolved'
            }
            elseif (
                @($directEvidence |
                    Where-Object { $_.Status -eq 'InsufficientPermission' }
                ).Count -gt 0
            ) {
                $status = 'InsufficientPermission'
                $limitations.Add(
                    'The user lookup could not be completed because Microsoft Graph returned 403.'
                )
            }
            elseif (
                @($directEvidence |
                    Where-Object {
                        $_.Status -in @(
                            'Failed',
                            'Throttled',
                            'ServiceUnavailable'
                        )
                    }
                ).Count -gt 0
            ) {
                $status = 'Indeterminate'
                $limitations.Add(
                    'The user lookup could not be completed because at least one Graph request failed transiently or unexpectedly.'
                )
            }
            else {
                $status = 'NotFound'
            }

            return [PSCustomObject][ordered]@{
                PSTypeName      = 'EntraObjectInspector.ResolutionResult'
                Input           = $inputValue
                NormalizedInput = $normalizedInput
                InputShape      = $inputShape
                Status          = $status
                ResolutionType  = if ($status -eq 'Resolved') {
                    'User'
                }
                else {
                    $null
                }
                PrimaryObject   = if ($status -eq 'Resolved') {
                    $directMatches[0]
                }
                else {
                    $null
                }
                DirectMatches   = $directMatches
                RelatedObjects  = @()
                Relationships   = @()
                Evidence        = @($evidence)
                Limitations     = @($limitations)
            }
        }

        # GUID input: probe all supported object-ID and appId meanings.
        $userObjectUri =
            "$graphBaseUri/users/${normalizedInput}?`$select=id,displayName,userPrincipalName"

        $groupObjectUri =
            "$graphBaseUri/groups/${normalizedInput}?`$select=id,displayName"

        $applicationObjectUri =
            "$graphBaseUri/applications/${normalizedInput}?`$select=id,appId,displayName"

        $servicePrincipalObjectUri =
            "$graphBaseUri/servicePrincipals/${normalizedInput}?`$select=id,appId,displayName"

        $applicationAppIdUri =
            "$graphBaseUri/applications(appId='$normalizedInput')?`$select=id,appId,displayName"

        $servicePrincipalAppIdUri =
            "$graphBaseUri/servicePrincipals(appId='$normalizedInput')?`$select=id,appId,displayName"

        & $mergeProbe `
            -Uri $userObjectUri `
            -RequiredPermission 'User.Read.All' `
            -QueryName 'UserByObjectId' `
            -ObjectType 'User' `
            -MatchBasis 'ObjectId' `
            -IsDirectMatchQuery $true

        & $mergeProbe `
            -Uri $groupObjectUri `
            -RequiredPermission 'GroupMember.Read.All' `
            -QueryName 'GroupByObjectId' `
            -ObjectType 'Group' `
            -MatchBasis 'ObjectId' `
            -IsDirectMatchQuery $true

        & $mergeProbe `
            -Uri $applicationObjectUri `
            -RequiredPermission 'Application.Read.All' `
            -QueryName 'ApplicationByObjectId' `
            -ObjectType 'Application' `
            -MatchBasis 'ObjectId' `
            -IsDirectMatchQuery $true

        & $mergeProbe `
            -Uri $servicePrincipalObjectUri `
            -RequiredPermission 'Application.Read.All' `
            -QueryName 'ServicePrincipalByObjectId' `
            -ObjectType 'ServicePrincipal' `
            -MatchBasis 'ObjectId' `
            -IsDirectMatchQuery $true

        & $mergeProbe `
            -Uri $applicationAppIdUri `
            -RequiredPermission 'Application.Read.All' `
            -QueryName 'ApplicationByAppId' `
            -ObjectType 'Application' `
            -MatchBasis 'AppId' `
            -IsDirectMatchQuery $true

        & $mergeProbe `
            -Uri $servicePrincipalAppIdUri `
            -RequiredPermission 'Application.Read.All' `
            -QueryName 'ServicePrincipalByAppId' `
            -ObjectType 'ServicePrincipal' `
            -MatchBasis 'AppId' `
            -IsDirectMatchQuery $true

        $directEvidence = @(
            $evidence |
            Where-Object { $_.IsDirectMatchQuery }
        )

        $directMatches = @(
            $candidateMap.Values |
            Where-Object { $_.IsDirectMatch }
        )

        $objectIdMatches = @(
            $directMatches |
            Where-Object {
                $_.MatchBasis -contains 'ObjectId'
            }
        )

        $appIdMatches = @(
            $directMatches |
            Where-Object {
                $_.MatchBasis -contains 'AppId'
            }
        )

        $isAmbiguous = $false

        if ($objectIdMatches.Count -gt 1) {
            $isAmbiguous = $true
        }
        elseif (
            $objectIdMatches.Count -eq 1 -and
            $appIdMatches.Count -gt 0
        ) {
            $objectMatch = $objectIdMatches[0]

            $objectAppId = [string](Get-InspectorPropertyValue `
                -InputObject $objectMatch.Identifiers `
                -Name 'AppId')

            $sameLogicalApplication =
                $objectMatch.ObjectType -in @(
                    'Application',
                    'ServicePrincipal'
                ) -and
                $objectAppId -eq $normalizedInput -and
                @(
                    $appIdMatches |
                    Where-Object {
                        $_.ObjectType -notin @(
                            'Application',
                            'ServicePrincipal'
                        ) -or
                        [string](Get-InspectorPropertyValue `
                            -InputObject $_.Identifiers `
                            -Name 'AppId') -ne $normalizedInput
                    }
                ).Count -eq 0

            if (-not $sameLogicalApplication) {
                $isAmbiguous = $true
            }
        }
        elseif ($objectIdMatches.Count -eq 0 -and $appIdMatches.Count -gt 0) {
            $invalidAppIdCandidate = @(
                $appIdMatches |
                Where-Object {
                    $_.ObjectType -notin @(
                        'Application',
                        'ServicePrincipal'
                    ) -or
                    [string](Get-InspectorPropertyValue `
                        -InputObject $_.Identifiers `
                        -Name 'AppId') -ne $normalizedInput
                }
            )

            if ($invalidAppIdCandidate.Count -gt 0) {
                $isAmbiguous = $true
            }
        }

        $hasPermissionFailure = @(
            $directEvidence |
            Where-Object {
                $_.Status -eq 'InsufficientPermission'
            }
        ).Count -gt 0

        $hasIndeterminateFailure = @(
            $directEvidence |
            Where-Object {
                $_.Status -in @(
                    'Failed',
                    'Throttled',
                    'ServiceUnavailable'
                )
            }
        ).Count -gt 0

        if ($isAmbiguous) {
            return [PSCustomObject][ordered]@{
                PSTypeName      = 'EntraObjectInspector.ResolutionResult'
                Input           = $inputValue
                NormalizedInput = $normalizedInput
                InputShape      = $inputShape
                Status          = 'Ambiguous'
                ResolutionType  = $null
                PrimaryObject   = $null
                DirectMatches   = $directMatches
                RelatedObjects  = @()
                Relationships   = @()
                Evidence        = @($evidence)
                Limitations     = @(
                    'The GUID produced direct matches for more than one logical identity. No object type was guessed.'
                )
            }
        }

        if ($hasPermissionFailure) {
            $limitations.Add(
                'At least one required GUID resolver probe returned 403. Resolution is intentionally not declared complete.'
            )

            return [PSCustomObject][ordered]@{
                PSTypeName      = 'EntraObjectInspector.ResolutionResult'
                Input           = $inputValue
                NormalizedInput = $normalizedInput
                InputShape      = $inputShape
                Status          = 'InsufficientPermission'
                ResolutionType  = $null
                PrimaryObject   = $null
                DirectMatches   = $directMatches
                RelatedObjects  = @()
                Relationships   = @()
                Evidence        = @($evidence)
                Limitations     = @($limitations)
            }
        }

        if ($hasIndeterminateFailure) {
            $limitations.Add(
                'At least one required GUID resolver probe failed transiently or unexpectedly. Resolution is intentionally not guessed.'
            )

            return [PSCustomObject][ordered]@{
                PSTypeName      = 'EntraObjectInspector.ResolutionResult'
                Input           = $inputValue
                NormalizedInput = $normalizedInput
                InputShape      = $inputShape
                Status          = 'Indeterminate'
                ResolutionType  = $null
                PrimaryObject   = $null
                DirectMatches   = $directMatches
                RelatedObjects  = @()
                Relationships   = @()
                Evidence        = @($evidence)
                Limitations     = @($limitations)
            }
        }

        if ($directMatches.Count -eq 0) {
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
                Evidence        = @($evidence)
                Limitations     = @()
            }
        }

        $resolutionType = $null
        $primaryObject = $null

        if ($appIdMatches.Count -gt 0) {
            $resolutionType = 'ApplicationIdentity'

            $primaryObject = @(
                $directMatches |
                Where-Object { $_.ObjectType -eq 'Application' }
            ) | Select-Object -First 1

            if ($null -eq $primaryObject) {
                $primaryObject = @(
                    $directMatches |
                    Where-Object {
                        $_.ObjectType -eq 'ServicePrincipal'
                    }
                ) | Select-Object -First 1
            }
        }
        else {
            $primaryObject = $directMatches[0]
            $resolutionType = $primaryObject.ObjectType
        }

        # Enrich a directly resolved Application or Service Principal with its
        # counterpart using the object's actual appId. These are related objects,
        # not additional direct matches for the original identifier.
        foreach ($directCandidate in @($directMatches)) {
            if (
                $directCandidate.ObjectType -notin @(
                    'Application',
                    'ServicePrincipal'
                )
            ) {
                continue
            }

            $candidateAppId = [string](Get-InspectorPropertyValue `
                -InputObject $directCandidate.Identifiers `
                -Name 'AppId')

            if ([string]::IsNullOrWhiteSpace($candidateAppId)) {
                continue
            }

            if ($directCandidate.ObjectType -eq 'Application') {
                $relatedUri =
                    "$graphBaseUri/servicePrincipals(appId='$candidateAppId')?`$select=id,appId,displayName"

                & $mergeProbe `
                    -Uri $relatedUri `
                    -RequiredPermission 'Application.Read.All' `
                    -QueryName 'RelatedServicePrincipalByAppId' `
                    -ObjectType 'ServicePrincipal' `
                    -MatchBasis 'RelatedByAppId' `
                    -IsDirectMatchQuery $false
            }
            elseif ($directCandidate.ObjectType -eq 'ServicePrincipal') {
                $relatedUri =
                    "$graphBaseUri/applications(appId='$candidateAppId')?`$select=id,appId,displayName"

                & $mergeProbe `
                    -Uri $relatedUri `
                    -RequiredPermission 'Application.Read.All' `
                    -QueryName 'RelatedApplicationByAppId' `
                    -ObjectType 'Application' `
                    -MatchBasis 'RelatedByAppId' `
                    -IsDirectMatchQuery $false
            }
        }

        $allCandidates = @($candidateMap.Values)

        $relatedObjects = @(
            $allCandidates |
            Where-Object { -not $_.IsDirectMatch }
        )

        $relationships =
            [System.Collections.Generic.List[object]]::new()

        $applications = @(
            $allCandidates |
            Where-Object { $_.ObjectType -eq 'Application' }
        )

        $servicePrincipals = @(
            $allCandidates |
            Where-Object {
                $_.ObjectType -eq 'ServicePrincipal'
            }
        )

        foreach ($application in $applications) {
            $applicationAppId = [string](Get-InspectorPropertyValue `
                -InputObject $application.Identifiers `
                -Name 'AppId')

            if ([string]::IsNullOrWhiteSpace($applicationAppId)) {
                continue
            }

            foreach ($servicePrincipal in $servicePrincipals) {
                $servicePrincipalAppId = [string](Get-InspectorPropertyValue `
                    -InputObject $servicePrincipal.Identifiers `
                    -Name 'AppId')

                if (
                    -not [string]::IsNullOrWhiteSpace(
                        $servicePrincipalAppId
                    ) -and
                    $applicationAppId -eq $servicePrincipalAppId
                ) {
                    $relationships.Add(
                        [PSCustomObject][ordered]@{
                            PSTypeName               = 'EntraObjectInspector.ResolutionRelationship'
                            RelationshipType         = 'ApplicationToServicePrincipal'
                            AppId                    = $applicationAppId
                            ApplicationObjectId      = $application.Identifiers.ObjectId
                            ServicePrincipalObjectId = $servicePrincipal.Identifiers.ObjectId
                            Basis                    = 'SharedAppId'
                        }
                    )
                }
            }
        }

        $relatedEvidenceFailures = @(
            $evidence |
            Where-Object {
                -not $_.IsDirectMatchQuery -and
                $_.Status -notin @(
                    'Success',
                    'NotFound'
                )
            }
        )

        if ($relatedEvidenceFailures.Count -gt 0) {
            $limitations.Add(
                'Core resolution succeeded, but one or more related Application/Service Principal enrichment queries could not be completed.'
            )
        }

        return [PSCustomObject][ordered]@{
            PSTypeName      = 'EntraObjectInspector.ResolutionResult'
            Input           = $inputValue
            NormalizedInput = $normalizedInput
            InputShape      = $inputShape
            Status          = 'Resolved'
            ResolutionType  = $resolutionType
            PrimaryObject   = $primaryObject
            DirectMatches   = @(
                $candidateMap.Values |
                Where-Object { $_.IsDirectMatch }
            )
            RelatedObjects  = $relatedObjects
            Relationships   = @($relationships)
            Evidence        = @($evidence)
            Limitations     = @($limitations)
        }
    }
}
