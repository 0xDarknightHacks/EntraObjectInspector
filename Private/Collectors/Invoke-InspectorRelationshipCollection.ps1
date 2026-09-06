function Invoke-InspectorRelationshipCollection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Resolution
    )

    if ($Resolution.Status -ne 'Resolved') {
        return [PSCustomObject][ordered]@{
            PSTypeName    = 'EntraObjectInspector.RelationshipCollection'
            Status        = 'NotApplicable'
            Completeness  = 'Partial'
            CollectorResults = @()
            Relationships = @()
            Artifacts     = @()
            Evidence      = @()
            Limitations   = @(
                "Relationship collection requires a Resolved object. Resolution status was '$($Resolution.Status)'."
            )
        }
    }

    $collectorResults = [System.Collections.Generic.List[object]]::new()
    $seen = @{}

    $candidates = @(
        @($Resolution.DirectMatches) +
        @($Resolution.RelatedObjects)
    )

    if ($candidates.Count -eq 0 -and $null -ne $Resolution.PrimaryObject) {
        $candidates = @($Resolution.PrimaryObject)
    }

    foreach ($candidate in $candidates) {
        if ($null -eq $candidate) {
            continue
        }

        $objectType = [string]$candidate.ObjectType
        $objectId = [string]$candidate.Identifiers.ObjectId
        $key = "$objectType|$objectId"

        if ($seen.ContainsKey($key)) {
            continue
        }

        $seen[$key] = $true

        switch ($objectType) {
            'Application' {
                $collectorResults.Add(
                    (Get-InspectorApplicationRelationships -Candidate $candidate)
                )
            }
            'ServicePrincipal' {
                $collectorResults.Add(
                    (Get-InspectorServicePrincipalRelationships -Candidate $candidate)
                )
            }
            'User' {
                $collectorResults.Add(
                    (Get-InspectorUserRelationships -Candidate $candidate)
                )
            }
            'Group' {
                $collectorResults.Add(
                    (Get-InspectorGroupRelationships -Candidate $candidate)
                )
            }
            default {
                $collectorResults.Add(
                    (New-InspectorNotApplicableCollectorResult `
                        -CollectorName 'UnsupportedObjectType' `
                        -ExpectedObjectType 'Application, ServicePrincipal, User, or Group' `
                        -ActualObjectType $objectType `
                        -SourceObjectId $objectId)
                )
            }
        }
    }

    $statuses = @($collectorResults | ForEach-Object { $_.Status })

    $overallStatus =
        if (@($statuses | Where-Object { $_ -eq 'Failed' }).Count -gt 0) {
            'Failed'
        }
        elseif (@($statuses | Where-Object { $_ -eq 'InsufficientPermission' }).Count -gt 0) {
            'InsufficientPermission'
        }
        elseif (@($statuses | Where-Object { $_ -eq 'Success' }).Count -gt 0) {
            'Success'
        }
        elseif (@($statuses | Where-Object { $_ -eq 'NotFound' }).Count -gt 0) {
            'NotFound'
        }
        else {
            'NotApplicable'
        }

    $completeness =
        if (@($collectorResults | Where-Object { $_.Completeness -eq 'Partial' }).Count -gt 0) {
            'Partial'
        }
        else {
            'Complete'
        }

    return [PSCustomObject][ordered]@{
        PSTypeName       = 'EntraObjectInspector.RelationshipCollection'
        Status           = $overallStatus
        Completeness     = $completeness
        CollectorResults = @($collectorResults)
        Relationships    = @(
            $collectorResults |
            ForEach-Object { @($_.Relationships) }
        )
        Artifacts        = @(
            $collectorResults |
            ForEach-Object { @($_.Artifacts) }
        )
        Evidence         = @(
            $collectorResults |
            ForEach-Object { @($_.Evidence) }
        )
        Limitations      = @(
            $collectorResults |
            ForEach-Object { @($_.Limitations) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Select-Object -Unique
        )
    }
}
