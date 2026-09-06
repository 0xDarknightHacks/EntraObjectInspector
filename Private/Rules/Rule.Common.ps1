function Get-InspectorRuleProperty {
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

function New-InspectorRuleResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$RuleId,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [string]$Description = '',

        [object[]]$EvidenceIds = @(),

        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [ValidateSet('High', 'Medium', 'Low')]
        [string]$Confidence,

        [string[]]$Limitations = @(),

        [hashtable]$Metadata = @{}
    )

    return [PSCustomObject][ordered]@{
        PSTypeName  = 'EntraObjectInspector.RuleResult'
        RuleId      = $RuleId
        Title       = $Title
        Severity    = $Severity
        Description = $Description
        EvidenceIds = @($EvidenceIds | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } | Select-Object -Unique)
        Source      = $Source
        Confidence  = $Confidence
        Limitations = @($Limitations)
        Metadata    = [PSCustomObject]$Metadata
    }
}

function Get-InspectorSourceObjectsByType {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [Parameter(Mandatory)]
        [string[]]$ObjectType
    )

    return @(
        (Get-InspectorRuleProperty `
            -InputObject $ObjectInsight `
            -Name 'SourceObjects') |
        Where-Object {
            if ($null -eq $_) {
                return $false
            }

            $currentObjectType =
                Get-InspectorRuleProperty `
                    -InputObject $_ `
                    -Name 'ObjectType'

            $currentObjectId =
                Get-InspectorRuleProperty `
                    -InputObject $_ `
                    -Name 'ObjectId'

            return (
                $currentObjectType -in $ObjectType -and
                -not [string]::IsNullOrWhiteSpace([string]$currentObjectId)
            )
        }
    )
}

function Get-InspectorRelationshipsForSource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [Parameter(Mandatory)]
        [string]$SourceObjectId,

        [string[]]$RelationshipType = @()
    )

    $relationships = @(
        (Get-InspectorRuleProperty `
            -InputObject $ObjectInsight `
            -Name 'Relationships') |
        Where-Object {
            if ($null -eq $_) {
                return $false
            }

            $currentSourceObjectId =
                Get-InspectorRuleProperty `
                    -InputObject $_ `
                    -Name 'SourceObjectId'

            return $currentSourceObjectId -eq $SourceObjectId
        }
    )

    if (@($RelationshipType).Count -gt 0) {
        $relationships = @(
            $relationships |
            Where-Object {
                if ($null -eq $_) {
                    return $false
                }

                $currentRelationshipType =
                    Get-InspectorRuleProperty `
                        -InputObject $_ `
                        -Name 'RelationshipType'

                return $currentRelationshipType -in $RelationshipType
            }
        )
    }

    return @($relationships)
}

function Get-InspectorObjectDisplayName {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$SourceObject
    )

    $properties =
        Get-InspectorRuleProperty `
            -InputObject $SourceObject `
            -Name 'Properties'

    $displayName =
        Get-InspectorRuleProperty `
            -InputObject $properties `
            -Name 'DisplayName'

    if (-not [string]::IsNullOrWhiteSpace([string]$displayName)) {
        return [string]$displayName
    }

    return [string](
        Get-InspectorRuleProperty `
            -InputObject $SourceObject `
            -Name 'ObjectId'
    )
}

function Get-InspectorEvidenceIdsFromItems {
    [CmdletBinding()]
    param (
        [object[]]$Items
    )

    return @(
        $Items |
        ForEach-Object {
            $evidenceId = Get-InspectorRuleProperty -InputObject $_ -Name 'EvidenceId'
            if ([string]::IsNullOrWhiteSpace([string]$evidenceId)) {
                $evidenceId = Get-InspectorRuleProperty -InputObject $_ -Name 'ParentEvidenceId'
            }
            $evidenceId
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } |
        Select-Object -Unique
    )
}

function Get-InspectorMetadataValue {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Metadata,

        [Parameter(Mandatory)]
        [string]$Name
    )

    return Get-InspectorRuleProperty `
        -InputObject $Metadata `
        -Name $Name
}
