function Get-InspectorOrchestrationProperty {
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

function New-InspectorStructuredLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Stage,

        [Parameter(Mandatory)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data = @{}
    )

    return [PSCustomObject][ordered]@{
        PSTypeName = 'EntraObjectInspector.StructuredLog'
        Timestamp  = (Get-Date).ToUniversalTime().ToString('o')
        Stage      = $Stage
        Level      = $Level
        Message    = $Message
        Data       = [PSCustomObject]$Data
    }
}

function New-InspectorDiscoveredObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string]$ObjectType,

        [Parameter(Mandatory)]
        [string]$ObjectId,

        [string]$DisplayName,

        [string]$AppId,

        [string]$UserPrincipalName,

        [string]$DiscoverySource,

        [string]$EvidenceId,

        [hashtable]$Metadata = @{}
    )

    $inspectionIdentity =
        if ($ObjectType -eq 'User' -and -not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
            $UserPrincipalName
        }
        else {
            $ObjectId
        }

    return [PSCustomObject][ordered]@{
        PSTypeName         = 'EntraObjectInspector.DiscoveredObject'
        ObjectType         = $ObjectType
        ObjectId           = $ObjectId
        AppId              = $AppId
        UserPrincipalName  = $UserPrincipalName
        DisplayName        = $DisplayName
        InspectionIdentity = $inspectionIdentity
        ObjectKey          = "$ObjectType`:$ObjectId"
        DiscoverySource    = $DiscoverySource
        EvidenceId         = $EvidenceId
        Metadata           = [PSCustomObject]$Metadata
    }
}

function New-InspectorDiscoveryEvidence {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$QueryName,

        [Parameter(Mandatory)]
        [object]$GraphResult
    )

    return [PSCustomObject][ordered]@{
        PSTypeName         = 'EntraObjectInspector.DiscoveryEvidence'
        EvidenceId         = [guid]::NewGuid().ToString()
        QueryName          = $QueryName
        Endpoint           = $GraphResult.SourceEndpoint
        RequiredPermission = $GraphResult.RequiredPermission
        CollectionTime     = $GraphResult.CollectionTime
        Status             = $GraphResult.Status
        ResultCount        = @($GraphResult.ObservedValue).Count
        Limitations        = @($GraphResult.Limitations)
    }
}

function New-InspectorCheckpointState {
    [CmdletBinding()]
    param ()

    return [PSCustomObject][ordered]@{
        SchemaVersion       = '0.6.0'
        CreatedAt           = (Get-Date).ToUniversalTime().ToString('o')
        UpdatedAt           = (Get-Date).ToUniversalTime().ToString('o')
        ProcessedObjectKeys = @()
        FailedObjectKeys    = @()
        LastObjectKey       = $null
    }
}

function Read-InspectorCheckpointState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return New-InspectorCheckpointState
    }

    $json =
        Get-Content `
            -LiteralPath $Path `
            -Raw `
            -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($json)) {
        return New-InspectorCheckpointState
    }

    $state =
        $json |
        ConvertFrom-Json `
            -ErrorAction Stop

    if ($null -eq $state.PSObject.Properties['ProcessedObjectKeys']) {
        $state |
            Add-Member `
                -NotePropertyName 'ProcessedObjectKeys' `
                -NotePropertyValue @() `
                -Force
    }

    if ($null -eq $state.PSObject.Properties['FailedObjectKeys']) {
        $state |
            Add-Member `
                -NotePropertyName 'FailedObjectKeys' `
                -NotePropertyValue @() `
                -Force
    }

    return $state
}

function Write-InspectorCheckpointState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [object]$State
    )

    $directory =
        Split-Path `
            -Path $Path `
            -Parent

    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item `
            -ItemType Directory `
            -Path $directory `
            -Force |
            Out-Null
    }

    $State.UpdatedAt = (Get-Date).ToUniversalTime().ToString('o')

    $State |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -LiteralPath $Path `
            -Encoding UTF8 `
            -Force
}

function Add-InspectorCheckpointObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$State,

        [Parameter(Mandatory)]
        [string]$ObjectKey,

        [switch]$Failed
    )

    if ($Failed) {
        $failedKeys = @($State.FailedObjectKeys)
        if ($ObjectKey -notin $failedKeys) {
            $failedKeys += $ObjectKey
        }
        $State.FailedObjectKeys = @($failedKeys | Sort-Object -Unique)
        $State.ProcessedObjectKeys = @($State.ProcessedObjectKeys | Where-Object { $_ -ne $ObjectKey } | Sort-Object -Unique)
    }
    else {
        $processed = @($State.ProcessedObjectKeys)
        if ($ObjectKey -notin $processed) {
            $processed += $ObjectKey
        }
        $State.ProcessedObjectKeys = @($processed | Sort-Object -Unique)
        $State.FailedObjectKeys = @($State.FailedObjectKeys | Where-Object { $_ -ne $ObjectKey } | Sort-Object -Unique)
    }

    $State.LastObjectKey = $ObjectKey
}
