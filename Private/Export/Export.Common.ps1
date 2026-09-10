function Get-InspectorExportProperty {
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

function Set-InspectorExportProperty {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Value
    )

    $InputObject |
        Add-Member `
            -NotePropertyName $Name `
            -NotePropertyValue $Value `
            -Force
}

function ConvertTo-InspectorExportArray {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return @()
    }

    return @($Value)
}

function ConvertTo-InspectorExportString {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [array]) {
        return (@($Value) | ForEach-Object { [string]$_ }) -join '; '
    }

    if (
        $Value -is [System.Management.Automation.PSCustomObject] -or
        $Value -is [hashtable]
    ) {
        return (
            $Value |
            ConvertTo-Json -Depth 20 -Compress
        )
    }

    return [string]$Value
}

function ConvertTo-InspectorInventoryDetails {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$TenantSnapshot
    )

    $collections = Get-InspectorExportProperty -InputObject $TenantSnapshot -Name 'Collections'
    if ($null -eq $collections) { return $null }

    $getCollection = {
        param ([string]$Name)
        return @((Get-InspectorExportProperty -InputObject $collections -Name $Name) | Where-Object { $null -ne $_ })
    }
    $users = & $getCollection 'Users'
    $groups = & $getCollection 'Groups'
    $applications = & $getCollection 'Applications'
    $servicePrincipals = & $getCollection 'ServicePrincipals'
    $roleDefinitions = & $getCollection 'DirectoryRoleDefinitions'
    $administrativeUnits = & $getCollection 'AdministrativeUnits'

    $principalIndex = @{}
    foreach ($definition in @(
        [PSCustomObject]@{ Type='User'; Items=$users },
        [PSCustomObject]@{ Type='Group'; Items=$groups },
        [PSCustomObject]@{ Type='ServicePrincipal'; Items=$servicePrincipals }
    )) {
        foreach ($item in @($definition.Items)) {
            $id = [string](Get-InspectorExportProperty -InputObject $item -Name 'id')
            if (-not [string]::IsNullOrWhiteSpace($id)) {
                $principalIndex[$id] = [PSCustomObject]@{
                    DisplayName = [string](Get-InspectorExportProperty -InputObject $item -Name 'displayName')
                    Type = $definition.Type
                    AppId = $(if ($definition.Type -eq 'ServicePrincipal') { [string](Get-InspectorExportProperty -InputObject $item -Name 'appId') } else { '' })
                }
            }
        }
    }
    $roleIndex = @{}
    foreach ($role in $roleDefinitions) {
        $id = [string](Get-InspectorExportProperty -InputObject $role -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($id)) { $roleIndex[$id] = [string](Get-InspectorExportProperty -InputObject $role -Name 'displayName') }
    }
    $auIndex = @{}
    foreach ($unit in $administrativeUnits) {
        $id = [string](Get-InspectorExportProperty -InputObject $unit -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($id)) { $auIndex[$id] = [string](Get-InspectorExportProperty -InputObject $unit -Name 'displayName') }
    }

    $resolvePrincipal = {
        param ([string]$Id)
        if ($principalIndex.ContainsKey($Id)) {
            $name = [string]$principalIndex[$Id].DisplayName
            return [PSCustomObject]@{
                Name = $(if ([string]::IsNullOrWhiteSpace($name)) { $Id } else { $name })
                Type = $principalIndex[$Id].Type
                AppId = [string]$principalIndex[$Id].AppId
            }
        }
        return [PSCustomObject]@{ Name=$Id; Type='Unknown'; AppId='' }
    }
    $resolveRole = {
        param ([object]$Item)
        $embedded = Get-InspectorExportProperty -InputObject $Item -Name 'roleDefinition'
        $embeddedName = [string](Get-InspectorExportProperty -InputObject $embedded -Name 'displayName')
        if (-not [string]::IsNullOrWhiteSpace($embeddedName)) { return $embeddedName }
        $id = [string](Get-InspectorExportProperty -InputObject $Item -Name 'roleDefinitionId')
        if ($roleIndex.ContainsKey($id) -and -not [string]::IsNullOrWhiteSpace($roleIndex[$id])) { return $roleIndex[$id] }
        return $id
    }
    $resolveScope = {
        param ([object]$Item)
        $directoryScopeId = [string](Get-InspectorExportProperty -InputObject $Item -Name 'directoryScopeId')
        $appScopeId = [string](Get-InspectorExportProperty -InputObject $Item -Name 'appScopeId')
        if ([string]::IsNullOrWhiteSpace($directoryScopeId) -or $directoryScopeId -eq '/') { return 'Tenant' }
        if ($directoryScopeId -match '^/administrativeUnits/([^/]+)$') {
            $auId = $Matches[1]
            if ($auIndex.ContainsKey($auId) -and -not [string]::IsNullOrWhiteSpace($auIndex[$auId])) { return "Administrative Unit: $($auIndex[$auId])" }
        }
        if (-not [string]::IsNullOrWhiteSpace($appScopeId)) { return "App scope: $appScopeId" }
        return $directoryScopeId
    }

    $directoryAssignments = & $getCollection 'DirectoryRoleAssignments'
    $assignmentIds = @{}
    $assignmentTuples = @{}
    $directoryRoleRows = @(
        foreach ($item in $directoryAssignments) {
            $principalId = [string](Get-InspectorExportProperty -InputObject $item -Name 'principalId')
            $roleDefinitionId = [string](Get-InspectorExportProperty -InputObject $item -Name 'roleDefinitionId')
            $directoryScopeId = [string](Get-InspectorExportProperty -InputObject $item -Name 'directoryScopeId')
            $appScopeId = [string](Get-InspectorExportProperty -InputObject $item -Name 'appScopeId')
            $id = [string](Get-InspectorExportProperty -InputObject $item -Name 'id')
            if (-not [string]::IsNullOrWhiteSpace($id)) { $assignmentIds[$id] = $true }
            $assignmentTuples["$principalId|$roleDefinitionId|$directoryScopeId|$appScopeId"] = $true
            $principal = & $resolvePrincipal $principalId
            [PSCustomObject][ordered]@{ Principal=$principal.Name; PrincipalType=$principal.Type; PrincipalId=$principalId; AppId=$principal.AppId; Role=(& $resolveRole $item); RoleDefinitionId=$roleDefinitionId; Scope=(& $resolveScope $item); AssignmentId=$id }
        }
    )

    $pimRows = {
        param ([string]$CollectionName, [bool]$Eligible)
        return @(
            foreach ($item in (& $getCollection $CollectionName)) {
                $principalId = [string](Get-InspectorExportProperty -InputObject $item -Name 'principalId')
                $roleDefinitionId = [string](Get-InspectorExportProperty -InputObject $item -Name 'roleDefinitionId')
                $directoryScopeId = [string](Get-InspectorExportProperty -InputObject $item -Name 'directoryScopeId')
                $appScopeId = [string](Get-InspectorExportProperty -InputObject $item -Name 'appScopeId')
                $assignmentType = [string](Get-InspectorExportProperty -InputObject $item -Name 'assignmentType')
                $originId = [string](Get-InspectorExportProperty -InputObject $item -Name 'roleAssignmentOriginId')
                $tuple = "$principalId|$roleDefinitionId|$directoryScopeId|$appScopeId"
                if (-not $Eligible -and $assignmentType -eq 'Assigned' -and (($assignmentIds.ContainsKey($originId)) -or $assignmentTuples.ContainsKey($tuple))) { continue }
                $principal = & $resolvePrincipal $principalId
                [PSCustomObject][ordered]@{
                    Principal=$principal.Name; PrincipalType=$principal.Type; PrincipalId=$principalId; AppId=$principal.AppId
                    Role=(& $resolveRole $item); RoleDefinitionId=$roleDefinitionId; Scope=(& $resolveScope $item)
                    State=$(if ($Eligible) { 'Eligible' } elseif ($assignmentType -eq 'Activated') { 'Activated' } else { 'Active' })
                    Start=(Get-InspectorExportProperty -InputObject $item -Name 'startDateTime')
                    End=(Get-InspectorExportProperty -InputObject $item -Name 'endDateTime')
                    ScheduleId=$(if ($Eligible) { Get-InspectorExportProperty -InputObject $item -Name 'roleEligibilityScheduleId' } else { Get-InspectorExportProperty -InputObject $item -Name 'roleAssignmentScheduleId' })
                    InstanceId=(Get-InspectorExportProperty -InputObject $item -Name 'id')
                }
            }
        )
    }

    return [PSCustomObject][ordered]@{
        ActiveSkus = @((& $getCollection 'SubscribedSkus') | Where-Object { [string](Get-InspectorExportProperty -InputObject $_ -Name 'capabilityStatus') -eq 'Enabled' } | ForEach-Object { [PSCustomObject][ordered]@{ Product=$(if (Get-InspectorExportProperty -InputObject $_ -Name 'displayName') { Get-InspectorExportProperty -InputObject $_ -Name 'displayName' } else { Get-InspectorExportProperty -InputObject $_ -Name 'skuPartNumber' }); SkuPartNumber=(Get-InspectorExportProperty -InputObject $_ -Name 'skuPartNumber'); SkuId=(Get-InspectorExportProperty -InputObject $_ -Name 'skuId'); Status=(Get-InspectorExportProperty -InputObject $_ -Name 'capabilityStatus') } })
        Applications = @($applications | ForEach-Object { [PSCustomObject][ordered]@{ DisplayName=(Get-InspectorExportProperty -InputObject $_ -Name 'displayName'); AppId=(Get-InspectorExportProperty -InputObject $_ -Name 'appId'); ObjectId=(Get-InspectorExportProperty -InputObject $_ -Name 'id'); ObjectType='Application' } })
        ServicePrincipals = @($servicePrincipals | ForEach-Object { [PSCustomObject][ordered]@{ DisplayName=(Get-InspectorExportProperty -InputObject $_ -Name 'displayName'); AppId=(Get-InspectorExportProperty -InputObject $_ -Name 'appId'); ObjectId=(Get-InspectorExportProperty -InputObject $_ -Name 'id'); ObjectType='ServicePrincipal' } })
        Users = @($users | ForEach-Object { [PSCustomObject][ordered]@{ DisplayName=(Get-InspectorExportProperty -InputObject $_ -Name 'displayName'); UserPrincipalName=(Get-InspectorExportProperty -InputObject $_ -Name 'userPrincipalName'); ObjectId=(Get-InspectorExportProperty -InputObject $_ -Name 'id'); ObjectType='User' } })
        Groups = @($groups | ForEach-Object { [PSCustomObject][ordered]@{ DisplayName=(Get-InspectorExportProperty -InputObject $_ -Name 'displayName'); ObjectId=(Get-InspectorExportProperty -InputObject $_ -Name 'id'); IsAssignableToRole=(Get-InspectorExportProperty -InputObject $_ -Name 'isAssignableToRole'); ObjectType='Group' } })
        PrivilegedGroups = @($groups | Where-Object { (Get-InspectorExportProperty -InputObject $_ -Name 'isAssignableToRole') -eq $true } | ForEach-Object { [PSCustomObject][ordered]@{ DisplayName=(Get-InspectorExportProperty -InputObject $_ -Name 'displayName'); ObjectId=(Get-InspectorExportProperty -InputObject $_ -Name 'id'); ObjectType='Group' } })
        DirectoryRoleAssignments = @($directoryRoleRows)
        PimActive = @(& $pimRows 'RoleAssignmentScheduleInstances' $false)
        PimEligible = @(& $pimRows 'RoleEligibilityScheduleInstances' $true)
        AdministrativeUnits = @($administrativeUnits | ForEach-Object { [PSCustomObject][ordered]@{ DisplayName=(Get-InspectorExportProperty -InputObject $_ -Name 'displayName'); Description=(Get-InspectorExportProperty -InputObject $_ -Name 'description'); ObjectId=(Get-InspectorExportProperty -InputObject $_ -Name 'id'); Visibility=(Get-InspectorExportProperty -InputObject $_ -Name 'visibility'); RestrictedManagement=(Get-InspectorExportProperty -InputObject $_ -Name 'isMemberManagementRestricted'); ObjectType='AdministrativeUnit' } })
        RiskyUsers = @((& $getCollection 'RiskyUsers') | ForEach-Object { $id=[string](Get-InspectorExportProperty -InputObject $_ -Name 'id'); $principal=(& $resolvePrincipal $id); [PSCustomObject][ordered]@{ DisplayName=$principal.Name; UserPrincipalName=(Get-InspectorExportProperty -InputObject $_ -Name 'userPrincipalName'); ObjectId=$id; RiskLevel=(Get-InspectorExportProperty -InputObject $_ -Name 'riskLevel'); RiskState=(Get-InspectorExportProperty -InputObject $_ -Name 'riskState'); RiskDetail=(Get-InspectorExportProperty -InputObject $_ -Name 'riskDetail'); ObjectType='User' } })
    }
}

function ConvertTo-InspectorSafeFileName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    $invalidChars =
        [System.IO.Path]::GetInvalidFileNameChars()

    $safe = $Name

    foreach ($char in $invalidChars) {
        $safe = $safe.Replace([string]$char, '-')
    }

    $safe = $safe.Trim()

    if ([string]::IsNullOrWhiteSpace($safe)) {
        return 'assessment'
    }

    return $safe
}

function New-InspectorExportArtifactRecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Kind,

        [Parameter(Mandatory)]
        [string]$Path,

        [int]$RecordCount = 0
    )

    $sizeBytes =
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            (Get-Item -LiteralPath $Path).Length
        }
        else {
            $null
        }

    return [PSCustomObject][ordered]@{
        Name        = $Name
        Kind        = $Kind
        Path        = $Path
        RecordCount = $RecordCount
        SizeBytes   = $sizeBytes
    }
}


function Update-InspectorExportArtifactSizes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Manifest,

        [Parameter(Mandatory)]
        [string]$BasePath
    )

    foreach ($artifact in @(Get-InspectorExportProperty -InputObject $Manifest -Name 'Artifacts')) {
        if ($null -eq $artifact) {
            continue
        }

        $artifactName = [string](Get-InspectorExportProperty -InputObject $artifact -Name 'Name')
        if ([string]::IsNullOrWhiteSpace($artifactName)) {
            continue
        }

        $artifactPath = Join-Path -Path $BasePath -ChildPath $artifactName
        $sizeBytes =
            if (Test-Path -LiteralPath $artifactPath -PathType Leaf) {
                (Get-Item -LiteralPath $artifactPath).Length
            }
            else {
                $null
            }

        Set-InspectorExportProperty -InputObject $artifact -Name 'SizeBytes' -Value $sizeBytes
        Set-InspectorExportProperty -InputObject $artifact -Name 'Path' -Value $artifactPath
    }
}


function Get-InspectorExportWorkingSetMB {
    [CmdletBinding()]
    param ()

    try {
        return [math]::Round(
            [System.Diagnostics.Process]::GetCurrentProcess().WorkingSet64 / 1MB,
            2
        )
    }
    catch {
        return $null
    }
}

function Write-InspectorJsonFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [AllowNull()]
        [object]$Value,

        [int]$Depth = 20
    )

    # Use -InputObject instead of pipeline input so an empty collection is
    # serialized as [] rather than producing no pipeline output/file.
    ConvertTo-Json `
        -InputObject $Value `
        -Depth $Depth |
        Set-Content `
            -LiteralPath $Path `
            -Encoding UTF8 `
            -Force
}

function Write-InspectorCsvFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [object[]]$Rows,

        [string[]]$Header = @()
    )

    $safeRows = @($Rows)

    if ($safeRows.Count -gt 0) {
        $safeRows |
            Export-Csv `
                -LiteralPath $Path `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Force

        return
    }

    if ($Header.Count -gt 0) {
        ($Header -join ',') |
            Set-Content `
                -LiteralPath $Path `
                -Encoding UTF8 `
                -Force
    }
    else {
        '' |
            Set-Content `
                -LiteralPath $Path `
                -Encoding UTF8 `
                -Force
    }
}

function Get-InspectorExportSeverityOrder {
    [CmdletBinding()]
    param (
        [string]$Severity
    )

    switch ($Severity) {
        'High' { return 1 }
        'Medium' { return 2 }
        'Low' { return 3 }
        'Informational' { return 4 }
        default { return 99 }
    }
}

function Get-InspectorCurrentMandatoryArtifactNames {
    [CmdletBinding()]
    param ()

    return @(
        'assessment-manifest.json'
        'assessment-summary.json'
        'security-observations.json'
        'object-index.json'
        'evidence-index.json'
        'failed-objects.json'
        'execution-log.json'
        'assessment-intelligence.json'
        'tenant-posture.json'
        'assessment-findings.json'
        'assessment-recommendations.json'
        'assessment-correlations.json'
        'assessment-limitations.json'
    )
}
