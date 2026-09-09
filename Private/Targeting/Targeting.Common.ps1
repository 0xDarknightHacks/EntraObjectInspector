function Get-InspectorDeterministicToken {
    [CmdletBinding()]
    param ([Parameter(Mandatory)][string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        return (-join ($bytes[0..7] | ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
    }
    finally { $sha.Dispose() }
}

function ConvertTo-InspectorODataLiteral {
    [CmdletBinding()]
    param ([Parameter(Mandatory)][string]$Value)
    return $Value.Replace("'", "''")
}

function Import-InspectorTargetSpecification {
    [CmdletBinding()]
    param (
        [string]$TargetFile,
        [string[]]$Target = @(),
        [string[]]$AllowedObjectType = @('Application','ServicePrincipal','User','Group')
    )

    $rows = [System.Collections.Generic.List[object]]::new()

    function Add-TargetRow {
        param ([string]$ObjectType, [string]$Identity, [string]$Source)
        $trimmedIdentity = [string]$Identity
        if (-not [string]::IsNullOrWhiteSpace($trimmedIdentity)) { $trimmedIdentity = $trimmedIdentity.Trim() }
        if ([string]::IsNullOrWhiteSpace($trimmedIdentity)) { return }
        $trimmedType = [string]$ObjectType
        if (-not [string]::IsNullOrWhiteSpace($trimmedType)) { $trimmedType = $trimmedType.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($trimmedType) -and $trimmedType -notin @('Application','ServicePrincipal','User','Group')) {
            throw "Unsupported target ObjectType '$trimmedType' from $Source."
        }
        if (-not [string]::IsNullOrWhiteSpace($trimmedType) -and $trimmedType -notin @($AllowedObjectType)) {
            throw "Target '$trimmedIdentity' requests ObjectType '$trimmedType', which is outside the current -ObjectType scope."
        }
        $rows.Add([PSCustomObject][ordered]@{ ObjectType = $trimmedType; Identity = $trimmedIdentity; Source = $Source })
    }

    foreach ($value in @($Target)) {
        if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
        $text = [string]$value
        $separator = $text.IndexOf('|')
        if ($separator -gt 0) {
            Add-TargetRow -ObjectType $text.Substring(0, $separator) -Identity $text.Substring($separator + 1) -Source '-Target'
        }
        else {
            Add-TargetRow -ObjectType '' -Identity $text -Source '-Target'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($TargetFile)) {
        if (-not (Test-Path -LiteralPath $TargetFile -PathType Leaf)) { throw "Target file was not found: $TargetFile" }
        $extension = [System.IO.Path]::GetExtension($TargetFile)
        if ([string]::Equals($extension, '.csv', [System.StringComparison]::OrdinalIgnoreCase)) {
            foreach ($row in @(Import-Csv -LiteralPath $TargetFile)) {
                $identityProperty = $row.PSObject.Properties['Identity']
                if ($null -eq $identityProperty) { throw "Target CSV '$TargetFile' must contain an Identity column." }
                $typeProperty = $row.PSObject.Properties['ObjectType']
                Add-TargetRow -ObjectType $(if ($null -ne $typeProperty) { [string]$typeProperty.Value } else { '' }) -Identity ([string]$identityProperty.Value) -Source $TargetFile
            }
        }
        elseif ([string]::Equals($extension, '.txt', [System.StringComparison]::OrdinalIgnoreCase)) {
            foreach ($line in @(Get-Content -LiteralPath $TargetFile)) {
                $text = [string]$line
                if ([string]::IsNullOrWhiteSpace($text) -or $text.TrimStart().StartsWith('#')) { continue }
                $separator = $text.IndexOf('|')
                if ($separator -gt 0) { Add-TargetRow -ObjectType $text.Substring(0, $separator) -Identity $text.Substring($separator + 1) -Source $TargetFile }
                else { Add-TargetRow -ObjectType '' -Identity $text -Source $TargetFile }
            }
        }
        else {
            throw "Unsupported target file extension '$extension'. Use .csv or .txt."
        }
    }

    $deduped = @(
        $rows |
            Sort-Object ObjectType, Identity -Unique
    )
    if ($deduped.Count -eq 0) { throw 'Targeted assessment was requested but no target entries were supplied.' }
    return @($deduped)
}

function Get-InspectorTargetQueryDefinition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory)][string]$Identity
    )

    $graphBaseUri = 'https://graph.microsoft.com/v1.0'
    $literal = ConvertTo-InspectorODataLiteral -Value $Identity
    $guidValue = [guid]::Empty
    $isGuid = [guid]::TryParse($Identity, [ref]$guidValue)
    $upnLike = $Identity -match '^[^@\s]+@[^@\s]+$'

    switch ($ObjectType) {
        'Application' {
            $select = 'id,appId,displayName,signInAudience,publisherDomain,verifiedPublisher,appRoles,requiredResourceAccess,keyCredentials,passwordCredentials'
            $filter = if ($isGuid) { "id eq '$literal' or appId eq '$literal'" } else { "displayName eq '$literal'" }
            $permission = 'Application.Read.All'; $collection = 'Applications'
        }
        'ServicePrincipal' {
            $select = 'id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,tags,appRoles,appOwnerOrganizationId,publisherName,verifiedPublisher,keyCredentials,passwordCredentials'
            $filter = if ($isGuid) { "id eq '$literal' or appId eq '$literal'" } else { "displayName eq '$literal'" }
            $permission = 'Application.Read.All'; $collection = 'ServicePrincipals'
        }
        'User' {
            $select = 'id,userPrincipalName,displayName,userType,accountEnabled'
            $filter = if ($isGuid) { "id eq '$literal'" } elseif ($upnLike) { "userPrincipalName eq '$literal'" } else { "displayName eq '$literal'" }
            $permission = 'User.Read.All'; $collection = 'Users'
        }
        'Group' {
            $select = 'id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,visibility,membershipRule,membershipRuleProcessingState'
            $filter = if ($isGuid) { "id eq '$literal'" } else { "displayName eq '$literal'" }
            $permission = 'GroupMember.Read.All'; $collection = 'Groups'
        }
        default { throw "Unsupported target ObjectType '$ObjectType'." }
    }

    $encodedFilter = [uri]::EscapeDataString($filter)
    $queryName = "TargetResolve:${ObjectType}:$(Get-InspectorDeterministicToken -Value "$ObjectType|$Identity")"
    $top = if ($ObjectType -eq 'ServicePrincipal') { 100 } else { 999 }
    return [PSCustomObject][ordered]@{
        ObjectType = $ObjectType
        CollectionName = $collection
        QueryName = $queryName
        Uri = "$graphBaseUri/$($collection.Substring(0,1).ToLowerInvariant())$($collection.Substring(1))?`$select=$select&`$filter=$encodedFilter&`$top=$top"
        RequiredPermission = $permission
    }
}
