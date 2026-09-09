function Test-InspectorPortableSnapshotPropertyExists {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $false
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }

    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Test-InspectorPortableSnapshotJsonObject {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject
    )

    return (
        $null -ne $InputObject -and
        (
            $InputObject -is [System.Collections.IDictionary] -or
            $InputObject -is [PSCustomObject]
        )
    )
}

function Test-InspectorTenantSnapshotContract {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$TenantSnapshot,

        [switch]$ThrowOnError
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $schemaVersionValue = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'SchemaVersion'
    $snapshotIdValue = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'SnapshotId'
    $schemaVersion = [string]$schemaVersionValue
    $snapshotId = [string]$snapshotIdValue
    $collections = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Collections'

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $TenantSnapshot -Name 'SchemaVersion')) {
        $errors.Add('Snapshot SchemaVersion is required.')
    }
    elseif ($schemaVersionValue -isnot [string]) {
        $errors.Add('Snapshot SchemaVersion must be a string.')
    }
    elseif ([string]::IsNullOrWhiteSpace($schemaVersion)) {
        $errors.Add('Snapshot SchemaVersion is required.')
    }
    elseif (-not $schemaVersion.StartsWith('1.', [System.StringComparison]::Ordinal)) {
        $errors.Add("Unsupported snapshot SchemaVersion '$schemaVersion'. Expected major version 1.")
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $TenantSnapshot -Name 'SnapshotId')) {
        $errors.Add('SnapshotId is required.')
    }
    elseif ($snapshotIdValue -isnot [string]) {
        $errors.Add('SnapshotId must be a string.')
    }
    elseif ([string]::IsNullOrWhiteSpace($snapshotId)) {
        $errors.Add('SnapshotId is required.')
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $TenantSnapshot -Name 'CreatedAt')) {
        $errors.Add("Required snapshot property 'CreatedAt' is missing.")
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $TenantSnapshot -Name 'GraphCallsAllowedAfterSnapshot')) {
        $errors.Add("Required snapshot property 'GraphCallsAllowedAfterSnapshot' is missing.")
    }
    else {
        $graphCallsAllowedAfterSnapshot = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'GraphCallsAllowedAfterSnapshot'
        if ($graphCallsAllowedAfterSnapshot -isnot [bool] -or $graphCallsAllowedAfterSnapshot) {
            $errors.Add('GraphCallsAllowedAfterSnapshot must be the Boolean value false in a portable snapshot.')
        }
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $TenantSnapshot -Name 'Collections')) {
        $errors.Add('Collections is required.')
    }
    elseif (-not (Test-InspectorPortableSnapshotJsonObject -InputObject $collections)) {
        $errors.Add('Collections must be a JSON object.')
    }

    foreach ($requiredProperty in @('CollectionScope','CollectionSummary','AssessmentCoverage','TenantMetadata','ScopeInventory')) {
        if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $TenantSnapshot -Name $requiredProperty)) {
            $errors.Add("Required snapshot property '$requiredProperty' is missing.")
        }
    }

    if (Test-InspectorPortableSnapshotPropertyExists -InputObject $TenantSnapshot -Name 'CollectionScope') {
        $collectionScope = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'CollectionScope'
        if (-not (Test-InspectorPortableSnapshotJsonObject -InputObject $collectionScope)) {
            $errors.Add('CollectionScope must be a JSON object.')
        }
    }

    foreach ($collectionName in @(
        'Applications','ServicePrincipals','Users','Groups','Organization','OAuth2PermissionGrants','DirectoryRoleAssignments',
        'ApplicationOwners','ServicePrincipalOwners','ServicePrincipalOwnedObjects','ServicePrincipalGroupMemberships','GroupOwners','GroupMembers',
        'GroupMemberships','UserTransitiveMemberships','AppRoleAssignments','AppRoleAssignedTo','ApplicationCredentials',
        'ServicePrincipalCredentials','RequiredResourceAccess','ExposedAppRoles'
    )) {
        if (-not (Test-InspectorPortableSnapshotJsonObject -InputObject $collections)) {
            break
        }

        if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $collections -Name $collectionName)) {
            $errors.Add("Required collection '$collectionName' is missing.")
        }
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $TenantSnapshot -Name 'Evidence')) {
        $errors.Add("Required snapshot property 'Evidence' is missing.")
        $evidence = @()
    }
    else {
        $evidenceProperty =
            if ($TenantSnapshot -is [System.Collections.IDictionary]) {
                $TenantSnapshot['Evidence']
            }
            else {
                $TenantSnapshot.PSObject.Properties['Evidence'].Value
            }

        if ($evidenceProperty -isnot [System.Array] -and $evidenceProperty -isnot [System.Collections.IList]) {
            $errors.Add('Evidence must be a JSON array.')
            $evidence = @()
        }
        else {
            $evidence = @($evidenceProperty)
        }
    }

    $evidenceIds = [System.Collections.Generic.List[string]]::new()
    foreach ($evidenceRow in $evidence) {
        if (-not (Test-InspectorPortableSnapshotJsonObject -InputObject $evidenceRow)) {
            $errors.Add('Every portable snapshot evidence row must be a JSON object.')
            continue
        }

        if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $evidenceRow -Name 'EvidenceId')) {
            $errors.Add('Every portable snapshot evidence row must contain a nonblank EvidenceId.')
            continue
        }

        $evidenceIdValue = Get-InspectorSnapshotProperty -InputObject $evidenceRow -Name 'EvidenceId'
        if ($evidenceIdValue -isnot [string]) {
            $errors.Add('Every portable snapshot EvidenceId must be a string.')
            continue
        }

        if ([string]::IsNullOrWhiteSpace([string]$evidenceIdValue)) {
            $errors.Add('Every portable snapshot evidence row must contain a nonblank EvidenceId.')
            continue
        }

        $evidenceIds.Add([string]$evidenceIdValue)
    }
    if (@($evidenceIds | Sort-Object -Unique).Count -ne $evidenceIds.Count) {
        $errors.Add('EvidenceId values must be unique within a portable snapshot.')
    }

    $result = [PSCustomObject][ordered]@{
        PSTypeName      = 'EntraObjectInspector.SnapshotContractValidation'
        ContractName    = 'EntraObjectInspector.PortableTenantSnapshot'
        ContractVersion = '1.0.0'
        Valid           = $errors.Count -eq 0
        Errors          = @($errors)
    }

    if ($ThrowOnError -and -not $result.Valid) {
        throw "Portable snapshot validation failed: $(@($result.Errors) -join ' ')"
    }

    return $result
}

function Test-InspectorPortableSnapshotEnvelopeContract {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Envelope,

        [switch]$ThrowOnError
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $allowedProperties = @('ContractName','ContractVersion','ExportedAt','Integrity','Snapshot')
    $propertyNames =
        if ($Envelope -is [System.Collections.IDictionary]) {
            @($Envelope.Keys | ForEach-Object { [string]$_ })
        }
        else {
            @($Envelope.PSObject.Properties.Name)
        }

    foreach ($propertyName in $propertyNames) {
        if ($propertyName -notin $allowedProperties) {
            $errors.Add("Portable snapshot envelope property '$propertyName' is not allowed by the contract schema.")
        }
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $Envelope -Name 'ContractName')) {
        $errors.Add('Portable snapshot ContractName is required.')
    }
    elseif ([string](Get-InspectorSnapshotProperty -InputObject $Envelope -Name 'ContractName') -cne 'EntraObjectInspector.PortableTenantSnapshot') {
        $errors.Add('The file is not an Entra Object Inspector portable tenant snapshot.')
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $Envelope -Name 'ContractVersion')) {
        $errors.Add('Portable snapshot ContractVersion is required.')
    }
    elseif ([string](Get-InspectorSnapshotProperty -InputObject $Envelope -Name 'ContractVersion') -cne '1.0.0') {
        $errors.Add("Unsupported portable snapshot contract version '$([string](Get-InspectorSnapshotProperty -InputObject $Envelope -Name 'ContractVersion'))'.")
    }

    if (Test-InspectorPortableSnapshotPropertyExists -InputObject $Envelope -Name 'ExportedAt') {
        $exportedAt = Get-InspectorSnapshotProperty -InputObject $Envelope -Name 'ExportedAt'
        if ($exportedAt -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$exportedAt)) {
            $errors.Add('Portable snapshot ExportedAt must be a nonblank string when present.')
        }
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $Envelope -Name 'Integrity')) {
        $errors.Add('Portable snapshot Integrity is required.')
        $integrity = $null
    }
    else {
        $integrity = Get-InspectorSnapshotProperty -InputObject $Envelope -Name 'Integrity'
        if (-not (Test-InspectorPortableSnapshotJsonObject -InputObject $integrity)) {
            $errors.Add('Portable snapshot Integrity must be a JSON object.')
        }
    }

    if ($null -ne $integrity -and (Test-InspectorPortableSnapshotJsonObject -InputObject $integrity)) {
        if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $integrity -Name 'Algorithm')) {
            $errors.Add('Portable snapshot Integrity.Algorithm is required.')
        }
        else {
            $algorithm = Get-InspectorSnapshotProperty -InputObject $integrity -Name 'Algorithm'
            if ($algorithm -isnot [string] -or [string]$algorithm -cne 'SHA256') {
                $errors.Add("Portable snapshot Integrity.Algorithm must be exactly 'SHA256'.")
            }
        }

        if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $integrity -Name 'PayloadHash')) {
            $errors.Add('Portable snapshot Integrity.PayloadHash is required.')
        }
        else {
            $payloadHash = Get-InspectorSnapshotProperty -InputObject $integrity -Name 'PayloadHash'
            if ($payloadHash -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$payloadHash) -or [string]$payloadHash -notmatch '^[A-Fa-f0-9]{64}$') {
                $errors.Add('Portable snapshot Integrity.PayloadHash must be a 64-character hexadecimal SHA256 hash.')
            }
        }
    }

    if (-not (Test-InspectorPortableSnapshotPropertyExists -InputObject $Envelope -Name 'Snapshot')) {
        $errors.Add('Portable snapshot Snapshot is required.')
    }
    else {
        $snapshot = Get-InspectorSnapshotProperty -InputObject $Envelope -Name 'Snapshot'
        if (-not (Test-InspectorPortableSnapshotJsonObject -InputObject $snapshot)) {
            $errors.Add('Portable snapshot Snapshot must be a JSON object.')
        }
        else {
            $snapshotValidation = Test-InspectorTenantSnapshotContract -TenantSnapshot $snapshot
            foreach ($snapshotError in @($snapshotValidation.Errors)) {
                $errors.Add([string]$snapshotError)
            }
        }
    }

    $result = [PSCustomObject][ordered]@{
        PSTypeName      = 'EntraObjectInspector.PortableSnapshotEnvelopeValidation'
        ContractName    = 'EntraObjectInspector.PortableTenantSnapshot'
        ContractVersion = '1.0.0'
        Valid           = $errors.Count -eq 0
        Errors          = @($errors)
    }

    if ($ThrowOnError -and -not $result.Valid) {
        throw "Portable snapshot validation failed: $(@($result.Errors) -join ' ')"
    }

    return $result
}

function ConvertTo-InspectorPortableSnapshotPayload {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$TenantSnapshot
    )

    Test-InspectorTenantSnapshotContract -TenantSnapshot $TenantSnapshot -ThrowOnError | Out-Null

    return [PSCustomObject][ordered]@{
        PSTypeName                     = 'EntraObjectInspector.TenantSnapshot'
        SchemaVersion                  = [string](Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'SchemaVersion')
        SnapshotId                     = [string](Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'SnapshotId')
        CreatedAt                      = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'CreatedAt'
        CollectionMode                 = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'CollectionMode'
        PersistenceMode                = 'PortableJson'
        GraphCallsAllowedAfterSnapshot = $false
        SourceTenantId                 = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'SourceTenantId'
        SourceClientId                 = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'SourceClientId'
        CollectionScope                = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'CollectionScope'
        Collections                    = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Collections'
        CollectionSummary              = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'CollectionSummary'
        AssessmentCoverage             = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'AssessmentCoverage'
        TenantMetadata                 = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'TenantMetadata'
        ScopeInventory                 = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'ScopeInventory'
        Evidence                       = @(Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Evidence')
        Limitations                    = @(Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Limitations')
    }
}

function Export-InspectorTenantSnapshot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$TenantSnapshot,

        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$Force
    )

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "Portable snapshot already exists: $Path. Use -Force to overwrite it."
    }

    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $payload = ConvertTo-InspectorPortableSnapshotPayload -TenantSnapshot $TenantSnapshot
    $payloadJson = $payload | ConvertTo-Json -Depth 100 -Compress
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payloadJson)) | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $sha.Dispose()
    }

    $envelope = [PSCustomObject][ordered]@{
        ContractName    = 'EntraObjectInspector.PortableTenantSnapshot'
        ContractVersion = '1.0.0'
        ExportedAt      = (Get-Date).ToUniversalTime().ToString('o')
        Integrity       = [PSCustomObject][ordered]@{
            Algorithm   = 'SHA256'
            PayloadHash = $hash.ToUpperInvariant()
        }
        Snapshot        = $payload
    }

    $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding UTF8 -Force

    return [PSCustomObject][ordered]@{
        PSTypeName      = 'EntraObjectInspector.PortableSnapshotExportResult'
        Status          = 'Success'
        Path            = (Resolve-Path -LiteralPath $Path).Path
        SnapshotId      = $payload.SnapshotId
        ContractVersion = '1.0.0'
        PayloadHash     = $envelope.Integrity.PayloadHash
    }
}

function Import-InspectorTenantSnapshot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Portable snapshot was not found: $Path"
    }

    $envelope = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -DateKind String
    Test-InspectorPortableSnapshotEnvelopeContract -Envelope $envelope -ThrowOnError | Out-Null

    $snapshot = Get-InspectorSnapshotProperty -InputObject $envelope -Name 'Snapshot'
    $integrity = Get-InspectorSnapshotProperty -InputObject $envelope -Name 'Integrity'
    $expectedHash = [string](Get-InspectorSnapshotProperty -InputObject $integrity -Name 'PayloadHash')

    $payloadJson = $snapshot | ConvertTo-Json -Depth 100 -Compress
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualHash = (-join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payloadJson)) | ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
    }
    finally {
        $sha.Dispose()
    }
    if ($actualHash -cne $expectedHash.ToUpperInvariant()) {
        throw 'Portable snapshot integrity validation failed: payload hash mismatch.'
    }

    $collections = Get-InspectorSnapshotProperty -InputObject $snapshot -Name 'Collections'

    $tenantMetadata = Get-InspectorSnapshotProperty -InputObject $snapshot -Name 'TenantMetadata'
    if ($null -eq $tenantMetadata) {
        $tenantMetadata = [PSCustomObject][ordered]@{}
        $snapshot | Add-Member -NotePropertyName 'TenantMetadata' -NotePropertyValue $tenantMetadata -Force
    }

    $licenseValidation = Get-InspectorSnapshotProperty -InputObject $tenantMetadata -Name 'LicenseValidation'
    if ($null -eq $licenseValidation) {
        $licenseValidation = Resolve-InspectorTenantCapabilities -Snapshot $snapshot
        $tenantMetadata | Add-Member -NotePropertyName 'LicenseValidation' -NotePropertyValue $licenseValidation -Force
    }

    $indexes = New-InspectorTenantSnapshotIndexes -Collections $collections -Evidence @($snapshot.Evidence)
    $snapshot | Add-Member -NotePropertyName 'Indexes' -NotePropertyValue $indexes -Force
    $snapshot | Add-Member -NotePropertyName 'PersistenceMode' -NotePropertyValue 'PortableJsonImported' -Force
    $snapshot | Add-Member -NotePropertyName 'GraphCallsAllowedAfterSnapshot' -NotePropertyValue $false -Force

    return $snapshot
}
