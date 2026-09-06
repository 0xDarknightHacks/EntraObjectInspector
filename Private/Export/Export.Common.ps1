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
