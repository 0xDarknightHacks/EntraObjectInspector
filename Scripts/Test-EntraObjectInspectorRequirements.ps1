<#
.SYNOPSIS
Validates the local environment for Entra Object Inspector.

.DESCRIPTION
Test-EntraObjectInspectorRequirements.ps1 checks whether the host has the baseline
runtime and module requirements needed to run Entra Object Inspector.

The script is intentionally validation-first:
- It does not connect to Microsoft Graph.
- It does not validate tenant credentials.
- It does not run an assessment.
- It installs missing modules only when explicitly requested or approved interactively.

Recommended usage:
  pwsh ./Scripts/Test-EntraObjectInspectorRequirements.ps1
  pwsh ./Scripts/Test-EntraObjectInspectorRequirements.ps1 -InstallMissing
  pwsh ./Scripts/Test-EntraObjectInspectorRequirements.ps1 -ShowManualCommands

.NOTES
Place this file under:
  Scripts/Test-EntraObjectInspectorRequirements.ps1

For first public release usage, keep this script as a helper. Do not make it a mandatory
execution step for advanced administrators.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Version]$MinimumPowerShellVersion = [Version]'7.6',

    [string]$ProjectRoot,

    [string[]]$RequiredModules,

    [string[]]$OptionalModules = @('Pester'),

    [switch]$IncludeOptionalModules,

    [switch]$InstallMissing,

    [switch]$ShowManualCommands,

    [switch]$NonInteractive,

    [switch]$SkipGalleryReachability,

    [switch]$RunTests,

    [string]$TestOutputPath,

    [string]$LogDirectory,

    [switch]$AsJson,

    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Ui {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('Info','Success','Warning','Error','Header')]
        [string]$Kind = 'Info'
    )

    if ($AsJson) { return }

    $prefix = switch ($Kind) {
        'Success' { '[OK]' }
        'Warning' { '[!]' }
        'Error'   { '[X]' }
        'Header'  { '' }
        default   { '[i]' }
    }

    if ($NoColor) {
        if ($Kind -eq 'Header') { Write-Host $Message }
        elseif ([string]::IsNullOrWhiteSpace($Message)) { Write-Host '' }
        else { Write-Host "$prefix $Message" }
        return
    }

    $color = switch ($Kind) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Header'  { 'Cyan' }
        default   { 'Gray' }
    }

    if ($Kind -eq 'Header') { Write-Host $Message -ForegroundColor $color }
    elseif ([string]::IsNullOrWhiteSpace($Message)) { Write-Host '' }
    else { Write-Host "$prefix $Message" -ForegroundColor $color }
}

function New-CheckResult {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [string]$Message,
        [string]$ManualAction,
        [ValidateSet('Required','Recommended','Optional')]
        [string]$Severity = 'Required',
        [object]$Data = $null
    )

    [PSCustomObject]@{
        Name         = $Name
        Passed       = $Passed
        Severity     = $Severity
        Message      = $Message
        ManualAction = $ManualAction
        Data         = $Data
    }
}

function Resolve-ProjectRoot {
    param([string]$ExplicitRoot)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitRoot)) {
        return (Resolve-Path -LiteralPath $ExplicitRoot).Path
    }

    $candidates = @()

    if ($PSScriptRoot) {
        $candidates += $PSScriptRoot
        $parent = Split-Path -Parent $PSScriptRoot
        if ($parent) { $candidates += $parent }
    }

    $candidates += (Get-Location).Path

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (Test-Path -LiteralPath (Join-Path $candidate 'EntraObjectInspector.psd1')) {
            return $candidate
        }

        $child = Get-ChildItem -LiteralPath $candidate -Filter 'EntraObjectInspector.psd1' -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($child) {
            return $child.Directory.FullName
        }
    }

    if ($PSScriptRoot) {
        $parent = Split-Path -Parent $PSScriptRoot
        if ($parent) { return $parent }
    }

    return (Get-Location).Path
}

function Get-ManifestRequiredModules {
    param([string]$Root)

    $manifestPath = Join-Path $Root 'EntraObjectInspector.psd1'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        return [PSCustomObject]@{
            ManifestPath = $manifestPath
            Found        = $false
            Modules      = @()
            Specs        = @()
        }
    }

    try {
        $data = Import-PowerShellDataFile -LiteralPath $manifestPath
        $specs = @()

        if ($data.ContainsKey('RequiredModules') -and $null -ne $data.RequiredModules) {
            foreach ($entry in @($data.RequiredModules)) {
                if ($entry -is [string]) {
                    $specs += [PSCustomObject]@{ ModuleName = $entry; MinimumVersion = $null }
                }
                elseif ($entry -is [hashtable] -and $entry.ContainsKey('ModuleName')) {
                    $minimumVersion = $null
                    if ($entry.ContainsKey('RequiredVersion') -and $entry.RequiredVersion) {
                        $minimumVersion = [version]$entry.RequiredVersion
                    }
                    elseif ($entry.ContainsKey('ModuleVersion') -and $entry.ModuleVersion) {
                        $minimumVersion = [version]$entry.ModuleVersion
                    }

                    $specs += [PSCustomObject]@{
                        ModuleName     = [string]$entry.ModuleName
                        MinimumVersion = $minimumVersion
                    }
                }
            }
        }

        $specs = @(
            $specs |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.ModuleName) } |
                Sort-Object ModuleName -Unique
        )

        [PSCustomObject]@{
            ManifestPath = $manifestPath
            Found        = $true
            Modules      = @($specs | ForEach-Object { $_.ModuleName })
            Specs        = $specs
        }
    }
    catch {
        [PSCustomObject]@{
            ManifestPath = $manifestPath
            Found        = $true
            Modules      = @()
            Specs        = @()
            Error        = $_.Exception.Message
        }
    }
}

function Test-ModuleInstalled {
    param(
        [string]$Name,
        [Version]$MinimumVersion
    )

    $module = Get-Module -ListAvailable -Name $Name |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if ($module) {
        $meetsMinimum = ($null -eq $MinimumVersion -or $module.Version -ge $MinimumVersion)
        return [PSCustomObject]@{
            Name                 = $Name
            Installed            = $true
            Version              = $module.Version.ToString()
            MinimumVersion       = if ($null -ne $MinimumVersion) { $MinimumVersion.ToString() } else { $null }
            MeetsMinimum         = [bool]$meetsMinimum
            SatisfiesRequirement = [bool]$meetsMinimum
            Path                 = $module.Path
        }
    }

    [PSCustomObject]@{
        Name                 = $Name
        Installed            = $false
        Version              = $null
        MinimumVersion       = if ($null -ne $MinimumVersion) { $MinimumVersion.ToString() } else { $null }
        MeetsMinimum         = $false
        SatisfiesRequirement = $false
        Path                 = $null
    }
}

function Test-GalleryReachable {
    if ($SkipGalleryReachability) {
        return [PSCustomObject]@{
            Checked = $false
            Passed  = $true
            Message = 'Skipped by -SkipGalleryReachability.'
        }
    }

    try {
        $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
        return [PSCustomObject]@{
            Checked            = $true
            Passed             = $true
            Name               = $repo.Name
            SourceLocation     = $repo.SourceLocation
            InstallationPolicy = $repo.InstallationPolicy
            Message            = 'PSGallery repository is registered.'
        }
    }
    catch {
        return [PSCustomObject]@{
            Checked = $true
            Passed  = $false
            Message = "PSGallery repository is not available: $($_.Exception.Message)"
        }
    }
}

function Get-ManualCommands {
    param(
        [string[]]$MissingRequired,
        [string[]]$MissingOptional,
        [hashtable]$MinimumVersions = @{}
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Run these commands from PowerShell 7.6 LTS or later.')

    if ($MissingRequired.Count -gt 0) {
        foreach ($moduleName in $MissingRequired) {
            if ($MinimumVersions.ContainsKey($moduleName)) {
                $lines.Add("Install-Module -Name '$moduleName' -MinimumVersion '$($MinimumVersions[$moduleName])' -Scope CurrentUser -Repository PSGallery -Force -AllowClobber")
            }
            else {
                $lines.Add("Install-Module -Name '$moduleName' -Scope CurrentUser -Repository PSGallery -Force -AllowClobber")
            }
        }
    }

    if ($IncludeOptionalModules -and $MissingOptional.Count -gt 0) {
        foreach ($moduleName in $MissingOptional) {
            $lines.Add("Install-Module -Name '$moduleName' -Scope CurrentUser -Repository PSGallery -Force -AllowClobber")
        }
    }

    if ($IsWindows) {
        $lines.Add('# If script execution is blocked on Windows, review your organization policy first.')
        $lines.Add('Get-ExecutionPolicy -List')
        $lines.Add('# For a current-user developer workstation policy, your administrator may allow:')
        $lines.Add('Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned')
    }

    $lines.Add('# Then rerun:')
    $lines.Add('./Scripts/Test-EntraObjectInspectorRequirements.ps1')

    $lines.ToArray()
}

function Install-MissingModules {
    param([string[]]$ModuleNames)

    foreach ($moduleName in $ModuleNames) {
        if ([string]::IsNullOrWhiteSpace($moduleName)) { continue }

        Write-Ui "Installing module: $moduleName" -Kind Info

        if ($PSCmdlet.ShouldProcess($moduleName, 'Install-Module -Scope CurrentUser')) {
            Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
        }
    }
}

function Test-ProjectModuleImport {
    param([string]$Root)

    $manifestPath = Join-Path $Root 'EntraObjectInspector.psd1'

    if (-not (Test-Path -LiteralPath $manifestPath)) {
        return [PSCustomObject]@{
            Imported          = $false
            ManifestPath      = $manifestPath
            ExportedFunctions = @()
            Message           = 'Module manifest was not found.'
        }
    }

    try {
        Push-Location -LiteralPath $Root
        Remove-Module EntraObjectInspector -Force -ErrorAction SilentlyContinue
        Import-Module .\EntraObjectInspector.psd1 -Force -ErrorAction Stop

        $module = Get-Module EntraObjectInspector
        $exportedFunctions = @()
        if ($module) {
            $exportedFunctions = @($module.ExportedFunctions.Keys | Sort-Object)
        }

        return [PSCustomObject]@{
            Imported          = $true
            ManifestPath      = $manifestPath
            ExportedFunctions = $exportedFunctions
            Message           = 'Module imported successfully.'
        }
    }
    catch {
        return [PSCustomObject]@{
            Imported          = $false
            ManifestPath      = $manifestPath
            ExportedFunctions = @()
            Message           = "Module import failed: $($_.Exception.Message)"
        }
    }
    finally {
        Pop-Location
    }
}

function Test-PublicCommandSurface {
    param(
        [string[]]$ExpectedCommands,
        [string[]]$ActualCommands
    )

    $expected = @($ExpectedCommands | Sort-Object)
    $actual = @($ActualCommands | Sort-Object)
    $missing = @($expected | Where-Object { $_ -notin $actual })
    $unexpected = @($actual | Where-Object { $_ -notin $expected })

    [PSCustomObject]@{
        ExpectedPublicCommands   = $expected
        ActualPublicCommands     = $actual
        MissingPublicCommands    = $missing
        UnexpectedPublicCommands = $unexpected
        Passed                   = ($missing.Count -eq 0 -and $unexpected.Count -eq 0)
    }
}

function Invoke-RequirementsPesterValidation {
    param(
        [string]$Root,
        [string]$RequestedLogDirectory,
        [string]$RequestedTestOutputPath
    )

    $pesterCommand = Get-Command Invoke-Pester -ErrorAction SilentlyContinue
    if (-not $pesterCommand) {
        return [PSCustomObject]@{
            Ran       = $false
            Passed    = 0
            Failed    = 0
            Skipped   = 0
            Total     = 0
            LogPath   = $null
            Message   = 'Pester is not installed. Install-Module -Name Pester -Scope CurrentUser -Repository PSGallery -Force'
        }
    }

    $resolvedLogDirectory = $RequestedLogDirectory
    if ([string]::IsNullOrWhiteSpace($resolvedLogDirectory)) {
        $resolvedLogDirectory = Join-Path $Root 'logs'
    }

    New-Item -ItemType Directory -Path $resolvedLogDirectory -Force | Out-Null

    $logPath = $RequestedTestOutputPath
    if ([string]::IsNullOrWhiteSpace($logPath)) {
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
        $logPath = Join-Path $resolvedLogDirectory "pester-$stamp.log"
    }

    $testPath = Join-Path $Root 'Tests'
    $pesterOutput = & {
        Invoke-Pester -Path $testPath -Output Detailed -PassThru
    } 2>&1 3>&1 4>&1 5>&1 6>&1

    $pesterOutput |
        Out-File -LiteralPath $logPath -Encoding UTF8 -Force

    $pesterResult =
        $pesterOutput |
        Where-Object { $null -ne $_.PSObject.Properties['TotalCount'] -and $null -ne $_.PSObject.Properties['Result'] } |
        Select-Object -Last 1

    [PSCustomObject]@{
        Ran     = $true
        Passed  = [int]$pesterResult.PassedCount
        Failed  = [int]$pesterResult.FailedCount
        Skipped = [int]$pesterResult.SkippedCount
        Total   = [int]($pesterResult.PassedCount + $pesterResult.FailedCount + $pesterResult.SkippedCount)
        LogPath = $logPath
        Message = "Pester completed. Detailed output: $logPath"
    }
}

$resolvedRoot = Resolve-ProjectRoot -ExplicitRoot $ProjectRoot
$manifestInfo = Get-ManifestRequiredModules -Root $resolvedRoot
$requiredModuleMinimumVersions = @{}

if (-not $RequiredModules -or $RequiredModules.Count -eq 0) {
    if ($manifestInfo.Found -and $manifestInfo.Modules.Count -gt 0) {
        $RequiredModules = @($manifestInfo.Modules)
        foreach ($spec in @($manifestInfo.Specs)) {
            if ($null -ne $spec.MinimumVersion) {
                $requiredModuleMinimumVersions[$spec.ModuleName] = [version]$spec.MinimumVersion
            }
        }
    }
    else {
        # The project primarily uses Connect-MgGraph / Invoke-MgGraphRequest.
        # Microsoft.Graph.Authentication is the minimal Microsoft Graph SDK dependency
        # for that usage pattern. Keep this conservative unless the module manifest
        # declares additional required modules.
        $RequiredModules = @('Microsoft.Graph.Authentication')
    }
}

$RequiredModules = @($RequiredModules | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
$OptionalModules = @($OptionalModules | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

$checks = New-Object System.Collections.Generic.List[object]

Write-Ui 'Entra Object Inspector - Environment Validation' -Kind Header
Write-Ui '=============================================' -Kind Header
Write-Ui "Project root: $resolvedRoot" -Kind Info

# Runtime checks
$psVersion = $PSVersionTable.PSVersion
$detectedPSEdition = $PSVersionTable.PSEdition

$checks.Add((New-CheckResult `
    -Name 'PowerShell version' `
    -Passed ($psVersion -ge $MinimumPowerShellVersion) `
    -Message "Detected PowerShell $psVersion. Minimum required: $MinimumPowerShellVersion." `
    -ManualAction "Install PowerShell $MinimumPowerShellVersion or later, then rerun this script." `
    -Data @{ Detected = $psVersion.ToString(); Minimum = $MinimumPowerShellVersion.ToString() }))

$checks.Add((New-CheckResult `
    -Name 'PowerShell edition' `
    -Passed ($detectedPSEdition -eq 'Core') `
    -Message "Detected PowerShell edition: $detectedPSEdition." `
    -ManualAction 'Run this tool from PowerShell 7.6 LTS or later (pwsh), not Windows PowerShell 5.1.' `
    -Data @{ Detected = $detectedPSEdition }))

$osName = if ($IsWindows) { 'Windows' } elseif ($IsLinux) { 'Linux' } elseif ($IsMacOS) { 'macOS' } else { 'Unknown' }
$checks.Add((New-CheckResult `
    -Name 'Operating system' `
    -Passed ($osName -ne 'Unknown') `
    -Message "Detected OS: $osName." `
    -ManualAction 'Use a supported PowerShell 7 host on Windows, Linux, or macOS.' `
    -Data @{ OS = $osName }))

# Project structure checks
$manifestPath = Join-Path $resolvedRoot 'EntraObjectInspector.psd1'
$modulePath = Join-Path $resolvedRoot 'EntraObjectInspector.psm1'
$manifestExists = Test-Path -LiteralPath $manifestPath
$psm1Exists = Test-Path -LiteralPath $modulePath
$publicExists = Test-Path -LiteralPath (Join-Path $resolvedRoot 'Public')
$privateExists = Test-Path -LiteralPath (Join-Path $resolvedRoot 'Private')

$checks.Add((New-CheckResult `
    -Name 'Project manifest' `
    -Passed $manifestExists `
    -Message "Manifest path: $manifestPath" `
    -ManualAction 'Run this script from the repository root or pass -ProjectRoot <path>.' `
    -Data @{ ManifestPath = $manifestPath }))

$checks.Add((New-CheckResult `
    -Name 'Project module file' `
    -Passed $psm1Exists `
    -Message "Module file expected at: $modulePath" `
    -ManualAction 'Confirm the repository or ZIP was extracted completely.' `
    -Data @{ Path = $modulePath }))

$checks.Add((New-CheckResult `
    -Name 'Project folders' `
    -Passed ($publicExists -and $privateExists) `
    -Message 'Public and Private module folders are present.' `
    -ManualAction 'Confirm the repository or ZIP was extracted completely.' `
    -Data @{ Public = $publicExists; Private = $privateExists }))

# Install tooling
$installModuleCommand = Get-Command Install-Module -ErrorAction SilentlyContinue
$checks.Add((New-CheckResult `
    -Name 'Install-Module availability' `
    -Passed ($null -ne $installModuleCommand) `
    -Message $(if ($installModuleCommand) { "Install-Module available from $($installModuleCommand.Source)." } else { 'Install-Module was not found.' }) `
    -ManualAction 'Install or repair PowerShellGet support, or install required modules manually.' `
    -Data @{ Available = ($null -ne $installModuleCommand); Source = $(if ($installModuleCommand) { $installModuleCommand.Source } else { $null }) }))

$gallery = Test-GalleryReachable
$checks.Add((New-CheckResult `
    -Name 'PowerShell Gallery' `
    -Passed ([bool]$gallery.Passed) `
    -Message $gallery.Message `
    -ManualAction 'Register or repair PSGallery access, or install modules from an approved internal repository.' `
    -Severity 'Recommended' `
    -Data $gallery))

# Execution policy, Windows only
if ($IsWindows) {
    try {
        $effectivePolicy = Get-ExecutionPolicy -ErrorAction Stop
        $blocked = $effectivePolicy -in @('Restricted','AllSigned')
        $checks.Add((New-CheckResult `
            -Name 'Execution policy' `
            -Passed (-not $blocked) `
            -Message "Effective execution policy: $effectivePolicy." `
            -ManualAction 'Review organization policy. For a user-scoped developer workstation policy, RemoteSigned may be acceptable if approved.' `
            -Severity 'Recommended' `
            -Data @{ EffectivePolicy = $effectivePolicy.ToString() }))
    }
    catch {
        $checks.Add((New-CheckResult `
            -Name 'Execution policy' `
            -Passed $false `
            -Message "Could not read execution policy: $($_.Exception.Message)" `
            -ManualAction 'Run Get-ExecutionPolicy -List manually and review organization policy.' `
            -Severity 'Recommended'))
    }
}

# Module checks
$moduleResults = New-Object System.Collections.Generic.List[object]
foreach ($moduleName in $RequiredModules) {
    $minimumVersion = if ($requiredModuleMinimumVersions.ContainsKey($moduleName)) { [version]$requiredModuleMinimumVersions[$moduleName] } else { $null }
    $moduleResult = Test-ModuleInstalled -Name $moduleName -MinimumVersion $minimumVersion
    $moduleResults.Add($moduleResult)

    $requirementText = if ($null -ne $minimumVersion) { "minimum $minimumVersion" } else { 'any installed version' }
    $message = if (-not $moduleResult.Installed) {
        "$moduleName is missing; required: $requirementText."
    }
    elseif (-not $moduleResult.MeetsMinimum) {
        "$moduleName $($moduleResult.Version) found, but $requirementText is required."
    }
    else {
        "$moduleName $($moduleResult.Version) found; required: $requirementText."
    }

    $manualAction = if ($null -ne $minimumVersion) {
        "Install-Module -Name '$moduleName' -MinimumVersion '$minimumVersion' -Scope CurrentUser -Repository PSGallery -Force -AllowClobber"
    }
    else {
        "Install-Module -Name '$moduleName' -Scope CurrentUser -Repository PSGallery -Force -AllowClobber"
    }

    $checks.Add((New-CheckResult `
        -Name "Required module: $moduleName" `
        -Passed ([bool]$moduleResult.SatisfiesRequirement) `
        -Message $message `
        -ManualAction $manualAction `
        -Data $moduleResult))
}

$optionalResults = New-Object System.Collections.Generic.List[object]
foreach ($moduleName in $OptionalModules) {
    $moduleResult = Test-ModuleInstalled -Name $moduleName -MinimumVersion $null
    $optionalResults.Add($moduleResult)
    $checks.Add((New-CheckResult `
        -Name "Optional module: $moduleName" `
        -Passed ([bool]$moduleResult.Installed) `
        -Message $(if ($moduleResult.Installed) { "$moduleName $($moduleResult.Version) found." } else { "$moduleName is missing. Optional, but useful for tests." }) `
        -ManualAction "Install-Module -Name '$moduleName' -Scope CurrentUser -Repository PSGallery -Force -AllowClobber" `
        -Severity 'Optional' `
        -Data $moduleResult))
}

$moduleImport = Test-ProjectModuleImport -Root $resolvedRoot
$checks.Add((New-CheckResult `
    -Name 'Module import' `
    -Passed ([bool]$moduleImport.Imported) `
    -Message $moduleImport.Message `
    -ManualAction 'Run Remove-Module EntraObjectInspector -Force -ErrorAction SilentlyContinue, then Import-Module .\EntraObjectInspector.psd1 -Force from the repository root and inspect the import error.' `
    -Data $moduleImport))

$expectedPublicCommands = @(
    'Connect-InspectorGraph',
    'Export-EntraAssessmentReport',
    'Export-EntraTenantInspection',
    'Get-EntraObjectInsight',
    'Invoke-EntraAssessmentIntelligence',
    'Invoke-EntraSecurityAssessment',
    'Invoke-EntraTenantInspection'
)

$commandSurface = Test-PublicCommandSurface -ExpectedCommands $expectedPublicCommands -ActualCommands $moduleImport.ExportedFunctions
$checks.Add((New-CheckResult `
    -Name 'Public command surface' `
    -Passed ([bool]$commandSurface.Passed) `
    -Message "Expected $(@($commandSurface.ExpectedPublicCommands).Count) public commands; found $(@($commandSurface.ActualPublicCommands).Count)." `
    -ManualAction 'Inspect EntraObjectInspector.psd1 and EntraObjectInspector.psm1 exported functions.' `
    -Data $commandSurface))

$pesterSummary = [PSCustomObject]@{
    Ran     = $false
    Passed  = 0
    Failed  = 0
    Skipped = 0
    Total   = 0
    LogPath = $null
    Message = 'Pester was not run. Use -RunTests to run the test suite.'
}

if ($RunTests) {
    Write-Ui 'Running Pester validation. Detailed output will be written to a log file.' -Kind Info
    $pesterSummary = Invoke-RequirementsPesterValidation -Root $resolvedRoot -RequestedLogDirectory $LogDirectory -RequestedTestOutputPath $TestOutputPath
    $pesterKind = if ($pesterSummary.Ran -and $pesterSummary.Failed -eq 0) { 'Success' } elseif ($pesterSummary.Ran) { 'Error' } else { 'Warning' }
    Write-Ui "Pester summary: Passed=$($pesterSummary.Passed); Failed=$($pesterSummary.Failed); Skipped=$($pesterSummary.Skipped); Total=$($pesterSummary.Total)" -Kind $pesterKind
    if (-not [string]::IsNullOrWhiteSpace($pesterSummary.LogPath)) {
        Write-Ui "Pester log: $($pesterSummary.LogPath)" -Kind Info
    }
}

$missingRequired = @($moduleResults | Where-Object { -not $_.Installed } | Select-Object -ExpandProperty Name)
$unsatisfiedRequired = @($moduleResults | Where-Object { -not $_.SatisfiesRequirement } | Select-Object -ExpandProperty Name)
$missingOptional = @($optionalResults | Where-Object { -not $_.Installed } | Select-Object -ExpandProperty Name)
$failedRequired = @($checks | Where-Object { $_.Severity -eq 'Required' -and -not $_.Passed })
$failedRecommended = @($checks | Where-Object { $_.Severity -eq 'Recommended' -and -not $_.Passed })
$failedOptional = @($checks | Where-Object { $_.Severity -eq 'Optional' -and -not $_.Passed })
$failedRequiredNames = @($failedRequired | ForEach-Object { $_.Name })
$failedRecommendedNames = @($failedRecommended | ForEach-Object { $_.Name })
$failedOptionalNames = @($failedOptional | ForEach-Object { $_.Name })

foreach ($check in $checks) {
    $kind = if ($check.Passed) { 'Success' } elseif ($check.Severity -eq 'Required') { 'Error' } else { 'Warning' }
    Write-Ui "$($check.Name): $($check.Message)" -Kind $kind
}

$manualCommands = Get-ManualCommands -MissingRequired $unsatisfiedRequired -MissingOptional $missingOptional -MinimumVersions $requiredModuleMinimumVersions

$modulesToInstall = @($unsatisfiedRequired)
if ($IncludeOptionalModules) {
    $modulesToInstall += $missingOptional
}
$modulesToInstall = @($modulesToInstall | Select-Object -Unique)

$canAttemptInstall = ($modulesToInstall.Count -gt 0 -and $installModuleCommand -and $gallery.Passed)

if ($ShowManualCommands -and -not $AsJson) {
    Write-Ui ''
    Write-Ui 'Manual installation commands:' -Kind Header
    $manualCommands | ForEach-Object { Write-Host $_ }
}

if ($InstallMissing -and $modulesToInstall.Count -gt 0) {
    if (-not $canAttemptInstall) {
        Write-Ui 'Automatic installation cannot continue because Install-Module or PSGallery is unavailable.' -Kind Error
    }
    else {
        Install-MissingModules -ModuleNames $modulesToInstall
        Write-Ui 'Installation attempted. Rerun this script to validate the final state.' -Kind Info
    }
}
elseif (-not $NonInteractive -and -not $ShowManualCommands -and $canAttemptInstall -and -not $AsJson) {
    Write-Ui ''
    Write-Ui "$($modulesToInstall.Count) module(s) missing." -Kind Warning
    Write-Host 'Choose an action:'
    Write-Host '  [A] Install automatically for CurrentUser'
    Write-Host '  [M] Show manual installation commands'
    Write-Host '  [E] Exit'
    $selection = Read-Host 'Selection'

    switch -Regex ($selection) {
        '^[Aa]$' {
            Install-MissingModules -ModuleNames $modulesToInstall
            Write-Ui 'Installation attempted. Rerun this script to validate the final state.' -Kind Info
        }
        '^[Mm]$' {
            Write-Ui 'Manual installation commands:' -Kind Header
            $manualCommands | ForEach-Object { Write-Host $_ }
        }
        default {
            Write-Ui 'No installation performed.' -Kind Info
        }
    }
}

$finalModuleResults = @(
    foreach ($moduleName in $RequiredModules) {
        $minimumVersion = if ($requiredModuleMinimumVersions.ContainsKey($moduleName)) { [version]$requiredModuleMinimumVersions[$moduleName] } else { $null }
        Test-ModuleInstalled -Name $moduleName -MinimumVersion $minimumVersion
    }
)
$finalMissingRequired = @($finalModuleResults | Where-Object { -not $_.Installed } | ForEach-Object { $_.Name })
$finalUnsatisfiedRequired = @($finalModuleResults | Where-Object { -not $_.SatisfiesRequirement } | ForEach-Object { $_.Name })
$canRunAssessment = ($failedRequired.Count -eq 0 -and $finalUnsatisfiedRequired.Count -eq 0)
$status = 'NotReady'
if ($canRunAssessment) {
    $status = 'Ready'
}

$requiredModuleMinimumVersionOutput = [ordered]@{}
foreach ($moduleName in @($requiredModuleMinimumVersions.Keys | Sort-Object)) {
    $requiredModuleMinimumVersionOutput[$moduleName] = $requiredModuleMinimumVersions[$moduleName].ToString()
}

$result = [PSCustomObject]@{
    PSTypeName                 = 'EntraObjectInspector.RequirementsValidation'
    SchemaVersion              = '1.0.0'
    Status                     = $status
    CanRunAssessment           = [bool]$canRunAssessment
    ProjectRoot                = $resolvedRoot
    PowerShellVersion          = $psVersion.ToString()
    PowerShellEdition          = $detectedPSEdition
    OperatingSystem            = $osName
    MinimumPowerShellVersion   = $MinimumPowerShellVersion.ToString()
    RequiredModules            = @($RequiredModules)
    RequiredModuleMinimumVersions = $requiredModuleMinimumVersionOutput
    RequiredModuleResults      = @($finalModuleResults)
    OptionalModules            = @($OptionalModules)
    MissingRequiredModules     = @($finalMissingRequired)
    UnsatisfiedRequiredModules = @($finalUnsatisfiedRequired)
    MissingOptionalModules     = @($missingOptional)
    ModuleImportSucceeded      = [bool]$moduleImport.Imported
    ModuleImportMessage        = $moduleImport.Message
    ExportedFunctions          = @($moduleImport.ExportedFunctions)
    ExpectedPublicCommands     = @($commandSurface.ExpectedPublicCommands)
    ActualPublicCommands       = @($commandSurface.ActualPublicCommands)
    MissingPublicCommands      = @($commandSurface.MissingPublicCommands)
    UnexpectedPublicCommands   = @($commandSurface.UnexpectedPublicCommands)
    PesterSummary              = $pesterSummary
    FailedRequiredChecks       = $failedRequiredNames
    FailedRecommendedChecks    = $failedRecommendedNames
    FailedOptionalChecks       = $failedOptionalNames
    ManualInstallationCommands = @($manualCommands)
    Checks                     = $checks.ToArray()
}

if ($AsJson) {
    $result | ConvertTo-Json -Depth 8
}
else {
    Write-Ui ''
    if ($result.CanRunAssessment) {
        Write-Ui 'All required checks passed. Environment is ready.' -Kind Success
        Write-Ui 'Next step: Connect-InspectorGraph or Invoke-EntraSecurityAssessment' -Kind Info
    }
    else {
        Write-Ui 'Environment is not ready yet.' -Kind Error
        Write-Ui 'Run with -ShowManualCommands or -InstallMissing, then rerun this script.' -Kind Info
    }
    return $result
}
