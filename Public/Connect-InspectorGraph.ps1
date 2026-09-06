function Test-InspectorSecretStorePasswordFailure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception.GetType().Name -eq 'PasswordRequiredException') {
            return $true
        }

        $exception = $exception.InnerException
    }

    $errorText = @(
        [string]$ErrorRecord.Exception.Message
        [string]$ErrorRecord.FullyQualifiedErrorId
        [string]$ErrorRecord
    ) -join ' '

    # Fallback for hosts/versions that wrap the SecretStore exception and expose
    # only the documented password-required text through SecretManagement.
    return $errorText -match '(?i)(valid password is required.*SecretStore|SecretStore.*(password|unlock))'
}

function Connect-InspectorGraph {
    [CmdletBinding()]
    param()

    $configPath = Join-Path `
        $HOME `
        ".entra-object-inspector/config.json"

    if (-not (Test-Path $configPath)) {
        throw "Inspector configuration was not found."
    }

    $config = Get-Content `
        -Path $configPath `
        -Raw |
        ConvertFrom-Json

    $secret = $null
    $maximumPasswordAttempts = 3

    for ($attempt = 1; $attempt -le $maximumPasswordAttempts; $attempt++) {
        try {
            $secret = Get-Secret `
                -Name "InspectorGraphClientSecret" `
                -Vault "EntraInspectorVault" `
                -ErrorAction Stop

            break
        }
        catch {
            if (-not (Test-InspectorSecretStorePasswordFailure -ErrorRecord $_)) {
                throw
            }

            if ($attempt -lt $maximumPasswordAttempts) {
                Write-Warning (
                    "SecretStore password was not accepted. " +
                    "Retrying vault access (attempt $($attempt + 1) of $maximumPasswordAttempts)."
                )
                continue
            }

            $vaultUnlockFailureMessage = @(
                "Microsoft.PowerShell.SecretStore vault 'EntraInspectorVault' could not be " +
                "unlocked after $maximumPasswordAttempts password attempts while retrieving " +
                "the secret 'InspectorGraphClientSecret'."
                ''
                'The vault password was rejected on every attempt, so the Microsoft Graph ' +
                'app-only connection could not be established.'
                ''
                'To recover:'
                "  1. Run 'Unlock-SecretStore' and enter the vault password configured when " +
                "the 'EntraInspectorVault' vault was registered, then retry the assessment."
                "  2. If the vault password has been lost, reset the vault with " +
                "'Reset-SecretStore -Name EntraInspectorVault' and re-register the client " +
                'secret as described in README.md. Resetting the vault permanently deletes ' +
                'all secrets it contains.'
            ) -join [System.Environment]::NewLine

            throw [System.InvalidOperationException]::new(
                $vaultUnlockFailureMessage,
                $_.Exception
            )
        }
    }

    if (-not $secret) {
        throw "Inspector client secret was not found."
    }

    $credential = [PSCredential]::new(
        [string]$config.ClientId,
        $secret
    )

    Connect-MgGraph `
        -TenantId ([string]$config.TenantId) `
        -ClientSecretCredential $credential `
        -NoWelcome |
        Out-Null

    $context = Get-MgContext

    if (-not $context -or $context.AuthType -ne "AppOnly") {
        throw "Microsoft Graph app-only authentication failed."
    }

    return $context
}
