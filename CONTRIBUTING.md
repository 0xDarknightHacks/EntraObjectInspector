# Contributing

Open an issue before large feature changes or changes that affect assessment behavior.

Submit focused pull requests with clear scope and include or update Pester tests when behavior, contracts, or public commands change.

Preserve the read-only security model. Logical Microsoft Graph operations must remain GET-only. The only permitted POST in collection code is the Microsoft Graph v1.0 `$batch` transport envelope, and its subrequests must be hard-coded to GET. Do not add tenant-mutating Graph calls, remediation, risk scoring, attack paths, or dashboard functionality without prior design discussion.

Do not commit secrets, tenant data, generated exports, reports, logs, transcripts, or local configuration files.

Keep documentation accurate when changing public commands, configuration, output artifacts, or report behavior.

## Release validation and dependencies

Use PowerShell 7.6 or later. The release-validation baseline is PowerShell 7.6.4 with `Microsoft.Graph.Authentication` 2.39.0, `Microsoft.PowerShell.SecretManagement` 1.1.2, `Microsoft.PowerShell.SecretStore` 1.0.6, and Pester 6.1.0. Runtime minimums are declared in the module manifest; CI intentionally installs the exact tested versions. Do not raise, lower, or exact-pin runtime requirements without compatibility evidence and a full test run.

Before a release, run `./Scripts/Test-EntraObjectInspectorRequirements.ps1 -NonInteractive -SkipGalleryReachability`, import the module, verify exactly seven exported functions, and run the complete Pester suite. The current suite contains 276 tests; the release gate requires 276 passed / 0 failed / 0 skipped. CI must remain tenant-independent and must not authenticate to Microsoft Graph.

## Source-release hygiene

Do not include generated `exports/`, `reports/`, `EntraObjectInspector-Exports/`, `EntraObjectInspector-Reports/`, logs, diagnostics, test results, local configuration, release-inventory output, or temporary ZIP/patch artifacts in commits or source-release archives. Validate from a real Git clone with `git status --short` and `git ls-files`; `.gitignore` protects untracked local files but cannot remove files that were already committed.
