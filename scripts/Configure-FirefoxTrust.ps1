#Requires -Version 7.2
<#
.SYNOPSIS
Configures lab CA trust only for the project's extracted Firefox distribution.
.DESCRIPTION
Does not modify Windows certificate stores or a personal Firefox installation.
Existing unrecognized policies are preserved and cause an explicit failure.
Firefox imports the CA into each disposable profile when that browser starts.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$firefoxRoot = Join-Path $projectRoot '.tools/firefox-160/core'
$distribution = Join-Path $firefoxRoot 'distribution'
$policyPath = Join-Path $distribution 'policies.json'
$caPath = Join-Path $projectRoot '.runtime/ca.pem'
$caDerPath = Join-Path $projectRoot '.runtime/ca.cer'

foreach ($required in @((Join-Path $firefoxRoot 'firefox.exe'), $caPath, $caDerPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required project-local Firefox trust input is missing: $required"
    }
}
# Refuse junctions/symlinks along the output path so the fixed lab path cannot
# silently redirect a write to another installation or a global policy file.
foreach ($relative in @('.tools', '.tools/firefox-160', '.tools/firefox-160/core', '.tools/firefox-160/core/distribution', '.tools/firefox-160/core/distribution/policies.json')) {
    $candidate = Join-Path $projectRoot $relative
    if ((Test-Path -LiteralPath $candidate) -and
        ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing a redirected Firefox policy path: $candidate"
    }
}

$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes($caDerPath))
try {
    if ($certificate.Subject -notlike 'CN=CSE4402 isolated TLS lab *') {
        throw 'The certificate is not the generated CSE4402 lab CA.'
    }
    $wanted = [ordered]@{
        policies = [ordered]@{
            DontCheckDefaultBrowser = $true
            DisableTelemetry = $true
            DisableAppUpdate = $true
            Certificates = [ordered]@{
                ImportEnterpriseRoots = $false
                Install = @($caPath)
            }
        }
    }
    $created = $false
    if (Test-Path -LiteralPath $policyPath) {
        try { $existing = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -AsHashtable }
        catch { throw "Existing policy is invalid JSON; preserved without changes: $policyPath" }
        $recognized = $existing -is [Collections.IDictionary] -and $existing.Count -eq 1 -and $existing.Contains('policies')
        if ($recognized) {
            $policies = $existing['policies']
            $recognized = $policies -is [Collections.IDictionary] -and $policies.Count -eq 4
        }
        if ($recognized) {
            foreach ($key in @('DontCheckDefaultBrowser', 'DisableTelemetry', 'DisableAppUpdate')) {
                if (-not $policies.Contains($key) -or $policies[$key] -isnot [bool] -or $policies[$key] -ne $true) {
                    $recognized = $false
                }
            }
            if (-not $policies.Contains('Certificates')) { $recognized = $false }
        }
        if ($recognized) {
            $certPolicy = $policies['Certificates']
            $recognized = $certPolicy -is [Collections.IDictionary] -and $certPolicy.Count -eq 2 -and
                $certPolicy.Contains('ImportEnterpriseRoots') -and $certPolicy.Contains('Install')
        }
        if ($recognized) {
            $recognized = $certPolicy['ImportEnterpriseRoots'] -is [bool] -and
                $certPolicy['ImportEnterpriseRoots'] -eq $false -and
                $certPolicy['Install'] -is [array] -and $certPolicy['Install'].Count -eq 1 -and
                [string]::Equals([string]$certPolicy['Install'][0], $caPath, [StringComparison]::OrdinalIgnoreCase)
        }
        if (-not $recognized) {
            throw "Existing Firefox policy is unrecognized; preserved without changes: $policyPath"
        }
    } else {
        $null = New-Item -ItemType Directory -Path $distribution -Force
        [IO.File]::WriteAllText($policyPath, ($wanted | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
        $created = $true
    }
    [pscustomobject][ordered]@{
        method = 'Firefox application-local Certificates.Install into the fresh project profile'
        policy_path = $policyPath
        policy_sha256 = (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash
        ca_path = $caPath
        ca_sha256 = (Get-FileHash -LiteralPath $caPath -Algorithm SHA256).Hash
        ca_thumbprint = $certificate.Thumbprint
        import_enterprise_roots = $false
        policy_created = $created
        windows_certificate_store_modified = $false
        verification_note = 'Policy configuration is recorded; a successful trusted browser handshake verifies its operation.'
    }
} finally {
    $certificate.Dispose()
}
