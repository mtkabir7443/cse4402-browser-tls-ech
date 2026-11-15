#Requires -Version 7.2
<#
.SYNOPSIS
Acquires the seven pinned browser candidates without installing or launching them.
.DESCRIPTION
Reuses installed Edge. Downloads official archives for project-local Chrome,
Firefox, Brave, Opera and historical Chrome. Checks archive hashes, executable
versions and Authenticode, then writes browsers.json. No browser/default, root
certificate, machine installation or personal-profile settings are changed.
#>
[CmdletBinding()]
param([ValidateRange(30, 600)][int]$DownloadTimeoutSeconds = 180)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$toolsRoot = Join-Path $projectRoot '.tools'
$null = New-Item -ItemType Directory -Path $toolsRoot -Force
$sevenZip = (Get-Command 7z -ErrorAction Stop).Source
$utf8 = [Text.UTF8Encoding]::new($false)

# SHA256 pins for Brave, Opera and both Firefox installers were matched against
# publisher checksum documents on 2026-11-15. CfT does not publish SHA256 here:
# its pin is the observed archive from the official Google version manifest,
# additionally checked against Google Storage's Content-MD5 metadata.
$archives = @(
    @{
        Id='chrome-current'; Product='Chrome'; Version='157.0.8103.78'; FileVersion='157.0.8103.78'; Family='chromium'; EngineVersion='157.0.8103.78'; Cohort='current';
        Archive='chrome-157.0.8103.78-win64.zip'; Folder='chrome-157.0.8103.78'; Executable='chrome-win64/chrome.exe'; Signer='';
        Url='https://storage.googleapis.com/chrome-for-testing-public/157.0.8103.78/win64/chrome-win64.zip';
        ChecksumUrl=$null; Hash='5F6EC40206407112702E163BF694D07F9FDC8CCBD346C70CE61FA62F716493F9';
        Md5Base64='XK8XW84hYqn3HhjK4XBk7w==';
        Distribution='Official Chrome for Testing stable Windows x64 ZIP; unsigned executable; isolated policy namespace'; EngineSource='Official stable channel manifest and executable metadata';
        Provenance='https://googlechromelabs.github.io/chrome-for-testing/157.0.8103.78.json'
    },
    @{
        Id='firefox-current'; Product='Firefox'; Version='160.0'; FileVersion='160.0'; Family='gecko'; EngineVersion='160.0'; Cohort='current';
        Archive='Firefox-160.0.exe'; Folder='firefox-160'; Executable='core/firefox.exe'; Signer='Mozilla Corporation';
        Url='https://ftp.mozilla.org/pub/firefox/releases/160.0/win64/en-US/Firefox%20Setup%20160.0.exe';
        ChecksumUrl='https://ftp.mozilla.org/pub/firefox/releases/160.0/SHA256SUMS';
        Hash='8732312EE2D7960C6EA830A4E0D3C0FF5FE0B10856DAB44E2C432FCDEB63FF63';
        Distribution='Official Firefox Windows x64 en-US installer, extracted only'; EngineSource='application.ini Gecko version';
        Provenance='https://ftp.mozilla.org/pub/firefox/releases/160.0/'
    },
    @{
        Id='brave-current'; Product='Brave'; Version='1.99.57'; FileVersion='157.1.99.57'; Family='chromium'; EngineVersion='157.0.8103.79'; Cohort='current';
        Archive='brave-v1.99.57-win32-x64.zip'; Folder='brave-1.99.57'; Executable='brave.exe'; Signer='Brave Software';
        Url='https://github.com/brave/brave-browser/releases/download/v1.99.57/brave-v1.99.57-win32-x64.zip';
        ChecksumUrl='https://github.com/brave/brave-browser/releases/download/v1.99.57/brave-v1.99.57-win32-x64.zip.sha256';
        Hash='42BA3A5445F717B429FB3FE457E7E531CD1C208F06A2DC9315B1FA31C09BC8B9';
        Distribution='Official Brave release Windows x64 ZIP'; EngineSource='Official release title: Chromium 157.0.8103.79';
        Provenance='https://github.com/brave/brave-browser/releases/tag/v1.99.57'
    },
    @{
        Id='opera-current'; Product='Opera'; Version='140.0.6074.18'; FileVersion='140.0.6074.18'; Family='chromium'; EngineVersion='157.0.8103.39'; Cohort='current';
        Archive='Opera_140.0.6074.18_Setup_x64.exe'; Folder='opera-140.0.6074.18'; Executable='opera.exe'; Signer='Opera Norway AS';
        Url='https://get.opera.com/pub/opera/desktop/140.0.6074.18/win/Opera_140.0.6074.18_Setup_x64.exe';
        ChecksumUrl='https://get.opera.com/pub/opera/desktop/140.0.6074.18/win/Opera_140.0.6074.18_Setup_x64.exe.sha256sum';
        Hash='5E0DF23F7888407B22CB8B533A4CA19100FFC8F606E01C9CDB463C184CF6A2F6';
        Distribution='Official Opera stable Windows x64 offline installer, extracted only'; EngineSource='Official Opera 140 stable changelog; confirm runtime version during measurement';
        Provenance='https://blogs.opera.com/desktop/changelog-for-140/'
    },
    @{
        Id='chrome-116'; Product='Chrome'; Version='116.0.5845.96'; FileVersion='116.0.5845.96'; Family='chromium'; EngineVersion='116.0.5845.96'; Cohort='historical';
        Archive='chrome-116.0.5845.96-win64.zip'; Folder='chrome-116.0.5845.96'; Executable='chrome-win64/chrome.exe'; Signer='';
        Url='https://storage.googleapis.com/chrome-for-testing-public/116.0.5845.96/win64/chrome-win64.zip';
        ChecksumUrl=$null; Hash='58CE894D230738E5B05EC0E20F8283C77070A97AFB21BAE3175E13F2B0AF08B7';
        Md5Base64='X4ZYKnysXjF2jtNoP8ZIPQ==';
        Distribution='Official Chrome for Testing Windows x64 ZIP; unsigned executable'; EngineSource='Chrome for Testing version manifest and executable metadata';
        Provenance='https://googlechromelabs.github.io/chrome-for-testing/116.0.5845.96.json'
    },
    @{
        Id='firefox-115'; Product='Firefox'; Version='115.0.3esr'; FileVersion='115.0.3'; Family='gecko'; EngineVersion='115.0.3'; Cohort='historical';
        Archive='Firefox-115.0.3esr.exe'; Folder='firefox-115.0.3esr'; Executable='core/firefox.exe'; Signer='Mozilla Corporation';
        Url='https://ftp.mozilla.org/pub/firefox/releases/115.0.3esr/win64/en-US/Firefox%20Setup%20115.0.3esr.exe';
        ChecksumUrl='https://ftp.mozilla.org/pub/firefox/releases/115.0.3esr/SHA256SUMS';
        Hash='C20619C2FF4A22929B2F388E09EAF04DB9645DD76DC6F45010884D91D520E671';
        Distribution='Official Firefox ESR Windows x64 en-US installer, extracted only'; EngineSource='application.ini Gecko version';
        Provenance='https://ftp.mozilla.org/pub/firefox/releases/115.0.3esr/'
    }
)

function Get-BrowserRecord {
    param([hashtable]$Definition, [string]$Executable, [object]$Source)
    $item = Get-Item -LiteralPath $Executable -ErrorAction Stop
    $version = $item.VersionInfo.ProductVersion
    if ($Definition.ContainsKey('FileVersion') -and $version -ne $Definition.FileVersion) {
        throw "Unexpected executable version for $($Definition.Id): $version"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Executable
    $signatureStatus = $signature.Status.ToString()
    $publisher = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    if ($Definition.Id -in @('chrome-current','chrome-116')) {
        if ($signatureStatus -notin @('NotSigned', 'Valid')) { throw "Invalid CfT signature status: $signatureStatus" }
    } elseif ($signatureStatus -ne 'Valid' -or $publisher -notmatch [regex]::Escape($Definition.Signer)) {
        throw "Browser executable signature/publisher check failed for $($Definition.Id): $signatureStatus / $publisher"
    }
    $reportedVersion = if ($Definition.ContainsKey('Version')) { $Definition.Version } else { $version }
    [ordered]@{
        id = $Definition.Id
        product = $Definition.Product
        version = $reportedVersion
        executable_version = $version
        cohort = $Definition.Cohort
        engine = [ordered]@{ family=$Definition.Family; version=$Definition.EngineVersion; version_source=$Definition.EngineSource }
        distribution = $Definition.Distribution
        path = $item.FullName
        relative_path = if ($item.FullName.StartsWith($projectRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { [IO.Path]::GetRelativePath($projectRoot, $item.FullName) } else { $null }
        source = $Source
        sha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
        signature = [ordered]@{ status=$signatureStatus; signer=$publisher; signer_thumbprint=if($signature.SignerCertificate){$signature.SignerCertificate.Thumbprint}else{$null} }
        status = 'available'
        measurement_status = 'Acquisition verifies files only; consult run evidence for browser behavior.'
    }
}

$records = [Collections.Generic.List[object]]::new()
$installed = @(
    @{ Id='edge-current'; Product='Microsoft Edge'; Family='chromium'; EngineVersion=$null; EngineSource='Read runtime engine version during measurement'; Cohort='current'; Distribution='Installed Microsoft Edge'; Signer='Microsoft Corporation'; Paths=@((Join-Path ${env:ProgramFiles(x86)} 'Microsoft/Edge/Application/msedge.exe'),(Join-Path $env:ProgramFiles 'Microsoft/Edge/Application/msedge.exe')); Provenance='https://www.microsoft.com/edge/download' }
)
foreach ($definition in $installed) {
    $executable = $definition.Paths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $executable) { throw "Required installed browser unavailable: $($definition.Product)" }
    $source = [ordered]@{ provenance_url=$definition.Provenance; acquisition='Existing signed installation; no installer run by this script'; archive_sha256=$null; checksum_url=$null }
    $records.Add((Get-BrowserRecord -Definition $definition -Executable $executable -Source $source))
}

foreach ($definition in $archives) {
    $archivePath = Join-Path $toolsRoot $definition.Archive
    $folder = Join-Path $toolsRoot $definition.Folder
    $executable = Join-Path $folder $definition.Executable
    if (-not (Test-Path -LiteralPath $archivePath)) {
        $partial = $archivePath + '.partial'
        Write-Host "Downloading $($definition.Id) from its pinned official URL..."
        Invoke-WebRequest -Uri $definition.Url -OutFile $partial -TimeoutSec $DownloadTimeoutSeconds
        if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash -ne $definition.Hash) { throw "Archive hash mismatch: $partial" }
        Move-Item -LiteralPath $partial -Destination $archivePath
    }
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $definition.Hash) { throw "Archive hash mismatch: $archivePath" }
    if ($definition.ContainsKey('Md5Base64')) {
        $stream = [IO.File]::OpenRead($archivePath)
        $md5 = [Security.Cryptography.MD5]::Create()
        try { $digest = [Convert]::ToBase64String($md5.ComputeHash($stream)) }
        finally { $stream.Dispose(); $md5.Dispose() }
        if ($digest -ne $definition.Md5Base64) { throw 'CfT archive does not match recorded Google Storage MD5 metadata.' }
    }
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        & $sevenZip x $archivePath ('-o' + $folder) -y -bso0 -bsp0
        if ($LASTEXITCODE -ne 0) { throw "Archive extraction failed: $archivePath" }
    }
    $archiveSignature = if ($archivePath.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { (Get-AuthenticodeSignature -LiteralPath $archivePath).Status.ToString() } else { 'NotApplicableZip' }
    if ($archiveSignature -notin @('Valid','NotApplicableZip')) { throw "Installer archive signature failed: $archivePath" }
    $source = [ordered]@{
        provenance_url=$definition.Provenance; download_url=$definition.Url; checksum_url=$definition.ChecksumUrl
        archive_path=$archivePath; archive_sha256=$definition.Hash; archive_signature=$archiveSignature
        checksum_basis=if($definition.Id -in @('chrome-current','chrome-116')){'Observed SHA256 pinned after official Google manifest and Storage MD5 verification; no publisher SHA256 asserted'}else{'Publisher SHA256 matched on 2026-11-15; pinned for reproducibility'}
        google_storage_md5_base64=if($definition.ContainsKey('Md5Base64')){$definition.Md5Base64}else{$null}
        acquisition='Project-local archive extraction; installer and browser not executed'
    }
    $records.Add((Get-BrowserRecord -Definition $definition -Executable $executable -Source $source))
}

$order = @('chrome-current','firefox-current','edge-current','brave-current','opera-current','chrome-116','firefox-115')
$manifest = [ordered]@{
    schema_version=1
    captured_at_utc=[DateTime]::UtcNow.ToString('o')
    scope='Seven Windows x64 browser builds for the CSE4402 12-case comparison'
    browser_execution_performed_by_acquisition=$false
    installed_browser_note='Installed Edge can auto-update; verify executable hash/version before each measurement. Consumer Chrome pilot evidence is preserved separately; the comparison uses pinned Chrome for Testing stable to isolate its policy namespace.'
    browsers=@($records | Sort-Object { $order.IndexOf($_.id) })
}
$manifestPath = Join-Path $projectRoot 'browsers.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 10), $utf8)
Write-Output ([pscustomobject]@{Manifest=$manifestPath; AvailableBuilds=$records.Count; BrowserLaunched=$false; GlobalInstallationChanged=$false})
