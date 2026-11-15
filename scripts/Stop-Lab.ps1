#Requires -Version 7.2
[CmdletBinding()]
param([switch]$KeepTrust)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$pidFile=Join-Path $root '.runtime/server.pid'
if(Test-Path -LiteralPath $pidFile){
    $proc=Get-Process -Id ([int](Get-Content -LiteralPath $pidFile)) -ErrorAction SilentlyContinue
    if($proc){
        if($proc.Path -ne (Join-Path $root '.runtime/tlslab.exe')){throw 'Recorded PID no longer belongs to this lab; refusing to stop it.'}
        Stop-Process -Id $proc.Id
    }
}
$thumbFile=Join-Path $root '.runtime/trusted-ca-thumbprint.txt'
if(-not $KeepTrust -and (Test-Path -LiteralPath $thumbFile)){
    $thumb=(Get-Content -LiteralPath $thumbFile -Raw).Trim()
    $ca=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $root '.runtime/ca.cer'))
    if($thumb -ne $ca.Thumbprint -or $ca.Subject -notlike '*CSE4402 isolated TLS lab*'){throw 'Lab trust identity mismatch; refusing certificate removal.'}
    $certPath='Cert:\CurrentUser\Root\'+$thumb
    if(Test-Path -LiteralPath $certPath){
        Write-Host 'Windows may ask to DELETE the CSE4402 isolated TLS lab certificate. Confirm that exact lab certificate in the Root Certificate Store dialog.'
        & certutil.exe -user -delstore Root $thumb
        if($LASTEXITCODE -ne 0){throw 'Windows did not complete lab certificate removal; inspect the certificate dialog/result.'}
    }
    if(Test-Path -LiteralPath $certPath){throw 'Temporary lab certificate remains trusted.'}
    Write-Output ('Removed/verified absent temporary lab trust: '+$thumb)
}
Write-Output 'Lab server stopped. Private fixtures and evidence are preserved locally.'
