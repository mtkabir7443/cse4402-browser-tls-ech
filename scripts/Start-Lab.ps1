#Requires -Version 7.2
[CmdletBinding()]
param([switch]$TrustLabCA)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location $root
try {
    $go=Join-Path $root '.tools/go/bin/go.exe'
    if(-not(Test-Path -LiteralPath $go)){throw 'Install the pinned Go toolchain described in README.md first.'}
    $exe=Join-Path $root '.runtime/tlslab.exe'
    $null=New-Item -ItemType Directory -Path '.runtime','evidence' -Force
    & $go build -buildvcs=false -o $exe .
    if($LASTEXITCODE -ne 0){throw 'Lab build failed.'}
    if(-not(Test-Path -LiteralPath '.runtime/ca.pem')){ & $exe -mode init; if($LASTEXITCODE -ne 0){throw 'Lab initialization failed.'} }
    $ca=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $root '.runtime/ca.cer'))
    if($TrustLabCA -and -not(Test-Path -LiteralPath ('Cert:\CurrentUser\Root\'+$ca.Thumbprint))){
        Write-Host 'Approve only the CSE4402 isolated TLS lab certificate in the Windows dialog. Stop-Lab removes this temporary entry.'
        $null=Import-Certificate -FilePath '.runtime/ca.cer' -CertStoreLocation 'Cert:\CurrentUser\Root'
        [IO.File]::WriteAllText((Join-Path $root '.runtime/trusted-ca-thumbprint.txt'),$ca.Thumbprint)
    }
    if(Test-Path -LiteralPath '.runtime/server.pid'){
        $old=Get-Process -Id ([int](Get-Content -LiteralPath '.runtime/server.pid')) -ErrorAction SilentlyContinue
        if($old -and $old.Path -eq $exe){throw 'This lab already has a running server; use Stop-Lab first.'}
    }
    $proc=Start-Process -FilePath $exe -ArgumentList '-mode','serve' -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput '.runtime/server-stdout.log' -RedirectStandardError '.runtime/server-stderr.log' -PassThru
    $proc.Id | Set-Content -LiteralPath '.runtime/server.pid'
    Start-Sleep -Milliseconds 500
    if($proc.HasExited){throw ('Server exited. Inspect .runtime/server-stderr.log.')}
    Write-Output ('Lab running: PID '+$proc.Id+'; dashboard https://127.0.0.1:8443/; CA '+$ca.Thumbprint)
} finally {Pop-Location}
