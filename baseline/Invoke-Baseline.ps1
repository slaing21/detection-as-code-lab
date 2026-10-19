<#
.SYNOPSIS
    Scripted benign Windows administration baseline for the Detection-as-Code lab.

.DESCRIPTION
    Runs a fixed sequence of ordinary admin actions on the isolated endpoint so the
    project can measure false-positive COST: how many times each detection rule fires
    against normal activity. Every action is timestamped into a manifest so an
    alert can later be attributed to a specific benign action.

.PARAMETER RunId
    Identifier for this baseline run, used in the manifest filename.

.PARAMETER SiemHost
    Host-only IP of the SIEM VM used as a local file source. Default 192.168.56.10.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-Baseline.ps1 -RunId b1

.NOTES
    This script CREATES and then DELETES everything it touches. A VM snapshot restore 
    should still be completed afterwards.
#>
[CmdletBinding()]
param(
    [string]$RunId = "b1",
    [string]$SiemHost = "192.168.56.10",
    [string]$OutDir = "$env:USERPROFILE\lab-baseline"
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$manifest = [System.Collections.Generic.List[object]]::new()

function Invoke-Action {
    param([string]$Name, [string]$AttackOverlap, [scriptblock]$Body)
    $start = (Get-Date).ToUniversalTime()
    $status = 'ok'
    try { 
        & $Body 
    } catch { 
        $status = "error: $($_.Exception.Message)" 
    }
    $end = (Get-Date).ToUniversalTime()
    $script:manifest.Add([pscustomobject]@{
        action         = $Name
        attack_overlap = $AttackOverlap
        start_utc      = $start.ToString('o')
        end_utc        = $end.ToString('o')
        status         = $status
    })
    Write-Host ("[{0}] {1} ({2})" -f $start.ToString('HH:mm:ss'), $Name, $status)
}

$svc  = "LabBenignSvc"
$task = "LabBenignTask"
$runKeyName = "LabBenignRun"

# 1. Windows service lifecycle
Invoke-Action 'service-create' 'T1543.003' {
    sc.exe create $svc binPath= "C:\Windows\System32\cmd.exe /c exit" start= demand | Out-Null
}
Invoke-Action 'service-start' 'T1543.003' {
    sc.exe start $svc 2>$null | Out-Null
}
Invoke-Action 'service-query' 'T1543.003' {
    sc.exe query $svc | Out-Null
}
Invoke-Action 'service-delete' 'T1543.003' {
    sc.exe stop $svc 2>$null | Out-Null; sc.exe delete $svc | Out-Null
}

# 2. Scheduled task lifecycle
Invoke-Action 'task-register' 'T1053.005' {
    schtasks.exe /Create /TN $task /TR "cmd.exe /c echo lab" /SC DAILY /ST 03:00 /F | Out-Null
}
Invoke-Action 'task-query'  'T1053.005' {
    schtasks.exe /Query /TN $task | Out-Null 
}
Invoke-Action 'task-delete' 'T1053.005' {
    schtasks.exe /Delete /TN $task /F | Out-Null
}

# 3. HKCU Run key write/delete
Invoke-Action 'runkey-write' 'T1547.001' {
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $runKeyName -Value 'C:\Windows\System32\notepad.exe' -PropertyType String -Force | Out-Null
}
Invoke-Action 'runkey-delete' 'T1547.001' {
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $runKeyName -Force
}

# 4. Account / system discovery
Invoke-Action 'enum-local-users' 'T1087.001' { 
    net.exe user | Out-Null
}
Invoke-Action 'enum-local-groups' 'T1087.001' { 
    net.exe localgroup | Out-Null
}
Invoke-Action 'systeminfo' 'T1082' { 
    systeminfo.exe | Out-Null
}
Invoke-Action 'ipconfig' 'T1082' { 
    ipconfig.exe /all | Out-Null
}
Invoke-Action 'tasklist' 'T1082' { 
    tasklist.exe | Out-Null
}

# 5. SMB admin share to localhost
Invoke-Action 'map-admin-share' 'T1021.002' { 
    net.exe use '\\127.0.0.1\C$' 2>$null | Out-Null 
}
Invoke-Action 'unmap-admin-share' 'T1021.002' { 
    net.exe use '\\127.0.0.1\C$' /delete /y 2>$null | Out-Null 
}

# 6. Local file download from SIEM VM
Invoke-Action 'download-local-file' 'T1105' {
    $dest = Join-Path $OutDir 'benign.bin'
    try { 
        Invoke-WebRequest -Uri "http://$SiemHost/benign.bin" -OutFile $dest -TimeoutSec 10 -UseBasicParsing 
    } catch { 
        Set-Content -Path $dest -Value 'placeholder (SIEM HTTP server not up)' 
    }
}

# 7. Archive a log folder
Invoke-Action 'archive-logs' 'T1560' {
    $zip = Join-Path $OutDir "logs-$RunId.zip"
    Compress-Archive -Path "$env:windir\Logs\*" -DestinationPath $zip -Force -ErrorAction SilentlyContinue
}

# 8. Install + uninstall a signed MSI
Invoke-Action 'msi-install' 'installer-noise' {
    $msi = Join-Path $OutDir 'sample.msi'
    if (Test-Path $msi) { 
        Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait 
    }
}
Invoke-Action 'msi-uninstall' 'installer-noise' {
    $msi = Join-Path $OutDir 'sample.msi'
    if (Test-Path $msi) { 
        Start-Process msiexec.exe -ArgumentList "/x `"$msi`" /qn /norestart" -Wait 
    }
}

# 9. Scripted PowerShell activity
Invoke-Action 'powershell-activity' 'T1059.001' {
    1..20 | ForEach-Object {
        $x = Get-Random
        $null = [math]::Sqrt($x)
        Get-Process | Select-Object -First 1 | Out-Null
        Start-Sleep -Milliseconds 300
    }
    Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
}

# Write manifest
$manifestPath = Join-Path $OutDir "baseline-manifest-$RunId.json"
$runStart = $manifest[0].start_utc
$runEnd   = $manifest[-1].end_utc
[pscustomobject]@{
    run_id         = $RunId
    run_type       = 'baseline'
    host           = $env:COMPUTERNAME
    run_start_utc  = $runStart
    run_end_utc    = $runEnd
    action_count   = $manifest.Count
    actions        = $manifest
} | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host ""
Write-Host "Baseline $RunId complete. Manifest: $manifestPath"
Write-Host "Window (UTC): $runStart  ->  $runEnd"
Write-Host "Next: in Wazuh, count alerts per lab rule within this window = that rule's FP contribution for run $RunId."