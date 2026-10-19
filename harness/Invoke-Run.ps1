<#
.SYNOPSIS
    Run-harness wrapper for one malicious atomic execution in the Detection-as-Code lab.

.DESCRIPTION
    Stamps a UTC start time, runs a single Atomic Red Team test by GUID, confirms the
    executor actually ran, stamps an end time, and emits a partial result record.

.PARAMETER TechniqueId
    ATT&CK id.

.PARAMETER TestGuid
    Atomic test GUID.

.PARAMETER RunIndex
    1, 2, or 3.

.PARAMETER GetPrereqs
    Fetch test prerequisites first while NAT adapter is connected temporarily.

.EXAMPLE
    .\Invoke-Run.ps1 -TechniqueId T1059.001 -TestGuid 86a43bad-12e3-4e85-b97c-4d5cf25b95c3 -RunIndex 1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TechniqueId,
    [Parameter(Mandatory)][string]$TestGuid,
    [Parameter(Mandatory)][ValidateRange(1,5)][int]$RunIndex,
    [switch]$GetPrereqs,
    [string]$OutDir = "$env:USERPROFILE\lab-runs"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$confirm = Read-Host "Did you restore ep-02-baseline and confirm the agent is Active on 192.168.56.20? (yes/no)"
if ($confirm -ne 'yes') {
    throw "Aborting: start every run from a clean snapshot (evaluation-protocol.md section 1)."
}

if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
    throw "Invoke-AtomicRedTeam not installed. Import it before running (see lab-build guide)."
}
Import-Module invoke-atomicredteam -Force

if ($GetPrereqs) {
    Write-Host "Fetching prereqs for $TechniqueId / $TestGuid (NAT must be connected now) ..."
    Invoke-AtomicTest $TechniqueId -TestGuids $TestGuid -GetPrereqs
    Write-Host "Prereqs fetched. Disconnect NAT and re-snapshot before measuring."
}

$tStart = (Get-Date).ToUniversalTime()
$runId = "{0}_{1}_r{2}" -f $tStart.ToString('yyyy-MM-ddTHH-mm-ssZ'), $TechniqueId, $RunIndex
Write-Host "RUN $runId  t_start=$($tStart.ToString('o'))"

$atomicStatus = 'success'
try {
    Invoke-AtomicTest $TechniqueId -TestGuids $TestGuid -ExecutionLogPath (Join-Path $OutDir "exec-$runId.csv")
} catch {
    $atomicStatus = "execution_failed"
    Write-Warning "Atomic executor failed: $($_.Exception.Message)"
}
$tEnd = (Get-Date).ToUniversalTime()

$record = [pscustomobject]@{
    run_id                 = $runId
    run_type               = 'malicious'
    timestamp_utc          = $tStart.ToString('o')
    technique_id           = $TechniqueId
    atomic_test_guid       = $TestGuid
    atomic_status          = $atomicStatus
    run_index              = $RunIndex
    t_end_utc              = $tEnd.ToString('o')
    query_window_end_utc   = $tStart.AddMinutes(5).ToString('o')
    telemetry_present      = $null
    expected_sysmon_events = $null
    observed_sysmon_events = $null
    detected               = $null
    rule_id                = $null
    alert_count            = $null
    latency_s              = $null
    coverage_score         = $null
    tuning_pass            = 0
    notes                  = ''
}
$recordPath = Join-Path $OutDir "$runId.json"
$record | ConvertTo-Json -Depth 4 | Set-Content -Path $recordPath -Encoding UTF8

Write-Host ""
Write-Host "Atomic status: $atomicStatus"
Write-Host "Partial record: $recordPath"
Write-Host "Now in Wazuh, inspect [$($tStart.ToString('HH:mm:ssZ')) .. $($tStart.AddMinutes(5).ToString('HH:mm:ssZ'))]:"
Write-Host "  1. Discover/archives: did an expected Sysmon event appear?  -> telemetry_present"
Write-Host "  2. Alerts: did a lab rule fire? which rule_id? timestamp?    -> detected, rule_id, latency_s"
Write-Host "Then run cleanup and RESTORE the snapshot before the next run."
if ($atomicStatus -eq 'execution_failed') {
    Write-Host "NOTE: atomic did not execute. Do NOT assign a coverage score to this run (protocol section 3)." -ForegroundColor Yellow
}