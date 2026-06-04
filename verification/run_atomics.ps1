# Atomic Red Team test execution script (skeleton)
# Requires: Invoke-AtomicRedTeam module
# Usage: .\run_atomics.ps1 -TechniqueIds T1059.001,T1003.001

param(
    [Parameter(Mandatory=$true)]
    [string[]]$TechniqueIds,
    [int]$DelaySeconds = 120
)

Import-Module "Invoke-AtomicRedTeam" -ErrorAction Stop

$results = @()
foreach ($tid in $TechniqueIds) {
    Write-Host "[*] Running atomic test for $tid"
    try {
        Invoke-AtomicTest $tid -GetPrereqs
        Invoke-AtomicTest $tid -Confirm:$false
        $results += @{ technique = $tid; status = "executed"; timestamp = (Get-Date -Format o) }
    } catch {
        Write-Warning "[-] Failed: $tid - $_"
        $results += @{ technique = $tid; status = "failed"; error = $_.ToString() }
    }
}

Write-Host "[*] Waiting ${DelaySeconds}s for telemetry ingestion..."
Start-Sleep -Seconds $DelaySeconds

# Export results for check_alerts.py
$results | ConvertTo-Json | Out-File "verification/results/run_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
Write-Host "[+] Done. Run check_alerts.py to verify detection."
