$ErrorActionPreference = "Stop"

$LabDir = Join-Path $env:TEMP "MITRE_LAB"
$TaskName = "MITRE_T1053_005_Demo"
$SystemTaskName = "${TaskName}_SYSTEM"
$OutputFile = Join-Path $LabDir "T1053_005_output.txt"

Write-Host "[+] Initializing lab environment..." -ForegroundColor Cyan

if (-not (Test-Path $LabDir)) {
    New-Item -ItemType Directory -Path $LabDir -Force | Out-Null
}

if (Test-Path $OutputFile) {
    Remove-Item $OutputFile -Force
}

function Remove-TaskIfExists {
    param([string]$Name)

    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue

    if ($null -ne $task) {
        Write-Host "[+] Removing existing task: $Name" -ForegroundColor Yellow
        schtasks.exe /Delete /TN $Name /F | Out-Null
    }
    else {
        Write-Host "[*] Task does not exist: $Name" -ForegroundColor DarkGray
    }
}

Remove-TaskIfExists -Name $TaskName
Remove-TaskIfExists -Name $SystemTaskName

$UserTaskAction = "cmd.exe /c whoami >> `"$OutputFile`""

Write-Host "[+] Creating scheduled task..." -ForegroundColor Cyan

schtasks.exe /Create /SC ONCE /TN $TaskName /TR $UserTaskAction /ST 23:59 /F | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Failed to create scheduled task."
}

Write-Host "[+] Running task immediately..." -ForegroundColor Cyan

schtasks.exe /Run /TN $TaskName | Out-Null

Start-Sleep -Seconds 3

$SystemTaskAction = "cmd.exe /c whoami /priv >> `"$OutputFile`""

Write-Host "[+] Creating SYSTEM scheduled task..." -ForegroundColor Cyan

schtasks.exe /Create /SC ONCE /TN $SystemTaskName /TR $SystemTaskAction /ST 23:59 /RU SYSTEM /F | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] SYSTEM task creation failed. Run as Administrator." -ForegroundColor Red
}
else {
    Write-Host "[+] SYSTEM task created successfully." -ForegroundColor Green
}

Write-Host ""

if (Test-Path $OutputFile) {
    Write-Host "[+] Output:"
    Write-Host "----------------------------------------"

    Get-Content $OutputFile

    Write-Host "----------------------------------------"
}
else {
    Write-Host "[!] Output file not created yet." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[+] Cleanup:"
Write-Host "schtasks.exe /Delete /TN $TaskName /F"
Write-Host "schtasks.exe /Delete /TN $SystemTaskName /F"