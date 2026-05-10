# T1059.001 PowerShell Simulation
# Safe ATT&CK emulation for lab environments

Write-Host "[*] Starting T1059.001 simulation"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputFile = Join-Path $scriptRoot "simulation_output.txt"

"=== PowerShell ATT&CK Simulation ===" | Out-File $outputFile

# Hostname
"`n[+] Hostname" | Out-File $outputFile -Append
hostname | Out-File $outputFile -Append

# Current user
"`n[+] Current User" | Out-File $outputFile -Append
whoami | Out-File $outputFile -Append

# OS information
"`n[+] Operating System" | Out-File $outputFile -Append
Get-ComputerInfo |
    Select-Object WindowsProductName, WindowsVersion |
    Out-File $outputFile -Append

# Process discovery
"`n[+] Running Processes" | Out-File $outputFile -Append
Get-Process |
    Select-Object Name, Id |
    Out-File $outputFile -Append

# Benign T1059.001-like execution chain:
# Start-Process -> powershell -EncodedCommand -> FromBase64String -> Invoke-Expression.
"`n[+] EncodedCommand Simulation (Benign)" | Out-File $outputFile -Append
try {
    $safeOutputPath = $outputFile.Replace("'", "''")
    $stage2Command = "Write-Output '[+] Encoded payload executed (benign)' | Out-File -FilePath '$safeOutputPath' -Append; Get-Date -Format o | Out-File -FilePath '$safeOutputPath' -Append"
    $stage2Base64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($stage2Command))

    $innerScript = "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$stage2Base64')) | Invoke-Expression"
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($innerScript))

    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $encodedCommand" -NoNewWindow -Wait
    "[+] EncodedCommand process finished" | Out-File $outputFile -Append
}
catch {
    "[-] EncodedCommand simulation failed: $($_.Exception.Message)" | Out-File $outputFile -Append
}

Write-Host "[*] Results written to simulation_output.txt"