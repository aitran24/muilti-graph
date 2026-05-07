param(
  [switch]$InstallSysmon,
  [string]$PythonExe = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

if (-not $PythonExe) {
  $venvPython = Join-Path $repoRoot "venv\Scripts\python.exe"
  if (Test-Path $venvPython) {
    $PythonExe = $venvPython
  }
}

if (-not $PythonExe) {
  $pyCommand = Get-Command py -ErrorAction SilentlyContinue
  if ($null -ne $pyCommand) {
    $PythonExe = "py"
  }
}

if (-not $PythonExe) {
  throw "Cannot find Python runtime. Use -PythonExe <path> or create venv at .\venv."
}

$arguments = @(
  (Join-Path $scriptDir "run_streamline.py")
)

if ($InstallSysmon) {
  $arguments += "--install-sysmon"
}

Write-Host "Starting Streamline with default ports..." -ForegroundColor Cyan
Write-Host " - WS: ws://127.0.0.1:8877" -ForegroundColor DarkGray
Write-Host " - Main UI: http://127.0.0.1:8080/index.html" -ForegroundColor DarkGray
Write-Host " - Match UI: http://127.0.0.1:8080/match/index.html" -ForegroundColor DarkGray
Write-Host " - Snapshot UI: http://127.0.0.1:8081/index.html" -ForegroundColor DarkGray

if ($PythonExe -eq "py") {
  & py -3 @arguments
} else {
  & $PythonExe @arguments
}

exit $LASTEXITCODE
