[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
& $Python -c "import sys; assert sys.version_info[:2] == (3, 11), 'Python 3.11 x64 is required'; import tkinter"
if ($LASTEXITCODE -ne 0) {
    throw "Install Python 3.11 x64 with Tcl/Tk support, then retry."
}

$source = $PSScriptRoot
$wheel = Join-Path $source "guiai_lab-0.1.0-py3-none-any.whl"
$vendor = Join-Path $source "vendor"
if (-not (Test-Path $wheel) -or -not (Test-Path $vendor)) {
    throw "The package is incomplete. Extract GUIAI-Windows-Native.zip before running the installer."
}

Push-Location $source
try {
    & $Python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Unable to create the virtual environment." }
    $venvPython = Join-Path $source ".venv\Scripts\python.exe"
    & $venvPython -m pip install --no-index --find-links $vendor $wheel
    if ($LASTEXITCODE -ne 0) { throw "GUIAI installation failed." }
    & $venvPython -m guiai --help | Out-Null
    if (-not $SkipTests) {
        & $venvPython (Join-Path $source "windows_stress.py")
        if ($LASTEXITCODE -ne 0) { throw "Native Windows validation failed." }
    }
}
finally {
    Pop-Location
}

Write-Host "GUIAI is installed in $source\.venv"
Write-Host "Launch with your actual agent executable:"
Write-Host "  .venv\Scripts\Activate.ps1"
Write-Host "  guiai desktop TARGET --session SESSION --toolkit tk --agent kimi"
Write-Host "Replace kimi with claude, codex, or another installed agent executable."
