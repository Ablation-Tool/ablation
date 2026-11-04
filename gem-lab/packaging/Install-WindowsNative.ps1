[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$SkipTests,
    [switch]$NoDesktopShortcut
)

$ErrorActionPreference = "Stop"
& $Python -c "import sys; assert sys.version_info[:2] == (3, 11), 'Python 3.11 x64 is required'; import tkinter"
if ($LASTEXITCODE -ne 0) {
    throw "Install Python 3.11 x64 with Tcl/Tk support, then retry."
}

$source = $PSScriptRoot
$wheel = Join-Path $source "gem_lab-0.1.0-py3-none-any.whl"
$vendor = Join-Path $source "vendor"
$icon = Join-Path $source "gem-woven-diamond.ico"
if (-not (Test-Path $wheel) -or -not (Test-Path $vendor) -or -not (Test-Path $icon)) {
    throw "The package is incomplete. Extract GEM-Windows-Native.zip before running the installer."
}

Push-Location $source
try {
    & $Python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Unable to create the virtual environment." }
    $venvPython = Join-Path $source ".venv\Scripts\python.exe"
    $venvPythonw = Join-Path $source ".venv\Scripts\pythonw.exe"
    & $venvPython -m pip install --no-index --find-links $vendor $wheel
    if ($LASTEXITCODE -ne 0) { throw "GEM installation failed." }
    & $venvPython -m gem --help | Out-Null
    if (-not (Test-Path $venvPythonw)) { throw "The virtual environment has no pythonw.exe launcher." }
    if (-not $SkipTests) {
        & $venvPython (Join-Path $source "windows_stress.py")
        if ($LASTEXITCODE -ne 0) { throw "Native Windows validation failed." }
    }

    if (-not $NoDesktopShortcut -and $env:NO_DESKTOP_SHORTCUT -ne "1") {
        $shortcutRoot = $source
        if (-not [string]::IsNullOrWhiteSpace($env:GEM_INSTALL_DESTINATION)) {
            $shortcutRoot = $env:GEM_INSTALL_DESTINATION
        }
        $shortcutPythonw = Join-Path $shortcutRoot ".venv\Scripts\pythonw.exe"
        $shortcutIcon = Join-Path $shortcutRoot "gem-woven-diamond.ico"
        $desktop = [Environment]::GetFolderPath("Desktop")
        if ([string]::IsNullOrWhiteSpace($desktop)) { throw "Windows did not report a Desktop directory." }
        if (-not (Test-Path $desktop -PathType Container)) {
            New-Item -ItemType Directory -Path $desktop -Force | Out-Null
        }
        $shortcutPath = Join-Path $desktop "GEM.lnk"
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $shortcutPythonw
        $shortcut.Arguments = "-m gem launch --toolkit tk"
        $shortcut.WorkingDirectory = $shortcutRoot
        $shortcut.IconLocation = "$shortcutIcon,0"
        $shortcut.Description = "GEM agent-guided reverse-engineering workbench"
        $shortcut.Save()

        $installedShortcut = $shell.CreateShortcut($shortcutPath)
        if ($installedShortcut.TargetPath -ne $shortcutPythonw -or
            $installedShortcut.WorkingDirectory -ne $shortcutRoot -or
            $installedShortcut.Arguments -ne "-m gem launch --toolkit tk" -or
            $installedShortcut.IconLocation -ne "$shortcutIcon,0") {
            throw "The GEM Desktop shortcut failed validation."
        }
        Write-Host "Desktop shortcut: $shortcutPath"
    }
}
finally {
    Pop-Location
}

Write-Host "GEM is installed in $source\.venv"
Write-Host "Open GEM from the Desktop shortcut, or launch with your actual agent executable:"
Write-Host "  .venv\Scripts\Activate.ps1"
Write-Host "  gem lab TARGET --session SESSION --toolkit tk --agent kimi"
Write-Host "Replace kimi with claude, codex, or another installed agent executable."
