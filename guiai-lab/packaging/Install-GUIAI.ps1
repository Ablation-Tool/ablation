[CmdletBinding()]
param(
    [string]$Distro = "Ubuntu"
)

$ErrorActionPreference = "Stop"
$installed = @(& wsl.exe -l -q)

if (-not ($installed -contains $Distro)) {
    Write-Host "Installing $Distro through WSL. Windows may require a restart."
    & wsl.exe --install -d $Distro
    if ($LASTEXITCODE -ne 0) {
        throw "WSL installation failed. Enable WSL and retry."
    }
    Write-Host "Restart Windows if requested, complete the Ubuntu first-run setup, then run this installer again."
    exit 0
}

$wslSource = (& wsl.exe -d $Distro -- wslpath -a "$PSScriptRoot").Trim()
if (-not $wslSource) {
    throw "Could not locate the package inside WSL."
}

$bashScript = @'
set -e
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip python3-gi python3-cairo python3-gi-cairo gir1.2-gtk-3.0 gir1.2-vte-2.91
if [ ! -d "$HOME/ablation/.git" ]; then
    git clone https://github.com/Ablation-Tool/ablation.git "$HOME/ablation"
fi
cd "$HOME/ablation"
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install --no-index --find-links "$GUIAI_SOURCE/vendor" "$GUIAI_SOURCE/guiai_lab-0.1.0-py3-none-any.whl"
guiai --help >/dev/null
python -m metrix --help >/dev/null
'@

& wsl.exe -d $Distro -- env "GUIAI_SOURCE=$wslSource" bash -lc $bashScript
if ($LASTEXITCODE -ne 0) {
    throw "GUIAI installation inside $Distro failed."
}

Write-Host "GUIAI is installed in $Distro. WSLg or another X server is required for the GUI."
Write-Host "Open $Distro, activate the environment, and launch with your target and agent:"
Write-Host "  cd `$HOME/ablation"
Write-Host "  . .venv/bin/activate"
Write-Host "  guiai desktop /path/to/target --session /path/to/session --agent kimi"
Write-Host "Replace kimi with claude, codex, or another installed agent executable."
