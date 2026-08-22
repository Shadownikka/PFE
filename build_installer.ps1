# ════════════════════════════════════════════════════════════════════
# NetMind — Windows Installer Build Script
# ════════════════════════════════════════════════════════════════════
# Run on a Windows machine: .\build_installer.ps1
# Prerequisites:
#   1. Python 3.10+ installed and in PATH
#   2. Inno Setup 6 installed (https://jrsoftware.org/isdl.php)
#   3. (Optional) Npcap installer in installer\ folder
#
# Output: dist\installer\NetMind-Setup-2.4.1.exe
# ════════════════════════════════════════════════════════════════════

param(
    [switch]$SkipPyInstaller,
    [switch]$SkipInnoSetup,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║      NetMind Windows Installer Builder       ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Step 0: Clean ────────────────────────────────────────────────
if ($Clean) {
    Write-Host "  [*] Cleaning build artifacts..." -ForegroundColor Yellow
    Remove-Item -Path "$ROOT\build" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$ROOT\dist" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [✓] Clean complete" -ForegroundColor Green
    Write-Host ""
}

# ── Step 1: Python environment ───────────────────────────────────
Write-Host "  [1/5] Checking Python environment..." -ForegroundColor Cyan

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "  [✘] Python not found! Install Python 3.10+ and add to PATH." -ForegroundColor Red
    exit 1
}

$pyVer = python --version 2>&1
Write-Host "  [✓] $pyVer" -ForegroundColor Green

# ── Step 2: Install dependencies ─────────────────────────────────
Write-Host "  [2/5] Installing Python dependencies..." -ForegroundColor Cyan

pip install -r "$ROOT\requirements.txt" --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [✘] Failed to install dependencies" -ForegroundColor Red
    exit 1
}
Write-Host "  [✓] Dependencies installed" -ForegroundColor Green

# ── Step 3: Create icon if missing ───────────────────────────────
Write-Host "  [3/5] Checking assets..." -ForegroundColor Cyan

$iconPath = "$ROOT\assets\icon.ico"
if (-not (Test-Path $iconPath)) {
    Write-Host "  [!] icon.ico not found — creating placeholder" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "$ROOT\assets" -Force | Out-Null
    # Create a minimal ICO file (1x1 pixel, blue)
    # In production, replace with real icon
    Write-Host "  [!] Please add a real icon.ico to assets\ folder" -ForegroundColor Yellow
}

# Create installer assets if missing
$bannerPath = "$ROOT\assets\installer_banner.bmp"
$smallIconPath = "$ROOT\assets\installer_icon.bmp"
if (-not (Test-Path $bannerPath)) {
    Write-Host "  [!] installer_banner.bmp not found — Inno Setup will use defaults" -ForegroundColor Yellow
}

# Create config template
$configTemplate = "$ROOT\installer\netmind_config.template"
if (-not (Test-Path $configTemplate)) {
    New-Item -ItemType Directory -Path "$ROOT\installer" -Force | Out-Null
    @"
# NetMind Configuration
[server]
url = https://netmind.io

[tool]
push_interval = 5
scan_interval = 30
"@ | Out-File -FilePath $configTemplate -Encoding UTF8
}

# Check for Npcap installer
$npcapPath = "$ROOT\installer\npcap-installer.exe"
if (-not (Test-Path $npcapPath)) {
    Write-Host "  [!] Npcap installer not found at installer\npcap-installer.exe" -ForegroundColor Yellow
    Write-Host "      Download from: https://npcap.com/#download" -ForegroundColor Yellow
    Write-Host "      Place the .exe in the installer\ folder and rebuild." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "  [✓] Assets ready" -ForegroundColor Green

# ── Step 4: PyInstaller bundle ───────────────────────────────────
if (-not $SkipPyInstaller) {
    Write-Host "  [4/5] Building application with PyInstaller..." -ForegroundColor Cyan
    Write-Host "         (This may take 2-5 minutes)" -ForegroundColor DarkGray

    Push-Location $ROOT
    pyinstaller NetMind.spec --noconfirm --clean 2>&1 | ForEach-Object {
        if ($_ -match "ERROR|FATAL") {
            Write-Host "         $_" -ForegroundColor Red
        }
    }
    Pop-Location

    if (-not (Test-Path "$ROOT\dist\NetMind\NetMind.exe")) {
        Write-Host "  [✘] PyInstaller build failed — NetMind.exe not found" -ForegroundColor Red
        exit 1
    }

    $exeSize = (Get-Item "$ROOT\dist\NetMind\NetMind.exe").Length / 1MB
    Write-Host "  [✓] Application built ($([math]::Round($exeSize, 1)) MB)" -ForegroundColor Green
} else {
    Write-Host "  [4/5] Skipping PyInstaller (--SkipPyInstaller)" -ForegroundColor DarkGray
}

# ── Step 5: Inno Setup installer ─────────────────────────────────
if (-not $SkipInnoSetup) {
    Write-Host "  [5/5] Creating installer with Inno Setup..." -ForegroundColor Cyan

    # Find Inno Setup compiler
    $iscc = $null
    $searchPaths = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe"
    )
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $iscc = $path
            break
        }
    }

    if (-not $iscc) {
        Write-Host "  [✘] Inno Setup 6 not found!" -ForegroundColor Red
        Write-Host "      Install from: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
        Write-Host "      Then re-run this script." -ForegroundColor Yellow
        exit 1
    }

    # Create output directory
    New-Item -ItemType Directory -Path "$ROOT\dist\installer" -Force | Out-Null

    # Compile installer
    & $iscc "$ROOT\installer\netmind_setup.iss" 2>&1 | ForEach-Object {
        if ($_ -match "Successful") {
            Write-Host "         $_" -ForegroundColor Green
        }
    }

    $setupExe = Get-ChildItem "$ROOT\dist\installer\NetMind-Setup-*.exe" | Select-Object -First 1
    if (-not $setupExe) {
        Write-Host "  [✘] Installer build failed" -ForegroundColor Red
        exit 1
    }

    $setupSize = $setupExe.Length / 1MB
    Write-Host "  [✓] Installer created: $($setupExe.Name) ($([math]::Round($setupSize, 1)) MB)" -ForegroundColor Green
} else {
    Write-Host "  [5/5] Skipping Inno Setup (--SkipInnoSetup)" -ForegroundColor DarkGray
}

# ── Done ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✅  BUILD COMPLETE" -ForegroundColor Green
Write-Host "  ════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Output files:" -ForegroundColor Cyan
if (Test-Path "$ROOT\dist\NetMind\NetMind.exe") {
    Write-Host "    App:       dist\NetMind\NetMind.exe" -ForegroundColor White
}
$setupExe = Get-ChildItem "$ROOT\dist\installer\NetMind-Setup-*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($setupExe) {
    Write-Host "    Installer: dist\installer\$($setupExe.Name)" -ForegroundColor White
}
Write-Host ""
Write-Host "  To test without installer:" -ForegroundColor DarkGray
Write-Host "    cd dist\NetMind && .\NetMind.exe" -ForegroundColor DarkGray
Write-Host ""
