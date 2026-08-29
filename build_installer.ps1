param(
    [switch]$SkipPyInstaller,
    [switch]$SkipInnoSetup,
    [switch]$Clean
)

# NOTE: Run this script from a NORMAL (non-admin) PowerShell terminal.
# PyInstaller does NOT need admin rights to build.
# Run NetMind.exe as admin only when using it (for network features).

$ErrorActionPreference = "Continue"
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  NetMind Windows Installer Builder" -ForegroundColor Cyan
Write-Host "  ===================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Clean
if ($Clean) {
    Write-Host "  Cleaning build artifacts..." -ForegroundColor Yellow
    if (Test-Path "$ROOT\build") { Remove-Item -Path "$ROOT\build" -Recurse -Force }
    if (Test-Path "$ROOT\dist")  { Remove-Item -Path "$ROOT\dist"  -Recurse -Force }
    Write-Host "  Clean complete" -ForegroundColor Green
    Write-Host ""
}

# Step 1: Check Python
Write-Host "  Step 1 - Checking Python..." -ForegroundColor Cyan
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "  ERROR: Python not found. Install Python 3.10+ and add to PATH." -ForegroundColor Red
    exit 1
}
$pyVer = python --version 2>&1
Write-Host "  OK: $pyVer" -ForegroundColor Green

# Step 2: Install dependencies
Write-Host "  Step 2 - Installing Python dependencies..." -ForegroundColor Cyan
pip install -r "$ROOT\requirements.txt" --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Failed to install dependencies" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: Dependencies installed" -ForegroundColor Green

# Step 3: Prepare assets
Write-Host "  Step 3 - Checking assets..." -ForegroundColor Cyan

$assetsDir = "$ROOT\assets"
if (-not (Test-Path $assetsDir)) {
    New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null
}

$installerDir = "$ROOT\installer"
if (-not (Test-Path $installerDir)) {
    New-Item -ItemType Directory -Path $installerDir -Force | Out-Null
}

$configTemplate = "$ROOT\installer\netmind_config.template"
if (-not (Test-Path $configTemplate)) {
    $configContent = "# NetMind Configuration`r`n[server]`r`nurl = https://netmind.io`r`n[tool]`r`npush_interval = 5`r`nscan_interval = 30`r`n"
    Set-Content -Path $configTemplate -Value $configContent -Encoding UTF8
}

$npcapPath = "$ROOT\installer\npcap-installer.exe"
if (-not (Test-Path $npcapPath)) {
    Write-Host "  WARNING: Npcap installer not found at installer\npcap-installer.exe" -ForegroundColor Yellow
    Write-Host "  Download from: https://npcap.com/#download and place in installer\" -ForegroundColor Yellow
}

Write-Host "  OK: Assets ready" -ForegroundColor Green

# Step 4: PyInstaller
if (-not $SkipPyInstaller) {
    Write-Host "  Step 4 - Building with PyInstaller (may take 5 min)..." -ForegroundColor Cyan

    Push-Location $ROOT
    # Run PyInstaller — ignore deprecation warnings by capturing all output
    $buildOutput = pyinstaller NetMind.spec --noconfirm --clean 2>&1
    foreach ($line in $buildOutput) {
        if ($line -match "ERROR|FATAL") {
            Write-Host "    $line" -ForegroundColor Red
        }
    }
    Pop-Location

    $exePath = "$ROOT\dist\NetMind\NetMind.exe"
    if (-not (Test-Path $exePath)) {
        Write-Host "  ERROR: PyInstaller failed - NetMind.exe not found" -ForegroundColor Red
        exit 1
    }

    $exeBytes = (Get-Item $exePath).Length
    $exeMB = [math]::Round($exeBytes / 1MB, 1)
    Write-Host "  OK: Application built ($exeMB MB)" -ForegroundColor Green
} else {
    Write-Host "  Step 4 - Skipping PyInstaller" -ForegroundColor DarkGray
}

# Step 5: Inno Setup
if (-not $SkipInnoSetup) {
    Write-Host "  Step 5 - Creating installer with Inno Setup..." -ForegroundColor Cyan

    # Find ISCC.exe using multiple strategies
    function Find-ISCC {
        # Strategy 1: Registry wildcard search (handles any Inno Setup version key)
        $regBases = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        foreach ($base in $regBases) {
            if (-not (Test-Path $base)) { continue }
            Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -match "Inno Setup" -and $props.InstallLocation) {
                    $candidate = Join-Path $props.InstallLocation "ISCC.exe"
                    if (Test-Path $candidate) { return $candidate }
                }
            }
        }

        # Strategy 2: Direct filesystem search (Program Files + AppData per-user install)
        $searchRoots = @(
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)},
            "C:\Program Files",
            "C:\Program Files (x86)",
            "$env:LOCALAPPDATA\Programs",
            "$env:APPDATA\Programs"
        )
        foreach ($root in $searchRoots) {
            if (-not $root -or -not (Test-Path $root)) { continue }
            $found = Get-ChildItem -Path $root -Filter "ISCC.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { return $found.FullName }
        }

        return $null
    }

    $iscc = Find-ISCC

    if (-not $iscc) {
        Write-Host "  Inno Setup not found - looking for installer..." -ForegroundColor Yellow

        $innoDownload = "$env:TEMP\innosetup-installer.exe"

        # Check if user placed it in the installer\ folder
        $bundled = $null
        $candidates = @(
            "$ROOT\installer\innosetup.exe",
            "$ROOT\installer\innosetup",
            "$ROOT\installer\is.exe"
        )
        foreach ($c in $candidates) {
            if (Test-Path $c) { $bundled = $c; break }
        }

        if ($bundled) {
            Write-Host "  Found bundled installer: $bundled" -ForegroundColor Cyan
            Write-Host "  Installing Inno Setup silently..." -ForegroundColor Cyan
            Start-Process -FilePath $bundled -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait
        } else {
            Write-Host "  Finding latest Inno Setup version..." -ForegroundColor Cyan
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            try {
                $dlPage  = Invoke-WebRequest -Uri "https://jrsoftware.org/isdl.php" -UseBasicParsing
                $innoUrl = ($dlPage.Links | Where-Object {
                    $_.href -match "innosetup-6.*\.exe" -and $_.href -match "files\.jrsoftware\.org"
                } | Select-Object -First 1).href
            } catch { $innoUrl = $null }

            if (-not $innoUrl) {
                # Fallback: try known stable URLs in order
                $urlCandidates = @(
                    "https://files.jrsoftware.org/is/6/innosetup-6.4.3.exe",
                    "https://files.jrsoftware.org/is/6/innosetup-6.4.2.exe",
                    "https://files.jrsoftware.org/is/6/innosetup-6.4.1.exe",
                    "https://files.jrsoftware.org/is/6/innosetup-6.4.0.exe",
                    "https://files.jrsoftware.org/is/6/innosetup-6.3.3.exe"
                )
                foreach ($url in $urlCandidates) {
                    try {
                        $resp = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -ErrorAction Stop
                        if ($resp.StatusCode -eq 200) { $innoUrl = $url; break }
                    } catch {}
                }
            }

            if (-not $innoUrl) {
                Write-Host "  ERROR: Could not find Inno Setup download URL." -ForegroundColor Red
                Write-Host "  Place innosetup.exe in the installer\ folder and re-run." -ForegroundColor Yellow
                exit 1
            }

            Write-Host "  Downloading: $innoUrl" -ForegroundColor Cyan
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $innoUrl -OutFile $innoDownload -UseBasicParsing
            } catch {
                Write-Host "  ERROR: Download failed: $_" -ForegroundColor Red
                Write-Host "  Place innosetup.exe in the installer\ folder and re-run with -SkipPyInstaller" -ForegroundColor Yellow
                exit 1
            }

            Write-Host "  Installing Inno Setup silently..." -ForegroundColor Cyan
            Start-Process -FilePath $innoDownload -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait
            Remove-Item $innoDownload -Force -ErrorAction SilentlyContinue
        }

        # Re-check via registry after install
        $iscc = Find-ISCC

        if (-not $iscc) {
            Write-Host "  ERROR: ISCC.exe not found after install - restart PowerShell and retry." -ForegroundColor Red
            exit 1
        }

        Write-Host "  OK: Inno Setup installed automatically" -ForegroundColor Green
    }

    $outDir = "$ROOT\dist\installer"
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    & $iscc "$ROOT\installer\netmind_setup.iss"

    $setupExe = Get-ChildItem "$ROOT\dist\installer\NetMind-Setup-*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $setupExe) {
        Write-Host "  ERROR: Installer not created - Inno Setup may have failed" -ForegroundColor Red
        exit 1
    }

    $setupBytes = $setupExe.Length
    $setupMB = [math]::Round($setupBytes / 1MB, 1)
    $setupName = $setupExe.Name
    Write-Host "  OK: Installer created: $setupName ($setupMB MB)" -ForegroundColor Green
} else {
    Write-Host "  Step 5 - Skipping Inno Setup" -ForegroundColor DarkGray
}

# Done
Write-Host ""
Write-Host "  BUILD COMPLETE" -ForegroundColor Green
Write-Host "  ==============" -ForegroundColor Green
Write-Host ""

$appExe = "$ROOT\dist\NetMind\NetMind.exe"
if (Test-Path $appExe) {
    Write-Host "  App:       dist\NetMind\NetMind.exe" -ForegroundColor White
}

$setupExe = Get-ChildItem "$ROOT\dist\installer\NetMind-Setup-*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($setupExe) {
    Write-Host "  Installer: dist\installer\$($setupExe.Name)" -ForegroundColor White
}

Write-Host ""
Write-Host "  To run without installer: cd dist\NetMind && .\NetMind.exe" -ForegroundColor DarkGray
Write-Host ""
