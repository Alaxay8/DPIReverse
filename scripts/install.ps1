# DPIReverse Installation Script for Windows (PowerShell)

$ErrorActionPreference = "Stop"

Write-Host "Starting DPIReverse installation..." -ForegroundColor Blue

# 1. Check for Go
if (!(Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Go is not installed. Please install Go (1.21+) to build the utility." -ForegroundColor Red
    exit 1
}

# 2. Build the binary
Write-Host "Building the binary..." -ForegroundColor Blue
go build -o dpi.exe .

# 3. Determine installation path
# We'll use a directory in the user's profile and add it to the PATH if it's not there
$InstallDir = "$HOME\AppData\Local\dpi"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

Move-Item -Path dpi.exe -Destination "$InstallDir\dpi.exe" -Force

# 4. Add to PATH for the current user if not present
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "Adding $InstallDir to User PATH..." -ForegroundColor Blue
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path += ";$InstallDir"
}

Write-Host "Success! DPIReverse is now installed as 'dpi'." -ForegroundColor Green
Write-Host "Note: You might need to restart your terminal to see the changes."
Write-Host "You can run it from any directory using: dpi scan youtube.com" -ForegroundColor Blue
