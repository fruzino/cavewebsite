$CaveDir = $PSScriptRoot
$CaveExe = Join-Path $CaveDir "cave.exe"

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "" -ForegroundColor Yellow
    Write-Host "WARNING: Not running as Administrator." -ForegroundColor Yellow
    Write-Host "Skipping File Association (requires admin rights)." -ForegroundColor Yellow
    Write-Host "Proceeding with PATH update for current user..." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Adding Cave to User PATH..." -ForegroundColor Cyan
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$CaveDir*") {
    $NewUserPath = "$UserPath;$CaveDir"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, [EnvironmentVariableTarget]::User)
    Write-Host "Success: Cave added to User PATH." -ForegroundColor Green
}
else {
    Write-Host "Note: Cave is already in your PATH." -ForegroundColor Gray
}

if ($IsAdmin) {
    Write-Host "Registering .cv and .cave file associations..." -ForegroundColor Cyan
    
    cmd /c "assoc .cv=CaveScript"
    cmd /c "ftype CaveScript=`"$CaveExe`" `"%1`" %*"
    
    cmd /c "assoc .cave=CaveScript"
    
    Write-Host "Success: Registered .cv and .cave with Cave interpreter." -ForegroundColor Green
}

Write-Host "Creating 'cave' command alias..." -ForegroundColor Cyan

$BatDir = Join-Path $CaveDir "bin\Bat"
if ($UserPath -notlike "*$BatDir*") {
    $NewUserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User) + ";$BatDir"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, [EnvironmentVariableTarget]::User)
}

Write-Host ""
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "You can now run 'cave script.cv' from any terminal."
Write-Host "Documentation is available at: $CaveDir\Doc\index.html"
Write-Host ""

if (-not $IsAdmin) {
    Write-Host "Tip: To enable double-clicking .cv files, run this installer as Administrator." -ForegroundColor Gray
}


Write-Host "Please RESTART your terminal to start using Cave." -ForegroundColor Yellow
