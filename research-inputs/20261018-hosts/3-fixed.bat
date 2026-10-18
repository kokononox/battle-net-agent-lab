@echo off
setlocal
:: Blizzard Launcher Minimalist Blocker (Play Button Only)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run this script as Administrator.
    pause
    exit /b 1
)

set "HOSTS_FILE=%SystemRoot%\System32\drivers\etc\hosts"
set "TEMP_HOSTS=%TEMP%\blizzard_minimal_temp.txt"

echo [*] Backing up current HOSTS file...
copy /Y "%HOSTS_FILE%" "%HOSTS_FILE%.blizzard-backup" >nul

echo [*] Removing previous Blizzard block entries...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$src='%HOSTS_FILE%'; $dst='%TEMP_HOSTS%'; $domains=@('telemetry-in.battle.net','breaking-news.support.blizzard.com:443','rum.battle.net','www.google-analytics.com','analytics.google.com','www.googletagmanager.com','cm.g.doubleclick.net','inn-pa.googleapis.com','fcmatch.google.com','www.google.com','eu.shop.battle.net','bnetstorefront.akamaized.net','catalog.blzstatic.com','blz-contentstack-images.akamaized.net','navbar.blizzard.com','content-ui.battle.net','images.blz-contentstack.com','www.youtube.com','www.youtube-nocookie.com','fcmatch.youtube.com','i.ytimg.com'); $inside=$false; $out=foreach($line in [IO.File]::ReadAllLines($src)){ if($line.Trim() -eq '# --- BLIZZARD-BLOCK START ---'){$inside=$true; continue}; if($line.Trim() -eq '# --- BLIZZARD-BLOCK END ---'){$inside=$false; continue}; $parts=$line.Trim() -split '\s+'; if(-not $inside -and -not ($parts.Count -ge 2 -and $parts[0] -eq '0.0.0.0' -and $domains -contains $parts[1])){$line} }; [IO.File]::WriteAllLines($dst,$out,(New-Object Text.UTF8Encoding($false)))"
if errorlevel 1 (
    echo [!] Failed to prepare the HOSTS file.
    pause
    exit /b 1
)

echo [*] Adding revised block entries...
>>"%TEMP_HOSTS%" echo.
>>"%TEMP_HOSTS%" echo # --- BLIZZARD-BLOCK START ---
>>"%TEMP_HOSTS%" echo 0.0.0.0 telemetry-in.battle.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 breaking-news.support.blizzard.com:443
>>"%TEMP_HOSTS%" echo 0.0.0.0 rum.battle.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 www.google-analytics.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 analytics.google.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 www.googletagmanager.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 cm.g.doubleclick.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 inn-pa.googleapis.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 fcmatch.google.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 eu.shop.battle.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 bnetstorefront.akamaized.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 catalog.blzstatic.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 blz-contentstack-images.akamaized.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 navbar.blizzard.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 content-ui.battle.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 images.blz-contentstack.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 www.youtube.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 www.youtube-nocookie.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 fcmatch.youtube.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 i.ytimg.com
>>"%TEMP_HOSTS%" echo # --- BLIZZARD-BLOCK END ---

copy /Y "%TEMP_HOSTS%" "%HOSTS_FILE%" >nul
if errorlevel 1 (
    echo [!] Failed to update the HOSTS file.
    del /Q "%TEMP_HOSTS%" >nul 2>&1
    pause
    exit /b 1
)
del /Q "%TEMP_HOSTS%" >nul 2>&1
ipconfig /flushdns >nul

echo.
echo [OK] Blizzard block applied. www.google.com is not blocked.
pause
endlocal
