@echo off
setlocal
:: Blizzard Launcher Minimalist Blocker - plain hosts BAT

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run this script as Administrator.
    pause
    exit /b 1
)

set "HOSTS_FILE=%SystemRoot%\System32\drivers\etc\hosts"
set "RUN_ID="
for /f %%I in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString()"') do set "RUN_ID=%%I"
if not defined RUN_ID (
    echo [!] Could not create a unique backup name. Nothing changed.
    pause
    exit /b 1
)
set "TEMP_HOSTS=%TEMP%\blizzard_minimal_%RUN_ID%.txt"
set "BACKUP_FILE=%HOSTS_FILE%.blizzard-backup-%RUN_ID%"
if exist "%BACKUP_FILE%" (
    echo [!] Backup already exists. Nothing changed.
    pause
    exit /b 1
)

echo [*] Backing up current HOSTS file...
copy /Y "%HOSTS_FILE%" "%BACKUP_FILE%" >nul
if errorlevel 1 (
    echo [!] Backup failed. Nothing changed.
    pause
    exit /b 1
)
echo [Backup] %BACKUP_FILE%

echo [*] Removing previous entries for the known Blizzard test list...
powershell -NoProfile -Command ^
"$ErrorActionPreference='Stop'; $src=$env:HOSTS_FILE; $dst=$env:TEMP_HOSTS; $domains=@('telemetry-in.battle.net','breaking-news.support.blizzard.com','rum.battle.net','www.google-analytics.com','analytics.google.com','www.googletagmanager.com','cm.g.doubleclick.net','inn-pa.googleapis.com','fcmatch.google.com','eu.shop.battle.net','bnetstorefront.akamaized.net','catalog.blzstatic.com','blz-contentstack-images.akamaized.net','navbar.blizzard.com','content-ui.battle.net','images.blz-contentstack.com','www.youtube.com','www.youtube-nocookie.com','fcmatch.youtube.com','i.ytimg.com','oauth.battle.net','distribution.version.battle.net','us.version.battle.net','level3.ssl.blizzard.com','level3.blizzard.com','breaking-news.support.blizzard.com:443'); $inside=$false; $out=@(foreach($line in [IO.File]::ReadAllLines($src)){ if($line.Trim() -eq '# --- BLIZZARD-BLOCK START ---'){ if($inside){throw 'Nested Blizzard block marker'}; $inside=$true; continue }; if($line.Trim() -eq '# --- BLIZZARD-BLOCK END ---'){ if(-not $inside){throw 'Unmatched Blizzard block marker'}; $inside=$false; continue }; $parts=$line.Trim() -split '\s+'; if(-not $inside -and -not ($parts.Count -ge 2 -and $parts[0] -eq '0.0.0.0' -and $domains -contains $parts[1])){ $line } }); if($inside){throw 'Unclosed Blizzard block marker'}; [IO.File]::WriteAllLines($dst,[string[]]$out,(New-Object Text.UTF8Encoding($false)))"

if errorlevel 1 (
    echo [!] Failed to prepare HOSTS. Original HOSTS was not written.
    del /Q "%TEMP_HOSTS%" >nul 2>&1
    pause
    exit /b 1
)

echo [Profile] 02-All-Except-OAuth.bat
echo [Info] Not blocked WITHIN THE KNOWN LIST: oauth.battle.net
echo [*] Adding block entries...
>>"%TEMP_HOSTS%" echo.
>>"%TEMP_HOSTS%" echo # --- BLIZZARD-BLOCK START ---
>>"%TEMP_HOSTS%" echo 0.0.0.0 telemetry-in.battle.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 breaking-news.support.blizzard.com
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
>>"%TEMP_HOSTS%" echo 0.0.0.0 distribution.version.battle.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 us.version.battle.net
>>"%TEMP_HOSTS%" echo 0.0.0.0 level3.ssl.blizzard.com
>>"%TEMP_HOSTS%" echo 0.0.0.0 level3.blizzard.com
>>"%TEMP_HOSTS%" echo # --- BLIZZARD-BLOCK END ---

:: Do not overwrite changes made by another program while preparing this file.
fc /b "%HOSTS_FILE%" "%BACKUP_FILE%" >nul 2>&1
if errorlevel 1 (
    echo [!] HOSTS changed or could not be checked. No update was written.
    del /Q "%TEMP_HOSTS%" >nul 2>&1
    pause
    exit /b 1
)

copy /Y "%TEMP_HOSTS%" "%HOSTS_FILE%" >nul
if errorlevel 1 (
    echo [!] Failed to update HOSTS. Keep the backup shown above.
    del /Q "%TEMP_HOSTS%" >nul 2>&1
    pause
    exit /b 1
)
del /Q "%TEMP_HOSTS%" >nul 2>&1
ipconfig /flushdns >nul
if errorlevel 1 (
    echo [!] HOSTS was written, but DNS cache flush failed.
) else (
    echo [OK] HOSTS profile applied and DNS cache flushed.
)
echo [NOTE] This changes HOSTS only. It is NOT an Internet allowlist.
echo [NOTE] Rules stay applied after this BAT exits.
echo.
pause
endlocal
