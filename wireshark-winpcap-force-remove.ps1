$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($key in $uninstallKeys) {
    Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
        $app = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue

        if ($app.DisplayName -like "*Wireshark*") {
            Write-Host "Found: $($app.DisplayName)" -ForegroundColor Yellow
            Write-Host "Uninstalling silently..." -ForegroundColor Yellow
            $uninstallPath = $app.UninstallString -replace '"', ''
            Start-Process -FilePath $uninstallPath -ArgumentList "/S" -Wait -NoNewWindow
            Write-Host "$($app.DisplayName) uninstalled successfully." -ForegroundColor Green
        }

        if ($app.DisplayName -like "*WinPcap*") {
            Write-Host "Found: $($app.DisplayName)" -ForegroundColor Yellow
            Write-Host "Uninstalling WinPcap silently using msiexec workaround..." -ForegroundColor Yellow
            
            # Get the uninstall string and extract the GUID if present
            $uninstallString = $app.UninstallString
            $guid = $app.PSChildName

            if ($guid -match "^\{.*\}$") {
                # Use msiexec for GUID-based uninstall — fully silent
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $guid /qn /norestart" -Wait
            } else {
                # Fallback: strip quotes, run with /S and auto-click Uninstall button
                $uninstallPath = $uninstallString -replace '"', ''
                $proc = Start-Process -FilePath $uninstallPath -ArgumentList "/S" -PassThru
                
                # Wait for the popup and auto-click the Uninstall button
                Start-Sleep -Seconds 2
                $wshell = New-Object -ComObject wscript.shell
                $wshell.AppActivate($proc.Id) | Out-Null
                Start-Sleep -Milliseconds 500
                $wshell.SendKeys("{ENTER}")
                $proc.WaitForExit()
            }
            Write-Host "$($app.DisplayName) uninstalled successfully." -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "Verifying uninstall..." -ForegroundColor Cyan
$remaining = foreach ($key in $uninstallKeys) {
    Get-ChildItem $key -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue } |
    Where-Object { $_.DisplayName -like "*Wireshark*" -or $_.DisplayName -like "*WinPcap*" }
}

if ($remaining) {
    Write-Host "WARNING: The following were not fully uninstalled:" -ForegroundColor Red
    $remaining | ForEach-Object { Write-Host $_.DisplayName -ForegroundColor Red }
} else {
    Write-Host "Wireshark and WinPcap are fully uninstalled." -ForegroundColor Green
}
