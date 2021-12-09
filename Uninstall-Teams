
Write-Host "Stopping Teams Process" -ForegroundColor Yellow
try{
    Get-Process -ProcessName Teams | Stop-Process -Force
    Start-Sleep -Seconds 3
}catch{
    echo $_
}

try{
    Get-ChildItem -Path $env:APPDATA\"Microsoft\teams\application cache\cache" | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:APPDATA\"Microsoft\teams\blob_storage" | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:APPDATA\"Microsoft\teams\databases" | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:APPDATA\"Microsoft\teams\cache" | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:APPDATA\"Microsoft\teams\gpucache" | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:APPDATA\"Microsoft\teams\Indexeddb" | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:APPDATA\"Microsoft\teams\Local Storage" | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:APPDATA\"Microsoft\teams\tmp" | Remove-Item -Confirm:$false
    Write-Host "Teams Disk Cache Cleaned" -ForegroundColor Green
}catch{
    echo $_
}
try{
    Get-Process -ProcessName Chrome| Stop-Process -Force
    Start-Sleep -Seconds 3
}catch{
    echo $_
}
    
try{
    Get-ChildItem -Path $env:LOCALAPPDATA"\Google\Chrome\User Data\Default\Cache" | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:LOCALAPPDATA"\Google\Chrome\User Data\Default\Cookies" -File | Remove-Item -Confirm:$false
    Get-ChildItem -Path $env:LOCALAPPDATA"\Google\Chrome\User Data\Default\Web Data" -File | Remove-Item -Confirm:$false
}catch{
    echo $_
}
        
try{
    Get-Process -ProcessName MicrosoftEdge | Stop-Process -Force
    Get-Process -ProcessName IExplore | Stop-Process -Force
}catch{
    echo $_
}


$MachineWide = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Teams Machine-Wide Installer"}
$MachineWide.Uninstall()
function unInstallTeams($path) {
        $clientInstaller = "$($path)\Update.exe"
  
        try {
            $process = Start-Process -FilePath "$clientInstaller" -ArgumentList "--uninstall /s" -PassThru -Wait -ErrorAction STOP
            if ($process.ExitCode -ne 0)
            {
                Write-Error "UnInstallation failed with exit code  $($process.ExitCode)."
            }
        }
        catch {
            Write-Error $_.Exception.Message
        }
}
#Locate installation folder
$localAppData = "$($env:LOCALAPPDATA)\Microsoft\Teams"
$programData = "$($env:ProgramData)\$($env:USERNAME)\Microsoft\Teams"
If (Test-Path "$($localAppData)\Current\Teams.exe") 
{
    unInstallTeams($localAppData)
    
}
elseif (Test-Path "$($programData)\Current\Teams.exe") {
    unInstallTeams($programData)
}
else {
    Write-Warning  "Teams installation not found"
}
