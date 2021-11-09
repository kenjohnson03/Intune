# Diagnostics script

<# 
    update this with the corresponding storage account SAS
    1) Open your container
    2) Create or click the $containerName in this example it is 'diagnostics'
    3) Click Shared access tokens
    4) Select 'Create' permissions then generate SAS token and URL
    5) Copy Blob SAS URL
#>
$sasURL = '<SAS>'
$containerName = "diagnostics"


$outRootPath = [system.io.path]::GetTempPath()
$diagnosticsFolder = New-Item -Path $outRootPath -ItemType Directory -Name "$($env:COMPUTERNAME)_Diag_$(Get-Date -Format "MMddyyyy-HHmm")"


#region Gather Registry Keys

$registryFolder = New-item -Path $diagnosticsFolder.FullName -ItemType Directory -Name "Registry Keys"
$registryKeys = @(
    "HKLM\Software\Microsoft\IntuneManagementExtension",
    "HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot",
    "HKLM\SOFTWARE\Microsoft\Windows Endpoint",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM\Software\Policies",
    "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Endpoint",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
)

foreach($key in $registryKeys)
{
    reg export $key $("{0}\{1}.reg" -f $registryFolder.FullName, $key.Replace("\","_"))
}

#endregion

#region CMD output 

$cmdFolder = New-item -Path $diagnosticsFolder.FullName -ItemType Directory -Name "CMD Output"
$commands = @{    
    "certutilMachine.txt" = { cd "$env:windir\system32"; .\certutil.exe -store };
    "certutilUser.txt" = { cd "$env:windir\system32"; .\certutil.exe -store -user my };
    "dsregcmd.txt" = { cd "$env:windir\system32"; .\Dsregcmd.exe /status };
    "ipconfig.txt" = { cd "$env:windir\system32"; .\ipconfig.exe /all };
    "mdmdiagnosticstool.txt" = { cd "$env:windir\system32"; .\mdmdiagnosticstool.exe };
    "NONEmsinfo32.txt" = { cd "$env:windir\system32"; .\msinfo32.exe /report $($cmdFolder.FullName + "\msinfo32.log") };
    "netshAdvfirewallAllprofiles.txt" = { cd "$env:windir\system32"; .\netsh.exe advfirewall show allprofiles };
    "netshAdvfirewallGlobal.txt" = { cd "$env:windir\system32"; .\netsh.exe advfirewall show global };
    "netshLanShowProfiles.txt" = { cd "$env:windir\system32"; .\netsh.exe lan show profiles };
    "netshShowProxy.txt" = { cd "$env:windir\system32";  .\netsh.exe winhttp show proxy };
    "netshWlanShowProfiles.txt" = { cd "$env:windir\system32"; .\netsh.exe wlan show profiles };
    "netshWlanWlanreport.txt" = { cd "$env:windir\system32"; .\netsh.exe wlan show wlanreport };
    "pingLocalhost.txt" = { cd "$env:windir\system32"; .\ping.exe -n 10 localhost };
    "NONEpowercfgBatteryReport.txt" = { cd "$env:windir\system32"; .\powercfg.exe /batteryreport /output $($cmdFolder.FullName + "\battery-report.html") };
    "NONEpowercfgEnergyReport.txt" = { cd "$env:windir\system32"; .\powercfg.exe /energy /output $($cmdFolder.FullName + "\energy-report.html") };
    "mpcmdrun.txt" = { cd "$($env:programfiles)\windows defender"; .\mpcmdrun.exe -GetFiles };
}

foreach($cmd in $commands.Keys)
{
    if($cmd.StartsWith("NONE"))
    {
        Invoke-Command -ScriptBlock $commands.Item($cmd) 
    }
    else
    {
        Invoke-Command -ScriptBlock $commands.Item($cmd) | Tee-Object -FilePath $("{0}\{1}" -f $cmdFolder.FullName,$cmd)
    }
}


#endregion 

#region Event Viewers

$eventFolder = New-item -Path $diagnosticsFolder.FullName -ItemType Directory -Name "Event Logs"

$logNames = @(
    "Application",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment",
    "Microsoft-Windows-AppLocker/Packaged app-Execution",
    "Microsoft-Windows-Bitlocker/Bitlocker Management",
    "Microsoft-Windows-HelloForBusiness/Operational",
    "Microsoft-Windows-SENSE/Operational",
    "Microsoft-Windows-SenseIR/Operational",
    "Setup",
    "System",
    "Microsoft-Windows-CAPI2/Operational",
    "Microsoft-Windows-PowerShell/Operational"
)

foreach ($log in $logNames)
{
    .\wevtutil.exe epl $log $("{0}\{1}.evtx" -f $eventFolder.FullName,$log.Replace("/","_"))
}

#endregion

#region Files Copied

$filesFolder = New-item -Path $diagnosticsFolder.FullName -ItemType Directory -Name "Files Copied"

$filePaths = @(
    "C:\Windows\INF\setupapi.dev.log"
)

$folderPaths = @(
    'C:\$WINDOWS.~BT\Sources\Panther',
    'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
)

foreach($file in $filePaths)
{
    Copy-Item $file $filesFolder
}

foreach($folder in $folderPaths)
{
    Copy-Item $folder $filesFolder -Recurse
}

#region 

#region Network tests

$networkFolder = New-item -Path $diagnosticsFolder.FullName -ItemType Directory -Name "Network" -Force


$hosts = @(
    # Intune endpoints from https://docs.microsoft.com/en-us/mem/intune/fundamentals/intune-us-government-endpoints
    "manage.microsoft.us:443",
    "enterpriseregistration.microsoftonline.us:443",
    "portal.azure.us:443",
    "portal.office365.us:443",
    "portal.manage.microsoft.us:443",
    "endpoint.microsoft.us:443",
    "login.microsoftonline.us:443",
    "directoryproxy.microsoftazure.us:443",
    "directory.microsoftazure.us:443",
    "graph.microsoft.us:443",
    "enterpriseregistration.microsoftonline.us:443",
    # MDE https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/gov?view=o365-worldwide
    "api-gov.securitycenter.microsoft.us:443",
    "wdatp-alertexporter-us.securitycenter.windows.us:443"
)

# DoD O365 hosts
$js = (Invoke-WebRequest "https://endpoints.office.com/endpoints/USGOVDoD?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7").Content | ConvertFrom-Json
foreach($entry in $js)
{
    foreach($url in $entry.urls)
    {
        if($url -notmatch "\*")
        {
            foreach($port in $entry.tcpPorts.Split(","))
            {
                $hosts += "${url}:${port}"
            }
        }        
    }
}

$results = @()

foreach($myhost in $hosts)
{
    $port = $myhost.Split(":")[1]
    $myhost = $myhost.Split(":")[0]
    $result = Test-NetConnection -ComputerName $myhost -Port $port -InformationLevel Detailed 
    $result | Out-File $("{0}\{1}_{2}.txt" -f $networkFolder.FullName,$myhost,$port)
    $results += $result | Select-Object @{l="URL";e={$myhost}},@{l="Port";e={$port}},remoteaddress,tcptestsucceeded
}

$results | Sort-Object tcptestsucceeded | Format-Table | Out-File -FilePath $("{0}\01-NetworkSummary.txt" -f $networkFolder.FullName)


#endregion 

#region Create zip

$zipFile = $("{0}\{1}.zip" -f $outRootPath,$diagnosticsFolder.Name)
Compress-Archive -Path $diagnosticsFolder.FullName -DestinationPath $zipFile

#endregion

#region Upload to Azure Storage
function Add-FileToBlobStorage{
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_ })]
        [string]
        $file,
        [Parameter(Mandatory=$true)]
        [string]
        $connectionstring
    )
    $URLargs = @{
        uri = $connectionstring.replace("?","/$([System.IO.Path]::GetFileName($file))?")
        method = "Put"
        InFile = $file
        headers = @{"x-ms-blob-type" = "BlockBlob"}
 
    }
    Invoke-RestMethod @URLargs
}

Add-FileToBlobStorage -file $zipFile -connectionstring $sasURL

#endregion

#region Remove files

Remove-Item -Path $diagnosticsFolder,$zipFile -Recurse

#endregion