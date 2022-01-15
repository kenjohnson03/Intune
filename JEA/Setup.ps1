Remove-Item $env:ProgramFiles\WindowsPowerShell\Modules\JEA\ -Recurse -Force
$d = md $env:ProgramFiles\WindowsPowerShell\Modules\JEA\RoleCapabilities
Copy-Item .\User_Actions.psrc $d -Force
Copy-Item .\User_Actions_Session.pssc "$env:ProgramFiles\WindowsPowerShell\Modules\JEA" -Force
UnRegister-PSSessionConfiguration -Name User_Actions -ErrorAction SilentlyContinue
Register-PSSessionConfiguration -Name User_Actions -Path 'C:\Program Files\WindowsPowerShell\Modules\JEA\User_Actions_Session.pssc'
Restart-Service WinRM
# invoke-command -ComputerName localhost -ConfigurationName 'User_Actions' -EnableNetworkAccess -ScriptBlock { Repair-Drivers }
# Enter-PSSession -ComputerName localhost -ConfigurationName 'User_Actions'  -EnableNetworkAccess