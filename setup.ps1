# vim: tabstop=4 shiftwidth=4 expandtab
# Copyright (C) 2024 shell32 <hi@shell32.net>. All Rights Reserved.
# See LICENSE file for more information on copyright and license.

# Param
param (
    [string]$profile = $null
)

# Variables
$SCOOP_DIR = "$env:USERPROFILE\scoop"
$SCOOP_MAIN_BUCKET_DIR = "$SCOOP_DIR\buckets\main"
$SCOOP_COMMONS_BUCKET_DIR = "$SCOOP_DIR\buckets\commons"
$SCOOP_COMMONS_BUCKET_URL = "https://github.com/hexBF00/bucket-commons/archive/main.zip"
$SCOOP_VM_BUCKET_URL = "https://gtihub.com/hexBF00/bucket-vm/archive/main.zip"
$SCOOP_WORKSTATION_BUCKET_URL = "https://github.com/hexBF00/bucket-workstation/archive/main.zip"

# Functions
function Log-Log {
    param (
        [Parameter(Mandatory = $True, Position = 0)]
        [String]$String,
        [Parameter(Mandatory = $False, Position = 1)]
        [System.ConsoleColor]$ForegroundColor = $host.UI.RawUI.ForegroundColor   
    )

    $old = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    Write-Output "$String"
    $host.UI.RawUI.ForegroundColor = $old
}

function Log-Info {
    param (
        [String]$message
    )

    Log-Log -String "[*] $message"
}

function Log-Task {
    param (
        [String]$message
    )

    Log-Log -String "[+] $message" -ForegroundColor Cyan
}

function Log-Warn {
    param (
        [String]$message
    )

    Log-Log -String "[!] $message" -ForegroundColor Yellow
}

function Log-Error {
    param (
        [String]$message,
        [Int]$errorCode = 1
    )

    Log-Log -String "[!] $message" -ForegroundColor DarkRed
    exit $errorCode
}

function Test-CommandAvaliable {
    param (
        [Parameter(Mandatory = $True, Position = 0)]
	    [String]$command
    )

    return [Boolean](Get-Command $command -ErrorAction SilentlyContinue)
}

function Test-IsFileLocked {
    param(
        [String] $path
    )

    $file = New-Object System.IO.FileInfo $path

    if (!(Test-Path $path)) {
        return $false
    }

    try {
        $stream = $file.Open(
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
        if ($stream) {
            $stream.Close()
        }
        return $false
    } catch {
        return $true
    }
}

function Expand-ZipArchive {
    param(
        [String] $path,
        [String] $to
    )

    if (!(Test-Path $path)) {
        Log-Error "Unzip failed: can't unzip because a process is locking the file"
    }

    $retries = 0
    while ($retries -le 10) {
        if ($retries -eq 10) {
            Log-Error "Unzip failed: can't unzip because a process is locking the file"
        }
        if (Test-IsFileLocked $path) {
            Log-Info "Unzip: waiting for $path to be unlocked by another process... ($retries/10)"
            $retries++
            Start-Sleep -Seconds 2
        } else {
            break
        }
    }

    $oldVerbosePreference = $VerbosePreference
    $global:VerbosePreference = 'SilentlyContinue'

    $oldProgressPreference = $ProgressPreference
    $global:ProgressPreference = 'SilentlyContinue'

    Microsoft.PowerShell.Archive\Expand-Archive -Path $path -DestinationPath $to -Force
    $global:VerbosePreference = $oldVerbosePreference
    $global:ProgressPreference = $oldProgressPreference
}

function Check-64Bit {
    Log-Task "Checking if you are using 64 bit powershell..."
    if (!([Environment]::Is64BitProcess)) {
        Log-Error "It seems like you are using 32 bit powershell. Please use 64 bit instead"
    }
}

function Check-PwshVersion {
    Log-Task "Checking if PowerShell version is compatible..."
    if ($PSVersionTable.PSVersion -lt [System.Version]"5.0.0") {
        Log-Error "It seems like you are using old powershell version. Please update to newer version"
    }
}

function Check-RunAsAdmin {
    Log-Task "Checking if script is running as administrator..."
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Log-Error "Please run this script as administrator"
    }
}

function Check-ExecPolicy {
    Log-Task "Checking if execution policy is unrestricted..."
    if ((Get-ExecutionPolicy).ToString() -ne "Unrestricted") {
        Log-Error "Please update execution policy to unrestricted"
    }
}

function Check-OS {
    Log-Task "Checking if Operation System is compatible..."
    if ((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") {
        Log-Error "Windows 7 or below is not supported"
    }
}

function Check-VM {
    Log-Task "Checking if machine is vurtual machine"
    $virtualModels = @("VirtualBox", "VMware", "Virtual Machine", "Hyper-V")
    $computerSystemModel = (Get-WmiObject win32_computersystem).model
    $isVirtualModel = $false

    foreach ($model in $virtualModels) {
        if ($computerSystemModel.Contains($model)) {
            $isVirtualModel = $true
            break
        }
    }

    if (!isVirtualModel) {
        Log-Warn "You are not on virtual machine or have hardened your machine to not appear as a virtual machine"
        Log-Warn "DO NOT INSTALL this on your host system"
        Write-Host "[-] Do you still wish to proceed? (y/N): " -NoNewline
        $response = Read-Host
        if ($response -notin @("y", "Y")) {
            exit 1
        } 
    }
}

function Check-TamperProtection {
    Log-Task "Checking if Windows Defender Tamper Protection is disabled..."
    try {
        $tp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction Stop
        if ($tp.TamperProtection -eq 5) {
            Log-Error "Please disable Tamper Protection before running this script"
        }
    } catch {
        Log-Warn "Failed to check if Tamper Protection is enabled or not"
        Write-Host "[-] Do you still wish to proceed? (y/N): " -NoNewline
        $response = Read-Host
        if ($response -notin @("y", "Y")) {
            exit 1
        } 
    }
}

function Check-WinDefend {
    Log-Task "Checking if Windows Defender service is disabled..."
    $defender = Get-Service -Name WinDefend -ea 0
    if ($null -ne $defender) {
        if ($defender.Status -eq "Running") {
            Log-Error "Please disable Windows Defender through Group Policy before running this script"
        }
    }
}

function Task-PassNeverExpire {
    Log-Task "Set password to never expire..."
    Set-LocalUser -Name "${Env:UserName}" -PasswordNeverExpires $true
}

function Task-SetPowerOpts {
    Log-Task "Set power options to prevent install from timing out..."
    powercfg -change -monitor-timeout-ac 0 | Out-Null
    powercfg -change -monitor-timeout-dc 0 | Out-Null
    powercfg -change -disk-timeout-ac 0 | Out-Null
    powercfg -change -disk-timeout-dc 0 | Out-Null
    powercfg -change -standby-timeout-ac 0 | Out-Null
    powercfg -change -standby-timeout-dc 0 | Out-Null
    powercfg -change -hibernate-timeout-ac 0 | Out-Null
    powercfg -change -hibernate-timeout-dc 0 | Out-Null
}

function Task-ConfigScoop {
    if (!(Test-CommandAvaliable("scoop"))) {
        Log-Task "Installing scoop..."
        & ([scriptblock]::Create((irm "https://get.scoop.sh"))) -RunAsAdmin | Out-Null
    }

    Log-Task "Configurating scoop..."
    scoop bucket rm main | Out-Null

    if (!(Test-Path $SCOOP_MAIN_BUCKET_DIR)) {
        New-Item -Type Directory $SCOOP_MAIN_BUCKET_DIR | Out-Null
    }

    if (!(Test-Path $SCOOP_COMMONS_BUCKET_DIR)) {
        New-Item -Type Directory $SCOOP_COMMONS_BUCKET_DIR | Out-Null
    }

    $scoopMainBucketArchive = "$SCOOP_MAIN_BUCKET_DIR\_bucket.zip"
    $scoopMainBucketExtract = "$SCOOP_MAIN_BUCKET_DIR\_tmp"
    $scoopCommonsBucketArchive = "$SCOOP_COMMONS_BUCKET_DIR\_bucket.zip"
    $scoopCommonsBucketExtract = "$SCOOP_COMMONS_BUCKET_DIR\_tmp"

    $profileBucketUrl = $SCOOP_WORKSTATION_BUCKET_URL
    if ($profile -eq "vm") {
        $profileBucketUrl = $SCOOP_VM_BUCKET_URL
    }

    $downloadSession = New-Object System.Net.WebClient
    $downloadSession.downloadFile($profileBucketUrl, $scoopMainBucketArchive)
    $downloadSession.downloadFile($SCOOP_COMMONS_BUCKET_URL, $scoopCommonsBucketArchive)

    Expand-ZipArchive $scoopMainBucketArchive $scoopMainBucketExtract
    Expand-ZipArchive $scoopCommonsBucketArchive $scoopCommonsBucketExtract

    Copy-Item "$scoopMainBucketExtract\**\*" $SCOOP_MAIN_BUCKET_DIR -Recurse -Force
    Copy-Item "$scoopCommonsBucketExtract\**\*" $SCOOP_COMMONS_BUCKET_DIR -Recurse -Force

    Remove-Item $scoopMainBucketArchive
    Remove-Item $scoopCommonsBucketArchive
    Remove-Item $scoopMainBucketExtract -Recurse -Force
    Remove-Item $scoopCommonsBucketExtract -Recurse -Force
}

function Task-InstallPackage {
    Log-Task "Installing pacakge..."
    $commonPackages = @("7zip", "vcredist", "debloat")
    $profilePackages =  @()

    if ($profile -eq "workstation") {
        $profilePackages = @(
            "git",
            "gpg",
            "keepassxc",
            "mullvad.vpn",
            "mullvad.browser",
            "neovim",
            "vesktop",
            "vmware-workstation",
            "wsl-ssh-pageant"
        )   
    } elseif ($profile -eq "vm") {
        $profilePackages = @(
            "capa",
            "cheatengine",
            "detect-it-easy",
            "dnspy",
            "ghidra",
            "hxd",
            "ida.free",
            "reclass-net",
            "x64dbg",
            "x64dbg.plugin.scyllahide",
            "yara"
        )
    }

    foreach ($package in $commonPackages) {
        scoop install "commons/$package" -u
    }

    foreach ($package in $profilePackages) {
        scoop install "main/$package" -u
    }
}

function Task-FinishingUp {
    Log-Task "Finishing up..."

    Log-Info "Installing winget..."
    # https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox
    $ErrorActionPreference = "Continue"
    Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
    Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx -OutFile Microsoft.UI.Xaml.2.8.x64.appx
    Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
    Add-AppxPackage Microsoft.UI.Xaml.2.8.x64.appx
    Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    Remove-Item Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle 
    Remove-Item Microsoft.VCLibs.x64.14.00.Desktop.appx
    Remove-Item Microsoft.UI.Xaml.2.8.x64.appx
    $ErrorActionPreference = "Stop"

    Log-Info "Running debloating script..."
    $debloatProcess = Start-Process powershell.exe -PassThru -ArgumentList "-executionpolicy bypass -File $SCOOP_DIR\apps\debloat\current\debloat.ps1" -Verb RunAs
    if ($null -ne $debloatProcess) {
        $debloatProcess.WaitForExit()
    }
    
    Log-Info "Unpining taskbar icons..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
 
    Log-Info "Removing desktop links..."
    Remove-Item (Join-Path $env:USERPROFILE "Desktop\*.lnk")
    Remove-Item (Join-Path $env:PUBLIC "Desktop\*.lnk")
}

# Main
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($profile -notin @("workstation", "vm")) {
    Write-Output "Usage: .\setup.ps1 [workstation/vm]"
    exit 1
}

## Checking requirement
Check-64Bit
Check-PwshVersion
Check-RunAsAdmin
Check-ExecPolicy
Check-OS
if ($profile -eq "vm") {
    Check-VM
}
Check-TamperProtection
Check-WinDefend

## Print out info
$desktopPath = [Environment]::GetFolderPath("Desktop")
Set-Location -Path $desktopPath -PassThru | Out-Null

Clear-Host
Log-Info "Welcome to shell32's environment bootstrap script"
Log-Info "Profile: $profile"
Write-Host "[-] Do you wish to proceed? (y/N): " -NoNewline
$response = Read-Host
if ($response -notin @("y", "Y")) {
    exit 1
}
Write-Host

## Run bootstrap
Task-PassNeverExpire
Task-SetPowerOpts
Task-ConfigScoop
Task-InstallPackage
Task-FinishingUp

## Finished
Log-Task "Finished!"
Log-Info "System will automatic restart in 5 seconds..."
shutdown.exe /r /t 5
