# Copyright (C) 2024 shell32 <hi@shell32.net>. All Rights Reserved.
# See LICENSE file for more information on copyright and license.

# vim: tabstop=4 shiftwidth=4 expandtab

# Param
param (
    [string]$profile = $null
)

# Variables
$SCOOP_DIR = "$env:USERPROFILE\scoop"
$SCOOP_BUCKET_DIR = "$SCOOP_DIR\buckets\main"
$SCOOP_BUCKET_URL = "https://github.com/scoopinstaller/main/archive/master.zip"

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

    if (!(Test-Path $SCOOP_BUCKET_DIR)) {
        New-Item -Type Directory $SCOOP_BUCKET_DIR | Out-Null
    }

    $scoopBucketArchive = "$SCOOP_BUCKET_DIR\_bucket.zip"
    $scoopBucketExtract = "$SCOOP_BUCKET_DIR\_tmp"

    $downloadSession = New-Object System.Net.WebClient
    $downloadSession.downloadFile($SCOOP_BUCKET_URL, $scoopBucketArchive)

    Expand-ZipArchive $scoopBucketArchive $scoopBucketExtract

    Copy-Item "$scoopBucketExtract\Main-*\*" $SCOOP_BUCKET_DIR -Recurse -Force

    Remove-Item $scoopBucketArchive
    Remove-Item $scoopBucketExtract -Recurse -Force
}

# Main
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($profile -notin @("workstation", "vm")) {
    Write-Output "Usage: .\setup.ps1 [workstation/vm]"
    exit 1
}

## Checking requirement
if (!([Environment]::Is64BitProcess)) {
    Log-Error "It seems like you are using 32 bit powershell. Please use 64 bit instead"
}

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
