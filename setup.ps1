# Copyright (C) 2024 shell322 <hi@shell32.net>. All Rights Reserved.
# See LICENSE file for more information on copyright and license.

# Param
param (
    [string]$profile = $null
)

# Functions
function Test-CommandAvaliable {
    param (
        [Parameter(Mandatory = $True, Position = 0)]
	[String] $Command
    )

    return [Boolean](Get-Command $Command -ErrorAction SilentlyContinue)
}

# Main
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($profile -notin @("workstation", "vm")) {
    exit 1
}

if (!([Environment]::Is64BitProcess)) {
    Write-Host "[!] It seems like you are using 32bit powershell. Please use 64 bit instead" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Checking if PowerShell version is compatible..."
if ($PSVersionTable.PSVersion -lt [System.Version]"5.0.0") {
    Write-Host "[!] It seems like you are using old powershell version. Please update to newer version" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Checking if script is running as administrator..."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Please run this script as administrator." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Checking if execution policy is unrestricted..."
if ((Get-ExecutionPolicy).ToString() -ne "Unrestricted") {
    Write-Host "[!] Please update execution policy to unrestricted" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Checking if Operation System is compatible..."
if ((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") {
    Write-Host "[!] Windows 7 or below is not supported" -ForegroundRed
    exit 1
}

if ($profile -eq "vm") {
    Write-Host "[+] Checking if machine is a virtual machine"
    $virtualModels = @("VirtualBox", "VMware", "Virtual Machine", "Hyper-V")
    $computerSystemModel = (Get-WmiObject win32_computersystem).model
    $isVirtualModel = $false

    foreach ($model in $virtualModels) {
	if ($computerSystemModel.Contains($model)) {
	    $isVirtualModel = $true
	    break
        }
    }

    if (!$isVirtualModel) {
	Write-Host "[!] You are not on virtual machine or have hardened your machine to not appear as a virtual machine" -ForegroundColor Red
	Write-Host "[!] DO NOT INSTALL this on your host system" -ForegroundColor Red
	Write-Host "[-] Do you still wish to proceed? (y/N): " -NoNewline
	$response = Read-Host
	if ($response -notin @("y", "Y")) {
	    exit 1
        }
    }
}

Write-Host "[+] Checking if Windows Defender Tamper Protection is disabled..."
try {
    $tpEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction Stop
    if ($tpEnabled.TamperProtection -eq 5) {
	Write-Host "[!] Please disable Tamper Protection before running this script." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "[!] Failed to check if Tamper Protection is enabled or not" -ForegroundColor Yellow
    Write-Host "[-] Do you still wish to proceed? (y/N): " -NoNewline
    $response = Read-Host
    exit 1
}

Write-Host "[+] Checking if Windows Defender service is disabled..."
$defender = Get-Service -Name WinDefend -ea 0
if ($null -ne $defender) {
    if ($defender.Status -eq "Running") {
        Write-Host "[!] Please disable Windows Defender through Group Policy before running this script" -ForegroundColor Red
	exit 1
    }
}

$desktopPath = [Environment]::GetFolderPath("Desktop")
Set-Location -Path $desktopPath -PassThru | Out-Null

Clear-Host
Write-Host "[*] Welcome to shell32's environment setup script"
Write-Host "[*] Profile: $profile"
Write-Host "[-] Do you wish to proceed? (y/N): " -NoNewline
$response = Read-Host
if ($response -notin @("y", "Y")) {
    exit 1
}

Write-Host ""

Write-Host "[+] Set password to never expire..." -ForegroundColor Cyan
Set-LocalUser -Name "${Env:UserName}" -PasswordNeverExpires $true

Write-Host "[+] Set power options to prevent install from timing out..." -ForegroundColor Cyan
powercfg -change -monitor-timeout-ac 0 | Out-Null
powercfg -change -monitor-timeout-dc 0 | Out-Null
powercfg -change -disk-timeout-ac 0 | Out-Null
powercfg -change -disk-timeout-dc 0 | Out-Null
powercfg -change -standby-timeout-ac 0 | Out-Null
powercfg -change -standby-timeout-dc 0 | Out-Null
powercfg -change -hibernate-timeout-ac 0 | Out-Null
powercfg -change -hibernate-timeout-dc 0 | Out-Null

if (!(Test-CommandAvaliable("scoop"))) {
    Write-Host "[+] Installing scoop..." -ForegroundColor Cyan
    & ([scriptblock]::Create((irm "https://get.scoop.sh"))) -RunAsAdmin | Out-Null
}

scoop bucket rm main

Write-Host "[+] Debloating windows..." -ForegroundColor Cyan
& ([scriptblock]::Create((irm "https://win11debloat.raphi.re/"))) -RunDefaults -Silent
