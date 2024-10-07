# vim: tabstop=4 shiftwidth=4 expandtab
# Copyright (C) 2024 shell32 <hi@shell32.net>. All Rights Reserved.
# See LICENSE file for more information on copyright and license.

# Variables
$SOURCE_DIR = ".\config"
$USERPROFILE_DIR = $env:USERPROFILE

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

function Task-CopyConfigFile {
    Log-Task "Copying configuration file..."
    Robocopy $SOURCE_DIR $USERPROFILE_DIR /S /COPY:DAT /R:0 /W:0
}

function Task-CmdAutoRunInit {
    Log-Task "Making cmd autorun init.cmd everytime it start..."
    $regPath = "HKCU:\Software\Microsoft\Command Processor"
    $regName = "AutoRun"
    $regValue = "$env:USERPROFILE\init.cmd"
    New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType ExpandString -Force
}

# Main
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (!(Test-CommandAvaliable("Robocopy"))) {
    Log-Error "Robocopy not found, Please make sure 'C:\Windows\System32' is in your PATH"
}

Task-CopyConfigFile
Task-CmdAutoRunInit

## Finishing Up
Log-Task "Finished!"
