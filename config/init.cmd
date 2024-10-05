@echo off

:: Environment
set SSH_AUTH_SOCK=\\.\pipe\ssh-pageant
set GIT_SSH=C:\Windows\System32\OpenSSH\ssh.exe

:: Alias
doskey ls=dir $*
doskey vim=nvim $*
doskey clear=cls $*
doskey mv=move $*
doskey cp=copy $*
doskey dev=cd %USERPROFILE%\Documents\Development
