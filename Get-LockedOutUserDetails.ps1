#=======================================================================================
# Get-LockedOutUserDetails
# Created on: 2017-01-04
# Version 1.1
# Last Updated: 2017-05-02
# Last Updated by: John Shelton | c: 260-410-1200 | e: john.shelton@lucky13solutions.com
#
# Purpose: This script determines which AD server has the PDC role.  It then reviews the
#          security event logs searching for Events with ID of 4740.  Next it pulls the
#          details of those event logs and looks for ones that match the username the
#          executor specifies.  It then returns a list of the Time Created, Username, 
#          and the ComputerName that was using the credentials.
# Notes: 
# 
# Change Log: Feature 1:  Output to HTML.  Adjusteed the Parameter to make it required.
# 
#
#=======================================================================================
#
# Enable setting the LockedUser via a param
#
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string] $LockedUser = $(throw "-LockedUser is required.")
    )
#
# Clear & Define Variables
#
# $LockedUser = ""
[array] $LockEvents
[array] $Events
#
# Configure HTML Header
#
$HTMLHead = "<style>"
$HTMLHead += "BODY{background-color:white;}"
$HTMLHead += "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$HTMLHead += "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:royalblue}"
$HTMLHead += "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:gainsboro}"
$HTMLHead += "</style>"
#
# Define Output Variables
#
$ExecutionStamp = Get-Date -Format yyyyMMdd_hh-mm-ss
$path = "c:\temp\"
$FilenamePrepend = 'temp_'
$FullFilename = "Get-LockedOutUserDetails.ps1"
$FileName = $FullFilename.Substring(0, $FullFilename.LastIndexOf('.'))
$FileExt = '.html'
#
$PathExists = Test-Path $path
IF($PathExists -eq $False)
    {
    New-Item -Path $path -ItemType  Directory
    }
#
$LockedUser = $LockedUser.ToUpper()
#
# Clear the screen
#
Clear-Host
#
<# Set the LockedUser via a popup window
#
# Add-Type -AssemblyName Microsoft.VisualBasic
# $LockedUser =[Microsoft.VisualBasic.Interaction]::InputBox('Enter the username that is locked out','UserName')
#
#> 
# Determine the AD Server with the PDCEmulator role enabled
#
$PDC = Get-ADDomain | Select-Object PDCEmulator
$PDCName = $PDC.PDCEmulator
Write-Host "We have determined that $PDCName is the PDC for the environment"
#
# Get all of the Events from the Security Log with Event ID 4740
#
Write-Host "We are now gathering Security Event Logs from the PDC...this may take a while..."
# $Events = Get-WinEvent -LogName "Security" -ComputerName $PDCName
$Events = Get-WinEvent -ComputerName $PDC.PDCEmulator -FilterHashtable @{Logname='Security';Id=4740} | Sort-Object -Property TimeCreated
$EventsCount = $Events.Count
$OldestEvent = $Events.TimeCreated | Select-Object -First 1
$NewestEvent = $Events.TimeCreated | Select-Object -Last 1
Write-Host "Found a total of $EventsCount lockout events"
#
# Search through all of the sorted Events for ones that match the specified UserName
#
$Continue = "Y"
While ($Continue -eq "Y" -or $Continue -eq "YES"){
    $LockEvents = @()    
    If($RunCount -ge 1)
    {
        $LockedUser = Read-Host "Please enter the username that you wish to generate the Locked Out report for"
        $LockedUser = $LockedUser.ToUpper()
    }
    $Progress = 0
    $OutputFile = $path + $FilenamePrePend + '_' + $FileName + '_For_' + $LockedUser + '_' + $ExecutionStamp + $FileExt
    ForEach ($event in $Events)
        {
        $UserLockEvent = $Event | Where-Object{$_.Properties[0].Value -like $LockedUser} | Select-Object -Property TimeCreated, @{Label='UserName'; Expression={$_.Properties[0].Value}},@{Label='ComputerName';Expression={$_.Properties[1].Value}}; $I = $I+1
        Write-Progress -Activity "Searching Events" -Status "Progress:" -PercentComplete (($Progress/$EventsCount)*100)
        $Progress ++
        $LockEvents += $UserLockEvent
        }
    If ($LockEvents.count -lt 1) 
        {
        #[Microsoft.VisualBasic.Interaction]::MsgBox("The user $lockeduser was not found to have been locked out.","OKOnly,SystemModal,Exclamation","Warning")
        Write-Host "The user $lockeduser was not found to have been locked out."
        }
    Else 
        {
        # $LockEvents | Out-GridView
        # $LockEvents | ConvertTo-HTML -head $HTMLHead &45;body "<H2> Lockout Events for $LockedUser" | Invoke-Item
        Write-Host "The Results for $LockedUser will be written to $OutputFile"
        $LockEvents | Sort-Object TimeCreated -Descending | ConvertTo-HTML TimeCreated,UserName,ComputerName -Title "Lock Events for $LockedUser" -body "$HTMLHead<H2> Lock Events for $LockedUser </H2> </P> The oldest event in the log is dated $OldestEvent </BR> The most recent event is dated $NewestEvent </P>" | Set-Content $OutputFile
        Invoke-Item $OutputFile
        }
    $Continue = Read-Host "Do you have another account to lookup? (Y or N)"
    $Continue = $Continue.ToUpper()
    $RunCount ++
}
