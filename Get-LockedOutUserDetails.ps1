#=======================================================================================
# Get-LockedOutUserDetails
# Created on: 2017-01-04
# Version 1.0
# Last Updated: 
# Last Updated by: John Shelton | c: 260-410-1200 | e: john.shelton@lucky13solutions.com
#
# Purpose: This script determines which AD server has the PDC role.  It then reviews the
#          security event logs searching for Events with ID of 4740.  Next it pulls the
#          details of those event logs and looks for ones that match the username the
#          executor specifies.  It then returns a list of the Time Created, Username, 
#          and the ComputerName that was using the credentials.
# Notes: 
# 
# Change Log:
# 
#
#=======================================================================================
#
# Clear & Define Variables
#
$LockedUser = ""
[array] $LockEvents
# Enable setting the LockedUser via a param
#
param (
    [string]$LockedUser = $(Read-Host "Input the Username who is locked")
    )
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
#
# Get all of the Events from the Security Log with Event ID 4740
#
$Events = Get-WinEvent -ComputerName $PDC.PDCEmulator -FilterHashtable @{Logname='Security';Id=4740}
#
# Search through all of the sorted Events for ones that match the specified UserName
#
$LockEvents = foreach ($event in $Events){
    $Event | Where-Object{$_.Properties[0].Value -like $LockedUser} | Select-Object -Property TimeCreated, @{Label='UserName'; Expression={$_.Properties[0].Value}},@{Label='ComputerName';Expression={$_.Properties[1].Value}}
}
If ($LockEvents.count -lt 1) {
#[Microsoft.VisualBasic.Interaction]::MsgBox("The user $lockeduser was not found to have been locked out.","OKOnly,SystemModal,Exclamation","Warning")
Write-Host "The user $lockeduser was not found to have been locked out."
}
Else {
$LockEvents | Out-GridView
}

