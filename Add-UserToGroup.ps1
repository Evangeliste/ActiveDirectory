 #########################################################################################################################
#
#		Script for : Populate ADGroup between Forest
#
#		Script author : Alexis Charrière
#		mail 	: alexis.charriere@talan.com
#		Create 	: 21 November 2021
#		Version	: 1.0.0
#
#########################################################################################################################

<#     
    .DESCRIPTION 

    .EXAMPLE
        .\Add-UserToGroup.ps1 -SamAccountSource SAMACCOUNTNAMESOURCE -SamAccountDest SAMACCOUNTNAMEDESTINATION -DomainDest server1.contoso.com

#> 

#Function/Module
#########################################################################################################################


[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [String]$SamAccountSource,
    [String]$SamAccountDest,
    [String]$DomainDest
    )

$MyDateTime = "$($((Get-Date).ToString('yyyy-MM-dd HH:mm')))"

Write-Host "#########################################################" -ForegroundColor Yellow
Write-Host "#                                                       #" -ForegroundColor Yellow
Write-Host "#                Start run at" $MyDateTime  "         #" -ForegroundColor Yellow
Write-Host "#                                                       #" -ForegroundColor Yellow
Write-Host "#########################################################" -ForegroundColor Yellow

Write-Host ""
Write-host "You are logon to the current AD Forest:" $env:USERDOMAIN -ForegroundColor Magenta
Write-Host ""

#
# Test Destination AD Forest
#
#########################################################################################################################

$DestForest = Get-ADForest -Server $DomainDest -ErrorAction SilentlyContinue -ErrorVariable ErrCheckADDest
IF ($ErrCheckADDest)
    {
    Write-Warning "Error when contacting AD Destination, the script stop now !!"
    Break
    }
Else
    {
    Write-Host "You are working to add group to the User present in the Forest:" $DestForest -ForegroundColor White -BackgroundColor Magenta
    }

$max = 15
for ($i=$max; $i -gt 1; $i--)
    {
    Write-Progress -Activity "You have 15 seconds before the script begin" -Status "Please Wait or Break" `
    -SecondsRemaining $i
    Start-Sleep 1
    }

#
# Ready to Run !! Let's GO GO GO
#
#########################################################################################################################

$groups = (Get-ADuser -Identity $SamAccountSource -Properties memberof).memberof
Write-Host "Bellow the Group list of the user was member" -ForegroundColor Yellow
$Groups | Get-ADGroup | Select-Object name | Sort-Object name

Write-Host "Trying to add" $SamAccountDest "to the groups" -ForegroundColor Green
foreach ($group in $groups) 
	{
	$DestUrs = Get-ADuser -Identity $SamAccountDest -Server $DomainDest -Properties *
    $DestGroup = $Group | Get-ADGroup -Properties *
    IF ($DestGroup.GroupScope -ne "DomainLocal")
        {
        Write-Host "Impossible d'ajouter l'utilisateur" $DestUrs.DisplayName "au groupe" $DestGroup.Name "car le groupe n'est pas du type DomainLocal : " $DestGroup.Name "=" $DestGroup.GroupScope -ForegroundColor Red
        }
    else 
        {   
	    Add-ADGroupMember -Identity $DestGroup.SamAccountName -Members $DestUrs -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable ErrAdd
        IF ($ErrAdd)
            {
            Write-Warning "Error when adding the user" $DestUrs.DisplayName "to" $DestGroup.DisplayName
            }
        else 
            {
            Write-Host "Success when adding the user" $DestUrs.DisplayName "to" $DestGroup.Name -ForegroundColor Green
            }
        }
    }

$EndDateTime = "$($((Get-Date).ToString('yyyy-MM-dd HH:mm')))"

Write-Host "#########################################################" -ForegroundColor Yellow
Write-Host "#                                                       #" -ForegroundColor Yellow
Write-Host "#                END run at" $EndDateTime  "           #" -ForegroundColor Yellow
Write-Host "#                                                       #" -ForegroundColor Yellow
Write-Host "#########################################################" -ForegroundColor Yellow