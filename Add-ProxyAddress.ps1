#########################################################################################################################
#
#		Script for : Add Domain to proxyAddress Active Directory Attribute
#
#		Script author : Alexis Charrière / Evangeliste
#		mail 	: alexis.charriere@ai3.fr
#		Create 	: 08 June 2018 (The Force be with me)
#		Version	: 1.1
#		UPDate 	: 10 August 2018 Optimization, integrate debug mode
#
#       Usage : .\Add-ProxyAddress.ps1 -CsvFile "CSVFILES" -Domain "domaintoadd.com"
#
#########################################################################################################################
<#     
    .DESCRIPTION 
        Reads the contents of a CSV specified during the runtime command, then updates all ADUser in file. 
        
    .EXAMPLE 
        Debug Mode
        Add-ProxyAddress.ps1 -CsvFile ".\AddProxy.CSV" -Domain "jedimaster.onmicrosoft.com" -DebugMode $True

        Production Mode
        Add-ProxyAddress.ps1 -CsvFile ".\AddProxy.CSV" -Domain "jedimaster.onmicrosoft.com" -DebugMode $False

        Source CSV must contain heading SamAccountName to function 
    
    Use : This script is provided as it and I accept no responsibility for any issues arising from its use. 
#> 

#Variables
#########################################################################################################################
[CmdletBinding(SupportsShouldProcess = $true)]
param
    (
    [parameter(Mandatory = $true, HelpMessage = "Location of CSV file containing Account to update", Position = 1)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $_ })]
    [string]$CsvFile,
    [string]$Domain,
    $DebugMode = $true
    )

$errorActionPreference = "SilentlyContinue"

$MyDate = get-date -Format yyyy-MM-dd
$CurrentDirectory = Get-Location
    
$LOGFILENAME = $CurrentDirectory.Path+"\Add-ProxyAddress_"+$MyDate+".log"
Remove-Item $LOGFILENAME
New-Item $LOGFILENAME -type file | Out-Null

#Module
#########################################################################################################################
Import-Module ActiveDirectory
$CheckModule = Get-Module
    IF ($CheckModule.name -eq "ActiveDirectory")
        {
        Write-Host "Module Active Directory is OK ! the script can be run" -ForegroundColor Green
        }
    ELSE 
        {
        Write-Host "You do not have Active Directory requiered module installed ! Please make the necesarry" -ForegroundColor Red
        Break
        }

#Active Mode
#########################################################################################################################
IF ($DebugMode -eq $true)
    {
    Write-Host "#####################################################################################################################" -ForegroundColor Yellow
    Write-Host "#                                                                                                                   #" -ForegroundColor Yellow
    Write-Host "#                                       /!\ Running in DEBUG mode /!\                                               #" -ForegroundColor Yellow
    Write-Host "#                                                                                                                   #" -ForegroundColor Yellow
    Write-Host "#####################################################################################################################" -ForegroundColor Yellow
    $errorActionPreference = "Continue"
    }
ELSE 
    {
    Write-Host "#####################################################################################################################" -ForegroundColor Green
    Write-Host "#                                                                                                                   #" -ForegroundColor Green
    Write-Host "#                                       /!\ Running in Active mode /!\                                              #" -ForegroundColor Red
    Write-Host "#                                                                                                                   #" -ForegroundColor Green
    Write-Host "#####################################################################################################################" -ForegroundColor Green
    $errorActionPreference = "SilentlyContinue"
    }

Write-Host ""
Start-Sleep 5
#                                                /!\ Script begining /!\
#########################################################################################################################


$ADUsers = Import-Csv -Path $CsvFile

ForEach ($ADUser in $ADUsers.SamAccountName)
    {
        $ADUserProperties = Get-Aduser $ADUser -properties *
        IF ($ADUserProperties.mailNickname -notlike $null)
        {
            $CheckProxy = ((Get-Aduser $ADUser -properties * | Where-Object {$_.proxyAddresses -like "*.mail.onmicrosoft.com"}).proxyAddresses)
            IF ($CheckProxy)
            {
            Write-Host "SMTP Address already present for" $ADUserProperties.mailNickname -ForegroundColor White -BackgroundColor Green
            }
            else
            {
            IF ($DebugMode -eq $true)
                {
                Set-ADUser $ADUser -Add @{ProxyAddresses="smtp:"+$ADUserProperties.mailNickname+"@$Domain"} -whatif
                }
                else 
                {
                Set-ADUser $ADUser -Add @{ProxyAddresses="smtp:"+$ADUserProperties.mailNickname+"@$Domain"}
                $Check = ((Get-Aduser $ADUser -properties * | Where-Object {$_.proxyAddresses -like "*.mail.onmicrosoft.com"}).proxyAddresses)
                #Write-Host "The user" $ADUserProperties.userPrincipalName "was updated" $Check -ForegroundColor Green
                "$($MyDate) : " + "The user"+ $ADUserProperties.userPrincipalName +"was updated"+ $Check | Tee-Object -FilePath $LOGFILENAME -Append | Write-Host -ForegroundColor Green
                }
            
            }
        }
        else
        {
        Write-Host "The user" $ADUser "Doesn't have an alias value" -ForegroundColor Red
        }
    }
