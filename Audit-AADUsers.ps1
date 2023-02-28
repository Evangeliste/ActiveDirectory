#########################################################################################################################
#
#		Script for : Audit Azure AD sign'in LOG
#
#		Script author : Alexis Charriere
#		mail 	: alexis.charriere@talan.com
#		Create 	: February 16th, 2023
#		Current Version	: 1.0.0 // February 16th, 2023
#		        UPDate 	: 1.0.0 - Intial Build
#
#########################################################################################################################

<#
    .DESCRIPTION
    /!\ This script used Graph API to work, please read these before use : 
        - https://learn.microsoft.com/en-us/graph/auth-register-app-v2
        - https://learn.microsoft.com/en-us/graph/auth-v2-user

    The necessary permission was : 
        - AuditLog.Read.All (Type : Application)
        - CrossTenantInformation.ReadBasic.All (Type : Application)
        - Directory.Read.All (Type : Application)
        - ManagedTenants.Read.All (Type : Delegated)
        - User.Read.All (Type : Delegated)
    This script extract all users (members & guest) from a Tenant with only specific information

    TODO
        - Generate an HTML report with logo

    .Example

    Audit-AADUsers.ps1 -clientID [CLIENTID of APPLICATION] -tenantName [TENANT NAME contoso.onmicrosoft.com] -ClientSecret [SECRET ID of APPLICATION] -TenantId [TENANT ID]
#>

#########################################################################################################################
#
#   Param/Config
#
#########################################################################################################################
[CmdletBinding(SupportsShouldProcess = $true)]
param 
    (
    #Setting credentials parameters
    [String]$clientID,
    [String]$tenantName,
    [String]$ClientSecret,
    [String]$TenantId,
    $resource = "https://graph.microsoft.com/"
    )
 
$ReqTokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    client_Id     = $clientID
    Client_Secret = $clientSecret
} 

# Build logs and Timer
####################################################################################################
$MyDate = "$($((Get-Date).ToString('yyyy-MM-dd')))"
$MyDateTime = "$($((Get-Date).ToString('yyyy-MM-dd_HH-mm')))"
$CurrentDirectory = Get-Location

$TranscriptLog = $CurrentDirectory.Path+"\"+$MyDateTime+"_Trace_AAD_EXPORT.log"
Start-Transcript -Path $TranscriptLog

Write-Host "#########################################################" -ForegroundColor DarkYellow
Write-Host "#                                                       #" -ForegroundColor DarkYellow
Write-Host "#                Start run at" $MyDateTime  "         #" -ForegroundColor DarkYellow
Write-Host "#                                                       #" -ForegroundColor DarkYellow
Write-Host "#########################################################" -ForegroundColor DarkYellow

#########################################################################################################################
#
#   Connect to Azure AD Tenant and display banner
#
#########################################################################################################################
$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody -ErrorVariable ErrorToConnect
    IF ($ErrorToConnect)
        {
        Write-Host "TOKEN error, please review the correct privileged or retry later" -ForegroundColor Red
        Break
        }
$Tenant = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"} -Uri "https://graph.microsoft.com/beta/tenantRelationships/findTenantInformationByTenantId(tenantId='$TenantId')" -Method GET

Write-Host ""
Write-Host ""
Write-Host "#########################################################################################################################" -ForegroundColor Green
Write-Host "#                                                                                                                        " -ForegroundColor Green
Write-Host "#                                          Welcome to" $Tenant.displayName.ToUpper() "Tenant                             " -ForegroundColor Green
Write-Host "#                                                                                                                        " -ForegroundColor Green
Write-Host "#########################################################################################################################" -ForegroundColor Green

$max = 10
for ($i=$max; $i -gt 1; $i--)
{
Write-Progress -Activity "You have 15 seconds for breaking the script if you are not connected to the good tenant" -Status "Please Wait or Break" `
-SecondsRemaining $i 
Start-Sleep 1
}   

# Get all users in source tenant
####################################################################################################
$uri = 'https://graph.microsoft.com/beta/users?$select=displayName,userPrincipalName,mail,companyName,department,usageLocation,country,userType,id,signInActivity'
 
# If the result is more than 999, we need to read the @odata.nextLink to show more than one side of users
####################################################################################################
$Data = while (-not [string]::IsNullOrEmpty($uri)) {
    # API Call
    $apiCall = try {
        Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"} -Uri $uri -Method Get
    }
    catch {
        $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
    }
    $uri = $null
    if ($apiCall) {
        # Check if any data is left
        $uri = $apiCall.'@odata.nextLink'
        $apiCall
    }
}
 
# Set the result into an variable
####################################################################################################
$result = ($Data | select-object Value).Value
$Export = $result | Select-Object displayName,userPrincipalName,mail,companyName,department,usageLocation,country,userType,id,@{n="LastLoginDate";e={$_.signInActivity.lastSignInDateTime}}
 
[datetime]::Parse('2023-02-15T16:55:35Z')
 
# Export data to CSV and generate Html
####################################################################################################
$Tempfile = $CurrentDirectory.Path+"\"+$MyDate+"_AAD_"+$Tenant.displayName.ToUpper().replace(" ","")+"_Export.csv"
$Outfile = $CurrentDirectory.Path+"\"+$MyDate+"_AAD_"+$Tenant.displayName.ToUpper().replace(" ","")+"_Export.html"

$TestFile = Get-Item -path $Tempfile -ErrorAction SilentlyContinue
IF ($TestFile)
    {
    Remove-Item $Tempfile -Force
    }

$Export | Select-Object displayName,userPrincipalName,mail,companyName,department,usageLocation,country,userType,id,@{Name='LastLoginDate';Expression={[datetime]::Parse($_.LastLoginDate)}} | Export-Csv -Delimiter ";" -NoTypeInformation -NoClobber -Path $Tempfile

$filedata = Import-CSV $Tempfile -Delimiter ";"
$filedata | Export-CSV $Tempfile -NoTypeInformation -Delimiter ";" -Force

#$CSVtoHTML = Import-CSV $Tempfile | ConvertTo-Html
#$CSVtoHTML | Out-File -FilePath $Outfile

# The end !
####################################################################################################
$EndDateTime = "$($((Get-Date).ToString('yyyy-MM-dd_HH-mm')))"

Write-Host "#########################################################" -ForegroundColor DarkYellow
Write-Host "#                                                       #" -ForegroundColor DarkYellow
Write-Host "#                END run at" $EndDateTime  "           #" -ForegroundColor DarkYellow
Write-Host "#                                                       #" -ForegroundColor DarkYellow
Write-Host "#########################################################" -ForegroundColor DarkYellow

Stop-Transcript