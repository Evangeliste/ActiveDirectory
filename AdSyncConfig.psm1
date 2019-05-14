<# 
 
.SYNOPSIS
    Prepares Active Directory configuration for various purposes.

.DESCRIPTION

    AdSyncConfig.psm1 is a Windows PowerShell script module that provides functions that are
    used to prepare your Active Directory forest and domains for Azure AD Connect Sync
    features.
#>

#----------------------------------------------------------
# STATIC VARIABLES
#----------------------------------------------------------
# Well known SIDS
$selfSid = "S-1-5-10"
$enterpriseDomainControllersSid = "S-1-5-9"

# Regex variables
$distinguishedNameRegex = [Regex] '^(?:(?<cn>CN=(?<name>[^,]*)),)?(?:(?<path>(?:(?:CN|OU)=[^,]+,?)+),)?(?<domain>(?:DC=[^,]+,?)+)$'
$defaultADobjProperties = @('UserPrincipalName','ObjectGUID','ObjectSID','mS-DS-ConsistencyGuid','sAMAccountName')

# Parameter variables
$commaSeparator =","
$periodSeparator = "."
$colonSeparator = ":"
$atSeparator = "@"
$aclSeparator = '" "'
$inheritanceSubObjectsOnly = 'S'
$inheritanceThisAndSubObjects = 'T'
$inheritanceNone = 'N'

<#.SYNOPSIS
        Tighten permissions on an AD object that is not otherwise included in any AD protected security group.
        A typical example is the AD Connect account (MSOL) created by AAD Connect automatically. This account
        has replicate permissions on all domains, however can be easily compromised as it is not protected.

    .DESCRIPTION
        The Set-ADSyncRestrictedPermissions Function will tighten permissions oo the 
        account provided. Tightening permissions involves the following steps:
        1. Disable inheritance on the specified object
        2. Remove all ACEs on the specific object, except ACEs specific to SELF. We want to keep
           the default permissions intact when it comes to SELF.
        3. Assign these specific permissions:

                Type	Name										Access				Applies To
                =============================================================================================
                Allow	SYSTEM										Full Control		This object
                Allow	Enterprise Admins							Full Control		This object
                Allow	Domain Admins								Full Control		This object
                Allow	Administrators								Full Control		This object

                Allow	Enterprise Domain Controllers				List Contents
                                                                    Read All Properties
                                                                    Read Permissions	This object

                Allow	Authenticated Users							List Contents
                                                                    Read All Properties
                                                                    Read Permissions	This object

    .PARAMETER ADConnectorAccountDN
        DistinguishedName of the Active Directory account whose permissions need to be tightened. This is typically the MSOL_nnnnnnnnnn 
        account or a custom domain account that is configured in your AD Connector.

    .PARAMETER Credential
        Administrator credential that has the necessary privileges to restrict the permissions on the ADConnectorAccountDN account. 
        This is typically the Enterprise or Domain administrator. 
        Use the fully qualified domain name of the administrator account to avoid account lookup failures. Example: CONTOSO\admin

    .PARAMETER DisableCredentialValidation
        When DisableCredentialValidation is used, the function will not check if the credentials provided in -Credential are valid in AD 
        and if the account provided has the necessary privileges to restrict the permissions on the ADConnectorAccountDN account.

    .EXAMPLE
       Set-ADSyncRestrictedPermissions -ADConnectorAccountDN "CN=TestAccount1,CN=Users,DC=Contoso,DC=com" -Credential $(Get-Credential)
#>
Function Set-ADSyncRestrictedPermissions
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param(
        [Parameter(Mandatory=$True)] 
        [string] $ADConnectorAccountDN,

        [Parameter(Mandatory=$True)] 
        [System.Management.Automation.PSCredential] $Credential,

        [Parameter(Mandatory=$False)] 
        [switch] $DisableCredentialValidation
    )

    # Function init
    $functionMsg = "Set-ADSyncRestrictedPermissions :"

    If (!$DisableCredentialValidation)
    {
        # Validate Credential
        TestCredential $Credential
    }

    If ($PSCmdlet.ShouldProcess($ADConnectorAccountDN, "Set restricted permissions")) 
    {
        $networkCredential = $Credential.GetNetworkCredential()
        $path = "LDAP://" + $networkCredential.Domain + "/" + $ADConnectorAccountDN	

        $de = New-Object System.DirectoryServices.DirectoryEntry($path, $Credential.UserName, $networkCredential.Password)
        $selfName = ConvertSIDtoName $selfSid			

        Try
        {	
            [System.DirectoryServices.DirectoryEntryConfiguration]$deOptions = $de.get_Options()
            $deOptions.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        }
        Catch
        {
            Throw "$functionMsg Failure using credential to access Active Directory. Error Details: $($_.Exception.Message)"
        }

        Try
        {
            Write-Output "$functionMsg Setting Restricted permissions on '$ADConnectorAccountDN'..."
            # disable inheritance on the object and remove inherited DACLs
            $de.ObjectSecurity.SetAccessRuleProtection($true, $false);

            # remove all DACLs on the object except SELF
            $acl = $de.ObjectSecurity.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            ForEach ($ace in $acl) 
            {
                If ($ace.IdentityReference -ne $selfName) 
                {
                    $de.ObjectSecurity.RemoveAccessRule($ace) > $null
                }
            }

            # Add specific DACLs on the object
            # Add Full Control for SYSTEM
            $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
            $systemDacl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($systemSid, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AccessControlType]::Allow)
            $de.ObjectSecurity.AddAccessRule($systemDacl)

            # Add Full Control for Enterprise Admins
            $eaSid = GetEnterpriseAdminsSid $Credential
            $eaDacl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($eaSid, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AccessControlType]::Allow)
            $de.ObjectSecurity.AddAccessRule($eaDacl)

            # Add Full Control for Domain Admins
            $daSid = GetDomainAdminsSid $Credential
            $daDacl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($daSid, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AccessControlType]::Allow)
            $de.ObjectSecurity.AddAccessRule($daDacl)

            # Add Full Control for Administrators
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
            $adminDacl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($adminSid, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AccessControlType]::Allow)
            $de.ObjectSecurity.AddAccessRule($adminDacl)

            # Add Generic Read for ENTERPRISE DOMAIN CONTROLLERS
            $edcSid = New-Object System.Security.Principal.SecurityIdentifier($enterpriseDomainControllersSid)
            $edcDacl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($edcSid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, [System.Security.AccessControl.AccessControlType]::Allow)
            $de.ObjectSecurity.AddAccessRule($edcDacl)

            # Add Generic Read for Authenticated Users
            $authenticatedUsersSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid, $null)
            $authenticatedUsersDacl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($authenticatedUsersSid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, [System.Security.AccessControl.AccessControlType]::Allow)
            $de.ObjectSecurity.AddAccessRule($authenticatedUsersDacl)

            $de.CommitChanges()
        }
        Catch [Exception]
        {
            Throw "$functionMsg Setting Restricted permissions on $ADConnectorAccountDN failed. Error Details: $($_.Exception.Message)"
        }
        Finally
        {
            If ($de -ne $null)
            {
                $de.Dispose()
            }			
        }
    }
}

<#
    .SYNOPSIS
        Initialize your Active Directory forest and domain for password hash synchronization.

    .DESCRIPTION
        The Set-ADSyncPasswordHashSyncPermissions Function will give required permissions to the AD synchronization account, which include the following:
        1. Replicating Directory Changes
        2. Replicating Directory Changes All

        These permissions are given to all domains in the forest.

    .PARAMETER ADConnectorAccountName
        The Name of the Active Directory account that will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDomain
        The Domain of the Active Directory account that will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDN
        The DistinguishedName of the Active Directory account that will be used by Azure AD Connect Sync to manage objects in the directory.

    .EXAMPLE
       Set-ADSyncPasswordHashSyncPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com'

    .EXAMPLE
       Set-ADSyncPasswordHashSyncPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com'

#>
Function Set-ADSyncPasswordHashSyncPermissions
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param
    (
        # AD Connector Account Name used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountName,

        # AD Connector Account Domain used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountDomain,

        # AD Connector Account DistinguishedName used by Azure AD Connect Sync
        [Parameter(ParameterSetName='DistinguishedName', Mandatory=$True)] 
        [string] $ADConnectorAccountDN
    )

    # Function init
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')

    # Resolve AD Connector account identity on AD
    $ADConnectorIdentity = ResolveADobject -IdentityName $ADConnectorAccountName -IdentityDomain $ADConnectorAccountDomain -IdentityDN $ADConnectorAccountDN `
                            -IdentityParameterSet $($PSCmdlet.ParameterSetName) -Verbose:$verboseOutput

    # Define AD ACL
    $acls = "`"$ADConnectorIdentity" + ":CA;Replicating Directory Changes`"" + " " 
    $acls += "`"$ADConnectorIdentity" + ":CA;Replicating Directory Changes All`""

    # Set root permissions for all Domains in the Forest
    $message = "Grant Password Hash Synchronization permissions"
    GrantADPermissionsOnAllDomains -ACL $acls -Message $message -SkipAdminSdHolders -Inheritance $inheritanceNone -Verbose:$verboseOutput
}

<#
    .SYNOPSIS
        Initialize your Active Directory forest and domain for password write-back from Azure AD.

    .DESCRIPTION
        The Set-ADSyncPasswordWritebackPermissions Function will give required permissions to the AD synchronization account, which include the following:
        1. Reset Password on descendant user objects
        2. Write Property access on lockoutTime attribute for all descendant user objects
        3. Write Property access on pwdLastSet attribute for all descendant user objects

        These permissions are applied to all domains in the forest.
        Optionally you can provide a DistinguishedName in ADobjectDN parameter to set these permissions on that AD Object only (including inheritance to sub objects).

    .PARAMETER ADConnectorAccountName
        The Name of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDomain
        The Domain of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDN
        The DistinguishedName of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER skipAdminSdHolders
        Optional parameter to indicate if AdminSDHolder container should not be updated with these permissions

    .EXAMPLE
       Set-ADSyncPasswordWritebackPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com'

    .EXAMPLE
       Set-ADSyncPasswordWritebackPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com'

    .EXAMPLE
       Set-ADSyncPasswordWritebackPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com' -SkipAdminSdHolders

    .EXAMPLE
       Set-ADSyncPasswordWritebackPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com' -ADobjectDN 'OU=AzureAD,DC=Contoso,DC=com'
#>
Function Set-ADSyncPasswordWritebackPermissions
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param
    (
        # AD Connector Account Name used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountName,

        # AD Connector Account Domain used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountDomain,

        # AD Connector Account DistinguishedName used by Azure AD Connect Sync
        [Parameter(ParameterSetName='DistinguishedName', Mandatory=$True)] 
        [string] $ADConnectorAccountDN,

        # DistinguishedName of the target AD object to set permissions (optional)
        [string] $ADobjectDN = $null,
        
        # Skip permissions on the AdminSdHolders container (optional)
        [switch] $SkipAdminSdHolders = $false
    )

    # Function init
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')

    # Resolve AD Connector account identity on AD
    $ADConnectorIdentity = ResolveADobject -IdentityName $ADConnectorAccountName -IdentityDomain $ADConnectorAccountDomain -IdentityDN $ADConnectorAccountDN `
                            -IdentityParameterSet $($PSCmdlet.ParameterSetName) -Verbose:$verboseOutput

    # Define AD ACL
    $acls = "`"$ADConnectorIdentity" + ":CA;Reset Password;user`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":WP;lockoutTime;user`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":WP;pwdLastSet;user`""

    # Check if setting permissions on a AD object only
    $message = "Grant Password Writeback permissions"
    If ($ADobjectDN -notlike $null)
    {
        # Set AD Permissions on a target AD object
        GrantADPermissionsOnADobject -ACL $acls -ADobjectDN $ADobjectDN -Message $message -Verbose:$verboseOutput
    }
    Else
    {
        # Set root permissions for all Domains in the Forest
        GrantADPermissionsOnAllDomains -ACL $acls -Message $message -SkipAdminSdHolders:$SkipAdminSdHolders -Verbose:$verboseOutput
    }
}

<#
    .SYNOPSIS
        Initialize your Active Directory forest and domain for Group writeback from Azure AD.

    .DESCRIPTION
        The Set-ADSyncUnifiedGroupWritebackPermissions Function will give required permissions to the AD synchronization account, which include the following:
        1. Generic Read/Write, Delete, Delete Tree and Create\Delete Child for group Object types and SubObjects

        These permissions are applied to all domains in the forest.
        Optionally you can provide a DistinguishedName in ADobjectDN parameter to set these permissions on that AD Object only (including inheritance to sub objects).
        In this case, ADobjectDN will be the Distinguished Name of the Container that you desire to link with the GroupWriteback feature.

    .PARAMETER ADConnectorAccountName
        The Name of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDomain
        The Domain of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDN
        The DistinguishedName of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER skipAdminSdHolders
        Optional parameter to indicate if AdminSDHolder container should not be updated with these permissions

    .EXAMPLE
       Set-ADSyncUnifiedGroupWritebackPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com'

    .EXAMPLE
       Set-ADSyncUnifiedGroupWritebackPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com'

    .EXAMPLE
       Set-ADSyncUnifiedGroupWritebackPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com' -SkipAdminSdHolders

    .EXAMPLE
       Set-ADSyncUnifiedGroupWritebackPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com' -ADobjectDN 'OU=AzureAD,DC=Contoso,DC=com'
#>
Function Set-ADSyncUnifiedGroupWritebackPermissions
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param
    (
        # AD Connector Account Name used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountName,

        # AD Connector Account Domain used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountDomain,

        # AD Connector Account DistinguishedName used by Azure AD Connect Sync
        [Parameter(ParameterSetName='DistinguishedName', Mandatory=$True)] 
        [string] $ADConnectorAccountDN,

        # DistinguishedName of the target AD object to set permissions (optional)
        [string] $ADobjectDN = $null,
        
        # Skip permissions on the AdminSdHolders container (optional)
        [switch] $SkipAdminSdHolders = $false
    )

    # Function init
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')

    # Resolve AD Connector account identity on AD
    $ADConnectorIdentity = ResolveADobject -IdentityName $ADConnectorAccountName -IdentityDomain $ADConnectorAccountDomain -IdentityDN $ADConnectorAccountDN `
                            -IdentityParameterSet $($PSCmdlet.ParameterSetName) -Verbose:$verboseOutput

    # Define AD ACL
    $acls = "`"$ADConnectorIdentity" + ":GRGWCCDCSDDT;;group`""

    # Check if setting permissions on a AD object only
    $message = "Grant Group Writeback permissions"
    If ($ADobjectDN -notlike $null)
    {
        # Set AD Permissions on a target AD object
        GrantADPermissionsOnADobject -ACL $acls -ADobjectDN $ADobjectDN -Message $message -ForceInheritanceOnThisAndSubObjects -Verbose:$verboseOutput
    }
    Else
    {
        # Set root permissions for all Domains in the Forest
        GrantADPermissionsOnAllDomains -ACL $acls -Message $message -SkipAdminSdHolders:$SkipAdminSdHolders -Verbose:$verboseOutput
    }
}

<#
    .SYNOPSIS
        Initialize your Active Directory forest and domain for mS-DS-ConsistencyGuid feature.

    .DESCRIPTION
        The Set-ADSyncMsDsConsistencyGuidPermissions Function will give required permissions to the AD synchronization account, which include the following:
        1. Read/Write Property access on mS-DS-ConsistencyGuid attribute for all descendant user objects

        These permissions are applied to all domains in the forest.
        Optionally you can provide a DistinguishedName in ADobjectDN parameter to set these permissions on that AD Object only (including inheritance to sub objects).

    .PARAMETER ADConnectorAccountName
        The Name of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDomain
        The Domain of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDN
        The DistinguishedName of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER skipAdminSdHolders
        Optional parameter to indicate if AdminSDHolder container should not be updated with these permissions

    .EXAMPLE
       Set-ADSyncMsDsConsistencyGuidPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com'

    .EXAMPLE
       Set-ADSyncMsDsConsistencyGuidPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com'

    .EXAMPLE
       Set-ADSyncMsDsConsistencyGuidPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com' -SkipAdminSdHolders

    .EXAMPLE
       Set-ADSyncMsDsConsistencyGuidPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com' -ADobjectDN 'OU=AzureAD,DC=Contoso,DC=com'
#>
Function Set-ADSyncMsDsConsistencyGuidPermissions
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param(
        # AD Connector Account Name used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountName,

        # AD Connector Account Domain used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountDomain,

        # AD Connector Account DistinguishedName used by Azure AD Connect Sync
        [Parameter(ParameterSetName='DistinguishedName', Mandatory=$True)] 
        [string] $ADConnectorAccountDN,

        # DistinguishedName of the target AD object to set permissions (optional)
        [string] $ADobjectDN = $null,
        
        # Skip permissions on the AdminSdHolders container (optional)
        [switch] $SkipAdminSdHolders = $false
    )	

    # Function init
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')

    # Resolve AD Connector account identity on AD
    $ADConnectorIdentity = ResolveADobject -IdentityName $ADConnectorAccountName -IdentityDomain $ADConnectorAccountDomain -IdentityDN $ADConnectorAccountDN `
                            -IdentityParameterSet $($PSCmdlet.ParameterSetName) -Verbose:$verboseOutput

    # Define AD ACL
    $acls = "`"$ADConnectorIdentity" + ":RPWP;mS-DS-ConsistencyGuid;user`""

    # Check if setting permissions on a AD object only
    $message = "Grant mS-DS-ConsistencyGuid permissions"
    If ($ADobjectDN -notlike $null)
    {
        # Set AD Permissions on a target AD object
        GrantADPermissionsOnADobject -ACL $acls -ADobjectDN $ADobjectDN -Message $message -Verbose:$verboseOutput
    }
    Else
    {
        # Set root permissions for all Domains in the Forest
        GrantADPermissionsOnAllDomains -ACL $acls -Message $message -SkipAdminSdHolders:$SkipAdminSdHolders -Verbose:$verboseOutput
    }
}

<#
    .SYNOPSIS
        Initialize your Active Directory forest and domain for Exchange Mail Public Folder feature.

    .DESCRIPTION
        The Set-ADSyncExchangeMailPublicFolderPermissions Function will give required permissions to the AD synchronization account, which include the following:
        1. Read Property access on all attributes for all descendant publicfolder objects

        These permissions are applied to all domains in the forest.
        Optionally you can provide a DistinguishedName in ADobjectDN parameter to set these permissions on that AD Object only (including inheritance to sub objects).

    .PARAMETER ADConnectorAccountName
        The Name of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDomain
        The Domain of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDN
        The DistinguishedName of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER skipAdminSdHolders
        Optional parameter to indicate if AdminSDHolder container should not be updated with these permissions

    .EXAMPLE
       Set-ADSyncExchangeMailPublicFolderPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com'

    .EXAMPLE
       Set-ADSyncExchangeMailPublicFolderPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com'

    .EXAMPLE
       Set-ADSyncExchangeMailPublicFolderPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com' -SkipAdminSdHolders

    .EXAMPLE
       Set-ADSyncExchangeMailPublicFolderPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com' -ADobjectDN 'OU=AzureAD,DC=Contoso,DC=com'
#>
Function Set-ADSyncExchangeMailPublicFolderPermissions
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param(
        # AD Connector Account Name used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountName,

        # AD Connector Account Domain used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountDomain,

        # AD Connector Account DistinguishedName used by Azure AD Connect Sync
        [Parameter(ParameterSetName='DistinguishedName', Mandatory=$True)] 
        [string] $ADConnectorAccountDN,

        # DistinguishedName of the target AD object to set permissions (optional)
        [string] $ADobjectDN = $null,
        
        # Skip permissions on the AdminSdHolders container (optional)
        [switch] $SkipAdminSdHolders = $false
    )

    # Function init
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')

    # Resolve AD Connector account identity on AD
    $ADConnectorIdentity = ResolveADobject -IdentityName $ADConnectorAccountName -IdentityDomain $ADConnectorAccountDomain -IdentityDN $ADConnectorAccountDN `
                            -IdentityParameterSet $($PSCmdlet.ParameterSetName) -Verbose:$verboseOutput

    # Define AD ACL
    $acls = "`"$ADConnectorIdentity" + ":RP;;publicFolder`""

    # Check if setting permissions on a AD object only
    $message = "Grant Exchange Mail Public Folder permissions"
    If ($ADobjectDN -notlike $null)
    {
        # Set AD Permissions on a target AD object
        GrantADPermissionsOnADobject -ACL $acls -ADobjectDN $ADobjectDN -Message $message -Verbose:$verboseOutput
    }
    Else
    {
        # Set root permissions for all Domains in the Forest
        GrantADPermissionsOnAllDomains -ACL $acls -Message $message -SkipAdminSdHolders:$SkipAdminSdHolders -Verbose:$verboseOutput
    }
}

<#.SYNOPSIS
        Initialize your Active Directory forest and domain for Exchange Hybrid feature.

    .DESCRIPTION
        The Set-ADSyncExchangeHybridPermissions Function will give required permissions to the 
        AD synchronization account, which include the following:
        1. Read/Write Property access on all attributes for all descendant user objects
        2. Read/Write Property access on all attributes for all descendant inetorgperson objects
        3. Read/Write Property access on all attributes for all descendant group objects
        4. Read/Write Property access on all attributes for all descendant contact objects

        These permissions are applied to all domains in the forest.
        Optionally you can provide a DistinguishedName in ADobjectDN parameter to set these permissions on that AD Object only (including inheritance to sub objects).

    .PARAMETER ADConnectorAccountName
        The Name of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDomain
        The Domain of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDN
        The DistinguishedName of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER skipAdminSdHolders
        Optional parameter to indicate if AdminSDHolder container should not be updated with these permissions

    .EXAMPLE
       Set-ADSyncExchangeHybridPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com'

    .EXAMPLE
       Set-ADSyncExchangeHybridPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com'

    .EXAMPLE
       Set-ADSyncExchangeHybridPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com' -SkipAdminSdHolders

    .EXAMPLE
       Set-ADSyncExchangeHybridPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com' -ADobjectDN 'OU=AzureAD,DC=Contoso,DC=com'
#>
Function Set-ADSyncExchangeHybridPermissions
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param
    (
        # AD Connector Account Name used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountName,

        # AD Connector Account Domain used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountDomain,

        # AD Connector Account DistinguishedName used by Azure AD Connect Sync
        [Parameter(ParameterSetName='DistinguishedName', Mandatory=$True)] 
        [string] $ADConnectorAccountDN,

        # DistinguishedName of the target AD object to set permissions (optional)
        [string] $ADobjectDN = $null,
        
        # Skip permissions on the AdminSdHolders container (optional)
        [switch] $SkipAdminSdHolders = $false
    )

    # Function init
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')

    # Resolve AD Connector account identity on AD
    $ADConnectorIdentity = ResolveADobject -IdentityName $ADConnectorAccountName -IdentityDomain $ADConnectorAccountDomain -IdentityDN $ADConnectorAccountDN `
                            -IdentityParameterSet $($PSCmdlet.ParameterSetName) -Verbose:$verboseOutput
    
    # Define AD ACL
    $acls  = "`"$ADConnectorIdentity" + ":RPWP;;user`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RPWP;;inetorgperson`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RPWP;;group`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RPWP;;contact`""

    # Check if setting permissions on a AD object only
    $message = "Grant Exchange Hybrid permissions"
    If ($ADobjectDN -notlike $null)
    {
        # Set AD Permissions on a target AD object
        GrantADPermissionsOnADobject -ACL $acls -ADobjectDN $ADobjectDN -Message $message -Verbose:$verboseOutput
    }
    Else
    {
        # Set root permissions for all Domains in the Forest
        GrantADPermissionsOnAllDomains -ACL $acls -Message $message -SkipAdminSdHolders:$SkipAdminSdHolders -Verbose:$verboseOutput
    }
}

<#
    .SYNOPSIS
        Initialize your Active Directory forest and domain for basic read permissions.

    .DESCRIPTION
        The Set-ADSyncBasicReadPermissions Function will give required permissions to the AD synchronization account, which include the following:
        1. Read Property access on all attributes for all descendant computer objects
        2. Read Property access on all attributes for all descendant device objects
        3. Read Property access on all attributes for all descendant foreignsecurityprincipal objects
        5. Read Property access on all attributes for all descendant user objects
        6. Read Property access on all attributes for all descendant inetorgperson objects
        7. Read Property access on all attributes for all descendant group objects
        8. Read Property access on all attributes for all descendant contact objects

        These permissions are applied to all domains in the forest.
        Optionally you can provide a DistinguishedName in ADobjectDN parameter to set these permissions on that AD Object only (including inheritance to sub objects).

    .PARAMETER ADConnectorAccountName
        The Name of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDomain
        The Domain of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER ADConnectorAccountDN
        The DistinguishedName of the Active Directory account that is or will be used by Azure AD Connect Sync to manage objects in the directory.

    .PARAMETER skipAdminSdHolders
        Optional parameter to indicate if AdminSDHolder container should not be updated with these permissions

    .EXAMPLE
       Set-ADSyncBasicReadPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com'

    .EXAMPLE
       Set-ADSyncBasicReadPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com'

    .EXAMPLE
       Set-ADSyncBasicReadPermissions -ADConnectorAccountDN 'CN=ADConnector,OU=AzureAD,DC=Contoso,DC=com' -SkipAdminSdHolders

    .EXAMPLE
       Set-ADSyncBasicReadPermissions -ADConnectorAccountName 'ADConnector' -ADConnectorAccountDomain 'Contoso.com' -ADobjectDN 'OU=AzureAD,DC=Contoso,DC=com'
#>
Function Set-ADSyncBasicReadPermissions
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param(
        # AD Connector Account Name used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountName,

        # AD Connector Account Domain used by Azure AD Connect Sync
        [Parameter(ParameterSetName='UserDomain', Mandatory=$True)] 
        [string] $ADConnectorAccountDomain,

        # AD Connector Account DistinguishedName used by Azure AD Connect Sync
        [Parameter(ParameterSetName='DistinguishedName', Mandatory=$True)] 
        [string] $ADConnectorAccountDN,

        # DistinguishedName of the target AD object to set permissions (optional)
        [string] $ADobjectDN = $null,
        
        # Skip permissions on the AdminSdHolders container (optional)
        [switch] $SkipAdminSdHolders = $false
    )

    # Function init
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')

    # Resolve AD Connector account identity on AD
    $ADConnectorIdentity = ResolveADobject -IdentityName $ADConnectorAccountName -IdentityDomain $ADConnectorAccountDomain -IdentityDN $ADConnectorAccountDN `
                            -IdentityParameterSet $($PSCmdlet.ParameterSetName) -Verbose:$verboseOutput

    # Define AD ACL
    $acls = "`"$ADConnectorIdentity" + ":RP;;computer`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RP;;device`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RP;;foreignsecurityprincipal`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RP;;user`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RP;;inetorgperson`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RP;;group`"" + " "
    $acls += "`"$ADConnectorIdentity" + ":RP;;contact`""

    # Check if setting permissions on a AD object only
    $message = "Grant basic read permissions"
    If ($ADobjectDN -notlike $null)
    {
        # Set AD Permissions on a target AD object
        GrantADPermissionsOnADobject -ACL $acls -ADobjectDN $ADobjectDN -Message $message -Verbose:$verboseOutput
    }
    Else
    {
        # Set root permissions for all Domains in the Forest
        GrantADPermissionsOnAllDomains -ACL $acls -Message $message -SkipAdminSdHolders:$SkipAdminSdHolders -Verbose:$verboseOutput
    }
}

<#
    .SYNOPSIS
        Gets AD objects with permission inheritance disabled

    .DESCRIPTION
        Searches in AD starting from the SearchBase parameter and returns all objects, filtered by ObjectClass parameter, that have the ACL Inheritance currently disabled.

    .PARAMETER SearchBase
        The SearchBase for the LDAP query that can be an AD Domain DistinguishedName or a FQDN

    .PARAMETER ObjectClass
        The class of the objects to search that can be '*' (for any object class), 'user', 'group', 'container', etc. By default, this function will search for 'organizationalUnit' object class.

    .EXAMPLE
        Find objects with disabled inheritance in 'Contoso' domain (by default returns 'organizationalUnit' objects only)
        Get-ADSyncObjectsWithInheritanceDisabled -SearchBase 'Contoso' 

    .EXAMPLE
        Find 'user' objects with disabled inheritance in 'Contoso' domain
        Get-ADSyncObjectsWithInheritanceDisabled -SearchBase 'Contoso' -ObjectClass 'user'

    .EXAMPLE
        Find all types of objects with disabled inheritance in a OU
        Get-ADSyncObjectsWithInheritanceDisabled -SearchBase OU=AzureAD,DC=Contoso,DC=com -ObjectClass '*'
#>
Function Get-ADSyncObjectsWithInheritanceDisabled
{
    [CmdletBinding()]    
    Param
    (
        [Parameter(Mandatory=$True,Position=0)]
        [String] $SearchBase,

        [Parameter(Mandatory=$False,Position=1)] 
        [String] $ObjectClass = 'organizationalUnit'
    )

    # Function init
    $functionMsg = "Get-ADSyncObjectsWithInheritanceDisabled :"
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')

    Try
    {
        # Init a DirectorySearcher object
        $ldapFilter = "(&(ObjectClass=$ObjectClass))"
        $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$SearchBase", $ldapFilter)
    }
    Catch
    {
        Throw "$functionMsg Unable to search Active Directory. Error Details: $($_.Exception.Message)"
    }

    Try
    {
        # Search All Objects
        Write-Verbose "$functionMsg Searching for objects in AD with LDAP Filter: $ldapFilter"
        $allADobjects = $DirectorySearcher.FindAll()
    }
    Catch
    {
        Throw "$functionMsg Unable to query Active Directory. Error Details: $($_.Exception.Message)"
    }

    # Check if Inheritance is Disabled
    Foreach ($object in $allADobjects) 
    {
        $object = $object.GetDirectoryEntry()
        Write-Verbose "$functionMsg $($object.DistinguishedName)"
        If ($object.ObjectSecurity.AreAccessRulesProtected -eq $True)
        {
            ResolveADobject -IdentityDN $object.DistinguishedName -IdentityParameterSet 'DistinguishedName' -ReturnADobject -Verbose:$verboseOutput
        }
    }
}

<#
.Synopsis
   Shows permissions of a specified AD object.
.DESCRIPTION
   This function retuns all the AD permissions currently set for a given AD object provided in the parameter -ADobjectDN.
   The ADobjectDN must be provided in a DistinguishedName format.
.EXAMPLE
   Show-ADSyncADObjectPermissions -ADobjectDN 'OU=AzureAD,DC=Contoso,DC=com'
#>
Function Show-ADSyncADObjectPermissions
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$True,Position=0)] 
        [string] $ADobjectDN
    )
    # Function init
    $functionMsg = "Get-ADSyncADObjectPermissions :"

    $cmd = "dsacls.exe `"$ADobjectDN`""
    Write-Verbose "$functionMsg Executing command : $cmd"
    
    # Execute DSACLS.exe
    $result = Invoke-Expression $cmd
    
    If ($lastexitcode -eq 0)
    {
        $result
    }
    Else
    {
        Throw "$functionMsg $result"
    }
}

<#
.Synopsis
   Gets the account name and domain that is configured in each AD Connector
.DESCRIPTION
   This function uses the 'Get-ADSyncConnector' cmdlet that is present in AAD Connect to retrieve from Connectivity Parameters a table showing the AD Connector(s) account.
.EXAMPLE
   Get-ADSyncADConnectorAccount
#>
Function Get-ADSyncADConnectorAccount
{
    $cmdlet = 'Get-ADSyncConnector'
    Try
    {
        Get-Command $cmdlet -ErrorAction Stop | Out-Null
    }
    Catch
    {
        Write-Error "Failure calling '$cmdlet' cmdlet. This function can only be executed with AAD Connect installed."
        Return $null
    }

    $adConnectors = Get-ADSyncConnector | where {$_.ConnectorTypeName -eq 'AD'}
    $adSyncADConnectorAccount = @()
    ForEach ($connector in $adConnectors)
    {
        $connectorAccount = "" | Select ADConnectorName, ADConnectorAccountName, ADConnectorAccountDomain
        $connectorAccount.ADConnectorName = $connector.Name
        $connectorAccount.ADConnectorAccountName = ($connector.ConnectivityParameters | Where {$_.Name -eq 'forest-login-user'}).Value
        $connectorAccount.ADConnectorAccountDomain = ($connector.ConnectivityParameters | Where {$_.Name -eq 'forest-login-domain'}).Value
        $adSyncADConnectorAccount += $connectorAccount
    }
    $adSyncADConnectorAccount

}

# Grants permissions to specified ObjectDN
Function GrantAcls
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$True,Position=0)] 
        [string] $ObjectDN,

        [Parameter(Mandatory=$True,Position=1)] 
        [string[]] $ACLs,

        [Parameter(Mandatory=$True,Position=2)] 
        [char] $InheritFlag
    )
    
    $cmd = "dsacls.exe `"$ObjectDN`" /G $ACLs /I:$InheritFlag"
    Write-Verbose "Grant ACLs : Executing command : $cmd"
    
    # Execute DSACLS.exe
    $result = Invoke-Expression $cmd
    
    If ($lastexitcode -eq 0)
    {
        $result
    }
    Else
    {
        $noExchangeShemaError = $result | Where {$_ -like "*No GUID Found for publicFolder*"}
        If (($noExchangeShemaError | Measure-Object).Count -gt 0)
        {
            Write-Error "AD Schema for Exchange not present : $result"
        }
        Else
        {
            Write-Error "$result"
        }
    }
}

# Grants permissions to specified ObjectDN
Function GrantAclsNoInheritance
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$True,Position=0)] 
        [string] $ObjectDN,

        [Parameter(Mandatory=$True,Position=1)] 
        [string[]] $ACLs
    )

    $cmd = "dsacls.exe `"$ObjectDN`" /G $ACLs"
    Write-Verbose "Grant ACLs without Inheritance : Executing command : $cmd"
    
    # Execute DSACLS.exe
    $result = Invoke-Expression $cmd
    
    If ($lastexitcode -eq 0)
    {
        $result
    }
    Else
    {
        Write-Error "$result"
    }

}

# Converts a FQDN to domain DistinguishedName
Function ConvertFQDNtoDN
{
    Param 
    (
        [Parameter(Mandatory=$True,Position=0)] [String] $FQDN
    )

    ForEach ($domain in $($FQDN.Split($periodSeparator)))
    {
        $dn = $dn + $connector + "DC=" + $domain
        $connector = $commaSeparator
    }
    Return $dn
}

# Converts a domain DistinguishedName to FQDN
Function ConvertDNtoFQDN
{
    Param 
    (
        [Parameter(Mandatory=$True,Position=0)] [String] $DN
    )

    ForEach ($domain in $($DN  -split $commaSeparator))
    {
        $fqdn += "$($domain.Substring(3))."
    }
    
    # Remove the last dot
    $fqdn = $fqdn.Substring(0,$fqdn.Length -1)
    
    Return $fqdn
}

# Get list of Domains in the Forest
Function GetADDomains
{
    [CmdletBinding()]
    Param()

    # Function init
    $functionMsg = "Get AD Domains :"
    
    Try
    {
        Write-Verbose "$functionMsg Retrieving list of Domains in the Forest..."
        $forest = Get-ADForest -ErrorAction Stop
    }
    Catch
    {
        Throw "$functionMsg Unable to get list of Domains in the Forest. Exception Details: $($_.Exception.Message)"
    }

    Return $($forest.Domains)
}

Function ResolveADobject
{
    [CmdletBinding()]
    Param(
        [string] $IdentityName,

        [string] $IdentityDomain,

        [string] $IdentityDN,

        [string] $IdentityParameterSet,

        [switch] $ReturnADobject
    )
    
    # Check if AD PowerShell Module is installed
    ImportADmodule

    # Init
    $functionMsg = "Resolve AD object :"
    Write-Verbose "ParameterSetName: $IdentityParameterSet"

    switch ($IdentityParameterSet)
    {
        'UserDomain' 
        {
            # Search for AD object using object name and target domain
            Write-Verbose "$functionMsg Resolving AD object '$IdentityName' in Domain '$IdentityDomain'..."
            Try
            {        
                $targetDomain = Get-ADDomain -Identity $IdentityDomain -ErrorAction Stop
            }
            Catch
            {
                Throw "$functionMsg Unable to find Domain '$IdentityDomain' in AD Forest. Exception Details: $($_.Exception.Message)"
            }

            $ldapFilter = "(|(Name=$IdentityName)(sAMAccountName=$IdentityName))"
            $targetDomainDNSname = $targetDomain.DNSRoot
            Write-Verbose "$functionMsg LDAP Filter to search object: $ldapFilter"
            Write-Verbose "$functionMsg Target Domain to search object: $targetDomainDNSname"

            Try
            {
                $adObject = Get-ADObject -LDAPFilter $ldapFilter -Server $targetDomainDNSname -Properties $defaultADobjProperties -ErrorAction Stop
            }
            Catch
            {
                Throw "$functionMsg Unable to get object '$IdentityName' in AD Forest. Exception Details: $($_.Exception.Message)"
            }
        }
        'DistinguishedName' 
        {
            # Search for AD object using DistinguishedName against an AD Global Catalog (AD Forest wide search)
            Write-Verbose "$functionMsg Resolving AD object DN $IdentityDN..."
            If ($IdentityDN -match $distinguishedNameRegex)
            {
                Write-Verbose "$functionMsg Matches in DistinguishedName input: $($Matches.Values | %{"$_;"})"
                $IdentityDomainDN = $Matches.domain
                $IdentityName = $Matches.name

                Try
                {
                    # Get an array of Domain Controllers running Global Catalog service 
                    $globalCatalogSrv = @(Get-ADDomainController -Discover -Service GlobalCatalog -ErrorAction Stop)
                }
                Catch
                {
                    Throw "$functionMsg Unable to find a Global Catalog DC in AD. Exception Details: $($_.Exception.Message)"
                }
    
                If (($globalCatalogSrv | Measure-Object).Count -gt 0)
                {
                    # Pick the first DC in the array and add the GC port
                    $globalCatalogHost = [string] $globalCatalogSrv[0].HostName[0].ToString() + ":3268"
                    Write-Verbose "$functionMsg Target Global Catalog Server to search object: $globalCatalogHost"
                }
                Else
                {
                    Throw "$functionMsg Could not find any available Global Catalog DC in AD."
                }

                Try
                {
                    # Get the AD object based on the DistinguishedName from a GC server in AD
                    $adObject = Get-ADObject -Identity $IdentityDN -Server $globalCatalogHost -Properties $defaultADobjProperties -ErrorAction Stop
                }
                Catch
                {
                    Throw "$functionMsg Unable to get object '$IdentityDN' in AD Forest. Exception Details: $($_.Exception.Message)"
                }

                # If going to return Domain\Username, need to get the AD Domain object
                If (-not $ReturnADobject)
                {
                    $IdentityDomain = ConvertDNtoFQDN $IdentityDomainDN

                    Try
                    {        
                        Write-Verbose "$functionMsg Resolving AD Domain '$IdentityDomain'..."
                        $targetDomain = Get-ADDomain -Identity $IdentityDomain -ErrorAction Stop
                    }
                    Catch
                    {
                        Throw "$functionMsg Unable to find Domain '$IdentityDomain' in AD Forest. Exception Details: $($_.Exception.Message)"
                    }
                }
            }
            Else
            {
                Throw "$functionMsg Cannot validate argument on parameter 'ADConnectorAccountDN'. The argument '$IdentityDN' does not match a DistinguishedName format."
            }
        }
    }

    # If found, return the identity
    If ($adObject -ne $null)
    {
        If ($ReturnADobject) 
        {
            # Return AD object
            Write-Verbose "$functionMsg Returning AD object: $($adObject.Name)"
            Return $adObject
        }
        Else
        {
            # Get the domain NetBIOS name and return Domain\Username
            $targetDomainNetBIOS = $targetDomain.NetBIOSName
            $targetUsername = $adObject.sAMAccountName
            Write-Verbose "$functionMsg Returning NetBIOS Domain name: $targetDomainNetBIOS"
            Write-Verbose "$functionMsg Returning Username: $targetUsername"
            $identity = [String] $targetDomainNetBIOS + "\" + $targetUsername
            Return $identity
        }
    }
    Else
    {
        Throw "$functionMsg Unable to find '$IdentityName' in AD Forest."
    }
}

# Sets permissions on a target AD object
Function GrantADPermissionsOnADobject
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param
    (
        # AD permission ACEs to set
        [Parameter(Mandatory=$True)] 
        [ValidateNotNullOrEmpty()] 
        [String] $ACL,

        # DistinguishedName of the target AD object to set permissions
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()] 
        [String] $ADobjectDN,

        # Permissions description message for console output
        [String] $Message = "Grant Active Directory Permissions",

        # Forces inheritance on ThisAndSubObjects
        [switch] $ForceInheritanceOnThisAndSubObjects
    )

    # Function init
    ImportADmodule
    $functionMsg = "Grant permissions on AD object :"
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')
    Write-Verbose "$functionMsg AD permissions ACEs to add: $ACL"

    # Search for AD object using DistinguishedName
    $targetADObj = ResolveADobject -IdentityDN $ADobjectDN -IdentityParameterSet 'DistinguishedName' -ReturnADobject -Verbose:$verboseOutput
    $targetADObjClass = $targetADObj.ObjectClass
    Write-Verbose "$functionMsg Target AD Object Class: $targetADObjClass"

    # Default action: set permission Inheritance for AD objects - This object and subobjects
    $Inheritance = $inheritanceThisAndSubObjects

    If (($targetADObjClass -eq 'organizationalUnit' -or $targetADObjClass -eq 'container') -and -not $ForceInheritanceOnThisAndSubObjects)
    {
        # Set permission Inheritance for OUs and Containers - Subobjects only
        $Inheritance = $inheritanceSubObjectsOnly
        $finalACL = $ACL
    }
    Else
    {
        # Adapt ACL to target the specific AD object
        $ACEarray = $ACL -split $aclSeparator
        $targetADObjACL = @()

        # For each ACE, check if applies to an ObjectClass and if the ObjectClass matches the target AD object
        ForEach ($ace in $ACEarray)
        {
            $indexOfObjClass = $ace.LastIndexOf(";")
            If ($indexOfObjClass -lt 0)
            {
                # No ObjectClass defined in ACE - applies to all objects
                $targetADObjACL += $ace
            }
            Else
            {
                # Specific ObjectClass defined in ACE - applies only if the same as the target object
                $aceTargetClass = $ace.Substring($indexOfObjClass)
                If ($aceTargetClass.Contains($targetADObjClass))
                {
                    # Take this ACE but remove the InheritedObjectType since we will apply ACL to a non-container object
                    $targetADObjACL += $ace -replace ";$targetADObjClass", ""
                }
            }
        }

        # Finalize the filtered ACEs for the target AD object
        If (($targetADObjACL | Measure-Object).Count -eq 0)
        {
             Throw "$functionMsg AD permissions are not applicable for AD ObjectClass '$targetADObjClass': $ACL"
        }
        Else
        {
            # Glue all the ACEs in a string back again separated by $aclSeparator
            $finalACL = $null
            for ($i = 0; $i -lt $targetADObjACL.Count-1; $i++)
            { 
                $finalACL += [String] $targetADObjACL[$i]+ $aclSeparator
            }
            $finalACL += [String] $targetADObjACL[$targetADObjACL.Count-1]
        }
        
        # Enclose all the ACEs in double quotes
        If ($finalACL[0] -ne '"') 
        {
            $finalACL =  '"' + $finalACL
        }
        If ($finalACL[$finalACL.Length-1] -ne '"') 
        {
            $finalACL =  $finalACL + '"'
        }
        Write-Verbose  "$functionMsg AD permissions ACEs for target AD object: $finalACL"
    }

    # Set AD Permissions on a target AD object
    If ($PSCmdlet.ShouldProcess($targetADObj.Name, $Message)) 
    {
        Write-Output "$functionMsg Setting permissions on AD object '$($targetADObj.DistinguishedName)'..."
        GrantAcls $targetADObj.DistinguishedName $finalACL $Inheritance -Verbose:$verboseOutput
    }
    Else
    {
        Write-Verbose "$functionMsg Operation canceled."
    }
}

# Sets permissions on all Domains in the Forest
Function GrantADPermissionsOnAllDomains
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="high")]
    Param
    (
        # AD permission ACEs to set
        [Parameter(Mandatory=$True)] 
        [ValidateNotNullOrEmpty()] 
        [String] $ACL,

        # Skip permissions on the AdminSdHolders container
        [Switch] $SkipAdminSdHolders,

        # Permission Inheritance
        [String] $Inheritance = $inheritanceSubObjectsOnly,

        # Permissions description message for console output
        [String] $Message = "Grant Active Directory Permissions"
    )

    # Function init
    ImportADmodule
    $functionMsg = "Grant permissions on all Domains :"
    $verboseOutput = $PSBoundParameters.ContainsKey('Verbose')
    Write-Verbose "$functionMsg AD permissions ACEs to add: $ACL"

    # Get list of all Domains in the Forest
    $domains = GetADDomains 

    # Set root permissions for all Domains in the Forest
    ForEach($domain in $domains) 
    {
        If ($PSCmdlet.ShouldProcess($domain, $Message)) 
        {
            $domainDN = ConvertFQDNtoDN -FQDN $domain
            Write-Output "$functionMsg AD Domain '$domainDN'..."
            If ($Inheritance -eq $inheritanceNone)
            {
                GrantAclsNoInheritance $domainDN $ACL -Verbose:$verboseOutput
            }
            Else
            {
                GrantAcls $domainDN $ACL $Inheritance -Verbose:$verboseOutput
            }

            # Check if setting permissions on AdminSdHolder container
            If ($SkipAdminSdHolders) 
            {
                Write-Output "$functionMsg Skipping permissions on AdminSDHolder container of '$domainDN'."
            }
            Else 
            {
                Try 
                {
                    Write-Output "$functionMsg Setting permissions on AdminSDHolder container of '$domainDN'"
                    $adminSDHolderDN = (Get-ADObject -Server $domain -Filter "Name -like 'adminsdholder'").DistinguishedName
                }
                Catch 
                {
                    Throw "$functionMsg Unable to get AdminSDHolder container of '$domainDN'. Exception details: $($_.Exception)"
                }
                # Setting permissions on AdminSdHolder container
                GrantAcls $adminSDHolderDN $ACL $Inheritance -Verbose:$verboseOutput
            }
        }
        Else
        {
            Write-Verbose "$functionMsg Operation canceled."
        }
    }
}

Function TestCredential
{
    Param(
        [Parameter(Mandatory=$True)] 
        [System.Management.Automation.PSCredential] $Credential
    )

    # Function init
    $functionMsg = "Test Credential :"
    $networkCredential = $Credential.GetNetworkCredential()

    If ($networkCredential.UserName.Contains("@") -or $networkCredential.Domain.ToString() -eq "")
    {
        Throw [System.ArgumentException] "$functionMsg Validating credential parameter failed. Credential should use the fully qualified domain name of the administrator account. Example: CONTOSO\admin"
    }
    
    Try
    {
        # $Credential.UserName == FQDN\Username, $networkCredential.UserName == just the Username portion.  We need to use the FQDN from here
        $dc = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $networkCredential.Domain, $Credential.UserName, $networkCredential.Password) -ErrorAction Stop
    }
    Catch
    {
        Throw [System.ArgumentException] "$functionMsg Validating credential parameter failed. Unable to use credentials to access AD. Error Details: $($_.Exception.Message)"
    }

    Try
    {
        # Validating credential
        $credentialValid = $false
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($dc)
        $enterpriseAdminsSid = GetEnterpriseAdminsSid $Credential
        $domainAdminsSid = GetDomainAdminsSid $Credential

        $domainDE = $domain.GetDirectoryEntry()
        $searchFilter = "(samAccountName=$($networkCredential.UserName))"
        $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($domainDE, $searchFilter)

        $searchResult = $directorySearcher.FindOne()
        If ($searchResult -eq $null)
        {
            Throw [System.ArgumentException] "$functionMsg Validating credential parameter failed. Admin account '$($Credential.UserName)' could not be found."
        }

        $adminDE = $searchResult.GetDirectoryEntry()

        [string[]] $propertyName = @("tokenGroups")
        $adminDE.RefreshCache($propertyName)
        ForEach ($resultBytes in $adminDE.Properties["tokenGroups"])
        {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($resultBytes, 0)
            If ($sid.Equals($enterpriseAdminsSid) -or $sid.Equals($domainAdminsSid))
            {
                $credentialValid = $true
                Break
            }
        }

        If (!$credentialValid)
        {
            Throw [System.ArgumentException] "$functionMsg Validating credential parameter failed. Enterprise Admin or Domain Admin credential is required to restrict permissions on the account."
        }
    }
    Catch [Exception]
    {
        Throw "$functionMsg Validating credential parameter failed. Error Details: $($_.Exception.Message)"
    }
    Finally
    {
        # Clean up memory
        If ($domain -ne $null)
        {
            $domain.Dispose()
        }

        If ($domainDE -ne $null)
        {
            $domainDE.Dispose()
        }

        If ($directorySearcher -ne $null)
        {
            $directorySearcher.Dispose()
        }

        If ($adminDE -ne $null)
        {
            $adminDE.Dispose()
        }
    }
}

Function GetEnterpriseAdminsSid
{
    param(
        [Parameter(Mandatory=$True)] 
        [System.Management.Automation.PSCredential] $Credential
    )

    $networkCredential = $Credential.GetNetworkCredential()
    $dc = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $networkCredential.Domain, $Credential.UserName, $networkCredential.Password)			

    try
    {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($dc)		
        try
        {
            $de = $domain.Forest.RootDomain.GetDirectoryEntry()
            $rootDomainSidInBytes = $de.Properties["ObjectSID"].Value
            $domainSid = New-Object System.Security.Principal.SecurityIdentifier($rootDomainSidInBytes, 0)
            $eaSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid, $domainSid)
            return $eaSid
        }
        finally
        {
            if ($de -ne $null)
            {
                $de.Dispose()
            }
        }
    }
    finally
    {
        if ($domain -ne $null)
        {
            $domain.Dispose()
        }
    }
}

Function GetDomainAdminsSid
{
    param(
        [Parameter(Mandatory=$True)] 
        [System.Management.Automation.PSCredential] $Credential
    )

    $networkCredential = $Credential.GetNetworkCredential()
    $dc = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $networkCredential.Domain, $Credential.UserName, $networkCredential.Password)

    try
    {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($dc)		
        try
        {
            $de = $domain.GetDirectoryEntry()
            $domainSidInBytes = $de.Properties["ObjectSID"].Value
            $domainSid = New-Object System.Security.Principal.SecurityIdentifier($domainSidInBytes, 0)
            $domainAdminsSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $domainSid)
            return $domainAdminsSid
        }
        finally
        {
            if ($de -ne $null)
            {
                $de.Dispose()
            }
        }
    }
    finally
    {
        if ($domain -ne $null)
        {
            $domain.Dispose()
        }
    }
}

# Convert SIDs to readable names
Function ConvertSIDtoName
{
    Param(
        [Parameter(Mandatory=$True,Position=0)] 
        [string] $SID
    )

    $ID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sid
    $User = $ID.Translate([System.Security.Principal.NTAccount])
    $User.Value
}

# Confirm if ActiveDirectory PowerShell Module is present and load it
Function ImportADmodule
{
    If (-not (Get-Module ActiveDirectory))
    {
        Try
        {
            # Load ActiveDirectory module
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        Catch
        {

            Throw "Import-Module : Unable to import ActiveDirectory PowerShell Module. Run 'Install-WindowsFeature RSAT-AD-Tools' to install Active Directory RSAT."
        }
    }
}

# Export ADSyncConfig Module Functions
Export-ModuleMember -Function Set-ADSyncRestrictedPermissions
Export-ModuleMember -Function Set-ADSyncPasswordHashSyncPermissions
Export-ModuleMember -Function Set-ADSyncExchangeHybridPermissions
Export-ModuleMember -Function Set-ADSyncMsDsConsistencyGuidPermissions
Export-ModuleMember -Function Set-ADSyncPasswordWritebackPermissions
Export-ModuleMember -Function Set-ADSyncUnifiedGroupWritebackPermissions
Export-ModuleMember -Function Set-ADSyncExchangeMailPublicFolderPermissions
Export-ModuleMember -Function Set-ADSyncBasicReadPermissions
Export-ModuleMember -Function Get-ADSyncObjectsWithInheritanceDisabled
Export-ModuleMember -Function Get-ADSyncADConnectorAccount
Export-ModuleMember -Function Show-ADSyncADObjectPermissions



# SIG # Begin signature block
# MIIkfwYJKoZIhvcNAQcCoIIkcDCCJGwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCmVLUlH3I2PTOG
# C5v7NTphEDfnAuQvTuoi956xXuwtvaCCDY0wggYLMIID86ADAgECAhMzAAABD/I/
# eNv5ffYVAAAAAAEPMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTgwOTA2MjEwNjE0WhcNMTkwOTA2MjEwNjE0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDvd54eOFN58/jzmNf9H5AhIB6AfOhf2Rz+tZUJu/WJDlDatLr5bD4f/1Snq4Lw
# dd+/VoOfvzViAIP1g4l/Cx8X0G39bfl+hl4PxXWImnMXvOWF2jUJlXSXoceqyTF0
# +cIYQMUKt1ZUv1B8eVuDT4YppoE3VM43W7Lm/CtfkUsUr06wtzDlIZrknzG5mtEy
# 6dZP4LmZ8P0mhY/I+hcj7khmAoWKLWMxMx2rw3drk88frICCjbYjaINoR+DiKxI8
# lx+dz4qOBCiAuSBFwxt0ju+vRAJRkupNAZFYqifIXxpo7J6iFeJfXaZRF79ScYVg
# A2wssHH4Bkjnk1FrhjoP+wKVAgMBAAGjggGKMIIBhjArBgNVHSUEJDAiBgorBgEE
# AYI3TBMBBgorBgEEAYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUR1Ddu7Kb3O6l
# 8LmADTUeIV0295MwUAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzMxMTArNDQ0ODg5MB8G
# A1UdIwQYMBaAFEhuZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWG
# Q2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BD
# QTIwMTFfMjAxMS0wNy0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAC
# hkVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNp
# Z1BDQTIwMTFfMjAxMS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0B
# AQsFAAOCAgEAVK1UCQHlVWPrURmbuk4jxv77kjSVK8gl1r6qnri72CzLajWCaysf
# CZD5dWY8eA6eUrVmLm7Fcxht8A2QukvyUyZ5wmyrYyp4phGsNXC1kwNvGfd3Q65G
# u+mAJZ967eLeR5R8IkJeiGXtDVdzezEP44MehSo5XHx+D1YhNSTD2kCLpGxYgv8M
# mt16fbmvbDIO2ZBBVuqbo4Syq+ku39c4P9KFFpcU8XGXI4Zjztj+YvWdMvcBsjYQ
# LiZK1uFMw86JTbqxJl1SZjLSdq0Sco7sejJ24cM/OpqBe1AUmXWABqursEtrY1Ez
# IpgNE3ZOhdbV+a7QND05YQrWrdz4DT8jdtkBcnZuFsz/mGQTlmnXg6LQeNw1x5Qr
# GG3KwLf6eRHgBUkwNJmYc+ctsMZibFqgmtxU4qWiTBDGwUlNtjJvI/AQ27D4OFxk
# 0NnkTRetWre3WslHCwLbQOFfgWirBF/Pn93ECDsWtkxo0+TUBIaI7uqNo121oVnu
# +W/b+a+u3HbYdtXO3TKi9uUVzwyErHv60uaQ40c5q4jX5tdCir5QJ4RiErMWhf9k
# REW/efQOXnWdBpoV6/42H1RboPy9Xq6rYAGNsyimpl4AC2I7QYWh2KwGnDCmd+6D
# 0Kt97ot95PxMN2NZdCO6UYlLlMeLeQrJrcM0N7xH3VZbjlyM4CtL9rQwggd6MIIF
# YqADAgECAgphDpDSAAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0y
# NjA3MDgyMTA5MDlaMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZY
# IZ9CGypr6VpQqrgGOBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+
# lGAkbK+eSZzpaF7S35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDP
# s0S3XdjELgN1q2jzy23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJ
# KecNvqATd76UPe/74ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJ
# T4Qa8qEvWeSQOy2uM1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qc
# D60ZI4TL9LoDho33X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm
# 7GEfauEoSZ1fiOIlXdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/b
# wBWzvRvUVUvnOaEP6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKer
# jt/sW5+v/N2wZuLBl4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHt
# bcMojyyPQDdPweGFRInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70
# lrC8RqBsmNLg1oiMCwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYD
# VR0OBBYEFEhuZOVQBdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1
# AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaA
# FHItOgIxkEO5FAVO4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIw
# MTFfMjAxMV8wM18yMi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIw
# MTFfMjAxMV8wM18yMi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGD
# MD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Rv
# Y3MvcHJpbWFyeWNwcy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8A
# cABvAGwAaQBjAHkAXwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQEL
# BQADggIBAGfyhqWY4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFt
# g/6+P+gKyju/R6mj82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/Wvj
# PgcuKZvmPRul1LUdd5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvt
# aPpoLpWgKj8qa1hJYx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+Z
# KJeYTQ49C/IIidYfwzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x
# 9Cf43iw6IGmYslmJaG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3bl
# QCplo8NdUmKGwx1jNpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8U
# vmFhtfDcxhsEvt9Bxw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGb
# pT9Fdx41xtKiop96eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNo
# deav+vyL6wuA6mk7r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uo
# zKRdwaGIm1dxVk5IRcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIWSDCCFkQC
# AQEwgZUwfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYG
# A1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAQ/yP3jb
# +X32FQAAAAABDzANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0B
# CQQxIgQgws9eCsWG//w2PWpnqJtwCl/UM0ug6iQEMtu+kyWxbb4wQgYKKwYBBAGC
# NwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQCfINLQaNDongaIt6KULi/tcCJt
# 2zZFNMRxlyxp/aZqG772SaXzBeLe8kWUkmIk9hmkShhVauW6oqErMksWKzi7k+6S
# mPuNg5joOD14NxkhisxJecxfcpnt2urDx9VHwX+71GB8iq5zbp77pPT0mnSGgDzp
# BwUyiBl0Og0vGFSoaQD7nENTBiGE5KisaJac8XbnFrw4JhnCEtdYOorpLkKr5Xwn
# 2ke9tNbrKpKnMltfLvGXA1HeoaCTLZ/GeSANmAS3r50sP6/F8D+wRFkWEqUpU4pZ
# CaJKIWm0i4ENwXZRpKJtN2vZNJjllG+KyFhZYKJmXH/AxfXwYNouqIq8RessoYIT
# 0jCCE84GCisGAQQBgjcDAwExghO+MIITugYJKoZIhvcNAQcCoIITqzCCE6cCAQMx
# DzANBglghkgBZQMEAgEFADCCAVgGCyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEB
# BgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIOExiQV/cUXZm90CbZzZFmLl
# T2iaMpKa9lPc89Sc0/TDAgZck+n+8YIYEzIwMTkwNDE3MjE1NjE4LjE5OFowBwIB
# AYACAfSggdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYw
# JAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo5OEZELUM2MUUtRTY0MTElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDyIwggT1MIID3aADAgECAhMz
# AAAAy194yyMOlJfDAAAAAADLMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwMB4XDTE4MDgyMzIwMjYyNFoXDTE5MTEyMzIwMjYyNFow
# gc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsT
# IE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFs
# ZXMgVFNTIEVTTjo5OEZELUM2MUUtRTY0MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AMV4yB3v8B1BcBxtNEo/VALKGnizA1WCEIU22DCpyy838O0VlW7D3KUomZPIU3ns
# x3MxaQXpai0OiVs+DPuHqdoKtsuYCaMxeDHhodCgPWdPT9NN0hngnC07R2nDB2Nh
# vtRBpr4V36791Pqi3CssKDdLjBrOQUhqEn8S0VP5xldDQPfMIpqRFQdP6Ut4dvaI
# /Mva5e86HbawJxdGKrTdHp7LOae3YHX25khbhuNatqp3dDu3Do6xDE1BIa2GuUGZ
# a4oHVNwWIWk3SZ4xZlarT3eAi712yWyeTrjGv56Ryje8yDiBtd+1UCn67t0TwQpT
# a+a2ZPP2v8HyQxQegc+9ThUCAwEAAaOCARswggEXMB0GA1UdDgQWBBQo5PLm9snR
# Ta5uyNsqlr8xw/vZdjAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQCL9GGFgwVi
# bMsUlJfD6SUDbHKxL9pN6ZYMg+aOTE8AyCh9oD6HcuinUjkj6afQU63TvgVRWExY
# JLzrQBysAh2GgbGkKIPtdV6yQQMlJxclXpR48t1jS1VvBX0KksR5Bq/4/0e58+jX
# vUaU2JcUQVw3lHn9I/YtQJeuAvnNfLENxJKE3A7FOjOAw+fEH49OGK1IBR9yhXS+
# r6HslFuFLfjK7DU89+Cu1zAg9JTCCrqlWSydWApAYh/ACInONLHHp9OZdilC42zG
# jB8Ro/07YqMAjPhK7Ze12lWThiZIFqc5fZTxCi3L2T8pQI91/Nxu4CnpIzLXUwSX
# UxkIpfSNsK7OMIIGcTCCBFmgAwIBAgIKYQmBKgAAAAAAAjANBgkqhkiG9w0BAQsF
# ADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UE
# AxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcN
# MTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkdDbx3
# EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEf
# QRsalR3OCROOfGEwWbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcmgqNFDdDq9UeB
# zb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5hoC732H8RsEn
# HSRnEnIaIYqvS2SJUGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9
# buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzA
# yURdXhacAQVPIk0CAwEAAaOCAeYwggHiMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1Ud
# DgQWBBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBi
# AEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV
# 9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3Js
# Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAx
# MC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2
# LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYB
# BQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVm
# YXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBj
# AHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAAfm
# iFEN4sbgmD+BcQM9naOhIW+z66bM9TG+zwXiqf76V20ZMLPCxWbJat/15/B4vceo
# niXj+bzta1RXCCtRgkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDI
# r79/xn/yN31aPxzymXlKkVIArzgPF/UveYFl2am1a+THzvbKegBvSzBEJCI8z+0D
# pZaPWSm8tv0E4XCfMkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/amJ/3cVKC5Em
# 4jnsGUpxY517IW3DnKOiPPp/fZZqkHimbdLhnPkd/DjYlPTGpQqWhqS9nhquBEKD
# uLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua2A5HmoDF0M2n
# 0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd46PioSKv33nJ+YWtv
# d6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqHczsI5pgt6o3g
# My4SKfXAL1QnIffIrE7aKLixqduWsqdCosnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1
# mYovG8chr1m1rtxEPJdQcdeh0sVV42neV8HR3jDA/czmTfsNv11P6Z0eGTgvvM9Y
# BS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950iEkSoYIDsDCCApgCAQEwgf6hgdSk
# gdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNV
# BAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo5OEZELUM2MUUtRTY0MTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQC5o5PSQHbRtx8V
# owRRl644K9uaIaCB3jCB26SB2DCB1TELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRv
# IFJpY28xJzAlBgNVBAsTHm5DaXBoZXIgTlRTIEVTTjo0REU5LTBDNUUtM0UwOTEr
# MCkGA1UEAxMiTWljcm9zb2Z0IFRpbWUgU291cmNlIE1hc3RlciBDbG9jazANBgkq
# hkiG9w0BAQUFAAIFAOBh2TowIhgPMjAxOTA0MTgwMDU2MjZaGA8yMDE5MDQxOTAw
# NTYyNlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA4GHZOgIBADAKAgEAAgICuAIB
# /zAHAgEAAgIZPTAKAgUA4GMqugIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMBoAowCAIBAAIDFuNgoQowCAIBAAIDB6EgMA0GCSqGSIb3DQEBBQUAA4IB
# AQAVTAR419FXTjcN1sm3Jvfpb2IZT8xV6uukLKQIIJxmqj3PUd199jxnV1e/arrz
# HMusrG8TMj2vLtxsZD9P2/geHEf7MGOYkoX4AqEiHJ5tZrOObleyqY33Rd+EGp2O
# SlH1s76m2EBAhgXeR8yVsVMmTY77obsAKfKp12/yrEy5tOT6Sx0lG2R62qzus7kJ
# T9WgRsPGSHRi/2BdGqmJlDuRlX3NrhLNIIQ4d/LKyzf2xDVm/b/oLU/1l6JaaZdc
# 2/ahHn+TFAItZdgyLb9tPzlX944Q1+kfBIV46Shb6smEjsP0KCsFBZr/q7G+pCX8
# CJg2L4wUr6n3fMoNmpK+HR3aMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAADLX3jLIw6Ul8MAAAAAAMswDQYJYIZIAWUDBAIB
# BQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQx
# IgQggKN9f2Kzg8U1gyNd++u5oRASJo+t5BWNWyPXUUQnPc0wgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCA2JyGqqWCnXutz0KS9S3wuF/afS9Mu7hRHXqpg3cEd
# ZDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAAy194
# yyMOlJfDAAAAAADLMCIEIA0VMeQ037K3/VLtl77iwwsIaS6iAPLGRLKN1bDtV+Up
# MA0GCSqGSIb3DQEBCwUABIIBAMMMFkHDYqQEe8DUyiVSXdbteJaEDgHddUivgif/
# 3CYOnQ8rRyqBbe7+r2vMO9dqNI54Vye+zhXyFRkarvkGIyaWGFPCmNuDXBZqtMAq
# 8enRCc82hdZ2SE8smrSpsUnZXpWd9QcjO4+93EgWi75Y60k/QOiN2Ah/FcnwhiZ0
# orBnqgZiL5c+8UY2xyptx2oVxyE9UsbrX5jVqAo/Oqh9imcnu6Ww5uhs8ZL+A6Gr
# Gj2g9qATRpOHBBCZaChXoXvAdpJz9FvLVrzSXD8JhatiqsrqbidGfMSsgzCQnQL/
# g/vl/2jWI9gA98rOTOBcEV+J9LGgvDEMXBHBgM9/hpVH734=
# SIG # End signature block
