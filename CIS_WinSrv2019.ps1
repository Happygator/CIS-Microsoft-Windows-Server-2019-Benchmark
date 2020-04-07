# CIS Microsoft Windows Server 2019 RTM Benchmark
# You can get the most up to date version in:
# https://github.com/viniciusmiguel/CIS-Microsoft-Windows-Server-2019-Benchmark

##########################################################################################################
$LogonLegalNoticeMessageTitle = "Warning Notice:"
$LogonLegalNoticeMessage = "You are about to enter a private network intended for the authorized users only. The use of this system may be,monitored and/or recorded for administrative and security reasons in,accordance with applicable law and policies."

#IF YOU HAVE SPECIAL SECURITY REQUIREMENTS YOU CAN DISABLE POLICIES BELLOW

$ExecutionList = @(
    #KEEP THESE IN THE BEGINING
    "RenameAdministratorAccount", #2.3.1.5 
    "RenameGuestAccount",         #2.3.1.6
    ###########################
    "EnforcePasswordHistory", #1.1.1
    "MaximumPasswordAge",     #1.1.2
    "MinimumPasswordAge",     #1.1.3
    "MinimumPasswordLength",  #1.1.4
    "WindowsPasswordComplexityPolicyMustBeEnabled", #1.1.5
    "DisablePasswordReversibleEncryption", #1.1.6
    "AccountLockoutDuration",     #1.2.1
    "AccountLockoutThreshold",    #1.2.2
    "ResetAccountLockoutCounter", #1.2.3
    "NoOneTrustCallerACM",        #2.2.1
     #2.2.2 Not Applicable to Member Server
    "AccessComputerFromNetwork",  #2.2.3
    "NoOneActAsPartOfOperatingSystem", #2.2.4
     #2.2.5 Not Applicable to Member Server
    "AdjustMemoryQuotasForProcess",      #2.2.6
    "AllowLogonLocallyToAdministrators", #2.2.7
     #2.2.8 Not Applicable to Member Server
    "LogonThroughRemoteDesktopServices", #2.2.9
    "BackupFilesAndDirectories", #2.2.10
    "ChangeSystemTime", #2.2.11
    "ChangeTimeZone",   #2.2.12
    "CreatePagefile",   #2.2.13
    "NoOneCreateTokenObject", #2.2.14
    "CreateGlobalObjects",    #2.2.15
    "NoOneCreatesSharedObjects",#2.2.16
     #2.2.17 Not Applicable to Member Server
    "CreateSymbolicLinks", #2.2.18
    "DebugPrograms", #2.2.19
     #2.2.20 Not Applicable to Member Server
    "DenyNetworkAccess",  #2.2.21
    "DenyGuestBatchLogon", #2.2.22
    "DenyGuestServiceLogon", #2.2.23
    "DenyGuestLocalLogon", #2.2.24
    #2.2.25 Not Applicable to Member Server
    "DenyRemoteDesktopServiceLogon", #2.2.26
    #2.2.27 Not Applicable to Member Server
    "NoOneTrustedForDelegation",     #2.2.28
    "ForceShutdownFromRemoteSystem", #2.2.29
    "GenerateSecurityAudits", #2.2.30
    #2.2.31 Not Applicable to Member Server
    "ImpersonateClientAfterAuthentication", #2.2.32
    "IncreaseSchedulingPriority", #2.2.33
    "LoadUnloadDeviceDrivers", #2.2.34
    "NoOneLockPagesInMemory",  #2.2.35
    #2.2.36 Not Applicable to Member Server
    #2.2.37 Not Applicable to Member Server
    "ManageAuditingAndSecurity", #2.2.38
    "NoOneModifiesObjectLabel",  #2.2.39
    "FirmwareEnvValues", #2.2.40
    "VolumeMaintenance", #2.2.41
    "ProfileSingleProcess", #2.2.42
    "ProfileSystemPerformance", #2.2.43
    "ReplaceProcessLevelToken", #2.2.44
    "RestoreFilesDirectories",  #2.2.45
    "SystemShutDown", #2.2.46
    #2.2.47 Not Applicable to Member Server
    "TakeOwnershipFiles", #2.2.48
    "DisableAdministratorAccount", #2.3.1.1
    "DisableMicrosoftAccounts",    #2.3.1.2
    "DisableGuestAccount",         #2.3.1.3
    "LimitBlankPasswordConsole",   #2.3.1.4
    "AuditForceSubCategoryPolicy",  #2.3.2.1
    "AuditForceShutdown", #2.3.2.2
    "DevicesAdminAllowedFormatEject", #2.3.4.1
    "PreventPrinterInstallation", #2.3.4.2
    #2.3.5.1 Not Applicable to Member Server
    #2.3.5.2 Not Applicable to Member Server
    #2.3.5.3 Not Applicable to Member Server
    "SignEncryptAllChannelData", #2.3.6.1
    "SecureChannelWhenPossible", #2.3.6.2
    "DigitallySignChannelWhenPossible", #2.3.6.3
    "EnableAccountPasswordChanges", #2.3.6.4
    "MaximumAccountPasswordAge",    #2.3.6.5
    "RequireStrongSessionKey",      #2.3.6.6
    "RequireCtlAltDel",      #2.3.7.1
    "DontDisplayLastSigned",  #2.3.7.2
    "MachineInactivityLimit", #2.3.7.3
    "LogonLegalNotice", #2.3.7.4
    "LogonLegalNoticeTitle", #2.3.7.5
    "PreviousLogonCache", #2.3.7.6
    "PromptUserPassExpiration", #2.3.7.7
    "RequireDomainControllerAuth", #2.3.7.8
    "SmartCardRemovalBehaviour", #2.3.7.9
    "NetworkClientSignCommunications", #2.3.8.1
    "EnableSecuritySignature",         #2.3.8.2
    "DisableSmbUnencryptedPassword",   #2.3.8.3
    "IdleTimeSuspendingSession",        #2.3.9.1
    "NetworkServerAlwaysDigitallySign", #2.3.9.2
    "EnableSecuritySignature", #2.3.9.3
    "LanManServerEnableForcedLogOff", #2.3.9.4
    "LanManServerSmbServerNameHardeningLevel", #2.3.9.5
    "LSAAnonymousNameDisabled", #2.3.10.1
    "RestrictAnonymousSAM", #2.3.10.2
    "RestrictAnonymous", #2.3.10.3
    "DisableDomainCreds", #2.3.10.4
    "EveryoneIncludesAnonymous", #2.3.10.5
    #2.3.10.6 Not Applicable to Member Server
    "NullSessionPipes", #2.3.10.7
    "AllowedExactPaths", #2.3.10.8
    "AllowedPaths", #2.3.10.9
    "RestrictNullSessAccess", #2.3.10.10
    "RestrictRemoteSAM", #2.3.10.11
    "NullSessionShares", #2.3.10.12
    "LsaForceGuest", #2.3.10.13
    "LsaUseMachineId", #2.3.11.1
    "AllowNullSessionFallback", #2.3.11.2
    "AllowOnlineID", #2.3.11.3
    "SupportedEncryptionTypes", #2.3.11.4
    "NoLMHash", #2.3.11.5
    "ForceLogoff", #2.3.11.6
    "LmCompatibilityLevel", #2.3.11.7
    "LDAPClientIntegrity", #2.3.11.8
    "NTLMMinClientSec", #2.3.11.9
    "NTLMMinServerSec", #2.3.11.10
    "ShutdownWithoutLogon", #2.3.13.1
    "ObCaseInsensitive", #2.3.15.1
    "SessionManagerProtectionMode", #2.3.15.2
    "FilterAdministratorToken", #2.3.17.1
    "ConsentPromptBehaviorAdmin", #2.3.17.2
    "ConsentPromptBehaviorUser", #2.3.17.3
    "EnableInstallerDetection", #2.3.17.4
    "EnableSecureUIAPaths", #2.3.17.5
    "EnableLUA", #2.3.17.6
    "PromptOnSecureDesktop", #2.3.17.7
    "EnableVirtualization", #2.3.17.8
    "DomainEnableFirewall", #9.1.1
    "DomainDefaultInboundAction", #9.1.2
    "DomainDefaultOutboundAction", #9.1.3
    "DomainDisableNotifications", #9.1.4
    "DomainLogFilePath", #9.1.5
    "DomainLogFileSize", #9.1.6
    "DomainLogDroppedPackets", #9.1.7
    "DomainLogSuccessfulConnections", #9.1.8
    "PrivateEnableFirewall", #9.2.1
    "PrivateDefaultInboundAction", #9.2.2
    "PrivateDefaultOutboundAction", #9.2.3
    "PrivateDisableNotifications", #9.2.4
    "PrivateLogFilePath", #9.2.5
    "PrivateLogFileSize", #9.2.6
    "PrivateLogDroppedPackets", #9.2.7
    "PrivateLogSuccessfulConnections", #9.2.8
    "PublicEnableFirewall", #9.3.1
    "PublicDefaultInboundAction", #9.3.2
    "PublicDefaultOutboundAction", #9.3.3
    "PublicDisableNotifications", #9.3.4
    "PublicAllowLocalPolicyMerge", #9.3.5
    "PublicAllowLocalIPsecPolicyMerge ", #9.3.6
    "PublicLogFilePath", #9.3.7
    "PublicLogFileSize", #9.3.8
    "PublicLogDroppedPackets", #9.3.9
    "PublicLogSuccessfulConnections", #9.3.10
    "AuditCredentialValidation", #17.1.1
    "AuditComputerAccountManagement", #17.2.1
    #17.2.2 Not Applicable to Member Server
    #17.2.3 Not Applicable to Member Server
    #17.2.4 Not Applicable to Member Server
    "AuditSecurityGroupManagement", #17.2.5
    "AuditUserAccountManagement", #17.2.6
    "AuditPNPActivity", #17.3.1
    "AuditProcessCreation", #17.3.2
    #17.4.1 Not Applicable to Member Server
    #17.4.2 Not Applicable to Member Server
    "AuditAccountLockout", #17.5.1
    "AuditGroupMembership", #17.5.2
    "AuditLogoff", #17.5.3
    "AuditLogon", #17.5.4
    "AuditOtherLogonLogoffEvents", #17.5.5
    "AuditSpecialLogon", #17.5.6
    "AuditDetailedFileShare", #17.6.1
    "AuditFileShare", #17.6.2
    "AuditOtherObjectAccessEvents", #17.6.3
    "AuditRemovableStorage", #17.6.4
    ""
)


$AdminAccountName = "Administrator"
$GuestAccountName = "Guest"

#Randomize the new admin and guest accounts on each system.
#This increases the security not affecting the accessibility since these accounts are always disabled. 

$seed_admin = Get-Random -Minimum 1000 -Maximum 9999
$seed_guest = Get-Random -Minimum 1000 -Maximum 9999

$AdminNewAccountName = "Admin$($seed_admin)"

$GuestNewAccountName = "Guest$($seed_guest)"

#DO NOT CHANGE CODE BELLOW THIS LINE IF YOU ARE NOT 100% SURE ABOUT WHAT YOU ARE DOING!
##########################################################################################################

#WINDOWS SID CONSTANTS
#https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

$SID_NOONE = "`"`""
$SID_ADMINISTRATORS = "*S-1-5-32-544"
$SID_SERVICE = "*S-1-5-6"
$SID_NETWORK_SERVICE = "*S-1-5-20"
$SID_LOCAL_SERVICE = "*S-1-5-19"
$SID_LOCAL_ACCOUNT = "*S-1-5-113"
$SID_WINDOW_MANAGER_GROUP = "*S-1-5-90-0"
$SID_REMOTE_DESKTOP_USERS = "*S-1-5-32-555"
$SID_VIRTUAL_MACHINE = "*S-1-5-83-0"
$SID_AUTHENTICATED_USERS = "*S-1-5-11"
$SID_WDI_SYSTEM_SERVICE = "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
$SID_BACKUP_OPERATORS = "S-1-5-32-551"

##########################################################################################################

$fc = $host.UI.RawUI.ForegroundColor
$host.UI.RawUI.ForegroundColor = "white"

function Write-Info($text) {
    Write-Host $text -ForegroundColor Yellow
}

function Write-Before($text) {
    Write-Host $text -ForegroundColor Cyan
}

function Write-After($text) {
    Write-Host $text -ForegroundColor Green
}

Write-Info "CIS Microsoft Windows Server 2019 RTM Benchmark"
Write-Info "Script written and tested by Vinicius Miguel"

function SetRegistry([string] $path, [string] $key, [string] $value) {
    $before = Get-ItemProperty -Path $path -Name $key
    Write-Before "Was: $($before.$key)"
    Set-ItemProperty -Path $path -Name $key -Value $value
    $after = Get-ItemProperty -Path $path -Name $key
    Write-After "Now is: $($after.$key)"
}

function SetSecEdit([string]$role, [string[]] $values, $area, $enforceCreation) {
    $valueSet = $false

    if($values -eq $null) {
        Write-Error "SetUserRight: At least one value must be provided to set the role:$($role)"
        return
    }
    
    if($enforceCreation -eq $null){
        $enforceCreation = $true
    }

    secedit /export /cfg ${env:appdata}\secpol.cfg /areas $area
    $lines = Get-Content ${env:appdata}\secpol.cfg
    
    $config = "$($role)= "
    for($r =0; $r -lt $values.Length; $r++){
        if($r -eq $values.Length -1) {
            $config = "$($config) $($values[$r])"
        } else {
            $config = "$($config) $($values[$r]), "
        }
    }

    for($i =0; $i -lt $lines.Length; $i++) {
        if($lines[$i].Contains($role)) {
            Write-Before "Was: $($lines[$i])"
            $lines[$i] = $config
            $valueSet = $true
            Write-After "Now is: $($lines[$i])"
        }
    }

    if($enforceCreation -eq $true){
        if($valueSet -eq $false) {
            Write-Before "Was: Not Defined"
            $lines += $config
            Write-After "Now is: $($lines[$lines.Length -1])"
        }
    }

    $lines | out-file ${env:appdata}\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas $area
    rm -force ${env:appdata}\secpol.cfg -confirm:$false
}

function SetUserRight([string]$role, [string[]] $values, $enforceCreation) {
    SetSecEdit $role $values "User_Rights" $enforceCreation
}

function SetSecurityPolicy([string]$role, [string[]] $values, $enforceCreation) {
    SetSecEdit $role $values "SecurityPolicy" $enforceCreation 
}

function InstallPolicyFileEditor {
    #This powershell module enables Set-PolicyFileEntry CmdLet
    register-packagesource -Name NuGet -ProviderName NuGet -location https://www.nuget.org/api/v2/
    Import-PackageProvider NuGet -Force
    Install-Module -Name PolicyFileEditor -Force
}

function InstallGPMC {
    #Installs Group Policy Manager
    Install-WindowsFeature –Name GPMC
    Get-Command -Module GroupPolicy
}

function EnforcePasswordHistory
{
    #1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Scored)
    Write-Info "1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Scored)"
	Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Length of password history maintained' )
    Write-After ("After hardening: *******                   ")
    net accounts /uniquepw:24
}

function MaximumPasswordAge
{
    #1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0' (Scored)
    Write-Info "1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0' (Scored)"
	Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Maximum password age' )
    Write-After ("After hardening: *******                   ")
    net accounts /maxpwage:60
}

function MinimumPasswordAge
{

    #1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)' (Scored)
    Write-Info "1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)' (Scored)"
	Write-Before ("Before hardening: *******               ")
    Write-Output (net accounts | Select-String -SimpleMatch 'Minimum password age' )
    Write-After ("After hardening: *******                   ")
    net accounts /minpwage:1
}

function MinimumPasswordLength
{

    #1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' (Scored)
    Write-Info "1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' (Scored)"
	Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Minimum password length')
    Write-After ("After hardening: *******                   ")
    net accounts /MINPWLEN:14
}

function WindowsPasswordComplexityPolicyMustBeEnabled
{

    #1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Scored)
    Write-Info "1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Scored)"
    secedit /export /cfg ${env:appdata}\secpol.cfg
    (gc ${env:appdata}\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File ${env:appdata}\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas SECURITYPOLICY
    rm -force ${env:appdata}\secpol.cfg -confirm:$false

}

function DisablePasswordReversibleEncryption {

    #1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Scored)
    Write-Info "1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Scored)"
    secedit /export /cfg ${env:appdata}\secpol.cfg
    (gc ${env:appdata}\secpol.cfg).replace("ClearTextPassword = 1", "ClearTextPassword = 0") | Out-File ${env:appdata}\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas SECURITYPOLICY
    rm -force ${env:appdata}\secpol.cfg -confirm:$false
}

function AccountLockoutDuration
{
    #1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)' (Scored)
    Write-Info "1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)' (Scored)"
	Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'lockout duration')

    Write-After ("After hardening: *******                   ")
    net accounts /lockoutduration:30
}

function AccountLockoutThreshold
{
    #1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0' (Scored)
    Write-Info "1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0' (Scored)"
	Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'lockout threshold' )

    Write-After ("After hardening: *******                   ")
    net accounts /lockoutthreshold:3

}

function  ResetAccountLockoutCounter
{
    # 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' (Scored)
    Write-Info "1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' (Scored)"
	Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Lockout observation window' )

    Write-After ("After hardening: *******                   ")
    net accounts /lockoutwindow:30
}

function NoOneTrustCallerACM {
    #2.2.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access Credential Manager as a trusted caller
    Write-Info "2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' (Scored)"
    SetUserRight "SeTrustedCredManAccessPrivilege" ($SID_NOONE)
}

function AccessComputerFromNetwork {
    #2.2.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access this computer from the network
    Write-Info "2.2.3 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users"
    SetUserRight "SeNetworkLogonRight" ($SID_ADMINISTRATORS, $SID_AUTHENTICATED_USERS)
}

function NoOneActAsPartOfOperatingSystem {
    #2.2.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Act as part of the operating system
    Write-Info "2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One' (Scored)"
    SetUserRight "SeTcbPrivilege" ($SID_NOONE)
}

function AdjustMemoryQuotasForProcess {
    #2.2.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Adjust memory quotas for a process
    Write-Info "2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
    SetUserRight "SeIncreaseQuotaPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE, $SID_ADMINISTRATORS)
}

function AllowLogonLocallyToAdministrators {
    #2.2.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on locally
    Write-Info "2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'"
    SetUserRight "SeInteractiveLogonRight" (,$SID_ADMINISTRATORS)
}

function LogonThroughRemoteDesktopServices {
    #2.2.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on through Remote Desktop Services
    Write-Info "2.2.9 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
    SetUserRight "SeRemoteInteractiveLogonRight" ($SID_ADMINISTRATORS, $SID_REMOTE_DESKTOP_USERS)
}

function BackupFilesAndDirectories {
    #2.2.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Back up files and directories
    Write-Info "2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'"
    SetUserRight "SeBackupPrivilege" (,$SID_ADMINISTRATORS)
}

function ChangeSystemTime {
    #2.2.11 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the system time
    Write-Info "2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
    SetUserRight "SeSystemtimePrivilege" ($SID_ADMINISTRATORS,$SID_LOCAL_SERVICE)
}

function ChangeTimeZone {
    #2.2.12 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the time zone
    Write-Info "2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
    SetUserRight "SeTimeZonePrivilege" ($SID_LOCAL_SERVICE,$SID_ADMINISTRATORS)
}

function CreatePagefile {
    #2.2.13 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a pagefile
    Write-Info "2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'"
    SetUserRight "SeCreatePagefilePrivilege" (,$SID_ADMINISTRATORS)
}

function NoOneCreateTokenObject {
    #2.2.14 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a token object
    Write-Info "2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'"
    SetUserRight "SeCreateTokenPrivilege" (,$SID_NOONE)
}

function CreateGlobalObjects {
    #2.2.15 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create global objects
    Write-Info "2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
    SetUserRight "SeCreateGlobalPrivilege" ($SID_ADMINISTRATORS,$SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE,$SID_SERVICE)
}

function NoOneCreatesSharedObjects {
    #2.2.16 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create permanent shared objects
    Write-Info "2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'"
    SetUserRight "SeCreatePermanentPrivilege" (,$SID_NOONE)
}

function CreateSymbolicLinks {
    #2.2.18 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create symbolic links
    Write-Info "2.2.18 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'"
    SetUserRight "SeCreateSymbolicLinkPrivilege" ($SID_ADMINISTRATORS,$SID_VIRTUAL_MACHINE)
}

function DebugPrograms {
    #2.2.19 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Debug programs
    Write-Info "2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'"
    SetUserRight "SeDebugPrivilege" (,$SID_ADMINISTRATORS)
}

function DenyNetworkAccess {
    #2.2.21 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny access to this computer from the network
    Write-Info "2.2.21 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group'"
    SetUserRight "SeDenyNetworkLogonRight"($SID_LOCAL_ACCOUNT, $($AdminNewAccountName),$($GuestAccountName))
}

function DenyGuestBatchLogon {
    #2.2.22 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a batch job
    Write-Info "2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
    SetUserRight "SeDenyBatchLogonRight" (,$GuestNewAccountName)
}

function DenyGuestServiceLogon {
    #2.2.23 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a service
    Write-Info "2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'"
    SetUserRight "SeDenyServiceLogonRight" (,$GuestNewAccountName)
}

function DenyGuestLocalLogon {
    #2.2.24 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on locally
    Write-Info "2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'"
    SetUserRight "SeDenyInteractiveLogonRight" (,$GuestNewAccountName)
}

function DenyRemoteDesktopServiceLogon {
    #2.2.26 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services
    Write-Info "2.2.26 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'"
    SetUserRight "SeDenyRemoteInteractiveLogonRight" ($SID_LOCAL_ACCOUNT, $GuestNewAccountName)
}

function NoOneTrustedForDelegation {
    #2.2.28 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Enable computer and user accounts to be trusted for delegation
    Write-Info "2.2.28 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
    SetUserRight "SeDelegateSessionUserImpersonatePrivilege" (,$SID_NOONE)
}

function ForceShutdownFromRemoteSystem {
    #2.2.29 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Force shutdown from a remote system
    Write-Info "2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
    SetUserRight "SeRemoteShutdownPrivilege" (,$SID_ADMINISTRATORS)
}

function GenerateSecurityAudits {
    #2.2.30 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Generate security audits
    Write-Info "2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE' (Scored)"
    SetUserRight "SeAuditPrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE)
}

function ImpersonateClientAfterAuthentication {
    #2.2.32 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Impersonate a client after authentication
    Write-Info "Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, IIS_IUSRS'"
    SetUserRight "SeImpersonatePrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE)
}

function IncreaseSchedulingPriority {
    #2.2.33 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Increase scheduling priority
    Write-Info "2.2.33 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
    SetUserRight "SeIncreaseBasePriorityPrivilege" ($SID_ADMINISTRATORS,$SID_WINDOW_MANAGER_GROUP)
}

function LoadUnloadDeviceDrivers {
    #2.2.34 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Load and unload device drivers
    Write-Info "2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
    SetUserRight "SeLoadDriverPrivilege" (,$SID_ADMINISTRATORS)
}

function NoOneLockPagesInMemory {
    #2.2.35 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Lock pages in memory
    Write-Info "2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'"
    SetUserRight "SeLockMemoryPrivilege" (,$SID_NOONE)
}

function ManageAuditingAndSecurity {
    #2.2.38 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Manage auditing and security log
    Write-Info "2.2.38 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'"
    SetUserRight "SeSecurityPrivilege" (,$SID_ADMINISTRATORS)
}

function NoOneModifiesObjectLabel {
    #2.2.39 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Modify an object label
    Write-Info "2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'"
    SetUserRight "SeRelabelPrivilege" (,$SID_NOONE)
}

function FirmwareEnvValues {
    #2.2.40 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Modify firmware environment values
    Write-Info "2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
    SetUserRight "SeSystemEnvironmentPrivilege" (,$SID_ADMINISTRATORS)
}

function VolumeMaintenance {
    #2.2.41 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Perform volume maintenance tasks
    Write-Info "2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
    SetUserRight "SeManageVolumePrivilege" (,$SID_ADMINISTRATORS)

}

function ProfileSingleProcess {
    #2.2.42 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Profile single process
    Write-Info "2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'"
    SetUserRight "SeProfileSingleProcessPrivilege" (,$SID_ADMINISTRATORS)
}

function ProfileSystemPerformance {
    #2.2.43 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Profile system performance
    Write-Info "2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators,NT SERVICE\WdiServiceHost'"
    SetUserRight "SeSystemProfilePrivilege" ($SID_ADMINISTRATORS,$SID_WDI_SYSTEM_SERVICE)
}

function ReplaceProcessLevelToken {
    #2.2.44 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Replace a process level token
    Write-Info "2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
    SetUserRight "SeAssignPrimaryTokenPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE)
}

function RestoreFilesDirectories {
    #2.2.45 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Restore files and directories
    Write-Info "2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'"
    SetUserRight "SeRestorePrivilege" (,$SID_ADMINISTRATORS)
}

function SystemShutDown {
    #2.2.46 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Shut down the system
    Write-Info "2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'"
    SetUserRight "SeShutdownPrivilege" (,$SID_ADMINISTRATORS)
}

function TakeOwnershipFiles {
    #2.2.48 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Take ownership of files or other objects
    Write-Info "2.2.48 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
    SetUserRight "SeTakeOwnershipPrivilege" (,$SID_ADMINISTRATORS)
}

function DisableAdministratorAccount {
    #2.3.1.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Administrator account status
    Write-Info "2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
    SetSecurityPolicy "EnableAdminAccount" (,"0")
}

function DisableMicrosoftAccounts {
    #2.3.1.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Block Microsoft accounts
    Write-Info "2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser" (,"4,3")
}

function DisableGuestAccount {
    #2.3.1.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Guest account status
    Write-Info "2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'"
    SetSecurityPolicy "EnableGuestAccount" (,"0")
}

function LimitBlankPasswordConsole {
    #2.3.1.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Limit local account use of blank passwords to console logon only
    Write-Info "2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" (,"4,1")
}

function RenameAdministratorAccount {
    #2.3.1.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename administrator account
    Write-Info "2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'"
    SetSecurityPolicy "NewAdministratorName" (,"`"$($AdminNewAccountName)`"")
}

function RenameGuestAccount {
    #2.3.1.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename guest account
    Write-Info "2.3.1.6 (L1) Configure 'Accounts: Rename guest account'"
    SetSecurityPolicy "NewGuestName" (,"`"$($GuestNewAccountName)`"")
}

function AuditForceSubCategoryPolicy {
    #2.3.2.1 =>Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings
    Write-Info "2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings to override audit policy category settings' is set to 'Enabled' "
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy" (,"4,1")
}

function AuditForceShutdown {
    #2.3.2.2 Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Audit: Shut down system immediately if unable to log security audits
    Write-Info "2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail" (,"4,0")
}

function DevicesAdminAllowedFormatEject {
    #2.3.4.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Devices: Allowed to format and eject removable media
    Write-Info "2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD" (,"1,`"0`"")
}

function PreventPrinterInstallation {
    #2.3.4.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Devices: Prevent users from installing printer drivers
    Write-Info "2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers'is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" (,"4,1")
}

function SignEncryptAllChannelData {
    #2.3.6.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally encrypt or sign secure channel data (always)
    Write-Info "2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal" (,"4,1")
}

function SecureChannelWhenPossible {
    #2.3.6.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally encrypt secure channel data (when possible)
    Write-Info "2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel" (,"4,1")
}

function DigitallySignChannelWhenPossible {
    #2.3.6.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally sign secure channel data (when possible)
    Write-Info "2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel" (,"4,1")
}

function EnableAccountPasswordChanges {
    #2.3.6.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Disable machine account password changes
    Write-Info "2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange" (,"4,0")
}

function MaximumAccountPasswordAge {
    #2.3.6.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Maximum machine account password age    Write-Info "2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge" (,"4,30")
}

function RequireStrongSessionKey {
    #2.3.6.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Require strong (Windows 2000 or later) session key
    Write-Info "2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey" (,"4,1")
}

function RequireCtlAltDel {
    #2.3.7.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Do not require CTRL+ALT+DEL
    Write-Info "2.3.7.1 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD" (,"4,0")
}

function DontDisplayLastSigned {
    #2.3.7.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Don't display last signed-in
    Write-Info "2.3.7.2 (L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName" (,"4,0")
}

function MachineInactivityLimit {
    #2.3.7.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Machine inactivity limit
    Write-Info "2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0' "
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs" (,"4,900")
}

function LogonLegalNotice {
    #2.3.7.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message text for users attempting to log on
    Write-Info "2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText" ("7",$LogonLegalNoticeMessage)
}

function LogonLegalNoticeTitle {
    #2.3.7.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message title for users attempting to log on
    Write-Info "2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption" (,"1,`"$($LogonLegalNoticeMessage)`"")
}

function PreviousLogonCache {
    #2.3.7.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Number of previous logons to cache (in case domain controller is not available)    Write-Info "2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount" (,"1,`"4`"")
}

function PromptUserPassExpiration {
    #2.3.7.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Prompt user to change password before expiration
    Write-Info "2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning" (,"4,5")
}

function RequireDomainControllerAuth {
    #2.3.7.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Require Domain Controller Authentication to unlock workstation
    Write-Info "2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon" (,"4,1")
}

function SmartCardRemovalBehaviour {
    #2.3.7.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Smart card removal behavior
    Write-Info "2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption" (,"1,`"1`"")
}

function NetworkClientSignCommunications {
    #2.3.8.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Digitally sign communications (always)
    Write-Info "2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" (,"4,1")
}

function EnableSecuritySignature {
    #2.3.8.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Digitally sign communications (if server agrees)
    Write-Info "2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' "
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature" (,"4,1")
}

function DisableSmbUnencryptedPassword {
    #2.3.8.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Send unencrypted password to third-party SMB servers
    Write-Info "2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" (,"4,0")
}

function IdleTimeSuspendingSession {
    #2.3.9.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Amount of idle time required before suspending session
    Write-Info "2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect" (,"4,15")
}

function NetworkServerAlwaysDigitallySign {
    #2.3.9.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Digitally sign communications (always)
    Write-Info "2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature" (,"4,1")
}

function LanManSrvEnableSecuritySignature{
    #2.3.9.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Digitally sign communications (if client agrees)
    Write-Info "2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature" (,"4,1")
}

function LanManServerEnableForcedLogOff {
    #2.3.9.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Disconnect clients when logon hours expire
    Write-Info "2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff" (,"4,1")
}

function LanManServerSmbServerNameHardeningLevel {
    #2.3.9.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Server SPN target name validation level
    Write-Info "2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel" (,"4,1")
}

function LSAAnonymousNameDisabled {
    #2.3.10.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Allow anonymous SID/Name translation
    Write-Info "2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
    SetSecurityPolicy "LSAAnonymousNameLookup" (,"0")
}

function RestrictAnonymousSAM {
    #2.3.10.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow anonymous enumeration of SAM accounts
    Write-Info "2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM" (,"4,1")
}

function RestrictAnonymous {
    #2.3.10.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow anonymous enumeration of SAM accounts and shares
    Write-Info "2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous" (,"4,1")
}

function DisableDomainCreds {
    #2.3.10.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow storage of passwords and credentials for network authentication
    Write-Info "2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds" (,"4,1")
}

function EveryoneIncludesAnonymous {
    #2.3.10.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Let Everyone permissions apply to anonymous users    Write-Info "2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous" (,"4,0")
}

function NullSessionPipes {
    #2.3.10.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Named Pipes that can be accessed anonymously
    Write-Info "2.3.10.7 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes" ("7", " ")
}

function AllowedExactPaths {
    #2.3.10.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths    Write-Info "2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine" (
        "7",
        "System\CurrentControlSet\Control\ProductOptions",
        "System\CurrentControlSet\Control\Server Applications",
        "Software\Microsoft\Windows NT\CurrentVersion")
}

function AllowedPaths {
    #2.3.10.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths and sub-paths    Write-Info "2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine" (
        "7",
        "System\CurrentControlSet\Control\Print\Printers",
        "System\CurrentControlSet\Services\Eventlog",
        "Software\Microsoft\OLAP Server",
        "Software\Microsoft\Windows NT\CurrentVersion\Print",
        "Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "System\CurrentControlSet\Control\ContentIndex",
        "System\CurrentControlSet\Control\Terminal Server",
        "System\CurrentControlSet\Control\Terminal Server\UserConfig",
        "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
        "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
        "System\CurrentControlSet\Services\SysmonLog")
}

function RestrictNullSessAccess {
    #2.3.10.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Restrict anonymous access to Named Pipes and Shares
    Write-Info "2.3.10.10 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess" (,"4,1")
}

function RestrictRemoteSAM {
    #2.3.10.11 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Restrict clients allowed to make remote calls to SAM
    Write-Info "2.3.10.11 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM" (,"1,O:BAG:BAD:(A;;RC;;;BA)")
}

function NullSessionShares {
    #2.3.10.12 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Shares that can be accessed anonymously
    Write-Info "2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares" (,"7,")
}

function LsaForceGuest {
    #2.3.10.13 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Sharing and security model for local accounts
    Write-Info "2.3.10.13 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest" (,"4,0")
}

function LsaUseMachineId {
    #2.3.11.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow Local System to use computer identity for NTLM    Write-Info "2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId" (,"4,1")
}

function AllowNullSessionFallback {
    #2.3.11.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow LocalSystem NULL session fallback    Write-Info "2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback " (,"4,0")
}

function AllowOnlineID {
    #2.3.11.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network Security: Allow PKU2U authentication requests to this computer to use online identities
    Write-Info "2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID " (,"4,0")
}

function SupportedEncryptionTypes {
    #2.3.11.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Configure encryption types allowed for Kerberos
    Write-Info "2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes" (,"4,2147483640")
}

function NoLMHash {
    #2.3.11.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Do not store LAN Manager hash value on next password change 
    Write-Info "2.3.11.5 Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash" (,"4,1")
}

function ForceLogoff {
    #2.3.11.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Force logoff when logon hours expire
    Write-Info "2.3.11.6 Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
    SetSecurityPolicy "ForceLogoffWhenHourExpire" (,"1")
}

function LmCompatibilityLevel {
    #2.3.11.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LAN Manager authentication level
    Write-Info "2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel" (,"4,5")
}

function LDAPClientIntegrity {
    #2.3.11.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LDAP client signing requirements
    Write-Info "2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity" (,"4,1")
}

function NTLMMinClientSec {
    #2.3.11.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
    Write-Info "2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec" (,"4,537395200")
}

function NTLMMinServerSec {
    #2.3.11.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
    Write-Info "2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec" (,"4,537395200")
}

function ShutdownWithoutLogon {
    #2.3.13.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Shutdown: Allow system to be shut down without having to log on
    Write-Info "2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon" (,"4,0")
}

function ObCaseInsensitive {
    #2.3.15.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Require case insensitivity for non Windows subsystems
    Write-Info "2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for nonWindows subsystems' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive" (, "4,1")
}

function SessionManagerProtectionMode {
    #2.3.15.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
    Write-Info "2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode" (,"4,1")
}

function FilterAdministratorToken {
    #2.3.17.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Admin Approval Mode for the Built-in Administrator account
    Write-Info "2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken" (,"4,1")
}

function ConsentPromptBehaviorAdmin {
    #2.3.17.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
    Write-Info "2.3.17.2 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" (,"4,2")
}

function ConsentPromptBehaviorUser {
    #2.3.17.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for standard users
    Write-Info "2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser" (,"4,0")
}

function EnableInstallerDetection {
    #2.3.17.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Detect application installations and prompt for elevation
    Write-Info "2.3.17.4 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection" (,"4,1")
}

function EnableSecureUIAPaths {
    #2.3.17.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Only elevate UIAccess applications that are installed in secure location
    Write-Info "2.3.17.5 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" (, "4,1")
}

function EnableLUA {
    #2.3.17.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Run all administrators in Admin Approval Mode
    Write-Info "2.3.17.6 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" (, "4,1")
}

function PromptOnSecureDesktop {
    #2.3.17.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Switch to the secure desktop when prompting for elevation
    Write-Info "2.3.17.7 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" (, "4,1")
}

function EnableVirtualization {
    #2.3.17.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Virtualize file and registry write failures to per-user locations
    Write-Info "2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" (, "4,1")
}

function DomainEnableFirewall {
    #9.1.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Firewall state
    Write-Info "9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall" "1"
}

function DomainDefaultInboundAction {
    #9.1.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Inbound connection 
    Write-Info "9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultInboundAction" "1"
}

function DomainDefaultOutboundAction {
    #9.1.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Outbound connections 
    Write-Info "9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultOutboundAction" "0"
}

function DomainDisableNotifications {
    #9.1.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Settings Customize\Display a notification
    Write-Info "9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DisableNotifications" "1"
}

function DomainLogFilePath {
    #9.1.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Name
    Write-Info "9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
}

function DomainLogFileSize {
    #9.1.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize" "16384"
}

function DomainLogDroppedPackets {
    #9.1.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Log dropped packets
    Write-Info "9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets" "1"
}

function DomainLogSuccessfulConnections {
    #9.1.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Log successful connections 
    Write-Info "9.1.8 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections" "1"
}

function PrivateEnableFirewall {
    #9.2.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Firewall state
    Write-Info "9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" "1"
}

function PrivateDefaultInboundAction {
    #9.2.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Inbound connection 
    Write-Info "9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultInboundAction" "1"
}

function PrivateDefaultOutboundAction {
    #9.2.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Outbound connections 
    Write-Info "9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultOutboundAction" "0"
}

function PrivateDisableNotifications {
    #9.2.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Settings Customize\Display a notification
    Write-Info "9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications" "1"
}

function PrivateLogFilePath {
    #9.2.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Name
    Write-Info "9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
}

function PrivateLogFileSize {
    #9.2.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" "16384"
}

function PrivateLogDroppedPackets {
    #9.2.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Log dropped packets
    Write-Info "9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" "1"
}

function PrivateLogSuccessfulConnections {
    #9.2.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Log successful connections 
    Write-Info "9.2.8 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" "1"
}

function PublicEnableFirewall {
    #9.3.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Firewall state
    Write-Info "9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "EnableFirewall" "1"
}

function PublicDefaultInboundAction {
    #9.3.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Inbound connection 
    Write-Info "9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultInboundAction" "1"
}

function PublicDefaultOutboundAction {
    #9.3.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Outbound connections 
    Write-Info "9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultOutboundAction" "0"
}

function PublicDisableNotifications {
    #9.3.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Settings Customize\Display a notification
    Write-Info "9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DisableNotifications" "1"
}

function PublicAllowLocalPolicyMerge  {
    #9.3.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Settings Customize\Apply local firewall rules
    Write-Info "9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "PublicAllowLocalPolicyMerge" "0"
}

function PublicAllowLocalIPsecPolicyMerge {
    #9.3.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Settings Customize\Apply local connection security rules 
    Write-Info "9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "PublicAllowLocalIPsecPolicyMerge" "0"
}

function PublicLogFilePath {
    #9.3.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Name
    Write-Info "9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
}

function PublicLogFileSize {
    #9.3.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize" "16384"
}

function PublicLogDroppedPackets {
    #9.3.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Log dropped packets
    Write-Info "9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets" "1"
}

function PublicLogSuccessfulConnections {
    #9.3.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Log successful connections 
    Write-Info "9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections" "1"
}

function AuditCredentialValidation {
    #17.1.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon\Audit Credential Validation
    Write-Info "17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
}

function AuditComputerAccountManagement {
    #17.2.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit Application Group Management
    Write-Info "17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Application Group Management" /success:disable /failure:disable
}

function AuditSecurityGroupManagement {
    #17.2.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit Security Group Management
    Write-Info "17.2.5 (L1) Ensure 'Audit Security Group Management' is set to include 'Success'"
    Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:disable
}

function AuditUserAccountManagement {
    #17.2.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit User Account Management 
    Write-Info "17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
}

function AuditPNPActivity {
    #17.3.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Detailed Tracking\Audit PNP Activity
    Write-Info "17.3.1 (L1) Ensure 'Audit PNP Activity' is set to include 'Success'"
    Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable
}

function AuditProcessCreation {
    #17.3.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Detailed Tracking\Audit Process Creation
    Write-Info "17.3.2 (L1) Ensure 'Audit Process Creation' is set to include 'Success'"
    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
}

function AuditAccountLockout {
    #17.5.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Account Lockout
    Write-Info "17.5.1 (L1) Ensure 'Audit Account Lockout' is set to include 'Failure'"
    Auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable
}

function AuditGroupMembership  {
    #17.5.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Group Membership
    Write-Info "17.5.2 (L1) Ensure 'Audit Group Membership' is set to include 'Success'"
    Auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable
}

function AuditLogoff {
    #17.5.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Logoff
    Write-Info "17.5.3 (L1) Ensure 'Audit Logoff' is set to include 'Success'"
    Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
}

function AuditLogon {
    #17.5.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Logon 
    Write-Info "17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
} 

function AuditOtherLogonLogoffEvents {
    #17.5.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Other Logon/Logoff Events
    Write-Info "17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
}

function AuditSpecialLogon {
    #17.5.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Special Logon
    Write-Info "17.5.6 (L1) Ensure 'Audit Special Logon' is set to include 'Success'"
    Auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
}

function AuditDetailedFileShare {
    #17.6.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Detailed File Share
    Write-Info "17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'"
    Auditpol /set /subcategory:"Detailed File Share" /success:disable /failure:enable
}

function AuditFileShare {
    #17.6.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit File Share 
    Write-Info "17.6.2 (L1) Ensure 'Audit File Share' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
}

function AuditOtherObjectAccessEvents {
    #17.6.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Other Object Access Events 
    Write-Info "17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
}

function AuditRemovableStorage {
    #17.6.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Removable Storage 
    Write-Info "17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
}













if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    
    $location = Get-Location
    $ExecutionList | ForEach { ( Invoke-Expression $_) } | Out-File $location\Report.txt 
    $ExecutionList | measure -Line 
    $ExecutionList | Out-File $location\PoliciesApplied.txt

} else {

    Write-Error "You must execute this script with administrator privileges!"

}

$host.UI.RawUI.ForegroundColor = $fc