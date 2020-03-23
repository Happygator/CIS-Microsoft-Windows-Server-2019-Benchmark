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
    "CreateSymbolicLinks'", #2.2.18
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
    "RequireCtlAltDel",      #3.3.7.1
    "DontDisplayLastSigned",  #3.3.7.2
    "MachineInactivityLimit", #3.3.7.3
    "LogonLegalNotice", #3.3.7.4
    "LogonLegalNoticeTitle", #3.3.7.5
    "PreviousLogonCache", #3.3.7.6
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

function SetSecEdit([string]$role, [string[]] $values, $area, $enforceCreation) {
    $valueSet = $false

    if($values -eq $null) {
        Write-Error "SetUserRight: At least one value must be provided to set the role:$($role)"
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
            $lines[$lines.Length] = $config
            Write-After "Now is: $($lines[$lines.Length -1])"
        }
    }

    $lines | out-file ${env:appdata}\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas $area
    rm -force ${env:appdata}\secpol.cfg -confirm:$false
}

function SetUserRight([string]$role, [string[]] $values, $enforceCreation) {
    SetSecEdit($role,$values,"User_Rights",$enforceCreation)
}

function SetSecurityPolicy([string]$role, [string[]] $values, $enforceCreation) {
    SetSecEdit($role,$values,"SecurityPolicy",$enforceCreation)
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
    Write-Info "2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE' (Scored)"
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
    SetSecurityPolicy "NewAdministratorName" (,$AdminNewAccountName)
}

function RenameGuestAccount {
    #2.3.1.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename guest account
    Write-Info "2.3.1.6 (L1) Configure 'Accounts: Rename guest account'"
    SetSecurityPolicy "NewGuestName" (,$GuestNewAccountName)
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

function LegalNotice {
    #2.3.7.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message text for users attempting to log on
    Write-Info "2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText" ("7",$LogonLegalNoticeMessage)
}

function LegalNoticeTitle {
    #2.3.7.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message title for users attempting to log on
    Write-Info "2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption" (,"1,`"$($LogonLegalNoticeMessage)`"")
}

function PreviousLogonCache {
    #2.3.7.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Number of previous logons to cache (in case domain controller is not available)    Write-Info "2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount" (,"1,`"4`"")
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