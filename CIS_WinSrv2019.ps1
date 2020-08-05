﻿param([string] $NewLocalAdminUsername = "",[string] $NewLocalAdminPswd = "", [string] $LegalNoticeMessageFile = "", [string] $ExecutionListFile = "")

# CIS Microsoft Windows Server 2019 RTM Benchmark
# You can get the most up to date version in:
# https://github.com/viniciusmiguel/CIS-Microsoft-Windows-Server-2019-Benchmark

##########################################################################################################
$LogonLegalNoticeMessageTitle = ""
$LogonLegalNoticeMessage = ""

#IF YOU HAVE SPECIAL SECURITY REQUIREMENTS YOU CAN DISABLE POLICIES BELLOW
$ExecutionList = @(
    #KEEP THESE IN THE BEGINING
    "CreateNewLocalAdminAccount", #Mandatory otherwise the system access is lost
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
    "AuditPolicyChange", #17.7.1
    "AuditAuthenticationPolicyChange",  #17.7.2
    "AuditAuthorizationPolicyChange",   #17.7.3
    "AuditMPSSVCRuleLevelPolicyChange", #17.7.4
    "AuditOtherPolicyChangeEvents", #17.7.5
    "AuditSpecialLogon", #17.8.1
	"AuditIPsecDriver", #17.9.1
	"AuditOtherSystemEvents", #17.9.2
	"AuditSecurityStateChange", #17.9.3
	"AuditSecuritySystemExtension", #17.9.4
	"AuditSystemIntegrity", #17.9.5
	"PreventEnablingLockScreenCamera", #18.1.1.1
	"PreventEnablingLockScreenSlideShow", #18.1.1.2
	"DisallowUsersToEnableOnlineSpeechRecognitionServices", #18.1.2.1
	"DisallowOnlineTips", #18.1.3
    #18.2.1 to 12.2.6 Not Applicable to Server outside AD Domain
	"LocalAccountTokenFilterPolicy", #18.3.1
	"ConfigureSMBv1ClientDriver", #18.3.2
	"ConfigureSMBv1server", #18.3.3
	"DisableExceptionChainValidation", #18.3.4
	#18.3.5 Not Applicable to Member Server
	"WDigestUseLogonCredential", #18.3.6
	"WinlogonAutoAdminLogon", #18.4.1
	"DisableIPv6SourceRouting", #18.4.2
	"DisableIPv4SourceRouting", #18.4.3
	"EnableICMPRedirect", #18.4.4
	"TcpIpKeepAliveTime", #18.4.5
	"NoNameReleaseOnDemand", #18.4.6
	"PerformRouterDiscovery", #18.4.7
	"SafeDllSearchMode", #18.4.8
	"ScreenSaverGracePeriod", #18.4.9
	"TcpMaxDataRetransmissionsV6", #18.4.10
	"TcpMaxDataRetransmissions", #18.4.11
	"SecurityWarningLevel", #18.4.12
	"NetBIOSNodeType", #18.5.4.1
	"EnableMulticast", #18.5.4.2
	"EnableFontProviders", #18.5.5.1
	"AllowInsecureGuestAuth", #18.5.8.1
	"LLTDIODisabled", #18.5.9.1
	"RSPNDRDisabled", #18.5.9.2
	"PeernetDisabled", #18.5.10.2
	"DisableNetworkBridges", #18.5.11.2
	"ProhibitInternetConnectionSharing", #18.5.11.3
	"StdDomainUserSetLocation", #18.5.11.4
	"HardenedPaths", #18.5.14.1
	"DisableIPv6DisabledComponents", #18.5.19.2.1
	"DisableConfigurationWirelessSettings", #18.5.20.1
	"ProhibitaccessWCNwizards", #18.5.20.2
	"fMinimizeConnections", #18.5.21.1
	"fBlockNonDomain", #18.5.21.2
	"NoCloudApplicationNotification", #18.7.1.1
	"ProcessCreationIncludeCmdLine", #18.8.3.1
	"EncryptionOracleRemediation", #18.8.4.1
	"AllowProtectedCreds", #18.8.4.2
	"EnableVirtualizationBasedSecurity", #18.8.5.1
	"RequirePlatformSecurityFeatures", #18.8.5.2
	"HypervisorEnforcedCodeIntegrity", #18.8.5.3
	"HVCIMATRequired", #18.8.5.4
	"LsaCfgFlags", #18.8.5.5
	"ConfigureSystemGuardLaunch", #18.8.6.7
	"DriverLoadPolicy", #18.8.14.1
	"NoBackgroundPolicy", #18.8.21.2
	"NoGPOListChanges", #18.8.21.3
	"EnableCdp", #18.8.21.4
	"DisableBkGndGroupPolicy", #18.8.21.5
	"DisableWebPnPDownload", #18.8.22.1.1
	"PreventHandwritingDataSharing", #18.8.22.1.2
	"PreventHandwritingErrorReports", #18.8.22.1.3
	"ExitOnMSICW", #18.8.22.1.4
	"NoWebServices", #18.8.22.1.5
	"DisableHTTPPrinting", #18.8.22.1.6
	"NoRegistration", #18.8.22.1.7
	"DisableContentFileUpdates", #18.8.22.1.8
	"NoOnlinePrintsWizard", #18.8.22.1.9
	"NoPublishingWizard", #18.8.22.1.10
	"CEIP", #18.8.22.1.11
	"CEIPEnable", #18.8.22.1.2
	"TurnoffWindowsErrorReporting", #18.8.22.1.13
	"SupportDeviceAuthenticationUsingCertificate", #18.8.25.1
	"DeviceEnumerationPolicy", #18.8.26.1
	"BlockUserInputMethodsForSignIn", #18.8.27.1
	"BlockUserFromShowingAccountDetailsOnSignin", #18.8.28.1
	"DontDisplayNetworkSelectionUI", #18.8.28.2
	"DontEnumerateConnectedUsers", #18.8.28.3
	"EnumerateLocalUsers", #18.8.28.4
	"DisableLockScreenAppNotifications", #18.8.28.5
	"BlockDomainPicturePassword", #18.8.28.6
	"AllowDomainPINLogon", #18.8.28.7
	"AllowCrossDeviceClipboard", #18.8.31.1
	"UploadUserActivities", #18.8.31.2
	"AllowNetworkBatteryStandby", #18.8.34.6.1
	"AllowNetworkACStandby", #18.8.34.6.2
	"RequirePasswordWakes", #18.8.34.6.3
	"RequirePasswordWakesAC", #18.8.34.6.4
	"fAllowUnsolicited", #18.8.36.1
	"fAllowToGetHelp", #18.8.36.2
	"EnableAuthEpResolution"
)


$AdminAccountName = "Administrator"
$GuestAccountName = "Guest"
$NewLocalAdmin = "User"
if($NewLocalAdminPswd -ne "") {
    $NewLocalAdminPassword = ConvertTo-SecureString $NewLocalAdminPswd -AsPlainText -Force
}


#Randomize the new admin and guest accounts on each system.
#This increases the security not affecting the accessibility since these accounts are always disabled. 

$seed_admin = Get-Random -Minimum 1000 -Maximum 9999
$seed_guest = Get-Random -Minimum 1000 -Maximum 9999

$AdminNewAccountName = "DisabledUser$($seed_admin)"

$GuestNewAccountName = "DisabledUserSec$($seed_guest)"

#DO NOT CHANGE CODE BELLOW THIS LINE IF YOU ARE NOT 100% SURE ABOUT WHAT YOU ARE DOING!
##########################################################################################################

#WINDOWS SID CONSTANTS
#https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

$SID_NOONE = "`"`""
$SID_ADMINISTRATORS = "*S-1-5-32-544"
$SID_GUESTS = "*S-1-5-32-546"
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

#Registry Key Types

$REG_SZ = "String"
$REG_EXPAND_SZ = "ExpandString"
$REG_BINARY = "Binary"
$REG_DWORD = "DWord"
$REG_MULTI_SZ = "MultiString"
$REG_QWORD = "Qword"

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

function CheckError([bool] $result, [string] $message) {
	# Checks the specified result value and terminates the
	# the script after printing the specified error message 
	# if the specified result is false.
    if ($result -eq $false) {
        Write-Host $message -ForegroundColor Red
        exit
    }
}

Write-Info "CIS Microsoft Windows Server 2019 RTM Benchmark"
Write-Info "Script written and tested by Vinicius Miguel"

function RegKeyExists([string] $path) {
	# Checks whether the specified registry key exists
	$result = Get-Item $path -ErrorAction SilentlyContinue
	$?
}

function SetRegistry([string] $path, [string] $key, [string] $value, [string] $keytype) {
	# Sets the specified registry value at the specified registry path to the specified value.
	# First the original value is read and print to the console.
	# If the original value does not exist, it is additionally checked
	# whether the according registry key is missing too.
	# If it is missing, the key is also created otherwise the 
	# Set-ItemProperty call would fail.
	#
	# The original implementation used try-catch to handle the errors
	# of Get-ItemProperty for missing values. However, Set-ItemProperty
	# is not throwing any exceptions. The error handling has to be done
	# by overwriting the -ErrorAction of the CmdLet and check the
	# $? variable afterwards.
	#
	# See: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7
	# See: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables?view=powershell-7

    $before = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
	
	if ($?) {
		Write-Before "Was: $($before.$key)"
	}
	else {
        Write-Before "Was: Not Defined!"
		$keyExists = RegKeyExists $path
		
		if ($keyExists -eq $false) {
            Write-Info "Creating registry key '$($path)'."
			New-Item $path -Force -ErrorAction SilentlyContinue
            CheckError $? "Creating registry key '$($path)' failed."
		}
	}

    Set-ItemProperty -Path $path -Name $key -Value $value -Type $keytype -ErrorAction SilentlyContinue

    CheckError $? "Creating registry value '$($path):$($value)' failed."
    
    $after = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
    Write-After "Now is: $($after.$key)"
}

function SetSecEdit([string]$role, [string[]] $values, $area, $enforceCreation) {
    $valueSet = $false

    if($values -eq $null) {
        Write-Error "SetSecEdit: At least one value must be provided to set the role:$($role)"
        return
    }
    
    if($enforceCreation -eq $null){
        $enforceCreation = $true
    }

    secedit /export /cfg ${env:appdata}\secpol.cfg /areas $area
	CheckError $? "Exporting '$($area)' to $(${env:appdata})\secpol.cfg' failed."
	
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
	CheckError $? "Configuring '$($area)' via $(${env:appdata})\secpol.cfg' failed."
	
    rm -force ${env:appdata}\secpol.cfg -confirm:$false
}

function SetUserRight([string]$role, [string[]] $values, $enforceCreation=$true) {
    SetSecEdit $role $values "User_Rights" $enforceCreation
}

function SetSecurityPolicy([string]$role, [string[]] $values, $enforceCreation=$true) {
    SetSecEdit $role $values "SecurityPolicy" $enforceCreation 
}

function CreateUserAccount([string] $username, [securestring] $password, [bool] $isAdmin=$false) {
    New-LocalUser -Name $username -Password $password -Description "" -AccountNeverExpires -PasswordNeverExpires
    if($isAdmin -eq $true) {
        Add-LocalGroupMember -Group "Administrators" -Member $username
    }
}

function CreateNewLocalAdminAccount {
    CreateUserAccount $NewLocalAdmin $NewLocalAdminPassword $true
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
    SetUserRight "SeDenyNetworkLogonRight" ($SID_LOCAL_ACCOUNT, $($AdminNewAccountName),$($SID_GUESTS))
}

function DenyGuestBatchLogon {
    #2.2.22 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a batch job
    Write-Info "2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
    SetUserRight "SeDenyBatchLogonRight" (,$SID_GUESTS)
}

function DenyGuestServiceLogon {
    #2.2.23 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a service
    Write-Info "2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'"
    SetUserRight "SeDenyServiceLogonRight" (,$SID_GUESTS)
}

function DenyGuestLocalLogon {
    #2.2.24 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on locally
    Write-Info "2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'"
    SetUserRight "SeDenyInteractiveLogonRight" (,$SID_GUESTS)
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
    Set-LocalUser -Name $AdminNewAccountName -Description " "
}

function RenameGuestAccount {
    #2.3.1.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename guest account
    Write-Info "2.3.1.6 (L1) Configure 'Accounts: Rename guest account'"
    SetSecurityPolicy "NewGuestName" (,"`"$($GuestNewAccountName)`"")
    Set-LocalUser -Name $GuestNewAccountName -Description " "
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
    #2.3.6.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Maximum machine account password age
    Write-Info "2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
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
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption" (,"1,`"$($LogonLegalNoticeMessageTitle)`"")
}

function PreviousLogonCache {
    #2.3.7.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Number of previous logons to cache (in case domain controller is not available)
    Write-Info "2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'"
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
    #2.3.10.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Let Everyone permissions apply to anonymous users
    Write-Info "2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous" (,"4,0")
}

function NullSessionPipes {
    #2.3.10.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Named Pipes that can be accessed anonymously
    Write-Info "2.3.10.7 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes" ("7", " ")
}

function AllowedExactPaths {
    #2.3.10.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths
    Write-Info "2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine" (
        "7",
        "System\CurrentControlSet\Control\ProductOptions",
        "System\CurrentControlSet\Control\Server Applications",
        "Software\Microsoft\Windows NT\CurrentVersion")
}

function AllowedPaths {
    #2.3.10.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths and sub-paths
    Write-Info "2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths'"
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
    #2.3.11.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow Local System to use computer identity for NTLM
    Write-Info "2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId" (,"4,1")
}

function AllowNullSessionFallback {
    #2.3.11.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow LocalSystem NULL session fallback
    Write-Info "2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
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
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall" "1" $REG_DWORD
}

function DomainDefaultInboundAction {
    #9.1.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Inbound connection 
    Write-Info "9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultInboundAction" "1" $REG_DWORD
}

function DomainDefaultOutboundAction {
    #9.1.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Outbound connections 
    Write-Info "9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultOutboundAction" "0" $REG_DWORD
}

function DomainDisableNotifications {
    #9.1.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Settings Customize\Display a notification
    Write-Info "9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DisableNotifications" "1" $REG_DWORD
}

function DomainLogFilePath {
    #9.1.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Name
    Write-Info "9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\domainfw.log" $REG_SZ
}

function DomainLogFileSize {
    #9.1.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize" "16384" $REG_DWORD
}

function DomainLogDroppedPackets {
    #9.1.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Log dropped packets
    Write-Info "9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function DomainLogSuccessfulConnections {
    #9.1.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Log successful connections 
    Write-Info "9.1.8 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
}

function PrivateEnableFirewall {
    #9.2.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Firewall state
    Write-Info "9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" "1" $REG_DWORD
}

function PrivateDefaultInboundAction {
    #9.2.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Inbound connection 
    Write-Info "9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultInboundAction" "1" $REG_DWORD
}

function PrivateDefaultOutboundAction {
    #9.2.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Outbound connections 
    Write-Info "9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultOutboundAction" "0" $REG_DWORD
}

function PrivateDisableNotifications {
    #9.2.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Settings Customize\Display a notification
    Write-Info "9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications" "1" $REG_DWORD
}

function PrivateLogFilePath {
    #9.2.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Name
    Write-Info "9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\privatefw.log" $REG_SZ
}

function PrivateLogFileSize {
    #9.2.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" "16384" $REG_DWORD
}

function PrivateLogDroppedPackets {
    #9.2.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Log dropped packets
    Write-Info "9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function PrivateLogSuccessfulConnections {
    #9.2.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Log successful connections 
    Write-Info "9.2.8 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
}

function PublicEnableFirewall {
    #9.3.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Firewall state
    Write-Info "9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "EnableFirewall" "1" $REG_DWORD
}

function PublicDefaultInboundAction {
    #9.3.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Inbound connection 
    Write-Info "9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultInboundAction" "1" $REG_DWORD
}

function PublicDefaultOutboundAction {
    #9.3.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Outbound connections 
    Write-Info "9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultOutboundAction" "0" $REG_DWORD
}

function PublicDisableNotifications {
    #9.3.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Settings Customize\Display a notification
    Write-Info "9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DisableNotifications" "1" $REG_DWORD
}

function PublicAllowLocalPolicyMerge  {
    #9.3.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Settings Customize\Apply local firewall rules
    Write-Info "9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "PublicAllowLocalPolicyMerge" "0" $REG_DWORD
}

function PublicAllowLocalIPsecPolicyMerge {
    #9.3.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Settings Customize\Apply local connection security rules 
    Write-Info "9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "PublicAllowLocalIPsecPolicyMerge" "0" $REG_DWORD
}

function PublicLogFilePath {
    #9.3.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Name
    Write-Info "9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\publicfw.log" $REG_SZ
}

function PublicLogFileSize {
    #9.3.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize" "16384" $REG_DWORD
}

function PublicLogDroppedPackets {
    #9.3.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Log dropped packets
    Write-Info "9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function PublicLogSuccessfulConnections {
    #9.3.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Log successful connections 
    Write-Info "9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
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

function AuditPolicyChange {
    #17.7.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Audit Policy Change
    Write-Info "17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success'"
    Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:disable
}

function AuditAuthenticationPolicyChange {
    #17.7.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authentication Policy Change 
    Write-Info "17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
    Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:disable
}

function AuditAuthorizationPolicyChange {
    #17.7.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authorization Policy Change 
    Write-Info "17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success'"
    Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:disable
}

function AuditMPSSVCRuleLevelPolicyChange {
    #17.7.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit MPSSVC RuleLevel Policy Change
    Write-Info "17.7.4 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
}

function AuditOtherPolicyChangeEvents {
    #17.7.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Other Policy Change Events
    Write-Info "17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"
    Auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:enable
}

function AuditSpecialLogon {
    #17.8.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Privilege Use\Audit Sensitive Privilege Use 
    Write-Info "17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
}

function AuditIPsecDriver  {
    #17.9.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit IPsec Driver
    Write-Info "17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
}

function AuditOtherSystemEvents  {
    #17.9.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit Other System Events
    Write-Info "17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
}

function AuditSecurityStateChange {
    #17.9.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit Security State Change 
    Write-Info "17.9.3 (L1) Ensure 'Audit Security State Change' is set to include 'Success'"
    Auditpol /set /subcategory:"Security State Change" /success:enable /failure:disable
}

function AuditSecuritySystemExtension {
    #17.9.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit Security System Extension 
    Write-Info "17.9.4 (L1) Ensure 'Audit Security System Extension' is set to include 'Success'"
    Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:disable
}

function AuditSystemIntegrity {
    #17.9.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit System Integrity
    Write-Info "17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
}

function PreventEnablingLockScreenCamera {
    #18.1.1.1 => Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen camera 
    Write-Info "18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" "1" $REG_DWORD
}

function PreventEnablingLockScreenSlideShow {
    #18.1.1.2 => Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen slide show
    Write-Info "18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" "1" $REG_DWORD
}

function DisallowUsersToEnableOnlineSpeechRecognitionServices {
    #18.1.2.1 => Computer Configuration\Policies\Administrative Templates\Control Panel\Regional and Language Options\Allow users to enable online speech recognition services
    Write-Info "18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0" $REG_DWORD
}

function DisallowOnlineTips  {
    #18.1.3 => Computer Configuration\Policies\Administrative Templates\Control Panel\Allow Online Tips 
    Write-Info "18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips" "0" $REG_DWORD
}

function LocalAccountTokenFilterPolicy {
    #18.3.1 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\Apply UAC restrictions to local accounts on network logons 
    Write-Info "18.3.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy" "1" $REG_DWORD
}

function ConfigureSMBv1ClientDriver  {
    #18.3.2 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure SMB v1 client driver 
    Write-Info "18.3.2 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb1" "Start" "1" $REG_DWORD
}

function ConfigureSMBv1server {
    #18.3.3 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure SMB v1 server
    Write-Info "18.3.3 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" "0" $REG_DWORD
}

function DisableExceptionChainValidation {
    #18.3.4 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\Enable Structured Exception Handling Overwrite Protection (SEHOP)
    Write-Info "18.3.4 (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "1" $REG_DWORD
}

function WDigestUseLogonCredential   {
    #18.3.6 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\WDigest Authentication (disabling may require KB2871997)
    Write-Info "18.3.6 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" "0" $REG_DWORD
}

# MSS Group Policies are not supported by GPEDIT anymore. the values must be ckecked directly on the registry

function WinlogonAutoAdminLogon {
    #18.4.1 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)
    Write-Info "18.4.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0" $REG_DWORD
}

function DisableIPv6SourceRouting {
    #18.4.2 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) 
    Write-Info "18.4.2 (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting" "1" $REG_DWORD
}

function DisableIPv4SourceRouting {
    #18.4.3 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
    Write-Info "18.4.3 (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting" "1" $REG_DWORD
}

function EnableICMPRedirect {
    #18.4.4 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
    Write-Info "18.4.4 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" "0"  $REG_DWORD
}

function TcpIpKeepAliveTime {
    #18.4.5 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds 
    Write-Info "18.4.5 (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "KeepAliveTime" "300000"  $REG_DWORD
}

function NoNameReleaseOnDemand {
    #18.4.6 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
    Write-Info "18.4.6 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand" "1" $REG_DWORD
}

function PerformRouterDiscovery {
    #18.4.7 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS) 
    Write-Info "18.4.7 (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "PerformRouterDiscovery" "0" $REG_DWORD
}

function SafeDllSearchMode {
    #18.4.8 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)
    Write-Info "18.4.8 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager" "SafeDllSearchMode" "1" $REG_DWORD
}

function ScreenSaverGracePeriod {
    #18.4.9 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended) 
    Write-Info "18.4.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScreenSaverGracePeriod" "5" $REG_DWORD
}

function TcpMaxDataRetransmissionsV6 {
    #18.4.10 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS:(TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted
    Write-Info "18.4.10 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "TcpMaxDataRetransmissions" "3" $REG_DWORD
}

function TcpMaxDataRetransmissions {
    #18.4.11 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS:(TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted
    Write-Info "18.4.11 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TcpMaxDataRetransmissions" "3" $REG_DWORD
}

function SecurityWarningLevel {
    #18.4.12 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning 
    Write-Info "18.4.12 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" "WarningLevel" "90" $REG_DWORD
}

function NetBIOSNodeType {
    #18.5.4.1 => Navigate to the Registry path articulated in the Remediation section and confirm it is set as prescribed. 
    Write-Info "18.5.4.1 (L1) Set 'NetBIOS node type' to 'P-node' (Ensure NetBT Parameter 'NodeType' is set to '0x2 (2)')"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType" "2" $REG_DWORD
}

function EnableMulticast {
    #18.5.4.2 => Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Turn off multicast name resolution 
    Write-Info "18.5.4.2 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "0" $REG_DWORD
}

function EnableFontProviders {
    #18.5.5.1 => Computer Configuration\Policies\Administrative Templates\Network\Fonts\Enable Font Providers
    Write-Info "18.5.5.1 (L2) Ensure 'Enable Font Providers' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders" "0" $REG_DWORD
}

function AllowInsecureGuestAuth {
    #18.5.8.1 => Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Enable insecure guest logons 
    Write-Info "18.5.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth" "0" $REG_DWORD
}

function LLTDIODisabled {
    #18.5.9.1 => Computer Configuration\Policies\Administrative Templates\Network\Link-Layer Topology Discovery\Turn on Mapper I/O (LLTDIO) driver
    Write-Info "18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnDomain" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnPublicNet" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableLLTDIO" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitLLTDIOOnPrivateNet " "0" $REG_DWORD
}

function RSPNDRDisabled {
    #18.5.9.2 => Computer Configuration\Policies\Administrative Templates\Network\Link-Layer Topology Discovery\Turn on Responder (RSPNDR) driver
    Write-Info "18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnDomain" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnPublicNet" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableRspndr" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitRspndrOnPrivateNet" "0" $REG_DWORD
}

function PeernetDisabled {
    #18.5.10.2 => Computer Configuration\Policies\Administrative Templates\Network\Microsoft Peer-to-Peer Networking Services\Turn off Microsoft Peer-to-Peer Networking Services
    Write-Info "18.5.10.2 (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" "Disabled" "1"  $REG_DWORD
}

function DisableNetworkBridges {
    #18.5.11.2 => Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Prohibit installation and configuration of Network Bridge on your DNS domain network 
    Write-Info "18.5.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA" "0"  $REG_DWORD
}

function ProhibitInternetConnectionSharing {
    #18.5.11.3 => Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Prohibit use of Internet Connection Sharing on your DNS domain network
    Write-Info "18.5.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI" "0"  $REG_DWORD
}

function StdDomainUserSetLocation {
    #18.5.11.4 => Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Require domain users to elevate when setting a network's location 
    Write-Info "18.5.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_StdDomainUserSetLocation" "1" $REG_DWORD
}

function HardenedPaths {
    #18.5.14.1 => Computer Configuration\Policies\Administrative Templates\Network\Network Provider\Hardened UNC Paths
    Write-Info "18.5.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON" "RequireMutualAuthentication=1, RequireIntegrity=1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL" "RequireMutualAuthentication=1, RequireIntegrity=1" $REG_SZ
}

function DisableIPv6DisabledComponents {
    #18.5.19.2.1 => Navigate to the Registry path articulated in the Remediation section and confirm it is set as prescribed. 
    Write-Info "18.5.19.2.1 (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "DisabledComponents" "255"  $REG_DWORD
}

function DisableConfigurationWirelessSettings {
    #18.5.20.1 => Computer Configuration\Policies\Administrative Templates\Network\Windows Connect Now\Configuration of wireless settings using Windows Connect Now 
    Write-Info "18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "EnableRegistrars" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableUPnPRegistrar" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableInBand802DOT11Registrar" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableFlashConfigRegistrar" "0" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableWPDRegistrar" "0" $REG_DWORD
}

function ProhibitaccessWCNwizards {
    #18.5.20.2 => Computer Configuration\Policies\Administrative Templates\Network\Windows Connect Now\Prohibit access of the Windows Connect Now wizards
    Write-Info "18.5.20.2 (L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" "DisableWcnUi" "1"  $REG_DWORD
}

function fMinimizeConnections {
    #18.5.21.1 => Computer Configuration\Policies\Administrative Templates\Network\Windows Connection Manager\Minimize the number of simultaneous connections to the Internet or a Windows Domain 
    Write-Info "18.5.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" "1" $REG_DWORD
}

function fBlockNonDomain {
    #18.5.21.2 => Computer Configuration\Policies\Administrative Templates\Network\Windows Connection Manager\Prohibit connection to non-domain networks when connected to domain authenticated network
    Write-Info "18.5.21.2 (L2) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain" "1" $REG_DWORD
}

function NoCloudApplicationNotification {
    #18.7.1.1 => Computer Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Turn off notifications network usage
    Write-Info "18.7.1.1 (L2) Ensure 'Turn off notifications network usage' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" "1" $REG_DWORD
}

function ProcessCreationIncludeCmdLine {
    #18.8.3.1 => Computer Configuration\Policies\Administrative Templates\System\Audit Process Creation\Include command line in process creation events
    Write-Info "18.8.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" "0" $REG_DWORD
}

function EncryptionOracleRemediation {
    #18.8.4.1 => Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Encryption Oracle Remediation
    Write-Info "18.8.4.1 (L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" "0" $REG_DWORD
}

function AllowProtectedCreds {
    #18.8.4.2 => Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Remote host allows delegation of non-exportable credentials
    Write-Info "18.8.4.2 (L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" "1" $REG_DWORD
}

function EnableVirtualizationBasedSecurity {
    #18.8.5.1 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security
    Write-Info "18.8.5.1 (NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" "1" $REG_DWORD
}

function RequirePlatformSecurityFeatures {
    #18.8.5.2 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Select Platform Security Level
    Write-Info "18.8.5.2 (NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures" "3" $REG_DWORD
}

function HypervisorEnforcedCodeIntegrity {
    #18.8.5.3 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity 
    Write-Info "18.8.5.3 (NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'" ""
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity" "1" $REG_DWORD
}

function HVCIMATRequired {
    #18.8.5.4 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Require UEFI Memory Attributes Table
    Write-Info "18.8.5.4 (NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired" "1" $REG_DWORD
}

function LsaCfgFlags {
    #18.8.5.5 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Credential Guard Configuration
    Write-Info "18.8.5.5 (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags" "1" $REG_DWORD
}

function ConfigureSystemGuardLaunch {
    #18.8.6.7 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Secure Launch Configuration
    Write-Info "18.8.5.7 (NG) Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureSystemGuardLaunch" "1" $REG_DWORD
}

function DriverLoadPolicy {
    #18.8.14.1 => Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\Boot-Start Driver Initialization Policy
    Write-Info "18.8.14.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" "1" $REG_DWORD
}

function NoBackgroundPolicy {
    #18.8.21.2 => Computer Configuration\Policies\Administrative Templates\System\Group Policy\Configure registry policy processing
    Write-Info "18.8.21.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" "0" $REG_DWORD
}

function NoGPOListChanges {
    #18.8.21.3 => Computer Configuration\Policies\Administrative Templates\System\Group Policy\Configure registry policy processing
    Write-Info "18.8.21.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" "1" $REG_DWORD
}

function EnableCdp {
    #18.8.21.4 => Computer Configuration\Policies\Administrative Templates\System\Group Policy\Continue experiences on this device
    Write-Info "18.8.21.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" "0" $REG_DWORD
}

function DisableBkGndGroupPolicy {
    #18.8.21.5 => Computer Configuration\Policies\Administrative Templates\System\Group Policy\Turn off background refresh of Group Policy 
    Write-Info "18.8.21.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled' "
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableBkGndGroupPolicy" "0" $REG_DWORD
}

function DisableWebPnPDownload {
    #18.8.22.1.1 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off downloading of print drivers over HTTP
    Write-Info "18.8.22.1.1 (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" "1" $REG_DWORD
}

function PreventHandwritingDataSharing {
    #18.8.22.1.2 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off handwriting personalization data sharing
    Write-Info "18.8.22.1.2 (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" "1" $REG_DWORD
}

function PreventHandwritingErrorReports {
    #18.8.22.1.3 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off handwriting recognition error reporting
    Write-Info "18.8.22.1.3 (L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" "1" $REG_DWORD
}

function ExitOnMSICW {
    #18.8.22.1.4 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com 
    Write-Info "18.8.22.1.4 (L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled' "
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" "ExitOnMSICW" "1" $REG_DWORD
}

function NoWebServices {
    #18.8.22.1.5 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Internet download for Web publishing and online ordering wizards 
    Write-Info "18.8.22.1.5 (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices" "1" $REG_DWORD
}

function DisableHTTPPrinting {
    #18.8.22.1.6 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off printing over HTTP
    Write-Info "18.8.22.1.6 (L2) Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting" "1" $REG_DWORD
}

function NoRegistration {
    #18.8.22.1.7 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Registration if URL connection is referring to Microsoft.com 
    Write-Info "18.8.22.1.7 (L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" "NoRegistration" "1" $REG_DWORD
}

function DisableContentFileUpdates {
    #18.8.22.1.8 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Search Companion content file updates 
    Write-Info "18.8.22.1.8 (L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" "DisableContentFileUpdates" "1" $REG_DWORD
}

function NoOnlinePrintsWizard {
    #18.8.22.1.9 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off the "Order Prints" picture task 
    Write-Info "18.8.22.1.9 (L2) Ensure 'Turn off the Order Prints picture task' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoOnlinePrintsWizard" "1" $REG_DWORD
}

function NoPublishingWizard {
    #18.8.22.1.10 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off the "Publish to Web" task for files and folders
    Write-Info "18.8.22.1.10 (L2) Ensure 'Turn off the Publish to Web task for files and folders' is set to 'Enabled'" 
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPublishingWizard" "1" $REG_DWORD
}

function CEIP {
    #18.8.22.1.11 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off the Windows Messenger Customer Experience Improvement Program
    Write-Info "18.8.22.1.11 (L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" "CEIP" "1" $REG_DWORD
}

function CEIPEnable {
    #18.8.22.1.2 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Windows Customer Experience Improvement Program 
    Write-Info "18.8.22.1.12 (L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" "1" $REG_DWORD
}

function TurnoffWindowsErrorReporting {
    #18.8.22.1.13 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Windows Error Reporting 
    Write-Info "18.8.22.1.13 (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" "1" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" "DoReport" "1" $REG_DWORD
}

function SupportDeviceAuthenticationUsingCertificate {
    #18.8.25.1 => Computer Configuration\Policies\Administrative Templates\System\Kerberos\Support device authentication using certificate 
    Write-Info "18.8.25.1 (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" "DevicePKInitBehavior" "1" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" "DevicePKInitEnabled" "1" $REG_DWORD
}

function DeviceEnumerationPolicy {
    #18.8.26.1 => Computer Configuration\Policies\Administrative Templates\System\Kernel DMA Protection\Enumeration policy for external devices incompatible with Kernel DMA Protection
    Write-Info "18.8.26.1 (L1) Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy" "1" $REG_DWORD
}

function BlockUserInputMethodsForSignIn {
    #18.8.27.1 => Computer Configuration\Policies\Administrative Templates\System\Locale Services\Disallow copying of user input methods to the system account for sign-in
    Write-Info "18.8.27.1 (L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" "BlockUserInputMethodsForSignIn" "1" $REG_DWORD
}

function BlockUserFromShowingAccountDetailsOnSignin {
    #18.8.28.1 => Computer Configuration\Policies\Administrative Templates\System\Logon\Block user from showing account details on sign-in
    Write-Info "18.8.28.1 (L1) Ensure 'Block user from showing account details on signin' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin" "1" $REG_DWORD
}

function DontDisplayNetworkSelectionUI {
    #18.8.28.2 => Computer Configuration\Policies\Administrative Templates\System\Logon\Do not display network selection UI
    Write-Info "18.8.28.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI" "1" $REG_DWORD
}

function DontEnumerateConnectedUsers {
    #18.8.28.3 => Computer Configuration\Policies\Administrative Templates\System\Logon\Do not enumerate connected users on domain-joined computers 
    Write-Info "18.8.28.3 (L1) Ensure 'Do not enumerate connected users on domainjoined computers' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontEnumerateConnectedUsers" "1" $REG_DWORD
}

function EnumerateLocalUsers {
    #18.8.28.4 => Computer Configuration\Policies\Administrative Templates\System\Logon\Enumerate local users on domain-joined computers
    Write-Info "18.8.28.4 (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' "
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers" "0" $REG_DWORD
}

function DisableLockScreenAppNotifications {
    #18.8.28.5 => Computer Configuration\Policies\Administrative Templates\System\Logon\Turn off app notifications on the lock screen 
    Write-Info "18.8.28.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications" "1" $REG_DWORD
}

function BlockDomainPicturePassword {
    #18.8.28.6 => Computer Configuration\Policies\Administrative Templates\System\Logon\Turn off picture password sign-in
    Write-Info "18.8.28.6 (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockDomainPicturePassword" "1" $REG_DWORD
}

function AllowDomainPINLogon {
    #18.8.28.7 => Computer Configuration\Policies\Administrative Templates\System\Logon\Turn on convenience PIN sign-in 
    Write-Info "18.8.28.7 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon" "0" $REG_DWORD
}

function AllowCrossDeviceClipboard {
    #18.8.31.1 => Computer Configuration\Policies\Administrative Templates\System\OS Policies\Allow Clipboard synchronization across devices
    Write-Info "18.8.31.1 (L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard" "0" $REG_DWORD
}

function UploadUserActivities {
    #18.8.31.2 => Computer Configuration\Policies\Administrative Templates\System\OS Policies\Allow upload of User Activities
    Write-Info "18.8.31.2 (L2) Ensure 'Allow upload of User Activities' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" "0" $REG_DWORD
}

function AllowNetworkBatteryStandby {
    #18.8.34.6.1 => Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Allow network connectivity during connected-standby (on battery)
    Write-Info "18.8.34.6.1 (L2) Ensure 'Allow network connectivity during connectedstandby (on battery)' is set to 'Disabled' "
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9" "DCSettingIndex" "0" $REG_DWORD
}

function AllowNetworkACStandby {
    #18.8.34.6.2 => Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Allow network connectivity during connected-standby (plugged in)
    Write-Info "18.8.34.6.2 (L2) Ensure 'Allow network connectivity during connectedstandby (plugged in)' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9" "ACSettingIndex" "0" $REG_DWORD
}

function RequirePasswordWakes {
    #18.8.34.6.3 => Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Require a password when a computer wakes (on battery)
    Write-Info "18.8.34.6.3 (L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex" "1" $REG_DWORD
}

function RequirePasswordWakesAC {
    #18.8.34.6.4 => Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Require a password when a computer wakes (plugged in)
    Write-Info "18.8.34.6.4 (L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex" "1" $REG_DWORD
}

function fAllowUnsolicited {
    #18.8.36.1 => Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Offer Remote Assistance
    Write-Info "18.8.36.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited" "0" $REG_DWORD
}

function fAllowToGetHelp {
    #18.8.36.2 => Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Solicited Remote Assistance
    Write-Info "18.8.36.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" "0" $REG_DWORD
}

function EnableAuthEpResolution {
    #18.8.37.1 => Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Enable RPC Endpoint Mapper Client Authentication 
    Write-Info "18.8.37.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution" "1" $REG_DWORD
}

function RestrictRemoteClients {
    #18.8.37.2 => Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Restrict Unauthenticated RPC clients 
    Write-Info "18.8.37.2 (L2) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients" "1" $REG_DWORD
}

function DisableQueryRemoteServer {
    #18.8.45.5 => Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Microsoft Support Diagnostic Tool\Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider 
    Write-Info "18.8.45.5.1 (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" "DisableQueryRemoteServer" "0" $REG_DWORD
}

function ScenarioExecutionEnabled {
    #18.8.45.11.1 => Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Windows Performance PerfTrack\Enable/Disable PerfTrack 
    Write-Info "18.8.45.11.1 (L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b9654fc3-8781-88dd50a6299d}" "ScenarioExecutionEnabled" "0" $REG_DWORD
}

function DisabledAdvertisingInfo {
    #18.8.47.1 => Computer Configuration\Policies\Administrative Templates\System\User Profiles\Turn off the advertising ID 
    Write-Info "18.8.47.1 (L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" "1" $REG_DWORD
}

function NtpClientEnabled {
    #18.8.50.1.1 => Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers\Enable Windows NTP Client 
    Write-Info "18.8.50.1.1 (L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" "Enabled" "1" $REG_DWORD
}

function DisableWindowsNTPServer {
    #18.8.50.1.2 => Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers\Enable Windows NTP Server
    Write-Info "18.8.50.1.2 (L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" "Enabled" "0" $REG_DWORD
}

function AllowSharedLocalAppData {
    #18.9.4.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment\Allow a Windows app to share application data between users
    Write-Info "18.9.4.1 (L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData" "0" $REG_DWORD
}

function MSAOptional {
    #18.9.6.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\App runtime\Allow Microsoft accounts to be optional 
    Write-Info "18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" "1" $REG_DWORD
}

function NoAutoplayfornonVolume {
    #18.9.8.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Disallow Autoplay for non-volume devices 
    Write-Info "18.9.8.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" "1" $REG_DWORD
}

function NoAutorun {
    #18.9.8.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Set the default behavior for AutoRun 
    Write-Info "18.9.8.2 (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" "1" $REG_DWORD
}

function NoDriveTypeAutoRun {
    #18.9.8.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Turn off Autoplay
    Write-Info "18.9.8.3 (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" "1" $REG_DWORD
}

function EnhancedAntiSpoofing {
    #18.9.10.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Biometrics\Facial Features\Configure enhanced anti-spoofing
    Write-Info "18.9.10.1.1 (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing" "1" $REG_DWORD
}

function DisallowCamera {
    #18.9.12.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Camera\Allow Use of Camera 
    Write-Info "18.9.12.1 (L2) Ensure 'Allow Use of Camera' is set to 'Disabled'" 
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera" "0" $REG_DWORD
}

function DisableWindowsConsumerFeatures {
    #18.9.13.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off Microsoft consumer experiences
    Write-Info "18.9.13.1 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1" $REG_DWORD
}

function RequirePinForPairing {
    #18.9.14.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Connect\Require pin for pairing 
    Write-Info "18.9.14.1 (L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing" "1" $REG_DWORD
}

function DisablePasswordReveal {
    #18.9.15.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Do not display the password reveal button
    Write-Info "18.9.15.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal" "1" $REG_DWORD
}

function DisableEnumerateAdministrators {
    #18.9.15.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Enumerate administrator accounts on elevation
    Write-Info "18.9.15.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators" "0" $REG_DWORD
}

function DisallowTelemetry {
    #18.9.16.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Telemetry 
    Write-Info "18.9.16.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "0" $REG_DWORD
}

function DisableEnterpriseAuthProxy {
    #18.9.16.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service
    Write-Info "18.9.16.2 (L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy" "1" $REG_DWORD
}

function DoNotShowFeedbackNotifications {
    #18.9.16.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Do not show feedback notifications
    Write-Info "18.9.16.3 (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" "1" $REG_DWORD
}

function AllowBuildPreview {
    #18.9.16.4 => Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Toggle user control over Insider builds
    Write-Info "18.9.16.4 (L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" "AllowBuildPreview" "0" $REG_DWORD
}

function EventLogRetention  {
    #18.9.26.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application\Control Event Log behavior when the log file reaches its maximum size
    Write-Info "18.9.26.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention" "0" $REG_DWORD
}

function EventLogMaxSize {
    #18.9.26.1.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application\Specify the maximum log file size (KB)
    Write-Info "18.9.26.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" "32768" $REG_DWORD
}

function EventLogSecurityRetention {
    #18.9.26.2.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security\Control Event Log behavior when the log file reaches its maximum size
    Write-Info "18.9.26.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention" "0" $REG_DWORD
}

function EventLogSecurityMaxSize {
    #18.8.26.2.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security\Specify the maximum log file size (KB)
    Write-Info "18.9.26.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize" "196608" $REG_DWORD
}

function EventLogSetupRetention {
    #18.9.26.3.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup\Control Event Log behavior when the log file reaches its maximum size
    Write-Info "18.9.26.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "Retention" "0" $REG_DWORD
}

function EventLogSetupMaxSize {
    #18.9.26.3.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup\Specify the maximum log file size (KB)
    Write-Info "18.9.26.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize" "32768" $REG_DWORD
}

function EventLogSystemRetention {
    #18.9.26.4.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System\Control Event Log behavior when the log file reaches its maximum size
    Write-Info "18.9.26.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "Retention" "0" $REG_DWORD
}

function EventLogSystemMaxSize {
    #18.9.26.4.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System\Specify the maximum log file size (KB)
    Write-Info "18.9.26.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize" "32768" $REG_DWORD
}

function NoDataExecutionPrevention {
    #18.9.30.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off Data Execution Prevention for Explorer 
    Write-Info "18.9.30.2 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "0" $REG_DWORD
}

function NoHeapTerminationOnCorruption {
    #18.9.30.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off heap termination on corruption 
    Write-Info "18.9.30.3 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "0" $REG_DWORD
}

function PreXPSP2ShellProtocolBehavior {
    #18.9.30.4 => Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off shell protocol protected mode
    Write-Info "18.9.30.4 (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "0" $REG_DWORD
}

function LocationAndSensorsDisableLocation {
    #18.9.39.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Location and Sensors\Turn off location
    Write-Info "18.9.39.2 (L2) Ensure 'Turn off location' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" "1" $REG_DWORD
}

function MessagingAllowMessageSync {
    #18.9.43.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Messaging\Allow Message Service Cloud Sync
    Write-Info "18.9.43.1 (L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" "AllowMessageSync" "0" $REG_DWORD
}

function MicrosoftAccountDisableUserAuth {
    #18.9.44.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft accounts\Block all consumer Microsoft account user authentication
    Write-Info "18.9.44.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth" "1" $REG_DWORD
}

function OneDriveDisableFileSyncNGSC {
    #18.9.52.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\OneDrive\Prevent the usage of OneDrive for file storage
    Write-Info "18.9.52.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "1" $REG_DWORD
}

function TerminalServicesDisablePasswordSaving {
    #18.9.59.2.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Connection Client\Do not allow passwords to be saved
    Write-Info "18.9.59.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving" "1"
}

function fSingleSessionPerUser {
    #18.9.59.3.2.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Connections\Restrict Remote Desktop Services users to a single Remote Desktop Services session 
    Write-Info "18.9.59.3.2.1 (L2) Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fSingleSessionPerUser" "1" $REG_DWORD
}
 
function TerminalServicesfDisableCcm {
    #18.9.59.3.3.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow COM port redirection
    Write-Info "18.9.59.3.3.1 (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Service" "fDisableCcm" "1" $REG_DWORD
}

function TerminalServicesfDisableCdm {
    #18.9.59.3.3.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection
    Write-Info "18.9.59.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" "1" $REG_DWORD
}

function TerminalServicesfDisableLPT {
    #18.9.59.3.3.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow LPT port redirection
    Write-Info "18.9.59.3.3.3 (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Service" "fDisableLPT" "1" $REG_DWORD
}

function TerminalServicesfDisablePNPRedir {
    #18.9.59.3.3.4 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow supported Plug and Play device redirection
    Write-Info "18.9.59.3.3.4 (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisablePNPRedir" "1" $REG_DWORD
}

function TerminalServicesfPromptForPassword {
    #18.9.59.3.9.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Always prompt for password upon connection
    Write-Info "18.9.59.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword" "1" $REG_DWORD
}

function TerminalServicesfEncryptRPCTraffic {
    #18.9.59.3.9.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require secure RPC communication
    Write-Info "18.9.59.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic" "1" $REG_DWORD
}

function TerminalServicesSecurityLayer {
    #18.9.59.3.9.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require use of specific security layer for remote (RDP) connections
    Write-Info "18.9.59.3.9.3 (L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer" "1" $REG_DWORD
}

function TerminalServicesUserAuthentication {
    #18.9.59.3.9.4 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require user authentication for remote connections by using Network Level Authentication
    Write-Info "18.9.59.3.9.4 (L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication" "1" $REG_DWORD
}

function TerminalServicesMinEncryptionLevel {
    #18.9.59.3.9.5 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Set client connection encryption level
    Write-Info "18.9.59.3.9.5 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel" "1" $REG_DWORD
}

function TerminalServicesMaxIdleTime {
    #18.9.59.3.10.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active but idle Remote Desktop Services sessions
    Write-Info "18.9.59.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime" "15" $REG_DWORD
}

function TerminalServicesMaxDisconnectionTime {
    #18.9.59.3.10.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for disconnected sessions 
    Write-Info "18.9.59.3.10.2 (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxDisconnectionTime" "1" $REG_DWORD
}

function TerminalServicesDeleteTempDirsOnExit {
    #18.9.59.3.11.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders\Do not delete temp folders upon exit
    Write-Info "18.9.59.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit" "0" $REG_DWORD
}

function TerminalServicesPerSessionTempDir {
    #18.9.59.3.11.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders\Do not use temporary folders per session
    Write-Info "18.9.59.3.11.2 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "PerSessionTempDir" "0" $REG_DWORD
}

function DisableEnclosureDownload {
    #18.9.60.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\RSS Feeds\Prevent downloading of enclosures
    Write-Info "18.9.60.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "1" $REG_DWORD
}

function WindowsSearchAllowCloudSearch {
    #18.9.61.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow Cloud Search
    Write-Info "18.9.61.2 (L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" "1" $REG_DWORD
}

function AllowIndexingEncryptedStoresOrItems {
    #18.9.61.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow indexing of encrypted files
    Write-Info "18.9.61.3 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" "0" $REG_DWORD
}

function NoGenTicket {
    #18.9.66.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Software Protection Platform\Turn off KMS Client Online AVS Validation
    Write-Info "18.9.66.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" "NoGenTicket" "1" $REG_DWORD
}

function LocalSettingOverrideSpynetReporting {
    #18.9.77.3.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS\Configure local setting override for reporting to Microsoft MAPS
    Write-Info "18.9.77.3.1 (L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "LocalSettingOverrideSpynetReporting" "0" $REG_DWORD
}

function SpynetReporting {
    #18.9.77.3.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS\Join Microsoft MAPS
    Write-Info "18.9.77.3.2 (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting" "0" $REG_DWORD
}

function DisableBehaviorMonitoring {
    #18.9.77.7.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Real-Time Protection\Turn on behavior monitoring 
    Write-Info "18.9.77.7.1 (L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
    SetRegistry "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring" "1" $REG_DWORD
}

function DisableGenericRePorts {
    #18.9.77.9.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Reporting\Configure Watson events
    Write-Info "18.9.77.9.1 (L2) Ensure 'Configure Watson events' is set to 'Disabled'"
    SetRegistry "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" "DisableGenericRePorts" "0" $REG_DWORD
}

function DisableRemovableDriveScanning {
    #18.9.77.10.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan\Scan removable drives
    Write-Info "18.9.77.10.1 (L1) Ensure 'Scan removable drives' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableRemovableDriveScanning" "1" $REG_DWORD
}

function DisableEmailScanning {
    #18.9.77.10.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan\Turn on e-mail scanning
    Write-Info "18.9.77.10.2 (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableEmailScanning" "1" $REG_DWORD
}

function ExploitGuard_ASR_Rules {
    #18.9.77.13.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules
    Write-Info "18.9.77.13.1.1 (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules" "1" $REG_DWORD
}

function ConfigureASRrules {
    #18.9.77.13.1.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules: Set the state for each ASR rule
    Write-Info "18.9.77.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "26190899-1602-49e8-8b27-eb1d0a1ce869" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "3b576869-a4ec-4529-8536-b80a7769e899" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "5beb7efe-fd9a-4556-801d-275e5ffc04cc" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d3e037e1-3eb8-44c8-a917-57927947596d" "1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d4f940ab-401b-4efc-aadc-ad5f3c50688a" "1" $REG_SZ
} 

function EnableNetworkProtection {
    #18.9.77.13.3.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Network Protection\Prevent users and apps from accessing dangerous websites
    Write-Info "18.9.77.13.3.1 (L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection" "1" $REG_DWORD
}

function PUAProtection {
    #18.9.77.14 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Configure detection for potentially unwanted applications
    Write-Info "18.9.77.14 (L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection" "1" $REG_DWORD
}

function DisableAntiSpyware {
    #18.9.77.15 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Turn off Windows Defender AntiVirus
    Write-Info "18.9.77.15 (L1) Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "0" $REG_DWORD
}

function DefenderSmartScreen {
    #18.9.80.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender SmartScreen\Explorer\Configure Windows Defender SmartScreen
    Write-Info "18.9.80.1.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" "1" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "1" $REG_DWORD
}

function AllowSuggestedAppsInWindowsInkWorkspace {
    #18.9.84.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Ink Workspace\Allow suggested apps in Windows Ink Workspace
    Write-Info "18.9.84.1 (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowSuggestedAppsInWindowsInkWorkspace" "0" $REG_DWORD
}

function AllowWindowsInkWorkspace {
    #18.9.84.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Ink Workspace\Allow Windows Ink Workspace
    Write-Info "18.9.84.2 (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" "1" $REG_DWORD
}

function InstallerEnableUserControl {
    #18.9.85.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Allow user control over installs
    Write-Info "18.9.85.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" "0" $REG_DWORD
}

function InstallerAlwaysInstallElevated {
    #18.9.85.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Always install with elevated privileges
    Write-Info "18.9.85.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0" $REG_DWORD
}

function InstallerSafeForScripting {
    #18.9.85.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Prevent Internet Explorer security prompt for Windows Installer scripts
    Write-Info "18.9.85.3 (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting" "0" $REG_DWORD
}

function DisableAutomaticRestartSignOn {
    #18.9.86.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\Sign-in last interactive user automatically after a system-initiated restart 
    Write-Info "18.9.86.1 (L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "0" $REG_DWORD
}

function EnableScriptBlockLogging {
    #18.9.95.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Script Block Logging
    Write-Info "18.9.95.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" "0" $REG_DWORD
}

function EnableTranscripting {
    #18.9.95.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Transcription 
    Write-Info "18.9.95.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "0" $REG_DWORD
}

function WinRMClientAllowBasic  {
    #18.9.97.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Allow Basic authentication
    Write-Info "18.9.97.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic" "0" $REG_DWORD
}

function WinRMClientAllowUnencryptedTraffic {
    #18.9.97.1.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Allow unencrypted traffic
    Write-Info "18.9.97.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" "0" $REG_DWORD
}

function WinRMClientAllowDigest {
    #18.9.97.1.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Disallow Digest authentication
    Write-Info "18.9.97.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest" "1" $REG_DWORD
}

function WinRMServiceAllowBasic {
    #18.9.97.2.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow Basic authentication 
    Write-Info "18.9.97.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic" "0" $REG_DWORD
}

function WinRMServiceAllowAutoConfig {
    #18.9.97.2.2 => Computer Configuration\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow remote server management through WinRM
    Write-Info "18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig" "0" $REG_DWORD
}

function WinRMServiceAllowUnencryptedTraffic {
    #18.9.97.2.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow unencrypted traffic
    Write-Info "18.9.97.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic" "0" $REG_DWORD
}

function WinRMServiceDisableRunAs {
    #18.9.97.2.4 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Disallow WinRM from storing RunAs credentials
    Write-Info "18.9.97.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs" "1" $REG_DWORD
}

function WinRSAllowRemoteShellAccess {
    #18.9.98.1 => Computer Configuration\Administrative Templates\Windows Components\Windows Remote Shell\Allow Remote Shell Access
    Write-Info "18.9.98.1 (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" "AllowRemoteShellAccess" "0" $REG_DWORD
}

function DisallowExploitProtectionOverride {
    #18.9.99.2.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Security\App and browser protection\Prevent users from modifying settings 
    Write-Info "18.9.99.2.1 (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitProtectionOverride" "1" $REG_DWORD
}

function Managepreviewbuilds {
    #18.9.102.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Windows Update for Business\Manage preview builds
    Write-Info "18.9.102.1.1 (L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuilds" "1" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuildsPolicyValue" "1" $REG_DWORD
}

function WindowsUpdateFeature {
    #18.9.102.1.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Windows Update for Business\Select when Preview Builds and Feature Updates are received
    Write-Info "18.9.102.1.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdates" "1" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdatesPeriodInDays" "180" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "BranchReadinessLevel" "16" $REG_DWORD
}

function WindowsUpdateQuality {
    #18.9.102.1.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Windows Update for Business\Select when Quality Updates are received
    Write-Info "18.9.102.1.3 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdates" "1" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays" "0" $REG_DWORD
}

function ConfigureAutomaticUpdates {
    #18.8.102.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Configure Automatic Updates
    Write-Info "18.9.102.2 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" "4" $REG_DWORD
}

function Scheduledinstallday {
    #18.9.102.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Configure Automatic Updates: Scheduled install day
    Write-Info "18.9.102.3 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" "0" $REG_DWORD
}

function NoAutoRebootWithLoggedOnUsers {
    #18.9.102.4 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\No auto-restart with logged on users for scheduled automatic updates installations
    Write-Info "18.9.102.4 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" "0" $REG_DWORD
}

function ValidatePasswords([string] $pass1, [string] $pass2) {
    if($pass1 -ne $pass2) { return $False }
    if($pass1 -notmatch "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$#^!%*?&])[A-Za-z\d@$#^!%*?&]{15,}$") { return $False }
    return $True;
}
if ([Environment]::Is64BitProcess -ne [Environment]::Is64BitOperatingSystem)
{
    Write-Error "You must execute this script on a x64 shell"
    Write-Error "Aborted."
    return 1;
}
if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    
    
    $temp_pass1 = ""
    $temp_pass2 = ""
    $invalid_pass = $true

    if($NewLocalAdminUsername -ne "") {
        if($NewLocalAdminPswd -eq "") {
            Write-Error "NewLocalAdminUsername set but NewLocalAdminPasswd not set."
            Write-Error "Please use -NewLocalAdminPassword parameter to set the password!"
            return
        } else {
            if((ValidatePasswords $NewLocalAdminPswd $NewLocalAdminPswd) -eq $False) {
                Write-Error "NewLocalAdminPassword does not fullfill the minimum security requirements"
                Write-Info "Your passwords must contain at least 15 characters, capital letters, numbers and symbols"
                return 1;
            } else {
                $temp_pass1 = ConvertTo-SecureString $NewLocalAdminPassword -AsPlainText -Force 
            }
        }
    } else {
        do {
            Write-Info "I will create a new Administrator account, you need to specify the new account password."
            Write-Info "Your password must contain at least 15 characters, capital letters, numbers and symbols"
            Write-Info "Please enter the new password:"
            $temp_pass1 = Read-Host
            Write-Info "Please repeat the new password:"
            $temp_pass2 = Read-Host 
            $invalid_pass = ValidatePasswords $temp_pass1 $temp_pass2 
            if($invalid_pass -eq $false) {
                Write-Error "Your passwords do not match or do not follow the minimum complexity requirements, try again."
            } else {
                $NewLocalAdminPassword = ConvertTo-SecureString $temp_pass1 -AsPlainText -Force 
            }
        } while($invalid_pass -eq $false)
    }
    
    

    if($LegalNoticeMessageFile -ne "") {
        if(Test-Path($LegalNoticeMessageFile) -eq $False) {
            Write-Error "The script cannot continue, The LegalNoticeMessageFile was provided but could not found"
            return 1;
        }
        $legalNoticeFilePath = Resolve-Path $LegalNoticeMessageFile

        $legalNoticeFileContent = Get-Content $legalNoticeFilePath -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" }

        if($legalNoticeFileContent.Length -ne 2) {
            Write-Error "The script cannot continue, The LegalNoticeMessageFile content should contain 2 Lines, being the first one the Legal Notice Title and the second one the Legal Notice Message"
            return 1;
        }
        $LogonLegalNoticeMessageTitle = $legalNoticeFileContent[0]
        $LogonLegalNoticeMessage = $legalNoticeFileContent[1]
    }

    if($ExecutionListFile -ne "") {
        if(Test-Path($ExecutionListFile) -eq $False) {
            Write-Error "A execution list file was provided as parameter but could not be found! Aborting."
            return 1;
        }
        $ExecutionList = Get-Content $ExecutionListFile -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
    }

    $location = Get-Location
    
    secedit /export /cfg $location\secedit_original.cfg
    
    $ExecutionList | ForEach-Object { ( Invoke-Expression $_) } | Out-File $location\Report.txt 
    $ExecutionList | Measure-Object -Line 
    $ExecutionList | Out-File $location\PoliciesApplied.txt

    secedit /export /cfg $location\secedit_final.cfg

} else {

    Write-Error "You must execute this script with administrator privileges!"
    Write-Error "Aborted."
    return 1;
}

$host.UI.RawUI.ForegroundColor = $fc