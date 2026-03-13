<#
newgoat.ps1
- made by Dashell Finn last updated mar 2026
- always a WIP script, there is always more I want to add.
- added windows defender registry search thing, still lags out at end...
- added pii search, not sure if im looking in the right directories
- ports enumeration version numbers now work
- added some random stuff from some schools at the top. Also added ntlmv1 fixes.
- I debugged it a bunch, only things that seem to cause issues are the Defender search and the registry backup thing, they either hang or take to long but for defender it at least works.
- if it ever stalls just send a newline and its usually fine (usually happens on port enum, should be almost instant)
#>


#allow for powershell built in things like -Verbose and -Debug with no parameters bc I dont want to memorize ts
[CmdletBinding()]
param()



# ---------- UI helpers ----------
function Write-Section([string]$title) { Write-Host ""; Write-Host ("----------[{0}]----------" -f $title) }

function Read-YesNo([string]$message, [bool]$default=$true) {
    $suffix = if ($default) { " (Y/n): " } else { " (y/N): " }
    while ($true) {
        $in = Read-Host ($message + $suffix)
        if ([string]::IsNullOrWhiteSpace($in)) { return $default }
        switch ($in.ToLower()) { 'y' { return $true } 'yes' { return $true } 'n' { return $false } 'no' { return $false } default { Write-Host "Please answer Y or N." -ForegroundColor Yellow } }
    }
}


# ssh helpers
function Escape-BashSingle([string]$s) {
    if ($null -eq $s) { return "''" }
    return "'" + ($s -replace "'", "'\''") + "'"
}

function Invoke-SshScriptB64 {
    param(
        [Parameter(Mandatory=$true)][string]$SshBin,
        [Parameter(Mandatory=$true)][string]$User,
        [Parameter(Mandatory=$true)][string]$TargetHost,
        [Parameter(Mandatory=$true)][string]$ScriptText,
        [string[]]$Args = @()
    )

    $argStr = if ($Args -and $Args.Count -gt 0) { ($Args | ForEach-Object { Escape-BashSingle $_ }) -join ' ' } else { "" }
    $remoteCmd = if ([string]::IsNullOrWhiteSpace($argStr)) { "sh -s" } else { "sh -s -- $argStr" }

    $sshArgs = @(
        "-T",
        "-l", $User,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=NUL",
        "-o", "GlobalKnownHostsFile=NUL",
        "-o", "LogLevel=ERROR",
        $TargetHost,
        $remoteCmd
    )

    # send script over STDIN (PowerShell-safe)
    $payload = ($ScriptText -replace "`r","")

   $oldOE = $OutputEncoding
    try {
        $OutputEncoding = [System.Text.Encoding]::UTF8

        # Run ssh, then FORCE everything into string[] (no ErrorRecord objects leak out)
        $raw = $payload | & $SshBin @sshArgs 2>&1
        return @($raw | ForEach-Object { [string]$_ })
    }
    finally {
        $OutputEncoding = $oldOE
    }
}


function Remove-AnsiAndControls([string]$s) {
    if ($null -eq $s) { return $s }
    # ANSI escapes
    $s = $s -replace "`e\[[0-9;]*[A-Za-z]", ""
    # other control chars (keep CR/LF/TAB)
    $s = $s -replace "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", ""
    return $s
}



# ---------- Core helpers (basically all gpo stuff) ----------
function Ensure-Modules { Import-Module ActiveDirectory -ErrorAction Stop; Import-Module GroupPolicy -ErrorAction Stop }
function New-OrGetGPO { param([string]$Name) $g=Get-GPO -Name $Name -ErrorAction SilentlyContinue; if(-not $g){$g=New-GPO -Name $Name}; $g }
function Link-GPO { param([Microsoft.GroupPolicy.Gpo]$Gpo,[string]$Target,[int]$Order=1) New-GPLink -Name $Gpo.DisplayName -Target $Target -ErrorAction SilentlyContinue | Out-Null; Set-GPLink -Target $Target -Guid $Gpo.Id -Order $Order | Out-Null }
function Set-Reg { param([string]$Gpo,[string]$Key,[string]$Name,[ValidateSet('DWord','String','MultiString')]$Type,$Value) Set-GPRegistryValue -Name $Gpo -Key $Key -ValueName $Name -Type $Type -Value $Value | Out-Null }
function Get-GpoSysvolMachinePath { 
    param([Microsoft.GroupPolicy.Gpo]$Gpo) $domain=(Get-ADDomain).DNSRoot
    $guid=$Gpo.Id.ToString("B").ToUpper()
    "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Microsoft\Windows NT\SecEdit" 
}
function Ensure-GptTmplValue {
    param([Microsoft.GroupPolicy.Gpo]$Gpo,[string]$Name,[int]$Value)
    $path = Get-GpoSysvolMachinePath -Gpo $Gpo
    if (-not (Test-Path $path)) { New-Item -Path $path -ItemType Directory -Force | Out-Null }
    $inf  = Join-Path $path 'GptTmpl.inf'
    if (-not (Test-Path $inf)) { "[Version]`r`nsignature=`"$CHICAGO$`"`r`nRevision=1`r`n[Event Audit]`r`n" | Set-Content -Path $inf -Encoding Unicode }
    $content = Get-Content -Path $inf -Encoding Unicode -Raw
    $nameEsc = [regex]::Escape($Name)
    $pattern = "^\s*$nameEsc\s*=\s*\d+\s*$"
    $opts = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::Multiline
    if ([regex]::IsMatch($content,$pattern,$opts)) { $content = [regex]::Replace($content,$pattern,"$Name = $Value",$opts) }
    else { if ($content -match '\[Event Audit\]') { $content = $content -replace '(\[Event Audit\][^\[]*)', ('$1'+"$Name = $Value`r`n") } else { $content += "[Event Audit]`r`n$Name = $Value`r`n" } }
    Set-Content -Path $inf -Value $content -Encoding Unicode
}



# the real gpo stuff begins ;)

function Configure-NetworkGPO {
    param([Microsoft.GroupPolicy.Gpo]$Gpo,[switch]$Aes256Only)
    $n=$Gpo.DisplayName
    # SMB signing/guest/SMB1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature'  DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature'  DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' DWord 0
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' DWord 4
    Set-Reg $n 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' DWord 0
    # Client plaintext off + SPN hardening
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnablePlainTextPassword' DWord 0
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SmbServerNameHardeningLevel' DWord 2
    # LSA/anonymous/blank pw
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' DWord 0
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'ForceGuest' DWord 0
    # Null sessions & SAM remote calls
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionPipes'  MultiString @()
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionShares' MultiString @()
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictRemoteSAM' String 'O:BAG:BAD:(A;;RC;;;BA)'
    # RPC
    Set-Reg $n 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' 'RestrictRemoteClients'  DWord 1
    Set-Reg $n 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' 'EnableAuthEpResolution' DWord 1
    # LDAP client signing
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' DWord 2
    # Netlogon secure channel
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireSignOrSeal' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SignSecureChannel' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SealSecureChannel' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireStrongKey'  DWord 1
    if ($Aes256Only) { Set-Reg $n 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' DWord 16 }
    # NTLM/LM posture
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' DWord 5
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec' DWord 537395200
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinServerSec' DWord 537395200
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic' DWord 2
    # Identity/fallback
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'UseMachineId' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AllowNullSessionFallback' DWord 0
    # Legacy Computer Browser service off
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Browser' 'Start' DWord 4
}

function Configure-DCSigningGPO { 
    param([Microsoft.GroupPolicy.Gpo]$Gpo) Set-Reg $Gpo.DisplayName 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity' DWord 2 
}

# it does a couple more things than audit but i dont want to make another func
function Configure-AuthAuditGPO {
    param([Microsoft.GroupPolicy.Gpo]$Gpo)
    $n=$Gpo.DisplayName

    #non audit stuff
    Set-Reg $n 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCAD' DWord 0
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' 'AllowOnlineID' DWord 0
    Set-Reg $n 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableUIADesktopToggle' DWord 0
    Set-Reg $n 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' DWord 5
    Set-Reg $n 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' 'Enabled' DWord 0
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' 'ObCaseInsensitive' DWord 1
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode' DWord 1
    Set-Reg $n 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ShutdownWithoutLogon' DWord 0
    Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'ClearPageFileAtShutdown' DWord 1
    Set-Reg $n 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' 'AuthenticodeEnabled' DWord 0

    #audit stuff
    Ensure-GptTmplValue -Gpo $Gpo -Name 'AuditAccountLogon' -Value 3
    Ensure-GptTmplValue -Gpo $Gpo -Name 'AuditLogonEvents'  -Value 3
    Ensure-GptTmplValue -Gpo $Gpo -Name 'AuditPolicyChange' -Value 3
}



# --- password input with "*" mask bc why not (doesnt work for ssh tho :,( ) ---
function Read-HostMasked([string]$Prompt) {
    $rawui = $Host.UI.RawUI
    Write-Host -NoNewline ($Prompt + ": ")
    $secure = New-Object System.Security.SecureString
    $count = 0
    while ($true) {
        $key = $rawui.ReadKey("NoEcho,IncludeKeyDown")
        $vk = $key.VirtualKeyCode
        $ch = $key.Character
        if ($vk -eq 13) { break }                               # enter
        elseif ($vk -eq 8) {                                     # backspace
            if ($count -gt 0 -and $secure.Length -gt 0) {
                $secure.RemoveAt($secure.Length - 1); $count--
                Write-Host -NoNewline "`b `b"
            }
        }
        elseif ($vk -eq 27) {                                    # Escape clears
            while ($secure.Length -gt 0) { $secure.RemoveAt($secure.Length - 1) }
            while ($count -gt 0) { Write-Host -NoNewline "`b `b"; $count-- }
        }
        elseif ($ch) { $secure.AppendChar($ch); $count++; Write-Host -NoNewline "*" }
    }
    Write-Host ""
    $secure.MakeReadOnly()
    return $secure
}
function Read-PasswordTwiceMasked([string]$Prompt) {
    while ($true) {
        $p1 = Read-HostMasked $Prompt
        $p2 = Read-HostMasked "Re-enter password to confirm"

        $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
        $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)

        try {
            $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
            $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)

            if ($s1 -eq $s2) {
                return $p1
            }

            Write-Host "Passwords do not match. Please try again." -ForegroundColor Yellow
        }
        finally {
            if ($b1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1) }
            if ($b2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
        }
    }
}



function Get-PortCat {
    param(
        [Parameter(Mandatory=$true)][int]$Port,
        [Parameter(Mandatory=$false)][string]$Loc
    )
    switch ($Port) {
        21 { "FTP" }
        22 { "SSH" }
        23 { "Telnet" }
        25 { "SMTP" }
        53 { "DNS" }
        { $_ -in 80,443,8080,8443,3000,5000 } { "Web" }
        123 { "NTP (Time)" }
        { $_ -in 135,593 } { "RPC" }
        { $_ -in 137,138 } { "NetBIOS" }
        { $_ -in 139,445 } { "SMB" }
        { $_ -in 389,636,3268,3269 } { "LDAP" }
        { $_ -in 88,464 } { "Kerberos" }
        { $_ -in 500,4500 } { "IPSec/VPN" }
        3389 { "RDP" }
        5353 { "mDNS" }
        5355 { "LLMNR" }
        { $_ -in 5985,5986 } { "WinRM" }
        9389 { "ADWS" }
        47001 { "WinRM Mgmt" }
        1433 { "SQL Server" }
        3306 { "MySQL" }
        5432 { "Postgres" }
        5900 { "VNC" }
        5800 { "VNC-Http" }
        default {
            if ($Loc -match 'iis|w3wp|apache|nginx|tomcat|node|python|php|gunicorn') { return "Web App" }
            if ($Loc -match 'sql|mongo|redis|oracle|postgres|mysqld') { return "Database" }
            if ($Loc -match 'dns|named|bind') { return "DNS" }
            return "N/A"
        }
    }
}


# Built-in Administrator account stuff
function Get-BuiltinAdmin { 
    $dom=Get-ADDomain
    $sid="$($dom.DomainSID)-500" 
    Get-ADUser -LDAPFilter "(objectSid=$sid)" 
}

function Set-DomainAdminPassword {
    [CmdletBinding()]
    param()
    $admin = Get-BuiltinAdmin
    if (-not $admin) { throw "Could not locate built-in Administrator (RID 500)." }
    Write-Host "----------[Password Reset]----------"
    $pwd = Read-PasswordTwiceMasked "Enter new DOMAIN 'Administrator' password"
    Set-ADAccountPassword -Identity $admin -NewPassword $pwd -Reset -ErrorAction Stop
    Enable-ADAccount -Identity $admin -ErrorAction SilentlyContinue
    Unlock-ADAccount -Identity $admin -ErrorAction SilentlyContinue
    Write-Host "[OK] Domain Administrator password reset"
}




# ---------- Main ----------

#make sure ur admin
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ 
    throw "Run in an elevated PowerShell." 
}
Ensure-Modules



#the chosen ones
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$dcOU    = $domain.DomainControllersContainer




#extra hardening I found from other schools
Write-Section "Local DC Safe Hardening (Logging + TLS + Cred Guardrails)"
if (Read-YesNo "Apply SAFE local hardening on THIS Domain Controller only?" $true) {

    # --- DC check (local only) ---
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.DomainRole -lt 4) {
            Write-Host "[SKIP] This machine is not a Domain Controller (DomainRole=$($cs.DomainRole))." -ForegroundColor Yellow
            return
        }
        Write-Host "[OK] Domain Controller detected. Applying LOCAL changes only." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Could not determine DomainRole. Skipping: $($_.Exception.Message)" -ForegroundColor Yellow
        return
    }

    # --- helper ---
    function Ensure-Key([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    }

    # =========================================================
    # 1) TLS 1.2 enablement (SCHANNEL Server+Client)
    # =========================================================
    try {
        $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
        Ensure-Key "$base\Server"
        New-ItemProperty -Path "$base\Server" -Name "Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "$base\Server" -Name "DisabledByDefault" -Value 0 -PropertyType DWord -Force | Out-Null

        Ensure-Key "$base\Client"
        New-ItemProperty -Path "$base\Client" -Name "Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "$base\Client" -Name "DisabledByDefault" -Value 0 -PropertyType DWord -Force | Out-Null

        Write-Host "[OK] TLS 1.2 SCHANNEL keys set (Server+Client)." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] TLS 1.2 SCHANNEL configuration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # =========================================================
    # 2) Audit policy (enable success+failure broadly + key subs)
    # =========================================================
    try {
        & auditpol /set /category:* /success:enable /failure:enable | Out-Null

        @(
            "Security State Change", "Security System Extension", "System Integrity",
            "Logon", "Logoff", "Account Lockout", "Special Logon",
            "Process Creation", "Process Termination",
            "User Account Management", "Security Group Management",
            "Audit Policy Change", "Authentication Policy Change",
            "Credential Validation", "Kerberos Authentication Service"
        ) | ForEach-Object {
            & auditpol /set /subcategory:"$_" /success:enable /failure:enable | Out-Null
        }

        Write-Host "[OK] Advanced audit policy enabled (success+failure) + key subcategories." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Audit policy configuration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # =========================================================
    # 3) PowerShell logging (ScriptBlock + Module + Transcription)
    # =========================================================
    try {
        # ScriptBlock logging
        Ensure-Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
            -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null

        # Module logging (log all modules)
        Ensure-Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
            -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force | Out-Null

        Ensure-Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
            -Name "*" -Value "*" -PropertyType String -Force | Out-Null

        # Transcription (policy-based)
        $txDir = "C:\Windows\Logs\PSTranscripts"
        try { New-Item -ItemType Directory -Path $txDir -Force | Out-Null } catch { }
        Ensure-Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
            -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
            -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
            -Name "OutputDirectory" -Value $txDir -PropertyType String -Force | Out-Null

        Write-Host "[OK] PowerShell logging enabled (ScriptBlock + Module + Transcription)." -ForegroundColor Green
        Write-Host "     Transcripts: $txDir" -ForegroundColor Gray
    } catch {
        Write-Host "[WARN] PowerShell logging configuration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # =========================================================
    # 4) Include command line in process creation events (4688)
    # =========================================================
    try {
        Ensure-Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
            -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force | Out-Null

        Write-Host "[OK] Enabled command-line capture for process creation auditing (4688)." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] ProcessCreationIncludeCmdLine setting failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # =========================================================
    # 5) Remove common accessibility IFEO debugger backdoors
    # =========================================================
    try {
        $ifeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        @("sethc.exe","Utilman.exe","osk.exe","Narrator.exe","Magnify.exe") | ForEach-Object {
            $k = Join-Path $ifeoBase $_
            if (Test-Path -LiteralPath $k) {
                try { Remove-ItemProperty -Path $k -Name "Debugger" -Force -ErrorAction SilentlyContinue } catch { }
            }
        }
        Write-Host "[OK] Cleared IFEO Debugger values for common accessibility binaries (if present)." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] IFEO cleanup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # =========================================================
    # 6) Safer autorun controls (does not touch web-search/Cortana)
    # =========================================================
    try {
        Ensure-Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -Name "NoAutorun" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWord -Force | Out-Null

        Write-Host "[OK] Autorun disabled via policy keys." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Autorun policy configuration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # =========================================================
    # 7) Credential guardrails (optional toggles to avoid breakage)
    # =========================================================
    # WDigest off is generally safe and helps prevent cleartext creds in LSASS
    try {
        Ensure-Key "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
            -Name "UseLogonCredential" -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
            -Name "Negotiate" -Value 0 -PropertyType DWord -Force | Out-Null

        Write-Host "[OK] WDigest UseLogonCredential disabled (reduces cleartext credential exposure)." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] WDigest hardening failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # RunAsPPL can affect some security/credential plugins; keep it opt-in
    if (Read-YesNo "Enable LSA Protection (RunAsPPL)? (More secure; may affect some credential/security software)" $false) {
        try {
            Ensure-Key "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host "[OK] LSA Protection enabled (RunAsPPL=1)." -ForegroundColor Green
        } catch {
            Write-Host "[WARN] RunAsPPL setting failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[SKIP] RunAsPPL not enabled." -ForegroundColor DarkGray
    }

    # Cached logons change can impact offline logon scenarios; keep opt-in
    if (Read-YesNo "Reduce cached logons to 2? (Helps limit cached creds; may impact offline logons)" $false) {
        try {
            Ensure-Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
                -Name "CachedLogonsCount" -Value "2" -PropertyType String -Force | Out-Null
            Write-Host "[OK] CachedLogonsCount set to 2." -ForegroundColor Green
        } catch {
            Write-Host "[WARN] CachedLogonsCount setting failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[SKIP] CachedLogonsCount unchanged." -ForegroundColor DarkGray
    }

    # =========================================================
    # 8) DNS cache flush (safe)
    # =========================================================
    try {
        & ipconfig /flushdns | Out-Null
        Write-Host "[OK] DNS cache flushed." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] DNS flush failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "[OK] Local DC safe hardening complete." -ForegroundColor Green
    Write-Host "     Some changes may require a reboot to fully take effect (notably RunAsPPL, SCHANNEL, some auditing)." -ForegroundColor Gray

} else {
    Write-Host "[SKIP] Local DC safe hardening" -ForegroundColor DarkGray
}



# =========================================================
# Ports & Services (Deep Config Inventory)  -- FIXED SSH + FIXED BRACES
# =========================================================
Write-Section "Ports & Services (Deep Config Inventory)"
$doScan = Read-YesNo "Enumerate listening ports with Config/Path Discovery + Version Enumeration?" $true

if ($doScan) {
    $wellKnownOnly = Read-YesNo "Only show well-known ports (<= 49151)?" $false

    # --- DISCOVERY & TOOL CHECK ---
    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch { Write-Host "[WARN] RSAT AD Module missing." -ForegroundColor Yellow; return }

    # Find SSH Binary (for Linux targets)
    $sshBin = "ssh.exe"
    if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
        $customPath = "C:\Users\Administrator\openssh\OpenSSH-Win64\ssh.exe"
        if (Test-Path $customPath) {
            $sshBin = $customPath
            Write-Host "[INFO] Found custom SSH at: $sshBin" -ForegroundColor Gray
        } else {
            Write-Host "[WARN] 'ssh.exe' not found in PATH." -ForegroundColor Yellow
            $sshBin = Read-Host "[INPUT] Please enter full path to ssh.exe"
            if (-not (Test-Path $sshBin)) { Write-Host "[FAIL] Invalid path. Linux scans will fail."; $sshBin = $null }
        }
    }

    Write-Host "[INFO] Querying Active Directory..." -ForegroundColor Cyan
    $comps = Get-ADComputer -Filter "Enabled -eq 'True'" -Properties "DNSHostName", "OperatingSystem", "Name"
    Write-Host ("[INFO] Targets found: {0}" -f $comps.Count)

    # --- WINDOWS PORT ENUM (REMOTE SCRIPTBLOCK) ---
    $windowsScriptBlock = {
        $results = New-Object System.Collections.Generic.List[object]

        function Split-ExeFromCmdLine([string]$cmd) {
            if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }
            $c = $cmd.Trim()
            if ($c -match '^\s*"([^"]+\.exe)"') { return $matches[1] }
            if ($c -match '^\s*([^\s]+\.exe)\b') { return $matches[1] }
            return $null
        }

        function Get-FileVersionSummary([string]$path) {
            try {
                if ([string]::IsNullOrWhiteSpace($path)) { return $null }
                $p = $path.Trim('"')
                if (-not (Test-Path -LiteralPath $p)) { return $null }
                $vi = (Get-Item -LiteralPath $p).VersionInfo
                $pv = $vi.ProductVersion
                $fv = $vi.FileVersion
                $pn = $vi.ProductName
                if ($pn -and $pv -and $fv -and ($pv -ne $fv)) { return "$pn $pv (file $fv)" }
                if ($pn -and $pv) { return "$pn $pv" }
                if ($fv) { return "FileVersion $fv" }
                return $null
            } catch { return $null }
        }

        function Get-IISVersionSummary {
            try {
                $inet = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue
                if ($inet -and $inet.VersionString) { return $inet.VersionString }
            } catch { }
            return $null
        }

        $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        $allSvcs  = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        $netstat  = & netstat -ano 2>$null

        $webMap = @{}
        if (Get-Module -ListAvailable WebAdministration) {
            try {
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
                if ($sites) {
                    foreach ($site in $sites) {
                        $path = $null
                        try { $path = $site.physicalPath } catch {}
                        if (-not $path) { $path = "Unknown Path" }

                        if ($site.bindings -and $site.bindings.Collection) {
                            foreach ($b in $site.bindings.Collection) {
                                if ($b.protocol -match "http" -and $b.bindingInformation) {
                                    $parts = $b.bindingInformation -split ":"
                                    if ($parts.Count -ge 2) {
                                        $port = [int]$parts[1]
                                        $webMap[$port] = "IIS Site: '$($site.name)' -> $path"
                                    }
                                }
                            }
                        }
                    }
                }
            } catch { }
        }

        $procMap = @{}
        if ($allProcs) { foreach ($p in $allProcs) { $procMap[[int]$p.ProcessId] = $p } }

        $svcMap = @{}
        if ($allSvcs) {
            foreach ($s in $allSvcs) {
                $pidVal = [int]$s.ProcessId
                if (-not $svcMap.ContainsKey($pidVal)) { $svcMap[$pidVal] = @() }
                $svcMap[$pidVal] += $s
            }
        }

        $iisVer = Get-IISVersionSummary

        if ($netstat) {
            foreach ($line in $netstat) {
                if ($line -match '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+.*?\s+(\d+)') {

                    $proto  = $matches[1]
                    $port   = [int]$matches[3]
                    $pidVal = [int]$matches[4]

                    $procObj = $procMap[$pidVal]
                    $svcList = $svcMap[$pidVal]

                    $finalLoc = "Unknown"
                    $version  = $null
                    $exePath  = $null

                    if ($webMap.ContainsKey($port) -and ($pidVal -eq 4 -or ($procObj -and $procObj.Name -eq "w3wp.exe"))) {
                        $finalLoc = $webMap[$port]
                        $w3wpPath = $null
                        if ($procObj -and $procObj.ExecutablePath) { $w3wpPath = $procObj.ExecutablePath }
                        if (-not $w3wpPath -and (Test-Path "$env:SystemRoot\System32\inetsrv\w3wp.exe")) { $w3wpPath = "$env:SystemRoot\System32\inetsrv\w3wp.exe" }

                        $v1 = if ($iisVer) { $iisVer } else { $null }
                        $v2 = Get-FileVersionSummary $w3wpPath
                        if ($v1 -and $v2) { $version = "$v1; $v2" }
                        elseif ($v1) { $version = $v1 }
                        elseif ($v2) { $version = $v2 }
                    }
                    elseif ($pidVal -eq 4 -or $pidVal -eq 0) {
                        $finalLoc = "System (Kernel/Drivers)"
                        try {
                            $os = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
                            if ($os -and $os.DisplayVersion) { $version = "Windows $($os.DisplayVersion) (Build $($os.CurrentBuildNumber))" }
                            elseif ($os -and $os.ReleaseId)  { $version = "Windows ReleaseId $($os.ReleaseId) (Build $($os.CurrentBuildNumber))" }
                        } catch { }
                    }
                    elseif ($procObj) {
                        if (-not [string]::IsNullOrWhiteSpace($procObj.ExecutablePath)) {
                            $exePath = $procObj.ExecutablePath
                        } elseif (-not [string]::IsNullOrWhiteSpace($procObj.CommandLine)) {
                            $exePath = Split-ExeFromCmdLine $procObj.CommandLine
                        }

                        if (-not [string]::IsNullOrWhiteSpace($procObj.CommandLine)) { $finalLoc = $procObj.CommandLine }
                        elseif ($procObj.ExecutablePath) { $finalLoc = $procObj.ExecutablePath }
                        else { $finalLoc = $procObj.Name }

                        if (-not $version) {
                            $v = Get-FileVersionSummary $exePath
                            if ($v) { $version = $v }
                        }
                    }

                    if ($svcList) {
                        $svcNames = ($svcList.Name | Sort-Object -Unique) -join ","
                        if (-not ($finalLoc -match "IIS Site")) { $finalLoc += " ; svc=$svcNames" }
                    }

                    if (-not $version) { $version = "N/A" }

                    $results.Add([pscustomobject]@{
                        Proto    = $proto
                        Port     = $port
                        Version  = $version
                        Location = $finalLoc
                    }) | Out-Null
                }
            }
        }

        return $results
    }

    foreach ($comp in $comps) {
        $target = if ($comp.DNSHostName) { $comp.DNSHostName } else { $comp.Name }
        $os     = $comp.OperatingSystem

        Write-Host "--------------------------------------------------------"
        Write-Host "Host: $target ($os)" -NoNewline

        if (-not $target) { Write-Host " [SKIP: no hostname]" -ForegroundColor Yellow; continue }
        if (-not (Test-Connection $target -Count 1 -Quiet)) {
            Write-Host " [OFFLINE]" -ForegroundColor Red
            continue
        }
        Write-Host " [ONLINE]" -ForegroundColor Green

        $data = @()
        $useSSH = ($os -match "Linux|Ubuntu|CentOS|Red Hat|Debian|Alpine") -or ($os -eq $null)

        if ($useSSH) {
            if (-not $sshBin) {
                Write-Host "    [SKIP] No SSH binary available." -ForegroundColor DarkGray
                continue
            }

            try {
                $splitMarker = "__GOAT_SPLIT__"

                $linuxRemoteScript = @'
set +e
# -------- version helpers --------
firstline() { head -n1 | tr -d '\r'; }

pkg_ver_from_file() {
  f="$1"
  [ -n "$f" ] || return 0

  # Debian/Ubuntu
  if command -v dpkg-query >/dev/null 2>&1; then
    pkg=$(dpkg-query -S "$f" 2>/dev/null | firstline | cut -d: -f1)
    if [ -n "$pkg" ]; then
      dpkg-query -W -f='${Package} ${Version}\n' "$pkg" 2>/dev/null | firstline
      return 0
    fi
  fi

  # RHEL/CentOS/Fedora
  if command -v rpm >/dev/null 2>&1; then
    rpm -qf "$f" 2>/dev/null | firstline
    return 0
  fi

  # Alpine
  if command -v apk >/dev/null 2>&1; then
    apk info -W "$f" 2>/dev/null | firstline
    return 0
  fi

  return 0
}

safe_run() {
  # run a command, return first line of stdout/stderr (trim CR)
  # usage: safe_run /path/to/bin --version
  "$@" 2>&1 | firstline
}


if command -v ss >/dev/null 2>&1; then
  ss -lntupH 2>&1
elif command -v netstat >/dev/null 2>&1; then
  netstat -lntup 2>&1
else
  echo "__NO_SS_OR_NETSTAT__"
fi

echo "__GOAT_SPLIT__"

ps -Ao pid,args 2>&1 || ps -o pid,args 2>&1

echo "__GOAT_SPLIT__"

pids=$(
  { ss -lntupH 2>/dev/null || netstat -lntup 2>/dev/null; } 2>/dev/null |
  sed -n -e 's/.*pid=\([0-9][0-9]*\).*/\1/p' -e 's/.* \([0-9][0-9]*\)\/[^ ]*$/\1/p' |
  sort -u
)

for pid in $pids; do
  exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
  base=$(basename "$exe" 2>/dev/null)
  v=""

  case "$base" in
    # --- SSH ---
    sshd)
      v=""
      if command -v dpkg-query >/dev/null 2>&1; then
        pv=$(dpkg-query -W -f='${Version}\n' openssh-server 2>/dev/null | firstline)
        [ -n "$pv" ] && v="openssh-server $pv"
      elif command -v rpm >/dev/null 2>&1; then
        pv=$(rpm -q openssh-server 2>/dev/null | firstline)
        [ -n "$pv" ] && v="$pv"
      fi
      [ -z "$v" ] && v=$(safe_run ssh -V)   # last resort
      ;;

    # --- web servers ---
    nginx)                v=$(safe_run nginx -v) ;;
    apache2|httpd)        v=$(safe_run "$exe" -v) ;;

    # --- databases ---
    mysqld)               v=$(safe_run "$exe" --version) ;;
    postgres|postmaster)  v=$(safe_run "$exe" -V) ;;
    redis-server)         v=$(safe_run "$exe" --version) ;;
    mongod)               v=$(safe_run "$exe" --version) ;;

    # --- runtimes ---
    node)                 v=$(safe_run "$exe" -v) ;;
    python|python3)       v=$(safe_run "$exe" --version) ;;
    java)
      # java prints to stderr; safe_run handles it
      v=$(safe_run "$exe" -version)
      ;;

    # --- system / logging / time ---
    systemd|systemd-resolved) v=$(safe_run "$exe" --version) ;;
    rsyslogd)                 v=$(safe_run "$exe" -v) ;;
    chronyd)                  v=$(safe_run "$exe" -v) ;;
    avahi-daemon)             v=$(safe_run "$exe" --version) ;;

    # --- containers ---
    dockerd)              v=$(safe_run "$exe" --version) ;;
    containerd)           v=$(safe_run "$exe" --version) ;;
    docker-proxy)
      # docker-proxy itself often has no version flag; report owning package if possible
      v=$(pkg_ver_from_file "$exe")
      [ -z "$v" ] && v=$(safe_run docker --version)
      ;;

    # --- object storage ---
    minio)                v=$(safe_run "$exe" --version) ;;

  esac

  # Generic fallback: if we still don't have a version, try package ownership.
  if [ -z "$v" ] || [ "$v" = "N/A" ]; then
    pv=$(pkg_ver_from_file "$exe")
    [ -n "$pv" ] && v="$pv"
  fi

  [ -z "$v" ] && v="N/A"
  echo "$pid|||$exe|||$v"
done

exit 0
'@

                Write-Host "    [INPUT] Connecting via SSH..." -ForegroundColor Cyan
                $rawOut = Invoke-SshScriptB64 -SshBin $sshBin -User "root" -TargetHost $target -ScriptText $linuxRemoteScript
                $joined = Remove-AnsiAndControls (($rawOut -join "`n"))

                $mk = [regex]::Escape($splitMarker)
                $parts = $joined -split "(?m)^$mk\s*$"
                if ($parts.Count -lt 3) {
                    Write-Host "    [FAIL] Remote output missing split markers. Raw output (first 80 lines):" -ForegroundColor Yellow
                    ($joined -split "`n" | Select-Object -First 80) | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow }
                    continue
                }

                $ssOut  = $parts[0] -split "`n"
                $psOut  = $parts[1] -split "`n"
                $verOut = $parts[2] -split "`n"

                $linuxProcMap = @{}
                foreach ($pLine in $psOut) {
                    $t = $pLine.Trim()
                    if ($t -match '^(\d+)\s+(.*)$') { $linuxProcMap[[int]$matches[1]] = $matches[2] }
                }

                $linuxVerMap = @{}
                $linuxExeMap = @{}
                foreach ($vLine in $verOut) {
                    $t = $vLine.Trim()
                    if ($t -match '^(\d+)\|\|\|([^|]+)\|\|\|(.*)$') {
                        $pidNum = [int]$matches[1]
                        $linuxExeMap[$pidNum] = $matches[2].Trim()
                        $linuxVerMap[$pidNum] = $matches[3].Trim()
                    }
                }

                foreach ($line in $ssOut) {
                    $t = $line.Trim()
                    if (-not $t) { continue }

                    if ($t -match '^(tcp6?|udp6?)\s+.*?:(\d+)\s+.*users:\(\("([^"]+)",pid=(\d+)') {
                        $proto  = ($matches[1] -replace '6$','').ToUpper()
                        $port   = [int]$matches[2]
                        $procId = [int]$matches[4]

                        $loc = $linuxProcMap[$procId]
                        if (-not $loc) { $loc = $matches[3] }

                        $exePath = $linuxExeMap[$procId]

                        $ver = $linuxVerMap[$procId]
                        if (-not $ver) { $ver = "N/A" }

                        # If ps output doesn't include a real path, prepend the exe path
                        if ($exePath -and ($loc -notmatch '/')) {
                            $loc = "$exePath ; $loc"
                        }

                        $data += [pscustomobject]@{
                            Proto    = $proto
                            Port     = $port
                            Version  = $ver
                            Location = $loc
                        }
                    }
                }
            }
            catch {
                Write-Host "    [FAIL] SSH Error: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        }
        else {
            # Windows target
            try {
                $data = Invoke-Command -ComputerName $target -ScriptBlock $windowsScriptBlock -ErrorAction Stop
            }
            catch {
                Write-Host "    [FAIL] WinRM/Invoke-Command error: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        }

        if ($wellKnownOnly) { $data = @($data | Where-Object { $_.Port -le 49151 }) }

        $data = @($data | Sort-Object Proto, Port, Version, Location -Unique)


        if (-not $data -or $data.Count -eq 0) {
            Write-Host "    [INFO] No listening ports found." -ForegroundColor DarkGray
            continue
        }

        # Add category + print
        $out = foreach ($row in ($data | Sort-Object Port, Proto)) {
            [pscustomobject]@{
                Proto    = $row.Proto
                Port     = $row.Port
                Category = (Get-PortCat -Port $row.Port -Loc $row.Location)
                Version  = $row.Version
                Location = $row.Location
            }
        }

        $out | Format-Table -AutoSize
    } # <-- closes foreach ($comp in $comps)

} else {
    Write-Host "[SKIP] Ports & Services scan" -ForegroundColor DarkGray
}





Write-Section "Shares (Inventory)"
if (Read-YesNo "Enumerate SMB shares across ALL AD Windows computers (ping -> WinRM -> RPC/DCOM -> SMB list)?" $true) {

    $inclAdmin       = Read-YesNo "Include ADMIN$/C$/IPC$?" $true
    $includeDisabled = Read-YesNo "Include DISABLED computer accounts?" $false
    $tryEvenIfNoPing = Read-YesNo "If ping fails, still try enumeration (ICMP may be blocked)?" $false
    $searchBase      = Read-Host "SearchBase DN (blank = entire domain; e.g. OU=Workstations,DC=corp,DC=contoso,DC=com)"

    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch {
        Write-Host "[WARN] ActiveDirectory module not available. Install RSAT (AD DS tools) and re-run." -ForegroundColor Yellow
        Write-Host "[SKIP] SMB shares inventory"
        return
    }

    $skip = @('ADMIN$','C$','IPC$')

    $adFilter = if ($includeDisabled) { "*" } else { "Enabled -eq 'True'" }

    try {
        $adArgs = @{
            Filter      = $adFilter
            Properties  = @("DNSHostName","OperatingSystem","Enabled")
            ErrorAction = "Stop"
        }
        if (-not [string]::IsNullOrWhiteSpace($searchBase)) { $adArgs.SearchBase = $searchBase }

        $comps = Get-ADComputer @adArgs |
                 Where-Object { $_.OperatingSystem -like "*Windows*" } |
                 Select-Object Name, DNSHostName, Enabled, OperatingSystem
    }
    catch {
        Write-Host "[WARN] Failed to query AD computers. Error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "[SKIP] SMB shares inventory"
        return
    }

    if (-not $comps -or $comps.Count -eq 0) {
        Write-Host "[WARN] No Windows computer accounts found with the given criteria." -ForegroundColor Yellow
        Write-Host "[SKIP] SMB shares inventory"
        return
    }

    Write-Host ("[INFO] Targets: {0} Windows computers" -f $comps.Count)

    foreach ($comp in $comps) {

        # Prefer NetBIOS name first (matches your single-host success case),
        # but try DNSHostName as a fallback.
        $candidates = New-Object System.Collections.Generic.List[string]
        if ($comp.Name)        { [void]$candidates.Add($comp.Name) }
        if ($comp.DNSHostName -and $comp.DNSHostName -ne $comp.Name) { [void]$candidates.Add($comp.DNSHostName) }

        # Display like your old output (short name)
        $display = $comp.Name

        # ---- Ping-first (try candidates until one responds) ----
        $pingOk = $false
        $pingUsed = $null
        foreach ($cand in $candidates) {
            try {
                if (Test-Connection -ComputerName $cand -Count 1 -Quiet -ErrorAction Stop) {
                    $pingOk = $true
                    $pingUsed = $cand
                    break
                }
            } catch { }
        }

        if (-not $pingOk -and -not $tryEvenIfNoPing) {
            Write-Host "[SKIP] $display did not answer ping (could be offline or blocking ICMP)" -ForegroundColor Yellow
            continue
        }

        $methodUsed = $null
        $printedAny = $false

        # ---------- Try 1: CIM over WSMan (WinRM) ----------
        foreach ($cand in $candidates) {
            if ($methodUsed) { break }
            try {
                $opt = New-CimSessionOption -Protocol Wsman
                $session = New-CimSession -ComputerName $cand -SessionOption $opt -Authentication Kerberos -ErrorAction Stop
                try {
                    $shares = Get-SmbShare -CimSession $session -ErrorAction Stop
                    if (-not $inclAdmin) { $shares = $shares | Where-Object { $_.Name -notin $skip } }

                    foreach ($share in $shares) {
                        $access = Get-SmbShareAccess -CimSession $session -Name $share.Name -ErrorAction SilentlyContinue |
                                  Where-Object { $_.AccessControlType -eq 'Allow' }

                        $full   = @($access | Where-Object AccessRight -eq 'Full'   | Select-Object -ExpandProperty AccountName)
                        $change = @($access | Where-Object AccessRight -eq 'Change' | Select-Object -ExpandProperty AccountName)
                        $read   = @($access | Where-Object AccessRight -eq 'Read'   | Select-Object -ExpandProperty AccountName)

                        $write = @($full + $change) | Sort-Object -Unique
                        $read  = $read | Sort-Object -Unique

                        Write-Host ("{0} | {1}" -f $display, $share.Name)
                        Write-Host ("Write | {0}" -f ( ($(if($write){$write}else{'(none)'}) -join ', ') ))
                        Write-Host ("Read  | {0}" -f ( ($(if($read){$read}else{'(none)'}) -join ', ') ))
                        Write-Host ""
                        $printedAny = $true
                    }

                    $methodUsed = "CIM-WSMan"
                }
                finally {
                    Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue
                }
            }
            catch {
                # swallow; try next candidate / fall through
            }
        }

        # ---------- Try 2: CIM over DCOM (RPC/DCOM) ----------
        if (-not $methodUsed) {
            foreach ($cand in $candidates) {
                if ($methodUsed) { break }
                try {
                    $opt = New-CimSessionOption -Protocol Dcom
                    $session = New-CimSession -ComputerName $cand -SessionOption $opt -ErrorAction Stop
                    try {
                        $shares = Get-SmbShare -CimSession $session -ErrorAction Stop
                        if (-not $inclAdmin) { $shares = $shares | Where-Object { $_.Name -notin $skip } }

                        foreach ($share in $shares) {
                            $access = Get-SmbShareAccess -CimSession $session -Name $share.Name -ErrorAction SilentlyContinue |
                                      Where-Object { $_.AccessControlType -eq 'Allow' }

                            $full   = @($access | Where-Object AccessRight -eq 'Full'   | Select-Object -ExpandProperty AccountName)
                            $change = @($access | Where-Object AccessRight -eq 'Change' | Select-Object -ExpandProperty AccountName)
                            $read   = @($access | Where-Object AccessRight -eq 'Read'   | Select-Object -ExpandProperty AccountName)

                            $write = @($full + $change) | Sort-Object -Unique
                            $read  = $read | Sort-Object -Unique

                            Write-Host ("{0} | {1}" -f $display, $share.Name)
                            Write-Host ("Write | {0}" -f ( ($(if($write){$write}else{'(none)'}) -join ', ') ))
                            Write-Host ("Read  | {0}" -f ( ($(if($read){$read}else{'(none)'}) -join ', ') ))
                            Write-Host ""
                            $printedAny = $true
                        }

                        $methodUsed = "CIM-DCOM"
                    }
                    finally {
                        Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    # swallow; try next candidate / fall through
                }
            }
        }

        # ---------- Try 3: SMB-only fallback (share NAMES only) ----------
        if (-not $methodUsed) {
            foreach ($cand in $candidates) {
                if ($methodUsed) { break }
                try {
                    $out = cmd /c "net view \\$cand" 2>$null
                    $names = @()

                    foreach ($line in $out) {
                        if ($line -match '^\s*([^\s\$][^\s]+)\s+(Disk|Print|IPC)\s*') { $names += $matches[1] }
                        if ($inclAdmin -and $line -match '^\s*([^\s]+)\s+(Disk|Print|IPC)\s*') { $names += $matches[1] }
                    }

                    $names = $names | Sort-Object -Unique
                    if (-not $inclAdmin) { $names = $names | Where-Object { $_ -notin $skip } }

                    if ($names.Count -gt 0) {
                        foreach ($n in $names) {
                            Write-Host ("{0} | {1}" -f $display, $n)
                            Write-Host ("Write | (unknown - enable WinRM or RPC mgmt for ACLs)")
                            Write-Host ("Read  | (unknown - enable WinRM or RPC mgmt for ACLs)")
                            Write-Host ""
                            $printedAny = $true
                        }
                        $methodUsed = "SMB-netview"
                    }
                }
                catch {
                    # no-op
                }
            }
        }

        if ($methodUsed) {
            Write-Host "[OK] Share enumeration complete ($methodUsed)"
        }
        elseif ($printedAny) {
            Write-Host "[OK] Share enumeration complete"
        }
        else {
            Write-Host "[WARN] Could not enumerate shares on $display via WinRM, RPC/DCOM, or SMB fallback." -ForegroundColor Yellow
            Write-Host "      If the host is up, this usually means firewall/ACLs are blocking management traffic." -ForegroundColor Yellow
        }
    }

} else {
    Write-Host "[SKIP] SMB shares inventory"
}



# =========================================================
# PII Finder (FAST)  -- ONLY <= 20KB + faster matching
# =========================================================
Write-Section "PII Finder (Domain-wide: Windows + Linux, Interactive Remediation)"
if (Read-YesNo "Scan ALL domain computers (Windows via WinRM, Linux via SSH) for PII patterns and prompt to delete/quarantine?" $false) {

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    # ----------------- Tuning (FAST) -----------------
    $MaxFileKB         = 20      # HARD CAP: 20KB or less
    $IncludeRecycleBin = $false  # huge time sink
    $IncludeTemp       = $false  # huge time sink
    $IncludeInetpub    = $false
    $IncludePictures   = $false
    $IncludeSharePaths = $false  # can explode runtime
    $ParallelWindows   = $true   # much faster
    $WinThrottle       = 12      # adjust up/down based on DC load

    # Only scan "text-ish" extensions.
    $AllowedExt = @(
        ".txt",".log",".csv",".tsv",".ini",".cfg",".conf",".config",".xml",".json",".yml",".yaml",
        ".ps1",".psm1",".bat",".cmd",".vbs",".js",".py",".php",".rb",".pl",".sql",".cs",".java",".go",".rs",".cpp",".h",".htm",".html"
    )

    # ----------------- Patterns -----------------
    $Patterns = @(
        "\b\d{3}[)]?[-| |.]\d{3}[-| |.]\d{4}\b",   # phone
        "\b\d{3}[-| |.]\d{2}[-| |.]\d{4}\b",       # SSN
        "\b[A|a]ve\b|\b[A|a]venue\b",
        "\b[S|s]t\b|\b[S|s]treet\b",
        "\b[B|b]lvd\b|\b[B|b]oulevard\b",
        "\b[R|r]d\b|\b[R|r]oad\b",
        "\b[D|d]r\b|\b[D|d]rive\b",
        "\b[C|c]t\b|\b[C|c]ourt\b",
        "\b[H|h]wy\b|\b[H|h]ighway\b",
        "\b[L|l]n\b|\b[L|l]ane\b",
        "\b[W|w]ay\b",
        "\b[Ii]nterstate\b"
    )

    # ONE combined regex (faster than N patterns per file)
    $CombinedPattern = '(?:' + (($Patterns | ForEach-Object { "(?:$_)" }) -join '|') + ')'

    # ----------------- Report + quarantine roots (on DC) -----------------
    $runStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $dcReportRoot = "C:\Windows\Backups\PII-Reports"
    try { New-Item -ItemType Directory -Path $dcReportRoot -Force | Out-Null } catch { }

    # Hide report directory
    try {
        $it = Get-Item -LiteralPath $dcReportRoot -Force
        $it.Attributes = $it.Attributes -bor ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System)
    } catch { }

    # ----------------- Ensure AD module -----------------
    try { Import-Module ActiveDirectory -ErrorAction Stop | Out-Null }
    catch { Write-Host "[ERROR] RSAT ActiveDirectory module missing; cannot enumerate domain computers." -ForegroundColor Red; return }

    # ----------------- Discover targets -----------------
    $adComps = Get-ADComputer -Filter "Enabled -eq 'True'" -Properties DNSHostName,OperatingSystem |
        Where-Object { $_.DNSHostName } |
        Select-Object DNSHostName, OperatingSystem

    if (-not $adComps -or $adComps.Count -eq 0) {
        Write-Host "[WARN] No enabled computer objects with DNSHostName found." -ForegroundColor Yellow
        return
    }

    $windowsTargets = @($adComps | Where-Object { $_.OperatingSystem -like "*Windows*" } | Select-Object -ExpandProperty DNSHostName)
    $linuxTargets   = @($adComps | Where-Object { $_.OperatingSystem -match "Linux|Ubuntu|CentOS|Red Hat|Debian|Alpine" -or $_.OperatingSystem -eq $null } | Select-Object -ExpandProperty DNSHostName)

    Write-Host ("[INFO] Windows targets: {0}" -f $windowsTargets.Count) -ForegroundColor Cyan
    Write-Host ("[INFO] Linux targets  : {0}" -f $linuxTargets.Count) -ForegroundColor Cyan

    # ----------------- SSH binary detection (for Linux) -----------------
    if (-not (Get-Variable -Name sshBin -Scope Script -ErrorAction SilentlyContinue) -and -not (Get-Variable -Name sshBin -ErrorAction SilentlyContinue)) {
        $sshBin = $null
    }
    if (-not $sshBin) {
        $sshBin = "ssh.exe"
        if (-not (Get-Command $sshBin -ErrorAction SilentlyContinue)) {
            $customPath = "C:\Users\Administrator\openssh\OpenSSH-Win64\ssh.exe"
            if (Test-Path $customPath) { $sshBin = $customPath }
            else { $sshBin = $null }
        }
    }

    # change user if root login is disabled (common)
    $LinuxUser = "root"

    if ($linuxTargets.Count -gt 0 -and -not $sshBin) {
        Write-Host "[WARN] ssh.exe not found; Linux PII scanning will be skipped." -ForegroundColor Yellow
    }

    # ----------------- Shared collection -----------------
    $allFindings = New-Object System.Collections.Generic.List[object]
    $maxBytes = [int64]($MaxFileKB * 1KB)
    $allowedLower = @($AllowedExt | ForEach-Object { $_.ToLowerInvariant() })

    # =========================================================
    # WINDOWS SCAN (FAST, compiled regex, <= 20KB only)
    # =========================================================
    $winScan = {
        param(
            [string]$CombinedPattern,
            [int64]$MaxBytes,
            [string[]]$AllowedExt,
            [bool]$IncludeRecycleBin,
            [bool]$IncludeTemp,
            [bool]$IncludeInetpub,
            [bool]$IncludePictures,
            [bool]$IncludeSharePaths
        )

        $ErrorActionPreference = "SilentlyContinue"

        $rx = [regex]::new(
            $CombinedPattern,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [Text.RegularExpressions.RegexOptions]::Compiled
        )

        function Is-AllowedExt([string]$path, [string[]]$Allowed) {
            if (-not $Allowed -or $Allowed.Count -eq 0) { return $true }
            $ext = [IO.Path]::GetExtension($path)
            if ([string]::IsNullOrWhiteSpace($ext)) { return $false }
            return ($Allowed -contains $ext.ToLowerInvariant())
        }

        function Read-TextSmart([string]$fp) {
            try {
                $bytes = [IO.File]::ReadAllBytes($fp)
                if (-not $bytes -or $bytes.Length -eq 0) { return $null }

                # BOM-aware decode
                if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($bytes) }
                if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($bytes) }
                if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($bytes) }

                # Cheap binary-ish heuristic
                $bad = 0
                for ($i=0; $i -lt $bytes.Length; $i++) {
                    $b = $bytes[$i]
                    if ($b -lt 9 -or ($b -gt 13 -and $b -lt 32)) { $bad++ }
                }
                if (($bad / [double]$bytes.Length) -gt 0.20) { return $null }

                return [Text.Encoding]::UTF8.GetString($bytes)
            } catch { return $null }
        }

        function Get-RecycleBinPath { 'C:\$Recycle.Bin' }

        $localPaths = @(
            "C:\Users\*\Downloads",
            "C:\Users\*\Documents",
            "C:\Users\*\Desktop"
        )
        if ($IncludePictures)    { $localPaths += "C:\Users\*\Pictures" }
        if ($IncludeInetpub)     { $localPaths += "C:\inetpub" }
        if ($IncludeTemp)        { $localPaths += "C:\Windows\Temp" }
        if ($IncludeRecycleBin)  { $localPaths += (Get-RecycleBinPath) }

        $sharePaths = @()
        if ($IncludeSharePaths) {
            try {
                $sharePaths = Get-CimInstance Win32_Share |
                    Where-Object {
                        $_.Path -and
                        $_.Path -notlike "C:\" -and
                        $_.Path -notlike "C:\Windows*" -and
                        $_.Name -notin @("ADMIN$","C$","IPC$")
                    } | Select-Object -ExpandProperty Path
            } catch { }
        }

        $paths = @($localPaths + $sharePaths | Select-Object -Unique)

        $found = New-Object System.Collections.Generic.List[object]
        $seen  = @{}

        foreach ($root in $paths) {
            if (-not $root) { continue }

            Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Name -ne 'desktop.ini' -and
                    $_.Length -gt 0 -and
                    $_.Length -le $MaxBytes -and
                    (Is-AllowedExt $_.FullName $AllowedExt) -and
                    ($_.FullName -notlike "C:\Windows\Backups\*")
                } |
                ForEach-Object {
                    $fp = $_.FullName
                    if ($seen.ContainsKey($fp)) { return }

                    $text = Read-TextSmart $fp
                    if (-not $text) { return }

                    $m = $rx.Matches($text)
                    if ($m.Count -gt 0) {
                        $samples = New-Object System.Collections.Generic.List[string]
                        foreach ($mm in $m) {
                            if ($samples.Count -ge 3) { break }
                            if ($mm.Value -and -not $samples.Contains($mm.Value)) { $samples.Add($mm.Value) }
                        }

                        $found.Add([pscustomobject]@{
                            Platform   = "Windows"
                            Computer   = $env:COMPUTERNAME
                            FilePath   = $fp
                            SizeBytes  = $_.Length
                            Sample     = ($samples -join " | ")
                            MatchCount = $m.Count
                            RootHint   = $root
                        }) | Out-Null

                        $seen[$fp] = $true
                    }
                }
        }

        return $found
    }

    # Windows remediation
    $winQuarantine = {
        param([string]$FilePath, [string]$RunStamp)

        $destRoot = "C:\Windows\Backups\PII-Quarantine\$RunStamp"
        try { New-Item -ItemType Directory -Path $destRoot -Force | Out-Null } catch { }

        try {
            $it = Get-Item -LiteralPath $destRoot -Force
            $it.Attributes = $it.Attributes -bor ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System)
        } catch { }

        if (-not (Test-Path -LiteralPath $FilePath)) { return "MISSING" }

        $name = [IO.Path]::GetFileName($FilePath)
        $dest = Join-Path $destRoot $name
        if (Test-Path -LiteralPath $dest) {
            $base = [IO.Path]::GetFileNameWithoutExtension($name)
            $ext  = [IO.Path]::GetExtension($name)
            $dest = Join-Path $destRoot ("{0}_{1}{2}" -f $base, (Get-Random), $ext)
        }

        try { Move-Item -LiteralPath $FilePath -Destination $dest -Force; return "QUARANTINED:$dest" }
        catch { return "FAIL:$($_.Exception.Message)" }
    }

    $winDelete = {
        param([string]$FilePath)
        if (-not (Test-Path -LiteralPath $FilePath)) { return "MISSING" }
        try { Remove-Item -LiteralPath $FilePath -Force; return "DELETED" }
        catch { return "FAIL:$($_.Exception.Message)" }
    }

    # =========================================================
    # LINUX SCAN (SSH)  -- ONLY <= 20KB
    # IMPORTANT: DO NOT use param name "Host" (conflicts with read-only $Host)
    # =========================================================
    function Invoke-LinuxPiiScan {
    param(
        [Parameter(Mandatory=$true)][string]$TargetHost,
        [Parameter(Mandatory=$true)][int]$MaxFileKB
    )

    $regex = '([0-9]{3}[)]?[- .|][0-9]{3}[- .|][0-9]{4}|[0-9]{3}[- .|][0-9]{2}[- .|][0-9]{4}|[Aa]ve|[Aa]venue|[Ss]t|[Ss]treet|[Bb]lvd|[Bb]oulevard|[Rr]d|[Rr]oad|[Dd]r|[Dd]rive|[Cc]t|[Cc]ourt|[Hh]wy|[Hh]ighway|[Ll]n|[Ll]ane|[Ww]ay|[Ii]nterstate)'
    $paths = "/home/*/Downloads /home/*/Documents /home/*/Desktop /var/www"

    $script = @'
set +e
MAX_KB="$1"
RE="$2"
PATHS="$3"

scan_path() {
  p="$1"
  find $p -type f -size -"${MAX_KB}"k -print0 2>/dev/null | while IFS= read -r -d "" f; do
    [ -r "$f" ] || continue
    grep -Iq . "$f" 2>/dev/null || continue

    out=$(grep -IEo "$RE" "$f" 2>/dev/null | awk 'NR<=3{gsub(/\r/,""); s=(s? s" | ":"")$0} {c++} END{if(c>0) print c"|||" (s?s:"") }')
    if [ -n "$out" ]; then
      sz=$(stat -c%s "$f" 2>/dev/null || wc -c < "$f" 2>/dev/null)
      echo "HIT|||$f|||$sz|||$out"
    fi
  done
}

for p in $PATHS; do
  scan_path "$p"
done

exit 0
'@

    Write-Host "    [INPUT] SSH to $TargetHost (Linux). You may be prompted for a password..." -ForegroundColor Cyan
    $out = Invoke-SshScriptB64 -SshBin $sshBin -User $LinuxUser -TargetHost $TargetHost -ScriptText $script -Args @("$MaxFileKB", $regex, $paths)

    $joined = Remove-AnsiAndControls ($out -join "`n")
    if ($joined -match "(?i)permission denied") { throw "Permission denied (bad creds OR login blocked for '$LinuxUser')." }
    if ($joined -match "(?i)could not resolve hostname|name or service not known") { throw "DNS/hostname resolution failed." }
    if ($joined -match "(?i)connection timed out|no route to host|connection refused") { throw "Network/connectivity failure." }

    $outLines = @($out | ForEach-Object { [string]$_ })

    $results = @()
    foreach ($line in $outLines) {
        $t = ([string]$line).Trim()

        if ($t -like 'HIT|||*') {
            # HIT|||file|||size|||count|||sample
            $parts = $t -split '\|\|\|', 5

            if ($parts.Count -ge 5) {
                $fp   = ([string]$parts[1]).Trim()
                $sz   = [int64]([string]$parts[2])
                $cnt  = [int]([string]$parts[3])
                $samp = ([string]$parts[4]).Trim()

                $results += [pscustomobject]@{
                    Platform   = "Linux"
                    Computer   = $TargetHost
                    FilePath   = $fp
                    SizeBytes  = $sz
                    MatchCount = $cnt
                    Sample     = $samp
                    RootHint   = "(linux scan set)"
                }
            }
        }
    }
    return $results
}

function Invoke-LinuxQuarantine {
    param([string]$TargetHost,[string]$FilePath,[string]$RunStamp)

    $script = @'
set +e
f="$1"
stamp="$2"
dst="/var/backups/.pii-quarantine/$stamp"
mkdir -p "$dst" 2>/dev/null || dst="$HOME/.pii-quarantine/$stamp"
mkdir -p "$dst" 2>/dev/null

if [ -e "$f" ]; then
  base=$(basename "$f")
  if mv -f "$f" "$dst/$base" 2>/dev/null; then
    echo "QUARANTINED:$dst/$base"
  else
    echo "FAIL"
  fi
else
  echo "MISSING"
fi
exit 0
'@

    Invoke-SshScriptB64 -SshBin $sshBin -User $LinuxUser -TargetHost $TargetHost -ScriptText $script -Args @($FilePath,$RunStamp)
}

function Invoke-LinuxDelete {
    param([string]$TargetHost,[string]$FilePath)

    $script = @'
set +e
f="$1"
if [ -e "$f" ]; then
  rm -f "$f" 2>/dev/null && echo "DELETED" || echo "FAIL"
else
  echo "MISSING"
fi
exit 0
'@

    Invoke-SshScriptB64 -SshBin $sshBin -User $LinuxUser -TargetHost $TargetHost -ScriptText $script -Args @($FilePath)
}


    # =========================================================
    # EXECUTE: WINDOWS (PARALLEL by default)
    # =========================================================
    $winHostCounts = @{}  # hostname -> count

    if ($ParallelWindows -and $windowsTargets.Count -gt 0) {

        Write-Host ("[INFO] Windows scans running in parallel (throttle={0})..." -f $WinThrottle) -ForegroundColor Cyan
        $jobs = @()

        foreach ($t in $windowsTargets) {
            Write-Host "--------------------------------------------------------"
            Write-Host "Host: $t (Windows)" -NoNewline
            if (-not (Test-Connection $t -Count 1 -Quiet)) { Write-Host " [OFFLINE]" -ForegroundColor Red; continue }
            Write-Host " [ONLINE]" -ForegroundColor Green

            $job = Invoke-Command -ComputerName $t -ScriptBlock $winScan -ArgumentList @(
                $CombinedPattern, $maxBytes, $allowedLower,
                $IncludeRecycleBin, $IncludeTemp, $IncludeInetpub, $IncludePictures, $IncludeSharePaths
            ) -AsJob -ErrorAction SilentlyContinue

            if ($job) { $jobs += $job }

            while (($jobs | Where-Object State -eq 'Running').Count -ge $WinThrottle) {
                Start-Sleep -Milliseconds 250
            }
        }

        if ($jobs.Count -gt 0) {
            $jobs | Wait-Job | Out-Null

            foreach ($j in $jobs) {
                $loc = $j.Location
                try {
                    $res = Receive-Job -Job $j -ErrorAction Stop
                    $cnt = 0
                    if ($res) {
                        foreach ($r in $res) { $allFindings.Add($r) | Out-Null; $cnt++ }
                    }
                    $winHostCounts[$loc] = $cnt
                } catch {
                    Write-Host ("    [FAIL] WinRM scan job error on {0}: {1}" -f $loc, $_.Exception.Message) -ForegroundColor Yellow
                    $winHostCounts[$loc] = 0
                }
            }

            Remove-Job -Job $jobs -Force -ErrorAction SilentlyContinue
        }

    } else {
        foreach ($t in $windowsTargets) {
            Write-Host "--------------------------------------------------------"
            Write-Host "Host: $t (Windows)" -NoNewline
            if (-not (Test-Connection $t -Count 1 -Quiet)) { Write-Host " [OFFLINE]" -ForegroundColor Red; continue }
            Write-Host " [ONLINE]" -ForegroundColor Green

            try {
                $res = Invoke-Command -ComputerName $t -ScriptBlock $winScan -ArgumentList @(
                    $CombinedPattern, $maxBytes, $allowedLower,
                    $IncludeRecycleBin, $IncludeTemp, $IncludeInetpub, $IncludePictures, $IncludeSharePaths
                ) -ErrorAction Stop

                $cnt = 0
                if ($res) { foreach ($r in $res) { $allFindings.Add($r) | Out-Null; $cnt++ } }
                $winHostCounts[$t] = $cnt
            } catch {
                Write-Host "    [FAIL] WinRM scan error: $($_.Exception.Message)" -ForegroundColor Yellow
                $winHostCounts[$t] = 0
            }
        }
    }

    # Optional summary per Windows host
    foreach ($k in ($winHostCounts.Keys | Sort-Object)) {
        $v = $winHostCounts[$k]
        if ($v -gt 0) { Write-Host ("[INFO] Windows findings on {0}: {1}" -f $k, $v) -ForegroundColor Yellow }
        else          { Write-Host ("[OK]   Windows findings on {0}: 0" -f $k) -ForegroundColor Green }
    }

    # =========================================================
    # EXECUTE: LINUX (SEQUENTIAL, password prompts)
    # =========================================================
    if ($sshBin -and $linuxTargets.Count -gt 0) {
        foreach ($t in $linuxTargets) {
            Write-Host "--------------------------------------------------------"
            Write-Host "Host: $t (Linux)" -NoNewline
            if (-not (Test-Connection $t -Count 1 -Quiet)) { Write-Host " [OFFLINE]" -ForegroundColor Red; continue }
            Write-Host " [ONLINE]" -ForegroundColor Green

            try {
                $res = Invoke-LinuxPiiScan -TargetHost $t -MaxFileKB $MaxFileKB
                if ($res -and $res.Count -gt 0) {
                    foreach ($r in $res) { $allFindings.Add($r) | Out-Null }
                    Write-Host ("    [INFO] Findings: {0}" -f $res.Count) -ForegroundColor Yellow
                } else {
                    Write-Host "    [OK] No PII hits found." -ForegroundColor Green
                }
            } catch {
                Write-Host "    [FAIL] SSH scan error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "[INFO] Linux scanning skipped (no ssh.exe or no Linux targets)." -ForegroundColor DarkGray
    }

    # =========================================================
    # REPORT
    # =========================================================
    $reportPath = Join-Path $dcReportRoot ("PII_Findings_{0}.csv" -f $runStamp)
    try {
        if ($allFindings.Count -gt 0) {
            $allFindings | Sort-Object Platform, Computer, FilePath | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
            Write-Host "[OK] Report saved -> $reportPath" -ForegroundColor Green
        } else {
            Write-Host "[OK] No findings across all scanned hosts." -ForegroundColor Green
        }
    } catch {
        Write-Host "[WARN] Could not write report: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # =========================================================
    # INTERACTIVE REMEDIATION
    # =========================================================
    if ($allFindings.Count -gt 0) {
        Write-Host ""
        Write-Host "==========[Interactive Remediation]==========" -ForegroundColor Cyan
        Write-Host "Actions: (Q)uarantine, (D)elete, (S)kip, (A)ll quarantine, (X)stop" -ForegroundColor Gray
        Write-Host ""

        $allQuarantine = $false

        foreach ($f in ($allFindings | Sort-Object Platform, Computer, FilePath)) {

            $plat = $f.Platform
            $comp = $f.Computer
            $path = $f.FilePath

            Write-Host "Platform: $plat" -ForegroundColor Cyan
            Write-Host "Host    : $comp" -ForegroundColor Cyan
            Write-Host "File    : $path" -ForegroundColor White
            if ($f.SizeBytes -ne $null) { Write-Host ("Size    : {0} bytes" -f $f.SizeBytes) -ForegroundColor Gray }
            Write-Host ("Matches : {0}" -f $f.MatchCount) -ForegroundColor Gray
            if ($f.Sample) { Write-Host ("Sample  : {0}" -f $f.Sample) -ForegroundColor Red }

            $action = "S"
            if ($allQuarantine) {
                $action = "Q"
            } else {
                $in = Read-Host "Action [Q/D/S/A/X]"
                if ([string]::IsNullOrWhiteSpace($in)) { $in = "S" }
                $action = $in.ToUpperInvariant()
            }

            if ($action -eq "X") { Write-Host "[STOP] Remediation stopped by user." -ForegroundColor Yellow; break }
            if ($action -eq "A") { $allQuarantine = $true; $action = "Q" }

            if ($action -eq "Q") {
                if ($plat -eq "Windows") {
                    try {
                        $out = Invoke-Command -ComputerName $comp -ScriptBlock $winQuarantine -ArgumentList $path, $runStamp -ErrorAction Stop
                        Write-Host "  -> $out" -ForegroundColor Green
                    } catch {
                        Write-Host "  -> [FAIL] Win quarantine error: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                } else {
                    try {
                        $out = Invoke-LinuxQuarantine -TargetHost $comp -FilePath $path -RunStamp $runStamp
                        Write-Host "  -> $($out -join ' ')" -ForegroundColor Green
                    } catch {
                        Write-Host "  -> [FAIL] Linux quarantine error: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            elseif ($action -eq "D") {
                if ($plat -eq "Windows") {
                    try {
                        $out = Invoke-Command -ComputerName $comp -ScriptBlock $winDelete -ArgumentList $path -ErrorAction Stop
                        Write-Host "  -> $out" -ForegroundColor Green
                    } catch {
                        Write-Host "  -> [FAIL] Win delete error: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                } else {
                    try {
                        $out = Invoke-LinuxDelete -TargetHost $comp -FilePath $path
                        Write-Host "  -> $($out -join ' ')" -ForegroundColor Green
                    } catch {
                        Write-Host "  -> [FAIL] Linux delete error: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Host "  -> [SKIP]" -ForegroundColor DarkGray
            }

            Write-Host ""
        }

        Write-Host "[OK] PII remediation loop complete." -ForegroundColor Green
        Write-Host ("     Findings report: {0}" -f $reportPath) -ForegroundColor Gray
        Write-Host ("     Windows quarantine root (per-host): C:\Windows\Backups\PII-Quarantine\{0}" -f $runStamp) -ForegroundColor Gray
        Write-Host "     Linux quarantine root (per-host): /var/backups/.pii-quarantine/$runStamp (fallback: ~/.pii-quarantine/$runStamp)" -ForegroundColor Gray
    }

    $stopWatch.Stop()
    Write-Host ("[DONE] PII scan elapsed: {0}" -f $stopWatch.Elapsed) -ForegroundColor Cyan
} else {
    Write-Host "[SKIP] PII Finder" -ForegroundColor DarkGray
}






#this part is based from stanford. spooky.
Write-Section "Suspicious Service Detection (local only [  for now >:)  ])"
if (Read-YesNo "Scan for potentially suspicious Windows services?" $true) {
    $EnableExtraChecks = Read-YesNo "Enable aggressive checks (may cause false positives)?" $false

    # Helper: split Win32_Service.PathName into executable + args
    function Split-ServiceCommandLine {
        param([string]$PathName)

        if ([string]::IsNullOrWhiteSpace($PathName)) {
            return [PSCustomObject]@{ Exe = ""; Args = "" }
        }

        $p = $PathName.Trim()

        # Quoted: "C:\Path To\App.exe" -arg1 -arg2
        if ($p -match '^\s*"([^"]+)"\s*(.*)$') {
            return [PSCustomObject]@{ Exe = $Matches[1]; Args = $Matches[2].Trim() }
        }

        # Unquoted: C:\Windows\System32\svchost.exe -k netsvcs
        if ($p -match '^\s*([^\s]+)\s*(.*)$') {
            return [PSCustomObject]@{ Exe = $Matches[1]; Args = $Matches[2].Trim() }
        }

        return [PSCustomObject]@{ Exe = $p; Args = "" }
    }

    function IsSuspiciousPath {
        param([string]$exePath)

        if ([string]::IsNullOrWhiteSpace($exePath)) { return $true }

        $norm = $exePath.ToLowerInvariant()

        # Flag common user-writable locations
        return (
            $norm -like 'c:\users\*' -or
            $norm -like 'c:\programdata\*' -or
            $norm -like '*\appdata\*' -or
            $norm -like 'c:\windows\temp\*' -or
            $norm -like '*\temp\*'
        )
    }

    function IsUnsigned {
        param([string]$exePath)

        try {
            if (-not (Test-Path -LiteralPath $exePath)) { return $true } # missing binary is suspicious
            (Get-AuthenticodeSignature -FilePath $exePath).Status -ne "Valid"
        }
        catch {
            $true
        }
    }

    function CalculateEntropy {
        param([string]$Text)

        if ([string]::IsNullOrEmpty($Text)) { return 0.0 }

        $chars = $Text.ToCharArray()
        $len   = $chars.Length
        if ($len -eq 0) { return 0.0 }

        $freq = @{}
        foreach ($c in $chars) {
            if ($freq.ContainsKey($c)) { $freq[$c]++ } else { $freq[$c] = 1 }
        }

        $entropy = 0.0
        foreach ($f in $freq.Values) {
            $p = $f / $len
            $entropy -= $p * [Math]::Log($p, 2)
        }
        return $entropy
    }

    function IsHighEntropyName {
        param([string]$Name)
        (CalculateEntropy -Text $Name) -gt 3.5
    }

    function HasSuspiciousExtension {
        param([string]$exePath)
        @('.vbs','.js','.bat','.cmd','.scr') -contains ([IO.Path]::GetExtension($exePath))
    }

    $SuspiciousServices = @()
    $services = Get-WmiObject Win32_Service

    foreach ($svc in $services) {
        $cmd    = Split-ServiceCommandLine -PathName $svc.PathName
        $exePath = $cmd.Exe
        $args    = $cmd.Args

        $flags = @()

        if (IsSuspiciousPath $exePath)                { $flags += "Suspicious path" }
        if ($svc.StartName -eq "LocalSystem")         { $flags += "Runs as LocalSystem" }
        if ([string]::IsNullOrEmpty($svc.Description)) { $flags += "No description" }
        if (IsUnsigned $exePath)                      { $flags += "Unsigned binary" }

        if ($EnableExtraChecks) {
            if ($svc.Name.Length -le 5)               { $flags += "Very short service name" }
            if ($svc.DisplayName.Length -le 5)        { $flags += "Very short display name" }
            if (IsHighEntropyName $svc.Name)          { $flags += "High entropy service name" }
            if (IsHighEntropyName $svc.DisplayName)   { $flags += "High entropy display name" }
            if (HasSuspiciousExtension $exePath)      { $flags += "Suspicious file extension" }
        }

        if ($flags.Count -gt 0) {
            $SuspiciousServices += [PSCustomObject]@{
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                State       = $svc.State
                StartName   = $svc.StartName
                Path        = $svc.PathName   # keep full original command line for display
                ExePath     = $exePath
                Flags       = $flags
            }
        }
    }

    if ($SuspiciousServices.Count -eq 0) {
        Write-Host "[OK] No suspicious services detected"
    }
    else {
        Write-Host "[WARN] Potentially suspicious services detected:`n"
        foreach ($s in $SuspiciousServices) {
            Write-Host "Service: $($s.Name) ($($s.DisplayName))"
            Write-Host "  State: $($s.State)"
            Write-Host "  Start: $($s.StartName)"
            Write-Host "  Path : $($s.Path)"
            foreach ($f in $s.Flags) {
                Write-Host "   - $f"
            }
            Write-Host ""
        }
    }
}
else {
    Write-Host "[SKIP] Suspicious service scan"
}



#basically confirm windows defender works
Write-Section "Force Microsoft Defender ON (Policy Cleanup + Service Restore)"
if (Read-YesNo "Remove Defender 'disable' policy values + start Defender?" $true) {

    # --- Ensure local DC ---
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.DomainRole -lt 4) {
            Write-Host "[SKIP] Not a Domain Controller (DomainRole=$($cs.DomainRole)). This segment is DC-local only." -ForegroundColor Yellow
            return
        }
    } catch {
        Write-Host "[WARN] Could not determine DomainRole; skipping Defender segment: $($_.Exception.Message)" -ForegroundColor Yellow
        return
    }

    # --- Ensure admin ---
    if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        Write-Host "[ERROR] Run in an elevated PowerShell." -ForegroundColor Red
        return
    }

    function Remove-RegValueIfPresent([string]$Path, [string]$ValueName) {
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        try {
            $p = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
            if ($null -eq $p) { return $false }
            if ($p.PSObject.Properties.Name -contains $ValueName) {
                Remove-ItemProperty -Path $Path -Name $ValueName -Force -ErrorAction Stop
                return $true
            }
        } catch { }
        return $false
    }

    $valueNames = @(
        "DisableBehaviorMonitoring",
        "DisableIOAVProtection",
        "DisableOnAccessProtection",
        "DisableRealtimeMonitoring",
        "DisableHeuristics",
        "DisableAntiSpyware",
        "DisableAntiVirus",
        "DisableRoutinelyTakingAction",
        "Notification_Suppress",
        "AllowFastServiceStartup",
        "ServiceKeepAlive",
        "CheckForSignaturesBeforeRunningScan",
        "UILockdown"
    )

    # Known common policy locations for these values
    $paths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration"
    )

    # Additional common “UI lockdown” location seen in some environments
    $paths += @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"
    )

    $removed = New-Object System.Collections.Generic.List[string]

    Write-Host "[INFO] Removing targeted Defender policy values (if present)..." -ForegroundColor Cyan

    foreach ($path in $paths) {
        foreach ($name in $valueNames) {
            if (Remove-RegValueIfPresent -Path $path -ValueName $name) {
                $removed.Add("$path -> $name") | Out-Null
            }
        }
    }

    # Deep sweep: remove those value names anywhere under the main policy roots
    $rootsToSweep = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center"
    )

    foreach ($root in $rootsToSweep) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $k = $_.PSPath
                foreach ($name in $valueNames) {
                    try {
                        $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                        if ($p -and ($p.PSObject.Properties.Name -contains $name)) {
                            Remove-ItemProperty -Path $k -Name $name -Force -ErrorAction SilentlyContinue
                            $removed.Add("$k -> $name") | Out-Null
                        }
                    } catch { }
                }
            }
        } catch { }
    }

    if ($removed.Count -gt 0) {
        Write-Host "[OK] Removed/cleared the following policy values:" -ForegroundColor Green
        $removed | Sort-Object -Unique | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
    } else {
        Write-Host "[NA] None of the targeted policy values were present." -ForegroundColor DarkGray
    }

    # Attempt to ensure Defender services are enabled/running
    Write-Host "[INFO] Attempting to start/enable Defender services..." -ForegroundColor Cyan
    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($svc) {
            try { Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
            if ($svc.Status -ne "Running") {
                Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            }
            Write-Host "[OK] WinDefend service state: $((Get-Service WinDefend).Status)" -ForegroundColor Green
        } else {
            Write-Host "[WARN] WinDefend service not found (Defender AV may not be installed/active on this build)." -ForegroundColor Yellow
        }

        # Security Center service (helps UI/status reporting)
        $wsc = Get-Service -Name "wscsvc" -ErrorAction SilentlyContinue
        if ($wsc) {
            try { Set-Service -Name "wscsvc" -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
            if ($wsc.Status -ne "Running") { Start-Service -Name "wscsvc" -ErrorAction SilentlyContinue }
        }
    } catch {
        Write-Host "[WARN] Service start attempts had issues: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Try to explicitly turn protections ON via Defender cmdlets (if available)
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {

            # These are “preference toggles”; policies/tamper protection can still override.
            try {
                Set-MpPreference `
                    -DisableBehaviorMonitoring $false `
                    -DisableIOAVProtection $false `
                    -DisableOnAccessProtection $false `
                    -DisableRealtimeMonitoring $false `
                    -ErrorAction SilentlyContinue | Out-Null
            } catch { }

            try { Update-MpSignature -ErrorAction SilentlyContinue | Out-Null } catch { }

            $st = Get-MpComputerStatus
            Write-Host "[INFO] Defender status summary:" -ForegroundColor Cyan
            Write-Host ("  AMServiceEnabled      : {0}" -f $st.AMServiceEnabled) -ForegroundColor Gray
            Write-Host ("  AntispywareEnabled    : {0}" -f $st.AntispywareEnabled) -ForegroundColor Gray
            Write-Host ("  AntivirusEnabled      : {0}" -f $st.AntivirusEnabled) -ForegroundColor Gray
            Write-Host ("  RealTimeProtection    : {0}" -f $st.RealTimeProtectionEnabled) -ForegroundColor Gray
            if ($st.PSObject.Properties.Name -contains "IsTamperProtected") {
                Write-Host ("  TamperProtected       : {0}" -f $st.IsTamperProtected) -ForegroundColor Gray
            }

            Write-Host "[OK] Defender enablement attempt complete." -ForegroundColor Green
            Write-Host "     If values come back, they’re being re-applied by GPO/Intune or blocked by Tamper Protection." -ForegroundColor Yellow
        } else {
            Write-Host "[WARN] Defender cmdlets not available (Get-MpComputerStatus). Skipping preference enforcement." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[WARN] Defender cmdlet actions failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

} else {
    Write-Host "[SKIP] Defender enablement segment" -ForegroundColor DarkGray
}




Write-Section "Backups (Hidden/System under C:\Windows\Backups)"
if (Read-YesNo "Run full backups now? (DNS files + DNS JSON + LocalSecPol + Firewall + Registry + Web/FTP)" $true) {

    # ---------- helpers ----------
    function Set-HiddenSystem([string]$Path) {
        try {
            if (Test-Path -LiteralPath $Path) {
                $it = Get-Item -LiteralPath $Path -Force
                $it.Attributes = $it.Attributes -bor ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System)
            }
        } catch { }
    }

    function Harden-BackupAcl([string]$Path) {
        try {
            $acl = Get-Acl -LiteralPath $Path

            # Disable inheritance (don't copy inherited ACLs)
            $acl.SetAccessRuleProtection($true, $false)

            # Clear existing explicit rules
            foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }

            # Allow: SYSTEM full, Administrators modify, Users read
            $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM",
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators",
                "Modify",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $ruleUsersRead = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Users",
                "ReadAndExecute",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )

            # Deny delete for normal users (helps against low-priv cleanup)
            $denyUsersDelete = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Users",
                "Delete,DeleteSubdirectoriesAndFiles",
                "ContainerInherit,ObjectInherit",
                "None",
                "Deny"
            )

            $acl.AddAccessRule($ruleSystem)     | Out-Null
            $acl.AddAccessRule($ruleAdmins)     | Out-Null
            $acl.AddAccessRule($ruleUsersRead)  | Out-Null
            $acl.AddAccessRule($denyUsersDelete)| Out-Null

            Set-Acl -LiteralPath $Path -AclObject $acl
        } catch { }
    }

    # ---------- base + run folder ----------
    $backupRoot = "C:\Windows\Backups"
    $ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $runRoot = Join-Path $backupRoot ("Run_{0}" -f $ts)

    try { New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null } catch { }
    try { New-Item -ItemType Directory -Path $runRoot    -Force | Out-Null } catch { }

    # Hide + harden folders
    Set-HiddenSystem $backupRoot
    Set-HiddenSystem $runRoot
    Harden-BackupAcl $backupRoot
    Harden-BackupAcl $runRoot

    # ----------------------------------------------------------
    # DNS FILE BACKUP (copies C:\Windows\System32\dns\*)
    # ----------------------------------------------------------
    try {
        $dnsSrc = "C:\Windows\System32\dns"
        if (Test-Path $dnsSrc) {
            $dnsDest = Join-Path $runRoot "DNS_Files"
            New-Item -ItemType Directory -Path $dnsDest -Force | Out-Null
            Copy-Item -Path (Join-Path $dnsSrc "*") -Destination $dnsDest -Recurse -Force -ErrorAction Stop
            Set-HiddenSystem $dnsDest
            Write-Host "[OK] DNS files backed up -> $dnsDest" -ForegroundColor Green
        } else {
            Write-Host "[SKIP] DNS folder not found at $dnsSrc" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[WARN] DNS file backup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ----------------------------------------------------------
    # LOCAL SECURITY POLICY BACKUP (secedit export)
    # ----------------------------------------------------------
    try {
        $secDir = Join-Path $runRoot "LocalSecurity"
        New-Item -ItemType Directory -Path $secDir -Force | Out-Null
        $secOut = Join-Path $secDir ("LocalSecurityPolicy_{0}.inf" -f $ts)
        & secedit /export /cfg $secOut | Out-Null
        Set-HiddenSystem $secDir
        if (Test-Path $secOut) {
            Set-HiddenSystem $secOut
            Write-Host "[OK] Local Security Policy exported -> $secOut" -ForegroundColor Green
        } else {
            Write-Host "[WARN] secedit export did not produce a file (check permissions)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[WARN] Local Security Policy backup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ----------------------------------------------------------
    # FIREWALL BACKUP (netsh advfirewall export)
    # ----------------------------------------------------------
    try {
        $fwDir = Join-Path $runRoot "Firewall"
        New-Item -ItemType Directory -Path $fwDir -Force | Out-Null
        $fwOut = Join-Path $fwDir ("Firewall_{0}.wfw" -f $ts)
        & netsh advfirewall export $fwOut | Out-Null
        Set-HiddenSystem $fwDir
        if (Test-Path $fwOut) {
            Set-HiddenSystem $fwOut
            Write-Host "[OK] Firewall exported -> $fwOut" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Firewall export did not produce a file (check permissions)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[WARN] Firewall backup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # # ----------------------------------------------------------
    # # REGISTRY BACKUP (HKLM/HKCU/HKCR/HKU/HKCC)
    # # ----------------------------------------------------------
    # try {
    #     $regDir = Join-Path $runRoot "Registry"
    #     New-Item -ItemType Directory -Path $regDir -Force | Out-Null

    #     $hklm = Join-Path $regDir "HKLM.reg"
    #     $hkcu = Join-Path $regDir "HKCU.reg"
    #     $hkcr = Join-Path $regDir "HKCR.reg"
    #     $hku  = Join-Path $regDir "HKU.reg"
    #     $hkcc = Join-Path $regDir "HKCC.reg"

    #     & reg.exe export HKLM $hklm /y | Out-Null
    #     & reg.exe export HKCU $hkcu /y | Out-Null
    #     & reg.exe export HKCR $hkcr /y | Out-Null
    #     & reg.exe export HKU  $hku  /y | Out-Null
    #     & reg.exe export HKCC $hkcc /y | Out-Null

    #     Set-HiddenSystem $regDir
    #     Set-HiddenSystem $hklm; Set-HiddenSystem $hkcu; Set-HiddenSystem $hkcr; Set-HiddenSystem $hku; Set-HiddenSystem $hkcc
    #     Write-Host "[OK] Registry hives exported -> $regDir" -ForegroundColor Green
    # } catch {
    #     Write-Host "[WARN] Registry backup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    # }

    # ----------------------------------------------------------
    # WEB SERVER BACKUP (IIS default path)
    # ----------------------------------------------------------
    try {
        $iisSrc = "C:\inetpub"
        if (Test-Path $iisSrc) {
            $webDest = Join-Path $runRoot "Web"
            New-Item -ItemType Directory -Path $webDest -Force | Out-Null
            Copy-Item -Path (Join-Path $iisSrc "*") -Destination $webDest -Recurse -Force -ErrorAction Stop
            Set-HiddenSystem $webDest
            Write-Host "[OK] Web root backed up -> $webDest" -ForegroundColor Green
        } else {
            Write-Host "[SKIP] IIS folder not found at $iisSrc" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[WARN] Web backup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ----------------------------------------------------------
    # FTP BACKUP (common path)
    # ----------------------------------------------------------
    try {
        $ftpSrc = "C:\ftp-site"
        if (Test-Path $ftpSrc) {
            $ftpDest = Join-Path $runRoot "FTP"
            New-Item -ItemType Directory -Path $ftpDest -Force | Out-Null
            Copy-Item -Path (Join-Path $ftpSrc "*") -Destination $ftpDest -Recurse -Force -ErrorAction Stop
            Set-HiddenSystem $ftpDest
            Write-Host "[OK] FTP site backed up -> $ftpDest" -ForegroundColor Green
        } else {
            Write-Host "[SKIP] FTP folder not found at $ftpSrc" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[WARN] FTP backup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ----------------------------------------------------------
    # DNS SERVER ZONES + RECORDS -> JSON (DnsServer module)
    # ----------------------------------------------------------
    try {
        $dnsJsonDir = Join-Path $runRoot "DNS_Server\DNS-Backups"
        New-Item -ItemType Directory -Path $dnsJsonDir -Force | Out-Null

        if (Get-Module -ListAvailable -Name DnsServer) {
            Import-Module DnsServer -ErrorAction Stop
        }

        if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) {
            Write-Host "[SKIP] DnsServer cmdlets not available; skipping DNS zones JSON export" -ForegroundColor Yellow
        } else {
            $dnsJsonOut = Join-Path $dnsJsonDir ("DNSBackup_{0}.json" -f (Get-Date -Format "yyyy-MM-dd_HHmmss"))
            $backup = @()
            $zones = Get-DnsServerZone

            foreach ($zone in $zones) {
                Write-Host "Backing up DNS zone -> JSON: $($zone.ZoneName)" -ForegroundColor Gray
                $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ErrorAction Stop
                $backup += [PSCustomObject]@{
                    ZoneName       = $zone.ZoneName
                    ZoneType       = $zone.ZoneType
                    IsDsIntegrated = $zone.IsDsIntegrated
                    Records        = $records
                }
            }

            $backup | ConvertTo-Json -Depth 10 | Out-File -FilePath $dnsJsonOut -Encoding UTF8
            Set-HiddenSystem $dnsJsonDir

            if (Test-Path $dnsJsonOut) {
                Set-HiddenSystem $dnsJsonOut
                Write-Host "[OK] DNS zones+records exported -> $dnsJsonOut" -ForegroundColor Green
            } else {
                Write-Host "[WARN] DNS JSON export did not produce a file" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "[WARN] DNS zones JSON export failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Re-apply Hidden/System flags to run root at end (helps if tools created new entries)
    Set-HiddenSystem $runRoot
    Set-HiddenSystem $backupRoot

    Write-Host "[OK] Backup routine complete. Root: $backupRoot (Run: $runRoot)" -ForegroundColor Green

} else {
    Write-Host "[SKIP] Backups" -ForegroundColor DarkGray
}



#the annoying stuff, most of which is in functions above
Write-Section "GPO Setup"
if(Read-YesNo "Apply SAFE baseline GPOs now?" $true){

    # network stuff
    $gpo1 = New-OrGetGPO -Name 'Baseline - Network Hardening (SAFE)'
    Link-GPO -Gpo $gpo1 -Target $domainDN -Order 1
    $aesOnly = Read-YesNo "Force Kerberos AES256-only (may break old systems)?" $false
    Configure-NetworkGPO -Gpo $gpo1 -Aes256Only:$aesOnly
    Write-Host "[OK] Network Hardening policy"


    # ldap stuff
    $gpo2 = New-OrGetGPO -Name 'Baseline - DC LDAP Signing (SAFE)'
    Link-GPO -Gpo $gpo2 -Target $dcOU -Order 1
    Configure-DCSigningGPO -Gpo $gpo2
    Write-Host "[OK] DC LDAP Signing policy"


    # audit + helpful stuff
    $gpo3 = New-OrGetGPO -Name 'Baseline - Auth & Audit (SAFE)'
    Link-GPO -Gpo $gpo3 -Target $domainDN -Order 1
    Configure-AuthAuditGPO -Gpo $gpo3
    Write-Host "[OK] Auth & Audit policy"



    #not gonna break passwords again lol, just doing this one setting
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -ReversibleEncryptionEnabled:$false -ErrorAction Stop
    $psos = Get-ADFineGrainedPasswordPolicy -Filter * -Properties ReversibleEncryptionEnabled -ErrorAction SilentlyContinue
    foreach($p in $psos){ 
        if($p.ReversibleEncryptionEnabled){ 
            Set-ADFineGrainedPasswordPolicy -Identity $p -ReversibleEncryptionEnabled $false -ErrorAction SilentlyContinue 
        } 
    }
    Write-Host "[OK] Domain password policy (no reversible encryption)"

}
else { 
    Write-Host "[SKIP] GPO setup" 
}




Write-Section "Domain-wide SMB Hardening"
if (Read-YesNo "Create/link a domain GPO to disable SMBv1, require SMB signing, and require SMB encryption?" $true) {

    try {
        Ensure-Modules

        $gpoSmb = New-OrGetGPO -Name 'Baseline - SMB Hardening'
        Link-GPO -Gpo $gpoSmb -Target $domainDN -Order 1
        $n = $gpoSmb.DisplayName

        # --- Disable SMBv1 (server + client driver) ---
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' DWord 0
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' DWord 4

        # --- Ensure SMBv2/3 is enabled (explicit, usually default) ---
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB2' DWord 1

        # --- Require SMB signing (server + client) ---
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'      'RequireSecuritySignature' DWord 1
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'      'EnableSecuritySignature'  DWord 1
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' DWord 1
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature'  DWord 1

        # --- Require SMB encryption (server rejects unencrypted SMB) ---
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RejectUnencryptedAccess' DWord 1

        # --- Disable legacy Computer Browser service (SMBv1-era) ---
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Browser' 'Start' DWord 4

        # ===================== INSERT RIGHT HERE =====================
        # LOCAL: remove SMB1 feature on THIS server (the one running goat.ps1)
        if (Read-YesNo "Also uninstall SMB1 feature locally on THIS server? (recommended; may require reboot)" $true) {
            Import-Module ServerManager -ErrorAction SilentlyContinue
            $f = Get-WindowsFeature FS-SMB1 -ErrorAction SilentlyContinue
            if ($f -and $f.Installed) {
                Uninstall-WindowsFeature FS-SMB1 -Remove -ErrorAction Stop | Out-Null
                Write-Host "[OK] Local FS-SMB1 feature removed (may require reboot)." -ForegroundColor Green
            } else {
                Write-Host "[NA] Local FS-SMB1 already not installed." -ForegroundColor DarkGray
            }
        }
        # ===================== END INSERT =====================

        Write-Host "[OK] Domain GPO applied: SMBv1 disabled, SMB signing required, SMB encryption required ($($gpoSmb.DisplayName))." -ForegroundColor Green
        Write-Host "[INFO] Reboot may be needed on some clients to fully unload SMB1 components." -ForegroundColor Gray
    }
    catch {
        Write-Host "[WARN] Domain SMB hardening failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

} else {
    Write-Host "[SKIP] Domain SMB hardening GPO" -ForegroundColor DarkGray
}




Write-Section "Specific Vuln Check domain wide >:)"
if (Read-YesNo "Run additional vuln checks (pre-auth, Guest, Spooler, Zerologon extras, MAQ, NTLMv1 hardening)?" $false) {
    $adReady = $true
    try { Import-Module ActiveDirectory -ErrorAction Stop | Out-Null }
    catch {
        $adReady = $false
        Write-Host "[WARN] ActiveDirectory module not available; AD-based actions will be skipped." -ForegroundColor Yellow
    }

    # --- DC-local settings enforced domain-wide via a NEW dedicated GPO (no edits to existing GPOs) ---
    $gpoReady = $true
    try { Import-Module GroupPolicy -ErrorAction Stop | Out-Null }
    catch {
        $gpoReady = $false
        Write-Host "[WARN] GroupPolicy module not available; DC-local settings won't be enforced via GPO." -ForegroundColor Yellow
    }

    if (-not $dcOU -and $adReady) {
        try { $dcOU = (Get-ADDomain -ErrorAction Stop).DomainControllersContainer }
        catch { Write-Host "[WARN] Could not resolve Domain Controllers container: $($_.Exception.Message)" -ForegroundColor Yellow }
    }

    # ===========================
    # NTLMv1 hardening (DOMAIN-WIDE) + local-DC immediate apply
    # ===========================
    $ntlmGpoName = "Baseline - NTLMv1 Hardening (SAFE)"
    $script:ntlmGpoEnsured = $false

    function Ensure-NtlmHardeningGpo {
        if (-not $gpoReady) { return $null }
        if (-not $domainDN) {
            Write-Host "[ERROR] domainDN not set; cannot link NTLM hardening GPO." -ForegroundColor Red
            return $null
        }
        if ($script:ntlmGpoEnsured) {
            return (Get-GPO -Name $ntlmGpoName -ErrorAction SilentlyContinue)
        }

        try {
            $gpo = Get-GPO -Name $ntlmGpoName -ErrorAction SilentlyContinue
            if (-not $gpo) {
                $gpo = New-GPO -Name $ntlmGpoName -Comment "Domain-wide: enforce NTLMv2-only (block LM/NTLMv1), tighten NTLM session security" -ErrorAction Stop
                Write-Host "[OK] Created GPO '$ntlmGpoName'"
            } else {
                Write-Host "[NA] GPO '$ntlmGpoName' already exists"
            }

            # link to domain root
            New-GPLink -Name $ntlmGpoName -Target $domainDN -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
            Set-GPLink -Name $ntlmGpoName -Target $domainDN -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[OK] Linked GPO '$ntlmGpoName' to '$domainDN'"

            $script:ntlmGpoEnsured = $true
            return $gpo
        }
        catch {
            Write-Host "[ERROR] Failed creating/linking NTLM hardening GPO: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }

    # NTLM hardening is opt-in because it can break legacy systems
    $doNtlmHardening = Read-YesNo "Harden NTLMv1/LM domain-wide (force NTLMv2-only)? May break legacy devices." $false
    if ($doNtlmHardening) {

        # --- Local DC immediate apply  ---
        try {
            $lsaKey   = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $msvKey   = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

            if (-not (Test-Path $lsaKey)) { New-Item -Path $lsaKey -Force | Out-Null }
            if (-not (Test-Path $msvKey)) { New-Item -Path $msvKey -Force | Out-Null }

            # Force NTLMv2 only; refuse LM + NTLMv1
            New-ItemProperty -Path $lsaKey -Name "LmCompatibilityLevel" -PropertyType DWord -Value 5 -Force | Out-Null
            # Do not store LM hashes
            New-ItemProperty -Path $lsaKey -Name "NoLMHash" -PropertyType DWord -Value 1 -Force | Out-Null

            # Tighten NTLM session security (signing/sealing + 128-bit)
            New-ItemProperty -Path $msvKey -Name "NTLMMinClientSec" -PropertyType DWord -Value 537395200 -Force | Out-Null
            New-ItemProperty -Path $msvKey -Name "NTLMMinServerSec" -PropertyType DWord -Value 537395200 -Force | Out-Null

            # Optional: audit receiving NTLM traffic (helps identify remaining NTLM usage)
            $doNtlmAudit = Read-YesNo "Also enable auditing of received NTLM traffic? (recommended for visibility)" $true
            if ($doNtlmAudit) {
                New-ItemProperty -Path $msvKey -Name "AuditReceivingNTLMTraffic" -PropertyType DWord -Value 2 -Force | Out-Null
            }

            Write-Host "[OK] Local DC NTLM hardening applied (NTLMv2-only + NoLMHash + MinSec)." -ForegroundColor Green
        }
        catch {
            Write-Host "[WARN] Local DC NTLM hardening failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # --- Domain-wide enforcement via new GPO ---
        if ($gpoReady) {
            $gpo = Ensure-NtlmHardeningGpo
            if ($gpo) {
                try {
                    # Force NTLMv2 only; refuse LM + NTLMv1
                    Set-GPRegistryValue -Name $ntlmGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 -ErrorAction Stop
                    # Do not store LM hashes
                    Set-GPRegistryValue -Name $ntlmGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "NoLMHash" -Type DWord -Value 1 -ErrorAction Stop

                    # Tighten NTLM session security (signing/sealing + 128-bit)
                    Set-GPRegistryValue -Name $ntlmGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "NTLMMinClientSec" -Type DWord -Value 537395200 -ErrorAction Stop
                    Set-GPRegistryValue -Name $ntlmGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "NTLMMinServerSec" -Type DWord -Value 537395200 -ErrorAction Stop

                    # Optional: audit receiving NTLM traffic
                    if ($doNtlmAudit) {
                        Set-GPRegistryValue -Name $ntlmGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "AuditReceivingNTLMTraffic" -Type DWord -Value 2 -ErrorAction Stop
                    }

                    Write-Host "[OK] Domain-wide NTLM hardening enforced via GPO: $ntlmGpoName" -ForegroundColor Green
                    Write-Host "     NOTE: Clients may need gpupdate/reboot; legacy NTLMv1/LM users will fail auth." -ForegroundColor Yellow
                }
                catch {
                    Write-Host "[ERROR] Failed configuring NTLM hardening GPO values: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "[WARN] GroupPolicy module missing; NTLM hardening applied locally only." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[SKIP] NTLMv1/LM hardening" -ForegroundColor DarkGray
    }


    $dcLocalGpoName = "DC Hardening - Spooler + Netlogon"
    $script:dcLocalGpoEnsured = $false
    function Ensure-DcLocalGpo {
        if (-not $gpoReady) { return $null }
        if (-not $dcOU) {
            Write-Host "[ERROR] DC OU/container DN not set; cannot link GPO." -ForegroundColor Red
            return $null
        }
        if ($script:dcLocalGpoEnsured) {
            return (Get-GPO -Name $dcLocalGpoName -ErrorAction SilentlyContinue)
        }

        try {
            $gpo = Get-GPO -Name $dcLocalGpoName -ErrorAction SilentlyContinue
            if (-not $gpo) {
                $gpo = New-GPO -Name $dcLocalGpoName -Comment "DC-only: disable Spooler + enforce Netlogon secure channel settings" -ErrorAction Stop
                Write-Host "[OK] Created GPO '$dcLocalGpoName'"
            } else {
                Write-Host "[NA] GPO '$dcLocalGpoName' already exists"
            }

            # link ONLY to Domain Controllers OU/container
            New-GPLink -Name $dcLocalGpoName -Target $dcOU -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
            Set-GPLink -Name $dcLocalGpoName -Target $dcOU -LinkEnabled Yes -ErrorAction Stop | Out-Null
            Write-Host "[OK] Linked GPO '$dcLocalGpoName' to '$dcOU'"

            # (optional safety) security-filter so it only applies to DCs even if someone links elsewhere later
            try {
                Set-GPPermissions -Name $dcLocalGpoName -TargetName "Domain Controllers" -TargetType Group -PermissionLevel GpoApply -ErrorAction Stop | Out-Null
                Set-GPPermissions -Name $dcLocalGpoName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[OK] GPO security filtering set (Domain Controllers=Apply; Authenticated Users=Read)"
            } catch {
                Write-Host "[WARN] Could not adjust GPO permissions (continuing): $($_.Exception.Message)" -ForegroundColor Yellow
            }

            $script:dcLocalGpoEnsured = $true
            return $gpo
        }
        catch {
            Write-Host "[ERROR] Failed creating/linking DC hardening GPO: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }

    #make sure users have to have authentication :D
    if ($adReady) {
        try {
            $targets = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -ErrorAction Stop
            if ($targets) {
                $targets | Set-ADAccountControl -DoesNotRequirePreAuth $false -ErrorAction Stop
                Write-Host "[OK] Kerberos pre-authentication enabled for applicable users"
            } else {
                Write-Host "[NA] No users found with 'DoesNotRequirePreAuth' enabled"
            }
        }
        catch {
            Write-Host "[ERROR] Failed enabling Kerberos pre-authentication: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    #disable guest account
    if ($adReady) {
        try {
            $guest = Get-ADUser -Identity "Guest" -Properties Enabled -ErrorAction Stop
            if ($guest.Enabled) {
                Disable-ADAccount -Identity $guest.SamAccountName -ErrorAction Stop
                Write-Host "[OK] Guest account disabled"
            } else {
                Write-Host "[NA] Guest account already disabled"
            }
        }
        catch {
            Write-Host "[WARN] Could not disable 'Guest' (may be renamed/missing): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    #disable print spooler (printnightmare) - local + enforce via DC-only GPO
    try {
        $svc = Get-Service -Name "Spooler" -ErrorAction Stop
        if ($svc.StartType -eq "Disabled" -and $svc.Status -eq "Stopped") {
            Write-Host "[NA] Print Spooler already disabled (local)"
        } else {
            if ($svc.Status -ne "Stopped") { Stop-Service -Name "Spooler" -Force -ErrorAction Stop }
            Set-Service -Name "Spooler" -StartupType Disabled -ErrorAction Stop
            Write-Host "[OK] Print Spooler service is now disabled (local)"
        }
    }
    catch {
        Write-Host "[ERROR] Failed disabling Print Spooler (local): $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($gpoReady) {
        $gpo = Ensure-DcLocalGpo
        if ($gpo) {
            try {
                # Enforce disabled startup across ALL DCs (GPO)
                Set-GPRegistryValue -Name $dcLocalGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" -ValueName "Start" -Type DWord -Value 4 -ErrorAction Stop
                Write-Host "[OK] GPO enforces Spooler disabled on all DCs ($dcLocalGpoName)"
            }
            catch {
                Write-Host "[ERROR] Failed setting Spooler GPO enforcement: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    #zerologon specifics - local + enforce via DC-only GPO
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        $cur = (Get-ItemProperty -Path $regPath -Name "FullSecureChannelProtection" -ErrorAction SilentlyContinue).FullSecureChannelProtection
        if ($cur -ne 1) {
            New-ItemProperty -Path $regPath -Name "FullSecureChannelProtection" -PropertyType DWord -Value 1 -Force | Out-Null
            Write-Host "[OK] FullSecureChannelProtection enabled (local)"
        } else {
            Write-Host "[NA] FullSecureChannelProtection already enabled (local)"
        }
        if (Get-ItemProperty -Path $regPath -Name "vulnerablechannelallowlist" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $regPath -Name "vulnerablechannelallowlist" -Force | Out-Null
            Write-Host "[OK] vulnerablechannelallowlist removed (local)"
        } else {
            Write-Host "[NA] vulnerablechannelallowlist not present (local)"
        }
    }
    catch {
        Write-Host "[ERROR] Failed applying Zerologon extras (local): $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($gpoReady) {
        $gpo = Ensure-DcLocalGpo
        if ($gpo) {
            try {
                $netlogonKey = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
                Set-GPRegistryValue -Name $dcLocalGpoName -Key $netlogonKey -ValueName "FullSecureChannelProtection" -Type DWord -Value 1 -ErrorAction Stop
                Remove-GPRegistryValue -Name $dcLocalGpoName -Key $netlogonKey -ValueName "vulnerablechannelallowlist" -ErrorAction SilentlyContinue
                Write-Host "[OK] GPO enforces Zerologon extras on all DCs ($dcLocalGpoName)"
            }
            catch {
                Write-Host "[ERROR] Failed setting Zerologon GPO enforcement: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    #set maq to 0
    if ($adReady) {
        try {
            $domainDn = (Get-ADDomain -ErrorAction Stop).DistinguishedName
            $domObj = Get-ADObject -Identity $domainDn -Properties "ms-DS-MachineAccountQuota" -ErrorAction Stop
            $curMaq = $domObj."ms-DS-MachineAccountQuota"

            if ($curMaq -eq 0) {
                Write-Host "[NA] ms-DS-MachineAccountQuota already 0"
            } else {
                Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{ "ms-DS-MachineAccountQuota" = 0 } -ErrorAction Stop | Out-Null
                Write-Host "[OK] ms-DS-MachineAccountQuota set to 0"
            }
        }
        catch {
            Write-Host "[ERROR] Failed setting ms-DS-MachineAccountQuota: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "[SKIP] Additional remediations skipped"
}




Write-Section "Backup Domain Administrator"
if (Read-YesNo "Create or update backup Domain Admin 'greg' now?" $false) {
    try {
        $ErrorActionPreference = "Stop"
        Import-Module ActiveDirectory

        # Pin all operations to one writable DC to avoid replication/timing issues
        $Server = (Get-ADDomain).PDCEmulator

        $Password = Read-PasswordTwiceMasked "Enter password for backup admin 'greg'"

        $User = Get-ADUser -Filter { SamAccountName -eq "greg" } -Server $Server -ErrorAction SilentlyContinue

        if ($User) {
            # if greg alr exists just give him a new password 
            Set-ADAccountPassword -Identity $User -NewPassword $Password -Reset -Server $Server
            Enable-ADAccount -Identity $User -Server $Server
        }
        else {
            New-ADUser `
                -Name "greg" `
                -SamAccountName "greg" `
                -AccountPassword $Password `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -CannotChangePassword $true `
                -Description "" `
                -Server $Server

            # re-read from the same DC so subsequent commands resolve the new object
            $User = Get-ADUser -Identity "greg" -Server $Server
        }

        # ensure Domain Admin membership 
        $isMember = Get-ADGroupMember "Domain Admins" -Server $Server |
            Where-Object { $_.SamAccountName -eq "greg" }

        if (-not $isMember) {
            Add-ADGroupMember -Identity "Domain Admins" -Members "greg" -Server $Server
        }

        Write-Host "[OK] greg is present and configured (DC: $Server)"
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host "Inner: $($_.Exception.InnerException.Message)" -ForegroundColor Red
        }
        Write-Host "FQID: $($_.FullyQualifiedErrorId)" -ForegroundColor Red
    }
}
else {
    Write-Host "[SKIP] greg creation :("
}




Write-Section "Privileged Group Cleanup (Interactive)"
$groupsToAudit = @(
    "Administrators",
    "Enterprise Admins",
    "Schema Admins",
    "Domain Admins",
    "Group Policy Creator Owners"
)

$safeUser = "Administrator"

foreach ($groupName in $groupsToAudit) {
    try {
        $group = Get-ADGroup -Identity $groupName -Properties Members -ErrorAction SilentlyContinue

        if ($group) {
            Write-Host "--- Auditing Group: $($group.Name) ---" -ForegroundColor Cyan

            # Direct members (DNs) so we can tell if a recursively-found object is directly removable from group
            $directMemberDns = @($group.Members)

            # Recursive membership listing (for audit visibility)
            $members = Get-ADGroupMember -Identity $group -Recursive | Sort-Object Name

            if ($members) {
                foreach ($member in $members) {

                    if ($member.SamAccountName -eq $safeUser) {
                        Write-Host "  [SKIP] $($member.Name) (Built-in Safe User)" -ForegroundColor DarkGray
                        continue
                    }

                    # Recursive results include nested members that are not directly removable here.
                    $isDirectMember = $false
                    if ($member.DistinguishedName -and ($directMemberDns -contains $member.DistinguishedName)) {
                        $isDirectMember = $true
                    }

                    if (-not $isDirectMember) {
                        Write-Host "  [NESTED] $($member.Name) ($($member.SamAccountName)) - nested member; not directly removable from '$($group.Name)'" -ForegroundColor DarkYellow
                        continue
                    }

                    $promptMsg = "  REMOVE '$($member.Name)' ($($member.SamAccountName)) from group '$($group.Name)'?"

                    if (Read-YesNo $promptMsg $false) {
                        try {
                            Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false -ErrorAction Stop
                            Write-Host "    [OK] Removed $($member.Name)" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "    [ERROR] Failed to remove $($member.Name): $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    else {
                        Write-Host "    [KEEP] $($member.Name) remains in group."
                    }
                }
            }
            else {
                Write-Host "  [INFO] Group is empty."
            }

            Write-Host "" # New line for readability
        }
        else {
            Write-Host "[SKIP] Group '$groupName' not found." -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "[ERROR] Processing group '$groupName': $($_.Exception.Message)" -ForegroundColor Red
    }
}



Write-Section "Advanced Logging"
if(Read-YesNo "Make sure advanced event viewer settings are on?" $false){
    try{ 
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

    	# Module logging (log all modules)
    	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
    	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
    	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
    	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -Type String -Force

    	# Transcription (registry-based, belt-and-suspenders with profile-based below)
    	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
    	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWord -Force
    	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Windows\Logs\PSTranscripts" -Type String -Force
    	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
    	New-Item -ItemType Directory -Path "C:\Windows\Logs\PSTranscripts" -Force | Out-Null

    	#----------------------------------------------------------
    	# Command-Line in Process Creation Events (Event 4688)
    	#----------------------------------------------------------
    	Write-Host "Enabling command-line in process creation events..."
    	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
    	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    	} 
    	catch { 
        	Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red 
    	}
} 
else { Write-Host "[SKIP] Password service autorestart" }





Write-Section "Set Major Services to autorestart"
if (Read-YesNo "Set Services like DNS and ADWS to auto-restart?" $false) {
    try {
        & sc.exe failure DNS    reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        & sc.exe failure W32Time reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        & sc.exe failure ADWS   reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        & sc.exe failure DFSR   reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        Write-Host "[OK] Service failure actions set." -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}
else { Write-Host "[SKIP] Password service autorestart" }




Write-Section "Administrator Password Reset"
if(Read-YesNo "Reset the DOMAIN 'Administrator' password now?" $false){
    try{ 
        Set-DomainAdminPassword; Write-Host "[OK] Password reset" 
    } 
    catch { 
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red 
    }
} 
else { Write-Host "[SKIP] Password reset" }




Write-Section "PingCastle Security Audit"
if(Read-YesNo "Download and run PingCastle audit on this DC?" $false){
    try {
        # Force TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        $pcZipPath = "$env:TEMP\PingCastle.zip"
        $pcInstallPath = "$env:SystemDrive\PingCastle"

        # 1. Check Local Cache (The fastest download is no download)
        if (Test-Path $pcZipPath) {
            Write-Host "[-] Found existing Zip at $pcZipPath. Skipping download."
        }
        else {
            # 2. Fetch URL (Only if we don't have the file)
            Write-Host "[-] Fetching latest release URL..."
            $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/vletoux/pingcastle/releases/latest"
            $downloadUrl = $latestRelease.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -ExpandProperty browser_download_url -First 1

            # 3. Download using BITS (Much faster than Invoke-WebRequest)
            Write-Host "[-] Downloading (BITS) from GitHub..."
            Start-BitsTransfer -Source $downloadUrl -Destination $pcZipPath
        }

        # 4. Extract
        if (Test-Path $pcInstallPath) { Remove-Item $pcInstallPath -Recurse -Force }
        Write-Host "[-] Extracting..."
        Expand-Archive -Path $pcZipPath -DestinationPath $pcInstallPath -Force

        # 5. Run
        $pcExe = Get-ChildItem -Path $pcInstallPath -Recurse -Filter "PingCastle.exe" | Select-Object -ExpandProperty FullName -First 1
        
        if ($pcExe) {
            Write-Host "[-] Starting PingCastle Healthcheck..."
            Start-Process -FilePath $pcExe -ArgumentList "--healthcheck --server $env:USERDNSDOMAIN" -Wait -NoNewWindow
            Write-Host "[OK] PingCastle finished. Reports located in: $pcInstallPath"
        }
        else {
            throw "PingCastle.exe not found."
        }
    } 
    catch { 
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red 
    }
} 
else { Write-Host "[SKIP] PingCastle audit" }



Write-Section "HardeningKitty Configuration Audit"
if(Read-YesNo "Download and run HardeningKitty audit (Report Only)?" $false){
    try {
        # 1. Setup
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $hkZipPath = "$env:TEMP\HardeningKitty.zip"
        $hkInstallPath = "$env:SystemDrive\HardeningKitty"

        # 2. Download Source Code (Robust method)
        # We only download if the folder doesn't already exist to save time
        if (-not (Test-Path $hkInstallPath)) {
            Write-Host "[-] Fetching latest release info..."
            $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/scipag/HardeningKitty/releases/latest"
            $url = $latest.zipball_url 

            Write-Host "[-] Downloading from GitHub..."
            Invoke-WebRequest -Uri $url -OutFile $hkZipPath -UseBasicParsing

            Write-Host "[-] Extracting to $hkInstallPath..."
            Expand-Archive -Path $hkZipPath -DestinationPath $hkInstallPath -Force
        }

        # 3. Import Module
        $hkManifest = Get-ChildItem -Path $hkInstallPath -Recurse -Filter "HardeningKitty.psd1" | Select-Object -ExpandProperty FullName -First 1

        if ($hkManifest) {
            Write-Host "[-] Found Module Manifest: $hkManifest"
            
            # Clean previous sessions
            if (Get-Module -Name HardeningKitty) { Remove-Module HardeningKitty }
            Import-Module $hkManifest -Force

            # 4. Run Audit (Fixed)
            Write-Host "[-] Starting Audit (This may take a moment)..."
            
            # FIX: We removed -LogPath. We capture the output ($results) instead.
            # We explicitly specify the default template if needed, or let it auto-detect.
            $results = Invoke-HardeningKitty -Mode Audit -SkipRestorePoint
            
            # 5. Save Report
            $timestamp = Get-Date -Format "yyyyMMdd-HHmm"
            $reportFile = "$hkInstallPath\HardeningKitty_Report_$timestamp.csv"
            
            if ($results) {
                $results | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8
                Write-Host "[OK] Audit Complete."
                Write-Host "[-] Report saved to: $reportFile" -ForegroundColor Green
            }
            else {
                Write-Host "[WARN] HardeningKitty ran but returned no results." -ForegroundColor Yellow
            }
            
            # Cleanup module
            Remove-Module HardeningKitty
        }
        else {
            throw "Could not find 'HardeningKitty.psd1' in extracted files."
        }
    } 
    catch { 
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red 
    }
} 
else { Write-Host "[SKIP] HardeningKitty audit" }





Write-Section "Next"
Write-Host "Apply policies on targets with: gpupdate /force on every windows computer (or wait for background refresh). Also run mrt on all windows computers. Check to see if firewall is on but be prepared to lose services if it breaks things."
