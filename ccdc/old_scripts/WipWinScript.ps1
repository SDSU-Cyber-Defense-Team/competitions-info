
<#
Domain_Hardening_DomainSharesOnly.ps1
- WIP script, needs to be tested a lot + whole bunch I still want to add.
- Works for smb signing, no smbv1, and no null auth, havent tested anything else yet (also doesnt bluescreen! (had to take a bunch of stuff out :( ))
- Still a whole bunch of stuff I want to add...
#>

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

# ---------- Core helpers ----------
function Ensure-Modules { Import-Module ActiveDirectory -ErrorAction Stop; Import-Module GroupPolicy -ErrorAction Stop }
function New-OrGetGPO { param([string]$Name) $g=Get-GPO -Name $Name -ErrorAction SilentlyContinue; if(-not $g){$g=New-GPO -Name $Name}; $g }
function Link-GPO { param([Microsoft.GroupPolicy.Gpo]$Gpo,[string]$Target,[int]$Order=1) New-GPLink -Name $Gpo.DisplayName -Target $Target -ErrorAction SilentlyContinue | Out-Null; Set-GPLink -Target $Target -Guid $Gpo.Id -Order $Order | Out-Null }
function Set-Reg { param([string]$Gpo,[string]$Key,[string]$Name,[ValidateSet('DWord','String','MultiString')]$Type,$Value) Set-GPRegistryValue -Name $Gpo -Key $Key -ValueName $Name -Type $Type -Value $Value | Out-Null }

function Get-GpoSysvolMachinePath { param([Microsoft.GroupPolicy.Gpo]$Gpo) $domain=(Get-ADDomain).DNSRoot; $guid=$Gpo.Id.ToString("B").ToUpper(); "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Microsoft\Windows NT\SecEdit" }
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

function Configure-NetworkGPO {
    param([Microsoft.GroupPolicy.Gpo]$Gpo,[switch]$DisablePwdFreeze,[switch]$Aes256Only)
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
    if ($DisablePwdFreeze) { Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'DisablePasswordChange' DWord 1; Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RefusePasswordChange' DWord 1 }
    else { Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'DisablePasswordChange' DWord 0; Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RefusePasswordChange' DWord 0 }
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

function Configure-DCSigningGPO { param([Microsoft.GroupPolicy.Gpo]$Gpo) Set-Reg $Gpo.DisplayName 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity' DWord 2 }
function Configure-AuthAuditGPO {
    param([Microsoft.GroupPolicy.Gpo]$Gpo)
    $n=$Gpo.DisplayName
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
    Ensure-GptTmplValue -Gpo $Gpo -Name 'AuditAccountLogon' -Value 3
    Ensure-GptTmplValue -Gpo $Gpo -Name 'AuditLogonEvents'  -Value 3
    Ensure-GptTmplValue -Gpo $Gpo -Name 'AuditPolicyChange' -Value 3
}

function Invoke-ShareNameInventory {
    [CmdletBinding()]
    param([string]$SearchBase,[switch]$IncludeAdminShares,[string]$OutFile="$env:USERPROFILE\Desktop\ShareNames.txt")
    Import-Module ActiveDirectory -ErrorAction Stop
    $comps = if ($SearchBase) { Get-ADComputer -Filter 'Enabled -eq $true -and OperatingSystem -like "*Windows*"' -SearchBase $SearchBase -SearchScope Subtree | Select-Object -Expand Name } else { Get-ADComputer -Filter 'Enabled -eq $true -and OperatingSystem -like "*Windows*"' | Select-Object -Expand Name }
    $skip=@('ADMIN$','C$','IPC$'); $dcom=New-CimSessionOption -Protocol Dcom
    $lines = New-Object System.Collections.Generic.List[string]
    foreach($c in $comps){
        try{ $s=New-CimSession -ComputerName $c -SessionOption $dcom -ErrorAction Stop
            try{
                $shares=Get-SmbShare -CimSession $s -ErrorAction Stop
                if(-not $IncludeAdminShares){ $shares=$shares | Where-Object { $_.Name -notin $skip } }
                foreach($x in $shares){ $lines.Add(("{0}\{1}" -f $c,$x.Name)) }
            } finally { Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue }
        } catch { $lines.Add(("{0}\(unreachable)" -f $c)) }
    }
    if($OutFile){ $lines | Set-Content -Path $OutFile -Encoding UTF8 }
    $lines
}

# --- Password input with "*" masking inline ---
function Read-HostMasked([string]$Prompt) {
    $rawui = $Host.UI.RawUI
    Write-Host -NoNewline ($Prompt + ": ")
    $secure = New-Object System.Security.SecureString
    $count = 0
    while ($true) {
        $key = $rawui.ReadKey("NoEcho,IncludeKeyDown")
        $vk = $key.VirtualKeyCode
        $ch = $key.Character
        if ($vk -eq 13) { break }                               # Enter
        elseif ($vk -eq 8) {                                     # Backspace
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
    $secure.MakeReadOnly(); return $secure
}
function Read-PasswordTwiceMasked([string]$Prompt) {
    $p1 = Read-HostMasked $Prompt
    $p2 = Read-HostMasked "Re-enter password to confirm"
    $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
    $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
    try {
        $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
        $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
        if ($s1 -ne $s2) { throw "Passwords do not match." }
    } finally {
        if ($b1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1) }
        if ($b2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
    }
    return $p1
}

# Built-in Administrator helpers
function Get-BuiltinAdmin { $dom=Get-ADDomain; $sid="$($dom.DomainSID)-500"; Get-ADUser -LDAPFilter "(objectSid=$sid)" }
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
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ throw "Run in an elevated PowerShell." }
Ensure-Modules

$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$dcOU    = $domain.DomainControllersContainer

Write-Section "GPO Setup"
if(Read-YesNo "Apply SAFE baseline GPOs now?" $true){
    $gpo1 = New-OrGetGPO -Name 'Baseline - Network Hardening (SAFE)'; Link-GPO -Gpo $gpo1 -Target $domainDN -Order 1
    $pwdFreeze = Read-YesNo "Enable Netlogon machine-account password freeze (NOT recommended)?" $false
    $aesOnly   = Read-YesNo "Force Kerberos AES256-only (may break old systems)?" $false
    Configure-NetworkGPO -Gpo $gpo1 -DisablePwdFreeze:$pwdFreeze -Aes256Only:$aesOnly; Write-Host "[OK] Network Hardening policy"

    $gpo2 = New-OrGetGPO -Name 'Baseline - DC LDAP Signing (SAFE)'; Link-GPO -Gpo $gpo2 -Target $dcOU -Order 1
    Configure-DCSigningGPO -Gpo $gpo2; Write-Host "[OK] DC LDAP Signing policy"

    $gpo3 = New-OrGetGPO -Name 'Baseline - Auth & Audit (SAFE)'; Link-GPO -Gpo $gpo3 -Target $domainDN -Order 2
    Configure-AuthAuditGPO -Gpo $gpo3; Write-Host "[OK] Auth & Audit policy"

    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -ReversibleEncryptionEnabled:$false -ErrorAction Stop
    $psos = Get-ADFineGrainedPasswordPolicy -Filter * -Properties ReversibleEncryptionEnabled -ErrorAction SilentlyContinue
    foreach($p in $psos){ if($p.ReversibleEncryptionEnabled){ Set-ADFineGrainedPasswordPolicy -Identity $p -ReversibleEncryptionEnabled $false -ErrorAction SilentlyContinue } }
    Write-Host "[OK] Domain password policy (no reversible encryption)"
} else { Write-Host "[SKIP] GPO setup" }

Write-Section "Local SMBv1 Disable"
if (Read-YesNo "Disable SMBv1 on THIS machine now (server+client) and require SMB signing? Recommended." $true) {
    try {
        $serverCmd = Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue
        $clientCmd = Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue
        if ($serverCmd) { try { Set-SmbServerConfiguration -EnableSMB1Protocol:$false -ErrorAction Stop | Out-Null } catch {} ; try { Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction SilentlyContinue | Out-Null } catch {} }
        if ($clientCmd) { try { Set-SmbClientConfiguration -EnableSMB1Protocol:$false -ErrorAction Stop | Out-Null } catch {} ; try { Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -ErrorAction SilentlyContinue | Out-Null } catch {} }
        # Registry fallback without creating missing keys
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') { New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Type DWord -Value 0 -Force | Out-Null }
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10') { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Type DWord -Value 4 -ErrorAction SilentlyContinue | Out-Null }
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation') {
            try {
                $dep = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' -ErrorAction Stop).DependOnService
                if ($dep) {
                    $new = @(); foreach ($d in $dep) { if ($d -ne 'MRxSmb10') { $new += $d } }
                    if ($new -notcontains 'MRxSmb20') { $new += 'MRxSmb20' }
                    if ($new -notcontains 'NSI')      { $new += 'NSI' }
                    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' -Name DependOnService -Type MultiString -Value $new -ErrorAction SilentlyContinue | Out-Null
                }
            } catch {}
        }
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Browser') { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Browser' -Name 'Start' -Type DWord -Value 4 -ErrorAction SilentlyContinue | Out-Null }
        try { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch {}
        Write-Host "[OK] Local: SMBv1 disabled (or confirmed absent), SMB signing required. A restart may be needed to fully unload SMB1 client driver."
    } catch { Write-Host "[WARN] Local SMB/Signing hardening issue: $($_.Exception.Message)" -ForegroundColor Yellow }
} else { Write-Host "[SKIP] Local SMBv1/Signing change" }

Write-Section "Shares (Domain Inventory)"
# Skip local compact display and the menu; act as if user chose full domain share enumeration (no OU scope prompt).
$inclAdmin = Read-YesNo "Include ADMIN$/C$/IPC$?" $false
try {
    $rows = Invoke-ShareNameInventory -IncludeAdminShares:$inclAdmin
    $max = 200; $i = 0
    foreach($r in $rows){ $i++; if($i -le $max){ $r } }
    if($rows.Count -gt $max){
        Write-Host ("... (truncated, full list saved to Desktop\ShareNames.txt, {0} entries)" -f $rows.Count) -ForegroundColor Yellow
    }
    Write-Host "[OK] Share enumeration complete"
} catch {
    Write-Host "[ERROR] Share enumeration failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Offer password reset last
if(Read-YesNo "Reset the DOMAIN 'Administrator' password now?" $false){
    try{ Set-DomainAdminPassword; Write-Host "[OK] Password reset" } catch { Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red }
} else { Write-Host "[SKIP] Password reset" }

Write-Section "Next"
Write-Host "Apply policies on targets with: gpupdate /force  (or wait for background refresh)."
