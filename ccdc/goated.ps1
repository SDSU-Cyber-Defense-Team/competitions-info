<#
goat.ps1
- made by Dashell Finn last updated feb 2026
- always a WIP script, there is always more I want to add.
- added hardeningkitty and pingcastle, will add winpeas soon
- added removal of users from all admin groups, not ballsy enough to do it auto so it asks per user
- ports enumeration works, will add version numbers soon
- still need to add registry hunter for DisableWindowsDefender and related registry names (currently making a list to look for)
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
    param($Port, $Loc)
    switch ($Port) {
        21 { "FTP" }; 22 { "SSH" }; 23 { "Telnet" }; 25 { "SMTP" }; 53 { "DNS" }
        { $_ -in 80,443,8080,8443,3000,5000 } { "Web" }; 123 { "NTP (Time)" }
        { $_ -in 135,593 } { "RPC" } 
        { $_ -in 137,138 } { "NetBIOS" }; { $_ -in 139,445 } { "SMB" }
        { $_ -in 389,636,3268,3269 } { "LDAP" }
        { $_ -in 88,464 } { "Kerberos" }; { $_ -in 500,4500 } { "IPSec/VPN" }
        3389 { "RDP" }; 5353 { "mDNS" }; 5355 { "LLMNR" }
        { $_ -in 5985,5986 } { "WinRM" }; 9389 { "ADWS" }
        47001 { "WinRM Mgmt" }
        1433 { "SQL Server" }; 3306 { "MySQL" }
        5432 { "Postgres" }; 5900 { "VNC" }; 5800 { "VNC-Http" }
        default {
            if ($Loc -match 'iis|w3wp|apache|nginx|tomcat|node|python|php|gunicorn') { return "Web App" }
            if ($Loc -match 'sql|mongo|redis|oracle') { return "Database" }
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





Write-Section "Ports & Services (Deep Config Inventory)"
$doScan = Read-YesNo "Enumerate listening ports with Config/Path Discovery?" $true

if ($doScan) {
    $wellKnownOnly = Read-YesNo "Only show well-known ports (<= 49151)?" $false

    # --- 3. DISCOVERY & TOOL CHECK ---
    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch { Write-Host "[WARN] RSAT AD Module missing." -ForegroundColor Yellow; return }

    # Find SSH Binary
    $sshBin = "ssh.exe" # Default assumption
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
    $comps = Get-ADComputer -Filter "Enabled -eq 'True'" -Properties "DNSHostName", "OperatingSystem"
    Write-Host ("[INFO] Targets found: {0}" -f $comps.Count)

    # --- 4. EXECUTION LOOP ---
    
    $windowsScriptBlock = {
        $results = New-Object System.Collections.Generic.List[object]

        # --- A. Collect Raw Data ---
        $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        $allSvcs  = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        $netstat  = & netstat -ano 2>$null

        # --- B. IIS / Web Config Discovery (Robust Version) ---
        $webMap = @{} 
        
        # Method 1: Powershell IIS Module
        if (Get-Module -ListAvailable WebAdministration) {
            try {
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
                
                if ($sites) {
                    foreach ($site in $sites) {
                        # Safe Path Extraction
                        $path = $null
                        try { $path = $site.physicalPath } catch {}
                        if (-not $path) { 
                            try { $path = (Get-ItemProperty $site.PSPath -Name physicalPath -ErrorAction SilentlyContinue).physicalPath } catch {}
                        }
                        if (-not $path) { $path = "Unknown Path" }

                        # Safe Binding Extraction
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
            } catch {
                # Just ignore IIS module errors and fall through to AppCmd
            }
        }
        
        # Method 2: AppCmd Fallback (if map still empty or partial)
        if ((Test-Path "$env:SystemRoot\system32\inetsrv\appcmd.exe")) {
            try {
                $appCmd = "$env:SystemRoot\system32\inetsrv\appcmd.exe"
                $siteOut = & $appCmd list site
                $vdirOut = & $appCmd list vdir

                foreach ($line in $siteOut) {
                    # Parse: SITE "Name" (id:1,bindings:http/*:80:,state:Started)
                    if ($line -match 'SITE "([^"]+)" .*bindings:([^,]+)') {
                        $siteName = $matches[1]
                        $bindStr  = $matches[2] 
                        
                        # Find path in vdirs
                        $sitePath = "Unknown Path"
                        $escapedName = [regex]::Escape($siteName)
                        $vdirLine = $vdirOut | Where-Object { $_ -match "VDIR `"$escapedName/`"" } | Select-Object -First 1
                        
                        if ($vdirLine -match 'physicalPath:(.*)\)') { 
                            $sitePath = $matches[1] 
                        }

                        # Extract Port
                        if ($bindStr -match ':(\d+):') {
                            $port = [int]$matches[1]
                            # Only overwrite if not already found by PS module
                            if (-not $webMap.ContainsKey($port)) {
                                $webMap[$port] = "IIS Site: '$siteName' -> $sitePath"
                            }
                        }
                    }
                }
            } catch {}
        }

        # --- C. Processing Maps ---
        $procMap = @{}
        if ($allProcs) {
            foreach ($p in $allProcs) { $procMap[[int]$p.ProcessId] = $p }
        }

        $svcMap = @{}
        if ($allSvcs) {
            foreach ($s in $allSvcs) {
                $pidVal = [int]$s.ProcessId
                if (-not $svcMap.ContainsKey($pidVal)) { $svcMap[$pidVal] = @() }
                $svcMap[$pidVal] += $s
            }
        }

        # --- D. Parse Ports & Build Output ---
        if ($netstat) {
            foreach ($line in $netstat) {
                if ($line -match '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+.*?\s+(\d+)') {
                    
                    $proto  = $matches[1]
                    $port   = [int]$matches[3]
                    $pidVal = [int]$matches[4]
                    
                    $procObj = $procMap[$pidVal]
                    $svcList = $svcMap[$pidVal]
                    
                    $finalLoc = "Unknown"

                    # 1. Check if it's a known IIS/Web Port First
                    if ($webMap.ContainsKey($port) -and ($pidVal -eq 4 -or ($procObj -and $procObj.Name -eq "w3wp.exe"))) {
                        $finalLoc = $webMap[$port]
                    }
                    # 2. Handle System / Kernel
                    elseif ($pidVal -eq 4 -or $pidVal -eq 0) {
                        $finalLoc = "System (Kernel/Drivers)"
                        if ($port -in 445,139) { $finalLoc += " [SMB/Srv]" }
                        if ($port -in 5985)    { $finalLoc += " [WinRM]" }
                        if ($port -eq 47001)   { $finalLoc += " [WinRM/EventLog]" }
                    }
                    # 3. Handle Standard Processes
                    elseif ($procObj) {
                        # Prefer CommandLine if it exists (shows config flags), else ExecutablePath
                        if (-not [string]::IsNullOrWhiteSpace($procObj.CommandLine)) {
                            $finalLoc = $procObj.CommandLine
                        } elseif ($procObj.ExecutablePath) {
                            $finalLoc = $procObj.ExecutablePath
                        } else {
                            $finalLoc = $procObj.Name
                        }
                    }
                    # 4. Fallback
                    else {
                        try { 
                            $p = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
                            if ($p) { $finalLoc = "$($p.ProcessName) [$($p.Path)]" }
                        } catch {}
                        if ($finalLoc -eq "Unknown") { $finalLoc = "(unknown - PID $pidVal)" }
                    }

                    # Append Services if present (and we haven't already found a specific IIS path)
                    if ($svcList) {
                        $svcNames = ($svcList.Name | Sort-Object -Unique) -join ","
                        
                        if (-not ($finalLoc -match "IIS Site")) {
                             $finalLoc += " ; svc=$svcNames"
                             
                             # Dig for DLLs (Deep Config)
                             $dlls = @()
                             foreach ($sName in $svcList.Name) {
                                $rp = "HKLM:\SYSTEM\CurrentControlSet\Services\$sName\Parameters"
                                try {
                                    $v = (Get-ItemProperty -Path $rp -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
                                    if ($v) { $dlls += $v }
                                } catch {}
                             }
                             if ($dlls) { $finalLoc += " ; DLL=" + (($dlls | Sort-Object -Unique) -join ",") }
                        }
                    }

                    $results.Add([pscustomobject]@{ Proto=$proto; Port=$port; Location=$finalLoc })
                }
            }
        }
        return $results 
    }

    foreach ($comp in $comps) {
        $target = $comp.DNSHostName
        $os     = $comp.OperatingSystem
        
        Write-Host "--------------------------------------------------------"
        Write-Host "Host: $target ($os)" -NoNewline
        if (-not (Test-Connection $target -Count 1 -Quiet)) {
            Write-Host " [OFFLINE]" -ForegroundColor Red; continue
        }
        Write-Host " [ONLINE]" -ForegroundColor Green

        $data = @()
        $useSSH = ($os -match "Linux|Ubuntu|CentOS|Red Hat|Debian|Alpine") -or ($os -eq $null)

        if ($useSSH) {
            if (-not $sshBin) { Write-Host "    [SKIP] No SSH binary available." -ForegroundColor DarkGray; continue }
            try {
                $ssCmd  = "ss -lntupH 2>/dev/null || netstat -lntup 2>/dev/null"
                $psCmd  = "ps -Ao pid,args 2>/dev/null || ps -o pid,args 2>/dev/null" 

                $sshArgs = @("-l", "root", "-o", "StrictHostKeyChecking=no", $target, "$ssCmd ; echo '|||' ; $psCmd")
                
                # FIXED: Hand control directly to SSH to avoid double prompting
                Write-Host "    [INPUT] Connecting to $target..." -NoNewline -ForegroundColor Cyan
                
                # Execute interactive SSH. The binary itself will prompt for the password safely.
                $rawOut = & $sshBin $sshArgs 2>&1
                
                # Insert a newline after SSH returns control to keep log clean
                Write-Host "" 
                
                if ($LASTEXITCODE -ne 0) { 
                    Write-Host "    [FAIL] SSH Access Denied or Connection Failed." -ForegroundColor Red
                    continue 
                }
                
                if (-not $rawOut) { throw "No output." }

                # Parsing
                $outStr = $rawOut -join "`n"
                $parts = $outStr -split "\|\|\|"
                $ssOut = $parts[0] -split "`n"
                $psOut = if ($parts.Count -gt 1) { $parts[1] -split "`n" } else { @() }
                
                $linuxProcMap = @{}
                foreach ($pLine in $psOut) { $pLine = $pLine.Trim(); if ($pLine -match '^(\d+)\s+(.*)') { $linuxProcMap[[int]$matches[1]] = $matches[2] } }

                foreach ($line in $ssOut) {
                    if ($line -match '^(tcp|udp)\s+.*?:(\d+)\s+.*users:\(\("([^"]+)",(?:pid=)?(\d+)') {
                        $proto = $matches[1]; $port = [int]$matches[2]; $procID = [int]$matches[4]
                        $fullPath = $linuxProcMap[$procID]; if (-not $fullPath) { $fullPath = $matches[3] }
                        $data += [pscustomobject]@{ Proto=$proto.ToUpper(); Port=$port; Location=$fullPath }
                    }
                    elseif ($line -match '^(tcp|udp)\s+.*?[:\s](\d+)\s+.*LISTEN\s+(\d+)/(\S+)') {
                         $proto = $matches[1]; $port = [int]$matches[2]; $procID = [int]$matches[3]
                         $fullPath = $linuxProcMap[$procID]; if (-not $fullPath) { $fullPath = $matches[4] }
                         $data += [pscustomobject]@{ Proto=$proto.ToUpper(); Port=$port; Location=$fullPath }
                    }
                }
            } catch {
                Write-Host "    [FAIL] SSH Error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        else {
            try {
                $data = Invoke-Command -ComputerName $target -ScriptBlock $windowsScriptBlock -ErrorAction Stop
            } catch {
                Write-Host "    [FAIL] WinRM Error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        if ($wellKnownOnly) { $data = $data | Where-Object { $_.Port -le 49151 } }
        
        # --- FIXED DISPLAY LOGIC (Wider Columns) ---
        if ($data) {
            $data | Sort-Object {[int]$_.Port} | Group-Object Port | ForEach-Object { 
                $group = $_.Group
                $port  = $_.Name
                
                $hasTCP = ($group.Proto -contains "TCP")
                $hasUDP = ($group.Proto -contains "UDP")
                $protoDisplay = if ($hasTCP -and $hasUDP) { "TCP+UDP" } elseif ($hasTCP) { "TCP" } else { "UDP" }
                
                # Prioritize a location that isn't empty/unknown if multiple protocols exist
                $bestLocObj = $group | Where-Object { $_.Location -and $_.Location -ne "Unknown" } | Select-Object -First 1
                if ($bestLocObj) { $loc = $bestLocObj.Location } else { $loc = $group[0].Location }

                $cat = Get-PortCat -Port $port -Loc $loc
                
                Write-Host ("    {0,-15} | {1,-12} | {2}" -f "$port/$protoDisplay", $cat, $loc)
            }
        } else {
            Write-Host "    [INFO] No ports found (or access denied)." -ForegroundColor Gray
        }
        Write-Host "    [OK] Enumeration complete." -ForegroundColor Green
    }
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



Write-Section "DNS backup"
if (Read-YesNo "Back up all DNS zones now?" $true) {

    $DNSBackupPath = "C:\Windows\DNSBackups"

    # make path
    if (!(Test-Path $DNSBackupPath)) {
        New-Item -Path $DNSBackupPath -ItemType Directory | Out-Null
    }

    # make the backup folder hidden
    try {
        $item = Get-Item -LiteralPath $DNSBackupPath -Force
	#set the file to system so file explorer cant find it >:)
        $item.Attributes = $item.Attributes -bor ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System)
    } catch { }

    # DNS service on your box runs as LocalSystem; make sure SYSTEM can write here (just in case ACLs are weird)
    try {
        $acl  = Get-Acl $DNSBackupPath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $DNSBackupPath -AclObject $acl
    } catch { }

    # Load DNS module if needed
    try { Import-Module DnsServer -ErrorAction Stop } catch { }

    if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) {
        Write-Host "[SKIP] DNS cmdlets not available (DnsServer module missing?)" -ForegroundColor Yellow
    }
    else {
        $zones = Get-DnsServerZone
        $ok = 0
        $fail = 0

        foreach ($zone in $zones) {
            $zoneName = $zone.ZoneName
            $safeName = ($zoneName -replace '[^\w\.\-]','_')
            $outFile  = Join-Path $DNSBackupPath ("$safeName.clixml")

            Write-Host "Backing up DNS zone '$zoneName' -> '$outFile'..."

            try {
                if (Test-Path $outFile) { Remove-Item $outFile -Force -ErrorAction SilentlyContinue }

                # Save BOTH zone config + records in one file (still a single "backup method")
                $backupObj = [PSCustomObject]@{
                    Zone    = (Get-DnsServerZone -Name $zoneName | Select-Object *)
                    Records = (Get-DnsServerResourceRecord -ZoneName $zoneName -ErrorAction Stop | Select-Object *)
                }

                $backupObj | Export-Clixml -Path $outFile -Force

                if ((Test-Path $outFile) -and ((Get-Item $outFile).Length -gt 0)) {
                    $ok++
                }
                else {
                    throw "backup produced empty file"
                }
            }
            catch {
                Write-Warning "Failed to back up zone '$zoneName': $($_.Exception.Message)"
                $fail++
            }
        }

        if ($fail -eq 0 -and $ok -gt 0) {
            Write-Host "[OK] DNS backup finished. Files are in '$DNSBackupPath'."
        }
        else {
            Write-Host "[WARN] DNS backup finished: $ok succeeded, $fail failed. Files are in '$DNSBackupPath'." -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "[SKIP] DNS backup"
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




Write-Section "Domain-wide SMBv1 Disable + SMB Signing"
if (Read-YesNo "Create/link a domain GPO to disable SMBv1 (server+client) and require SMB signing on ALL domain computers? (Recommended)" $true) {

    try {
        Ensure-Modules

        $gpoSmb = New-OrGetGPO -Name 'Baseline - SMB Hardening (SAFE)'

        # Put this at high precedence at the domain root (change Order if you want it lower priority)
        Link-GPO -Gpo $gpoSmb -Target $domainDN -Order 1

        $n = $gpoSmb.DisplayName

        # --- SMB Server: disable SMB1, require signing ---
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' DWord 0
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' DWord 1
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature'  DWord 1

        # --- SMB Client: require signing ---
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' DWord 1
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature'  DWord 1

        # --- Disable SMB1 client driver (mrxsmb10) ---
        # (If SMB1 is already removed on a machine, this is harmless.)
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' DWord 4

        # --- Disable legacy Browser service (SMBv1-era) ---
        Set-Reg $n 'HKLM\SYSTEM\CurrentControlSet\Services\Browser' 'Start' DWord 4

        Write-Host "[OK] Domain GPO: SMBv1 disabled + SMB signing required (Baseline - SMB Hardening (SAFE)). Reboot may be needed on clients to fully unload SMB1." -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Domain SMB hardening failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

} else {
    Write-Host "[SKIP] Domain SMBv1/Signing GPO" -ForegroundColor DarkGray
}




Write-Section "Specific Vuln Check domain wide >:)"
if (Read-YesNo "Run additional vuln checks (pre-auth, Guest, Spooler, Zerologon extras, MAQ)?" $false) {
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

    #make sure users have authentication :D
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



Write-Section "Next"
Write-Host "Apply policies on targets with: gpupdate /force on every windows computer (or wait for background refresh). Also run mrt on all windows computers. Check to see if firewall is on but be prepared to lose services if it breaks things."
