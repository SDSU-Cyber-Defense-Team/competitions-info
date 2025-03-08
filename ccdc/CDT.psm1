function Write-LogMessage {
    param(
        [string]$Text,
        [System.ConsoleColor]$Color
    )

    Write-Host $Text -ForegroundColor $Color
}
function Disable-Service {
    param(
        [string]$Name
    )

    $Service = Get-Service $Name -ErrorAction SilentlyContinue;

    if (!$Service) {
        Write-LogMessage "> $Name not found on system." -Color DarkGray
    }
    elseif ($Service.Status -eq "Running") {
        Set-Service $Name -StartupType Disabled
        Stop-Service $Name

        Write-LogMessage "> $Name has been stopped and disabled." -Color Yellow
    }
    else {
        Write-LogMessage "> $Name is already disabled." -Color DarkGray
    }
}
function Invoke-Download {
    param(
        [string]$FileName,
        [string]$Url
    )

    [Net.ServicePointManager]::SecurityProtocol = "Tls12, Ssl3"

    if (Test-Path $FileName) {
        Write-LogMessage "> $FileName was already downloaded." -Color DarkGray
    }
    else {
        Write-LogMessage "> $FileName not found! Downloading..." -Color Yellow
        Invoke-WebRequest $Url -OutFile $FileName
    }
}
function New-Directory {
    param(
        [string]$Path
    )

    New-Item $Path -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
}
function Disable-Feature {
    param(
        [string]$FeatureName
    )

    if (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName | Where-Object -Property State -EQ Enabled) {
        Write-LogMessage "> Uninstall of $FeatureName is pending restart..." -Color Red
        Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName $FeatureName
    }
    else {
        Write-LogMessage "> $FeatureName is not installed." -Color DarkGray
    }
}

function Invoke-CDTWindows {
    Write-LogMessage "[Windows]" -Color Magenta
    ## Download SysInternals
    Write-LogMessage "[Downloads]" -Color Cyan
    New-Directory "SysInternals"
    Invoke-Download "SysInternals/LogonSessions64.exe" "https://github.com/SDSU-Cyber-Defense-Team/competitions-info/raw/refs/heads/master/ccdc/sysinternals/logonsessions64.exe"

    ## SMBv1
    Write-LogMessage "[SMBv1]" -Color Cyan
    if (Get-SmbServerConfiguration | Where-Object -Property EnableSMB1Protocol -EQ $true) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
        Write-LogMessage "> Disabled SMBv1." -Color Yellow
    }
    else {
        Write-LogMessage "> SMBv1 not currently active." -Color DarkGray
    }

    ## Features
    Write-LogMessage "[Features]" -Color Cyan
    Disable-Feature SMB1Protocol
    Disable-Feature MSMQ
    Disable-Feature SimpleTCP
    Disable-Feature MicrosoftWindowsPowerShellV2
    Disable-Feature MicrosoftWindowsPowerShellV2Root
    

    ## Services
    Write-LogMessage "[Services]" -Color Cyan
    Disable-Service "Spooler"
    Disable-Service "SimpTCP"
    Disable-Service "MSMQ"
}

function Invoke-CDTWorkstation {
    Invoke-CDTWindows
}

function Invoke-CDTDomainController {
    Invoke-CDTWindows

}


Export-ModuleMember -Function Invoke-CDTWorkstation, Invoke-CDTWindows, Invoke-CDTDomainController
