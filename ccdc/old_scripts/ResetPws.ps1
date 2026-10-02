param(
    [string]$ADServer,
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential
)

function New-RandomPassword {
    $lowercase = "abcdefghijklmnopqrstuvwxyz"
    $uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $numbers = "0123456789"
    $special = "!@#$%^&*"
    
    $password = ""
    $pattern = "aa1AaaA#1#aAa"
    
    # Generate initial password based on pattern
    foreach ($char in $pattern.ToCharArray()) {
        $password += switch ($char) {
            "a" { $lowercase[(Get-Random -Maximum $lowercase.Length)] }
            "A" { $uppercase[(Get-Random -Maximum $uppercase.Length)] }
            "1" { $numbers[(Get-Random -Maximum $numbers.Length)] }
            "#" { $special[(Get-Random -Maximum $special.Length)] }
            default { $char }
        }
    }
    
    # Convert password to char array for shuffling
    $passwordArray = $password.ToCharArray()
    
    # Fisher-Yates shuffle algorithm
    $length = $passwordArray.Length
    for ($i = $length - 1; $i -gt 0; $i--) {
        $j = Get-Random -Maximum ($i + 1)
        # Swap characters
        $temp = $passwordArray[$i]
        $passwordArray[$i] = $passwordArray[$j]
        $passwordArray[$j] = $temp
    }
    
    # Convert back to string
    return -join $passwordArray
}

try {
    # WinRM connection to AD
    $session = New-PSSession -ComputerName $ADServer -Credential $Credential
    $success = $true

    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
    }

    # Get all AD users with non-empty surnames from remote session
    $gradeUsers = Invoke-Command -Session $session -ScriptBlock {
        Get-ADUser -Filter * | Where-Object -Property Surname -NE $Null
    }

    $results = @()

    foreach ($user in $gradeUsers) {
        try {
            $newPassword = New-RandomPassword

            Invoke-Command -Session $session -ScriptBlock {
                param($username, $password)
                
                $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
                Set-ADAccountPassword -Identity $username -NewPassword $securePassword -Reset
            } -ArgumentList $user.SamAccountName, $newPassword

            $results += [PSCustomObject]@{
                Username = $user.SamAccountName
                Password = $newPassword
            }
            
            Write-Host "Successfully reset password for $($user.SamAccountName)" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to reset password for $($user.SamAccountName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Host "Failed to establish remote connection: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # Clean up remote session
    if ($session) {
        Remove-PSSession $session
    }
}

if ($success -eq $true) {
    # Export results locally
    $exportPath = "password_reset_results-$(get-date -Format "HH-mm-ss").csv"
    $results | Export-Csv -Path $exportPath -NoTypeInformation -Delimiter "," -Encoding UTF8

    Write-Host "`nPassword reset complete. Results exported to $exportPath"
}