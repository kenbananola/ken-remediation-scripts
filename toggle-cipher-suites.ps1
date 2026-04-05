<#
.SYNOPSIS
    Toggle Windows Server 2025 crypto settings between secure and intentionally insecure lab modes.

.DESCRIPTION
    - Set $secureEnvironment = $true  for secure mode
    - Set $secureEnvironment = $false for intentionally insecure lab mode
    - Run in PowerShell ISE or PowerShell as Administrator
    - This script backs up current SCHANNEL and SSL policy settings
    - This script forces a reboot at the end

.NOTES
    Designed for Windows Server 2025 lab use.
    Secure mode:
      - Disables SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
      - Enables TLS 1.2 and TLS 1.3
      - Disables weak ciphers/hashes/key exchange
      - Applies a modern cipher suite order policy
    Insecure mode:
      - Re-enables older protocols for lab testing
      - Re-enables weaker ciphers/hashes/key exchange
      - Applies a broader, intentionally weaker cipher suite order policy
#>

# =========================
# CONFIGURATION
# =========================

$secureEnvironment = $true

# =========================
# PATHS
# =========================

$policyRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$localCipherOrderRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003"
$schannelRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$backupFolder = "C:\CipherHardeningBackup"

# =========================
# CIPHER SUITE LISTS
# =========================

$secureCipherSuites = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)

$insecureCipherSuites = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5"
)

# =========================
# HELPER FUNCTIONS
# =========================

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Good {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Bad {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

function Ensure-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as Administrator."
    }
}

function Ensure-RegistryKey {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Ensure-Folder {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Set-DwordValue {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )

    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Set-StringValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}

function Set-ProtocolState {
    param(
        [string]$ProtocolName,
        [bool]$Enable
    )

    $serverPath = "$schannelRoot\Protocols\$ProtocolName\Server"
    $clientPath = "$schannelRoot\Protocols\$ProtocolName\Client"

    if ($Enable) {
        Set-DwordValue -Path $serverPath -Name "Enabled" -Value 1
        Set-DwordValue -Path $serverPath -Name "DisabledByDefault" -Value 0
        Set-DwordValue -Path $clientPath -Name "Enabled" -Value 1
        Set-DwordValue -Path $clientPath -Name "DisabledByDefault" -Value 0
    }
    else {
        Set-DwordValue -Path $serverPath -Name "Enabled" -Value 0
        Set-DwordValue -Path $serverPath -Name "DisabledByDefault" -Value 1
        Set-DwordValue -Path $clientPath -Name "Enabled" -Value 0
        Set-DwordValue -Path $clientPath -Name "DisabledByDefault" -Value 1
    }
}

function Set-CipherState {
    param(
        [string]$CipherName,
        [bool]$Enable
    )

    $path = "$schannelRoot\Ciphers\$CipherName"

    if ($Enable) {
        Set-DwordValue -Path $path -Name "Enabled" -Value 0xffffffff
    }
    else {
        Set-DwordValue -Path $path -Name "Enabled" -Value 0
    }
}

function Set-HashState {
    param(
        [string]$HashName,
        [bool]$Enable
    )

    $path = "$schannelRoot\Hashes\$HashName"

    if ($Enable) {
        Set-DwordValue -Path $path -Name "Enabled" -Value 0xffffffff
    }
    else {
        Set-DwordValue -Path $path -Name "Enabled" -Value 0
    }
}

function Set-KeyExchangeState {
    param(
        [string]$AlgorithmName,
        [bool]$Enable
    )

    $path = "$schannelRoot\KeyExchangeAlgorithms\$AlgorithmName"

    if ($Enable) {
        Set-DwordValue -Path $path -Name "Enabled" -Value 0xffffffff
    }
    else {
        Set-DwordValue -Path $path -Name "Enabled" -Value 0
    }
}

function Backup-CurrentSettings {
    param([string]$FolderPath)

    Ensure-Folder -Path $FolderPath

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $schannelBackup = Join-Path $FolderPath "SCHANNEL_$timestamp.reg"
    $policyBackup   = Join-Path $FolderPath "SSLPolicy_$timestamp.reg"
    $notesBackup    = Join-Path $FolderPath "CipherOrder_$timestamp.txt"

    & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $schannelBackup /y | Out-Null
    & reg.exe export "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL" $policyBackup /y | Out-Null

    $content = @()
    $content += "Backup Time: $(Get-Date)"
    $content += ""

    try {
        $policyFunctions = (Get-ItemProperty -Path $policyRegPath -Name "Functions" -ErrorAction Stop).Functions
        $content += "[Policy Functions]"
        $content += $policyFunctions
        $content += ""
    }
    catch {
        $content += "[Policy Functions]"
        $content += "<not set>"
        $content += ""
    }

    try {
        $localFunctions = (Get-ItemProperty -Path $localCipherOrderRegPath -Name "Functions" -ErrorAction Stop).Functions
        $content += "[Local Functions]"
        $content += $localFunctions
        $content += ""
    }
    catch {
        $content += "[Local Functions]"
        $content += "<not found>"
        $content += ""
    }

    $content | Out-File -FilePath $notesBackup -Encoding utf8

    Write-Good "Backups saved to $FolderPath"
}

function Get-SupportedCipherSuiteNames {
    $names = @()

    try {
        $items = Get-TlsCipherSuite -ErrorAction Stop

        if ($items -and $items.Count -gt 0) {
            $properties = @($items[0].PSObject.Properties.Name)

            if ($properties -contains "Name") {
                $names = @($items | ForEach-Object { $_.Name } | Where-Object { $_ } | Select-Object -Unique)
            }
            elseif ($properties -contains "CipherSuite") {
                $names = @($items | ForEach-Object { $_.CipherSuite } | Where-Object { $_ -is [string] -and $_ } | Select-Object -Unique)
            }
        }
    }
    catch {
        Write-WarnMsg "Get-TlsCipherSuite failed. Falling back to local cipher order registry."
    }

    if (-not $names -or $names.Count -eq 0) {
        $raw = (Get-ItemProperty -Path $localCipherOrderRegPath -Name "Functions" -ErrorAction Stop).Functions
        $names = @(($raw -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    }

    if (-not $names -or $names.Count -eq 0) {
        throw "Unable to determine supported cipher suites."
    }

    return $names
}

function Apply-CipherSuitePolicy {
    param(
        [string[]]$RequestedSuites
    )

    $supported = @(Get-SupportedCipherSuiteNames)
    $selected = @($RequestedSuites | Where-Object { $_ -in $supported } | Select-Object -Unique)
    $unsupported = @($RequestedSuites | Where-Object { $_ -notin $supported } | Select-Object -Unique)

    if (-not $selected -or $selected.Count -eq 0) {
        throw "None of the requested cipher suites are supported on this server."
    }

    if ($unsupported.Count -gt 0) {
        Write-WarnMsg "Unsupported cipher suites skipped:"
        $unsupported | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    }

    Set-StringValue -Path $policyRegPath -Name "Functions" -Value ($selected -join ",")
    Set-DwordValue  -Path $policyRegPath -Name "Enabled"   -Value 1

    Write-Good "Cipher suite policy applied."
    Write-Host ""
    Write-Host "Applied cipher suites:" -ForegroundColor Green
    $selected | ForEach-Object { Write-Host "    $_" }
}

function Set-SecureMode {
    Write-Status "Applying SECURE mode..."

    Set-ProtocolState -ProtocolName "Multi-Protocol Unified Hello" -Enable $false
    Set-ProtocolState -ProtocolName "PCT 1.0"                      -Enable $false
    Set-ProtocolState -ProtocolName "SSL 2.0"                      -Enable $false
    Set-ProtocolState -ProtocolName "SSL 3.0"                      -Enable $false
    Set-ProtocolState -ProtocolName "TLS 1.0"                      -Enable $false
    Set-ProtocolState -ProtocolName "TLS 1.1"                      -Enable $false
    Set-ProtocolState -ProtocolName "TLS 1.2"                      -Enable $true
    Set-ProtocolState -ProtocolName "TLS 1.3"                      -Enable $true

    Set-CipherState -CipherName "DES 56/56"       -Enable $false
    Set-CipherState -CipherName "NULL"            -Enable $false
    Set-CipherState -CipherName "RC2 40/128"      -Enable $false
    Set-CipherState -CipherName "RC2 56/128"      -Enable $false
    Set-CipherState -CipherName "RC2 128/128"     -Enable $false
    Set-CipherState -CipherName "RC4 40/128"      -Enable $false
    Set-CipherState -CipherName "RC4 56/128"      -Enable $false
    Set-CipherState -CipherName "RC4 64/128"      -Enable $false
    Set-CipherState -CipherName "RC4 128/128"     -Enable $false
    Set-CipherState -CipherName "Triple DES 168"  -Enable $false
    Set-CipherState -CipherName "AES 128/128"     -Enable $true
    Set-CipherState -CipherName "AES 256/256"     -Enable $true

    Set-HashState -HashName "MD5"    -Enable $false
    Set-HashState -HashName "SHA"    -Enable $true
    Set-HashState -HashName "SHA256" -Enable $true
    Set-HashState -HashName "SHA384" -Enable $true
    Set-HashState -HashName "SHA512" -Enable $true

    Set-KeyExchangeState -AlgorithmName "PKCS"           -Enable $false
    Set-KeyExchangeState -AlgorithmName "Diffie-Hellman" -Enable $true
    Set-KeyExchangeState -AlgorithmName "ECDH"           -Enable $true

    Apply-CipherSuitePolicy -RequestedSuites $secureCipherSuites
    Write-Good "Secure mode applied."
}

function Set-InsecureMode {
    Write-Status "Applying INSECURE LAB mode..."

    Set-ProtocolState -ProtocolName "Multi-Protocol Unified Hello" -Enable $true
    Set-ProtocolState -ProtocolName "PCT 1.0"                      -Enable $true
    Set-ProtocolState -ProtocolName "SSL 2.0"                      -Enable $true
    Set-ProtocolState -ProtocolName "SSL 3.0"                      -Enable $true
    Set-ProtocolState -ProtocolName "TLS 1.0"                      -Enable $true
    Set-ProtocolState -ProtocolName "TLS 1.1"                      -Enable $true
    Set-ProtocolState -ProtocolName "TLS 1.2"                      -Enable $true
    Set-ProtocolState -ProtocolName "TLS 1.3"                      -Enable $true

    Set-CipherState -CipherName "DES 56/56"       -Enable $true
    Set-CipherState -CipherName "NULL"            -Enable $true
    Set-CipherState -CipherName "RC2 40/128"      -Enable $true
    Set-CipherState -CipherName "RC2 56/128"      -Enable $true
    Set-CipherState -CipherName "RC2 128/128"     -Enable $true
    Set-CipherState -CipherName "RC4 40/128"      -Enable $true
    Set-CipherState -CipherName "RC4 56/128"      -Enable $true
    Set-CipherState -CipherName "RC4 64/128"      -Enable $true
    Set-CipherState -CipherName "RC4 128/128"     -Enable $true
    Set-CipherState -CipherName "Triple DES 168"  -Enable $true
    Set-CipherState -CipherName "AES 128/128"     -Enable $true
    Set-CipherState -CipherName "AES 256/256"     -Enable $true

    Set-HashState -HashName "MD5"    -Enable $true
    Set-HashState -HashName "SHA"    -Enable $true
    Set-HashState -HashName "SHA256" -Enable $true
    Set-HashState -HashName "SHA384" -Enable $true
    Set-HashState -HashName "SHA512" -Enable $true

    Set-KeyExchangeState -AlgorithmName "PKCS"           -Enable $true
    Set-KeyExchangeState -AlgorithmName "Diffie-Hellman" -Enable $true
    Set-KeyExchangeState -AlgorithmName "ECDH"           -Enable $true

    Apply-CipherSuitePolicy -RequestedSuites $insecureCipherSuites
    Write-Good "Insecure lab mode applied."
}

# =========================
# MAIN
# =========================

try {
    Write-Status "Checking administrative privileges..."
    Ensure-Admin
    Write-Good "Running as Administrator."

    Write-Status "Creating backup..."
    Backup-CurrentSettings -FolderPath $backupFolder

    if ($secureEnvironment) {
        Set-SecureMode
    }
    else {
        Set-InsecureMode
    }

    Write-Status "Refreshing Group Policy..."
    & gpupdate.exe /force | Out-Null

    Write-WarnMsg "System will reboot in 10 seconds to apply all crypto changes..."
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
catch {
    Write-Bad "Script failed: $($_.Exception.Message)"
}

