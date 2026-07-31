#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Аудит безопасности Windows: пароли, учётные записи, firewall, службы, сетевые протоколы,
    обновления, защита и аудит/логирование. Формирует HTML-отчёт с конкретными шагами устранения.
.DESCRIPTION
    Для каждой проблемной проверки (Warning/Fail) отчёт содержит:
      - в чём риск
      - конкретные команды / шаги для устранения
.NOTES
    Запускать от имени администратора.
    Использование:  .\Windows-Security-Audit.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = $(Join-Path $PSScriptRoot "SecurityAudit_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html")
)

$ErrorActionPreference = 'SilentlyContinue'
$results = New-Object System.Collections.Generic.List[Object]

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('Pass','Warning','Fail','Info')][string]$Status,
        [string]$Details,
        [string]$Risk = '',
        [string]$Remediation = ''
    )
    $results.Add([PSCustomObject]@{
        Category    = $Category
        Check       = $Check
        Status      = $Status
        Details     = $Details
        Risk        = $Risk
        Remediation = $Remediation
    })
}

Write-Host "Запуск аудита безопасности Windows..." -ForegroundColor Cyan

# ============================================================
# 1. СИСТЕМА
# ============================================================
Write-Host " [1/9] Информация о системе..." -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem

Add-Result -Category "Система" -Check "ОС" -Status "Info" -Details "$($os.Caption) build $($os.BuildNumber), домен/группа: $($cs.Domain)"
Add-Result -Category "Система" -Check "Последняя загрузка" -Status "Info" -Details "$($os.LastBootUpTime)"

$secureBoot = Confirm-SecureBootUEFI 2>$null
if ($null -ne $secureBoot) {
    $status = if ($secureBoot) { "Pass" } else { "Fail" }
    Add-Result -Category "Система" -Check "Secure Boot" -Status $status `
        -Details $(if ($secureBoot) {"Включён"} else {"Отключён"}) `
        -Risk "Без Secure Boot загрузчик и ядро ОС не защищены от подмены вредоносным ПО уровня буткита." `
        -Remediation "Перезагрузите ПК -> войдите в UEFI/BIOS (обычно Del/F2/F10 при загрузке) -> раздел Boot/Security -> включите Secure Boot. Требуется режим загрузки UEFI (не Legacy/CSM)."
} else {
    Add-Result -Category "Система" -Check "Secure Boot" -Status "Info" -Details "Недоступно (Legacy BIOS или виртуальная машина без поддержки)"
}

try {
    $tpm = Get-Tpm -ErrorAction Stop
    $status = if ($tpm.TpmPresent -and $tpm.TpmReady) { "Pass" } else { "Warning" }
    Add-Result -Category "Система" -Check "TPM (доверенный платформенный модуль)" -Status $status `
        -Details "Присутствует: $($tpm.TpmPresent), Готов: $($tpm.TpmReady)" `
        -Risk "Без готового TPM недоступны BitLocker с аппаратной защитой ключей и Windows Hello for Business." `
        -Remediation "Включите TPM в UEFI/BIOS (fTPM для AMD / PTT для Intel). Затем: Get-Tpm для проверки, при необходимости Initialize-Tpm."
} catch {}

# ============================================================
# 2. ПАРОЛЬНАЯ ПОЛИТИКА
# ============================================================
Write-Host " [2/9] Парольная политика..." -ForegroundColor Yellow

$secCfgPath = Join-Path $env:TEMP "secpol_audit.cfg"
secedit /export /cfg $secCfgPath /quiet | Out-Null

function Get-SecPolValue {
    param([string]$Key)
    if (Test-Path $secCfgPath) {
        $line = Select-String -Path $secCfgPath -Pattern "^$Key\s*="
        if ($line) { return ($line.Line -split '=')[1].Trim() }
    }
    return $null
}

$minLen     = Get-SecPolValue "MinimumPasswordLength"
$complexity = Get-SecPolValue "PasswordComplexity"
$maxAge     = Get-SecPolValue "MaximumPasswordAge"
$lockoutBad = Get-SecPolValue "LockoutBadCount"
$lockoutDur = Get-SecPolValue "LockoutDuration"
$histSize   = Get-SecPolValue "PasswordHistorySize"

if ($minLen) {
    $status = if ([int]$minLen -ge 12) { "Pass" } elseif ([int]$minLen -ge 8) { "Warning" } else { "Fail" }
    Add-Result -Category "Пароли" -Check "Минимальная длина пароля" -Status $status -Details "$minLen символов" `
        -Risk "Короткие пароли взламываются перебором/подбором за минуты-часы на современном оборудовании." `
        -Remediation "secedit /export /cfg C:\pol.cfg -> отредактировать MinimumPasswordLength = 12 -> secedit /configure /db secedit.sdb /cfg C:\pol.cfg /areas SECURITYPOLICY`nЛибо через GPO: Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> Minimum password length = 12"
}
if ($complexity) {
    $status = if ($complexity -eq '1') { "Pass" } else { "Fail" }
    Add-Result -Category "Пароли" -Check "Требование сложности пароля" -Status $status `
        -Details $(if ($complexity -eq '1') {"Включено"} else {"Отключено"}) `
        -Risk "Без требований сложности пользователи используют слабые пароли (123456, qwerty и т.п.)." `
        -Remediation "GPO/локальная политика: Account Policies -> Password Policy -> 'Password must meet complexity requirements' = Enabled.`nБыстро: secedit /export /cfg C:\pol.cfg, изменить PasswordComplexity = 1, secedit /configure /db secedit.sdb /cfg C:\pol.cfg /areas SECURITYPOLICY"
}
if ($maxAge) {
    $status = if ([int]$maxAge -eq 0) { "Warning" } elseif ([int]$maxAge -le 90) { "Pass" } else { "Warning" }
    Add-Result -Category "Пароли" -Check "Максимальный срок действия пароля" -Status $status `
        -Details "$maxAge дней (0 = бессрочно)" `
        -Risk "Бессрочные или очень долгоживущие пароли увеличивают окно использования скомпрометированных учётных данных." `
        -Remediation "net accounts /maxpwage:90  (либо GPO Password Policy -> Maximum password age = 90). Современная альтернатива NIST: не менять пароль по таймеру, а использовать MFA + мониторинг компрометации через Have I Been Pwned/Azure AD Password Protection."
}
if ($lockoutBad) {
    $status = if ([int]$lockoutBad -gt 0 -and [int]$lockoutBad -le 10) { "Pass" } else { "Fail" }
    Add-Result -Category "Пароли" -Check "Порог блокировки учётной записи" -Status $status -Details "$lockoutBad неверных попыток" `
        -Risk "0 (отключено) означает отсутствие защиты от подбора пароля (brute-force/password spraying)." `
        -Remediation "net accounts /lockoutthreshold:5  (GPO: Account Policies -> Account Lockout Policy -> Account lockout threshold = 5)"
}
if ($lockoutDur) {
    $status = if ([int]$lockoutDur -ge 15 -or [int]$lockoutDur -eq -1) { "Pass" } else { "Warning" }
    Add-Result -Category "Пароли" -Check "Длительность блокировки" -Status $status -Details "$lockoutDur мин." `
        -Remediation "net accounts /lockoutduration:15 (минуты)"
}
if ($histSize) {
    $status = if ([int]$histSize -ge 5) { "Pass" } else { "Warning" }
    Add-Result -Category "Пароли" -Check "Хранимая история паролей" -Status $status -Details "$histSize последних паролей" `
        -Risk "Малая история позволяет быстро возвращаться к старому (возможно скомпрометированному) паролю." `
        -Remediation "net accounts /uniquepw:24 (GPO: Password Policy -> Enforce password history = 24)"
}
Remove-Item $secCfgPath -ErrorAction SilentlyContinue

# ============================================================
# 3. УЧЁТНЫЕ ЗАПИСИ
# ============================================================
Write-Host " [3/9] Учётные записи..." -ForegroundColor Yellow

$guest = Get-LocalUser -Name "Гость" -ErrorAction SilentlyContinue
if (-not $guest) { $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue }
if ($guest) {
    $status = if ($guest.Enabled) { "Fail" } else { "Pass" }
    Add-Result -Category "Учётные записи" -Check "Гостевая учётная запись" -Status $status `
        -Details $(if ($guest.Enabled) {"Включена"} else {"Отключена"}) `
        -Risk "Активная гостевая учётка даёт анонимный доступ к системе без пароля." `
        -Remediation "Disable-LocalUser -Name '$($guest.Name)'"
}

$neverExpire = Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null }
if ($neverExpire) {
    Add-Result -Category "Учётные записи" -Check "Пароли без срока действия" -Status "Warning" `
        -Details "Учётки: $($neverExpire.Name -join ', ')" `
        -Risk "Бессрочные пароли у активных учёток повышают риск долгосрочного использования скомпрометированных данных." `
        -Remediation "Для каждой сервисной учётки проверьте необходимость: Set-LocalUser -Name '<имя>' -PasswordNeverExpires `$false. Для сервисных/системных учёток лучше использовать managed service accounts (gMSA) вместо обычных паролей."
}

try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $status = if ($admins.Count -gt 3) { "Warning" } else { "Info" }
    Add-Result -Category "Учётные записи" -Check "Локальная группа Administrators" -Status $status `
        -Details "$($admins.Count) участник(ов): $($admins.Name -join ', ')" `
        -Risk "Избыточное число администраторов расширяет поверхность атаки — компрометация любой из этих учёток даёт полный контроль." `
        -Remediation "Аудит участников: Get-LocalGroupMember Administrators. Удалить лишних: Remove-LocalGroupMember -Group Administrators -Member '<имя>'. Использовать именные учётки вместо общих, применять принцип наименьших привилегий."
} catch {}

$restrictAnon = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue).RestrictAnonymousSAM
$status = if ($restrictAnon -eq 1) { "Pass" } else { "Warning" }
Add-Result -Category "Учётные записи" -Check "Анонимное перечисление учётных записей SAM" -Status $status `
    -Details $(if ($restrictAnon -eq 1) {"Запрещено"} else {"Разрешено (значение по умолчанию/не задано)"}) `
    -Risk "Анонимные пользователи могут перечислить локальные учётные записи и группы — полезно атакующему для разведки." `
    -Remediation "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1 -PropertyType DWORD -Force`nЛибо GPO: Local Policies -> Security Options -> 'Network access: Do not allow anonymous enumeration of SAM accounts' = Enabled"

$limitBlank = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue).LimitBlankPasswordUse
$status = if ($limitBlank -eq 1 -or $null -eq $limitBlank) { "Pass" } else { "Fail" }
Add-Result -Category "Учётные записи" -Check "Ограничение входа с пустым паролем по сети" -Status $status `
    -Details $(if ($limitBlank -eq 0) {"Отключено — учётки с пустым паролем доступны по сети!"} else {"Включено"}) `
    -Risk "Учётные записи с пустым паролем могут быть использованы для удалённого входа." `
    -Remediation "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -Value 1 -PropertyType DWORD -Force"

# ============================================================
# 4. FIREWALL
# ============================================================
Write-Host " [4/9] Брандмауэр Windows..." -ForegroundColor Yellow

foreach ($fwProfile in Get-NetFirewallProfile) {
    $status = if ($fwProfile.Enabled) { "Pass" } else { "Fail" }
    Add-Result -Category "Firewall" -Check "Профиль: $($fwProfile.Name)" -Status $status `
        -Details $(if ($fwProfile.Enabled) {"Включён"} else {"Отключён"}) `
        -Risk "Отключённый профиль брандмауэра оставляет систему без базовой сетевой фильтрации трафика." `
        -Remediation "Set-NetFirewallProfile -Profile $($fwProfile.Name) -Enabled True"

    if ($fwProfile.LogAllowed -eq 'False' -and $fwProfile.LogBlocked -eq 'False') {
        Add-Result -Category "Firewall" -Check "Логирование брандмауэра ($($fwProfile.Name))" -Status "Warning" `
            -Details "Логирование отключено" `
            -Risk "Без логов брандмауэра сложно расследовать сетевые инциденты постфактум." `
            -Remediation "Set-NetFirewallProfile -Profile $($fwProfile.Name) -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 16384"
    }
}

$openInbound = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { $_.Profile -match 'Public|Any' }
$status = if ($openInbound.Count -gt 15) { "Warning" } else { "Info" }
Add-Result -Category "Firewall" -Check "Открытые входящие правила (Public/Any)" -Status $status `
    -Details "$($openInbound.Count) активных правил разрешения" `
    -Risk "Каждое открытое входящее правило на публичном профиле — потенциальный вектор атаки из недоверенной сети." `
    -Remediation "Просмотреть правила: Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object {`$_.Profile -match 'Public'} | Format-Table DisplayName,Profile. Отключить ненужные: Disable-NetFirewallRule -DisplayName '<имя правила>'"

$rdpDeny = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
if ($null -ne $rdpDeny) {
    $rdpEnabled = ($rdpDeny -eq 0)
    $status = if ($rdpEnabled) { "Warning" } else { "Pass" }
    Add-Result -Category "Firewall" -Check "Удалённый рабочий стол (RDP)" -Status $status `
        -Details $(if ($rdpEnabled) {"Включён"} else {"Отключён"}) `
        -Risk "Открытый RDP — один из самых частых векторов первичного доступа при атаках шифровальщиков." `
        -Remediation "Если не нужен: Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1. Если нужен: ограничьте доступ через VPN/бастион, разрешите только доверенные IP в firewall, включите NLA и MFA."
    if ($rdpEnabled) {
        $nla = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        $status = if ($nla -eq 1) { "Pass" } else { "Fail" }
        Add-Result -Category "Firewall" -Check "Network Level Authentication (NLA) для RDP" -Status $status `
            -Details $(if ($nla -eq 1) {"Включена"} else {"Отключена"}) `
            -Risk "Без NLA аутентификация происходит после установки полной RDP-сессии — увеличивает поверхность атаки на уязвимости протокола (например, BlueKeep)." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
    }
}

# ============================================================
# 5. СЕТЕВЫЕ ПРОТОКОЛЫ
# ============================================================
Write-Host " [5/9] Сетевые протоколы (SMB/NTLM/LLMNR)..." -ForegroundColor Yellow

try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    $status = if ($smb1.State -eq 'Enabled') { "Fail" } else { "Pass" }
    Add-Result -Category "Сеть" -Check "Протокол SMBv1" -Status $status -Details "$($smb1.State)" `
        -Risk "SMBv1 — устаревший и небезопасный протокол, используемый в атаках WannaCry/NotPetya (эксплойт EternalBlue)." `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart  (после — перезагрузка)"
} catch {}

$smbSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
$status = if ($smbSigning -eq 1) { "Pass" } else { "Warning" }
Add-Result -Category "Сеть" -Check "Обязательная подпись SMB (сервер)" -Status $status `
    -Details $(if ($smbSigning -eq 1) {"Требуется"} else {"Не требуется"}) `
    -Risk "Без обязательной подписи SMB возможны атаки relay/man-in-the-middle (например, NTLM relay через SMB)." `
    -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force`nGPO: 'Microsoft network server: Digitally sign communications (always)' = Enabled"

$lmCompat = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
$status = if ($lmCompat -ge 5) { "Pass" } elseif ($lmCompat -ge 3) { "Warning" } else { "Fail" }
Add-Result -Category "Сеть" -Check "Уровень совместимости NTLM (LM Compatibility Level)" -Status $status `
    -Details "Текущий уровень: $lmCompat (0-5, рекомендуется 5 — только NTLMv2, отказ от LM и NTLM)" `
    -Risk "Низкий уровень допускает использование устаревших и легко взламываемых протоколов LM/NTLMv1." `
    -Remediation "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -PropertyType DWORD -Force`nGPO: 'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM'"

$llmnr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
$status = if ($llmnr -eq 0) { "Pass" } else { "Warning" }
Add-Result -Category "Сеть" -Check "LLMNR (Link-Local Multicast Name Resolution)" -Status $status `
    -Details $(if ($llmnr -eq 0) {"Отключён"} else {"Включён (значение по умолчанию)"}) `
    -Risk "LLMNR/NBT-NS подвержены атакам спуфинга и перехвата хешей (например, инструмент Responder), что позволяет получить учётные данные из локальной сети." `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -PropertyType DWORD -Force`nGPO: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> 'Turn off multicast name resolution' = Enabled"

$winrmSvc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
    $allowUnencrypted = (Get-Item -Path WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value
    $status = if ($allowUnencrypted -eq 'false') { "Pass" } else { "Warning" }
    Add-Result -Category "Сеть" -Check "WinRM — незашифрованный трафик" -Status $status `
        -Details $(if ($allowUnencrypted -eq 'true') {"Разрешён небезопасный (незашифрованный) трафик"} else {"Только зашифрованный"}) `
        -Risk "Незашифрованный WinRM-трафик может быть перехвачен в локальной сети (учётные данные, команды)." `
        -Remediation "Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value `$false"
}

# ============================================================
# 6. СЛУЖБЫ
# ============================================================
Write-Host " [6/9] Службы..." -ForegroundColor Yellow

$riskyServices = @(
    @{ Name = "RemoteRegistry"; Display = "Удалённый реестр" }
    @{ Name = "TlntSvr";        Display = "Telnet Server" }
    @{ Name = "SNMP";           Display = "SNMP Service" }
    @{ Name = "SSDPSRV";        Display = "SSDP Discovery" }
    @{ Name = "simptcp";        Display = "Simple TCP/IP Services" }
    @{ Name = "FTPSVC";         Display = "FTP Server (IIS)" }
)
foreach ($svc in $riskyServices) {
    $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($s) {
        $running = $s.Status -eq 'Running'
        $status = if ($running) { "Warning" } else { "Pass" }
        Add-Result -Category "Службы" -Check $svc.Display -Status $status `
            -Details $(if ($running) {"Запущена"} else {"Остановлена"}) `
            -Risk "Служба $($svc.Display) редко нужна на рядовой рабочей станции/сервере и увеличивает поверхность атаки, если не используется целенаправленно." `
            -Remediation "Если не требуется: Stop-Service -Name '$($svc.Name)' -Force; Set-Service -Name '$($svc.Name)' -StartupType Disabled"
    }
}

$winrmSvc2 = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrmSvc2) {
    Add-Result -Category "Службы" -Check "WinRM (удалённое управление PowerShell)" -Status "Info" `
        -Details $(if ($winrmSvc2.Status -eq 'Running') {"Запущена"} else {"Остановлена"}) `
        -Risk "Если WinRM не используется целенаправленно для удалённого администрирования — лишний открытый вектор." `
        -Remediation "Если не используется: Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"
}

# ============================================================
# 7. ОБНОВЛЕНИЯ
# ============================================================
Write-Host " [7/9] Обновления Windows..." -ForegroundColor Yellow

$wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($wuService) {
    $status = if ($wuService.Status -eq 'Running' -or $wuService.StartType -eq 'Manual') { "Pass" } else { "Warning" }
    Add-Result -Category "Обновления" -Check "Служба Windows Update" -Status $status `
        -Details "Статус: $($wuService.Status), тип запуска: $($wuService.StartType)" `
        -Risk "Отключённая служба Windows Update не позволяет системе получать патчи безопасности." `
        -Remediation "Set-Service -Name wuauserv -StartupType Manual; Start-Service wuauserv"
}

$lastHotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($lastHotfix -and $lastHotfix.InstalledOn) {
    $daysSince = (New-TimeSpan -Start $lastHotfix.InstalledOn -End (Get-Date)).Days
    $status = if ($daysSince -le 45) { "Pass" } elseif ($daysSince -le 90) { "Warning" } else { "Fail" }
    Add-Result -Category "Обновления" -Check "Последнее установленное обновление" -Status $status `
        -Details "$($lastHotfix.HotFixID) от $($lastHotfix.InstalledOn.ToShortDateString()) ($daysSince дн. назад)" `
        -Risk "Система без свежих патчей уязвима к публично известным (N-day) эксплойтам." `
        -Remediation "Проверить и установить обновления: Get-WindowsUpdate (модуль PSWindowsUpdate) либо через Параметры -> Обновление и безопасность -> Проверить наличие обновлений. Настроить автоматическую установку через WSUS/Intune для парка машин."
}

$pendingReboot = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $pendingReboot = $true }
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\WindowsUpdate\Auto Update\RebootRequired") { $pendingReboot = $true }
Add-Result -Category "Обновления" -Check "Ожидает перезагрузки после обновлений" -Status $(if ($pendingReboot) {"Warning"} else {"Pass"}) `
    -Details $(if ($pendingReboot) {"Да — обновления не применены полностью"} else {"Нет"}) `
    -Risk "Пока не выполнена перезагрузка, часть исправлений безопасности фактически не активна." `
    -Remediation "Запланируйте и выполните перезагрузку: Restart-Computer -Force (в удобное окно обслуживания)"

# ============================================================
# 8. ЗАЩИТА (Defender, UAC, автовход, BitLocker)
# ============================================================
Write-Host " [8/9] Defender, UAC, BitLocker..." -ForegroundColor Yellow

$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) {
    $status = if ($mp.RealTimeProtectionEnabled) { "Pass" } else { "Fail" }
    Add-Result -Category "Защита" -Check "Защита в реальном времени (Defender)" -Status $status `
        -Details $(if ($mp.RealTimeProtectionEnabled) {"Включена"} else {"Отключена"}) `
        -Risk "Без активной защиты в реальном времени вредоносное ПО может выполниться беспрепятственно." `
        -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false. Если используется сторонний антивирус — убедитесь, что он активен и обновлён, отключение Defender в этом случае ожидаемо."

    $sigAge = $mp.AntivirusSignatureAge
    $status = if ($sigAge -le 3) { "Pass" } elseif ($sigAge -le 7) { "Warning" } else { "Fail" }
    Add-Result -Category "Защита" -Check "Возраст сигнатур антивируса" -Status $status -Details "$sigAge дн." `
        -Risk "Устаревшие сигнатуры не распознают свежие угрозы и варианты вредоносного ПО." `
        -Remediation "Update-MpSignature. Проверьте доступ к интернету/WSUS для автоматических обновлений сигнатур."
}

$uac = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
if ($null -ne $uac) {
    $status = if ($uac -eq 1) { "Pass" } else { "Fail" }
    Add-Result -Category "Защита" -Check "Контроль учётных записей (UAC)" -Status $status `
        -Details $(if ($uac -eq 1) {"Включён"} else {"Отключён"}) `
        -Risk "Без UAC любой процесс (в т.ч. вредоносный) может тихо получить права администратора." `
        -Remediation "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -PropertyType DWORD -Force  (требуется перезагрузка)"
}

$autoLogon = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue).AutoAdminLogon
if ($autoLogon -eq "1") {
    Add-Result -Category "Защита" -Check "Автоматический вход в систему" -Status "Fail" `
        -Details "Включён (пароль хранится в реестре в открытом виде)" `
        -Risk "Любой, кто получит доступ к реестру или физически к диску, может извлечь пароль учётной записи в открытом виде." `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0`nRemove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue"
}

try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $status = if ($bl.ProtectionStatus -eq 'On') { "Pass" } else { "Warning" }
    Add-Result -Category "Защита" -Check "Шифрование диска BitLocker ($env:SystemDrive)" -Status $status `
        -Details "Статус защиты: $($bl.ProtectionStatus)" `
        -Risk "Без шифрования диска данные доступны при физическом доступе к устройству (кража/утеря ноутбука)." `
        -Remediation "Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector. Обязательно сохраните ключ восстановления (AD, Azure AD или распечатка)."
} catch {
    Add-Result -Category "Защита" -Check "Шифрование диска BitLocker" -Status "Info" -Details "Недоступно на этой редакции/конфигурации Windows"
}

# ============================================================
# 9. АУДИТ И ЛОГИРОВАНИЕ
# ============================================================
Write-Host " [9/9] Аудит и логирование..." -ForegroundColor Yellow

$auditLogon = auditpol /get /subcategory:"Logon" 2>$null | Select-String "Success and Failure|Success|Failure|No Auditing"
if ($auditLogon) {
    $line = $auditLogon.Line
    $status = if ($line -match "No Auditing") { "Fail" } elseif ($line -match "Success and Failure") { "Pass" } else { "Warning" }
    Add-Result -Category "Аудит и логирование" -Check "Аудит событий входа в систему (Logon)" -Status $status `
        -Details ($line.Trim() -replace '\s{2,}', ' ') `
        -Risk "Без аудита входов невозможно расследовать попытки несанкционированного доступа постфактум." `
        -Remediation "auditpol /set /subcategory:`"Logon`" /success:enable /failure:enable`nGPO: Advanced Audit Policy Configuration -> Logon/Logoff -> Audit Logon = Success and Failure"
}

$psLogging = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$status = if ($psLogging -eq 1) { "Pass" } else { "Warning" }
Add-Result -Category "Аудит и логирование" -Check "PowerShell Script Block Logging" -Status $status `
    -Details $(if ($psLogging -eq 1) {"Включено"} else {"Отключено"}) `
    -Risk "Без логирования блоков скриптов сложно обнаружить вредоносные PowerShell-скрипты (частый инструмент атакующих после получения доступа)." `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -PropertyType DWORD -Force`nGPO: Administrative Templates -> Windows Components -> Windows PowerShell -> 'Turn on PowerShell Script Block Logging' = Enabled"

$secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
if ($secLog) {
    $sizeMB = [math]::Round($secLog.MaximumSizeInBytes / 1MB)
    $status = if ($sizeMB -ge 196) { "Pass" } else { "Warning" }
    Add-Result -Category "Аудит и логирование" -Check "Максимальный размер журнала безопасности" -Status $status `
        -Details "$sizeMB МБ" `
        -Risk "Маленький журнал перезаписывается быстро — при активной атаке важные события могут быть потеряны до расследования." `
        -Remediation "Limit-EventLog -LogName Security -MaximumSize 512MB (рекомендуется 512МБ-1ГБ и выше в зависимости от активности системы, либо централизованный сбор логов через SIEM/Windows Event Forwarding)"
}

# ============================================================
# HTML ОТЧЁТ
# ============================================================
Write-Host "Формирование отчёта..." -ForegroundColor Yellow

$statusColors = @{ Pass = "#2e7d32"; Warning = "#f9a825"; Fail = "#c62828"; Info = "#546e7a" }
$statusBg     = @{ Pass = "#e8f5e9"; Warning = "#fff8e1"; Fail = "#ffebee"; Info = "#eceff1" }

$passCount = ($results | Where-Object Status -eq 'Pass').Count
$warnCount = ($results | Where-Object Status -eq 'Warning').Count
$failCount = ($results | Where-Object Status -eq 'Fail').Count
$infoCount = ($results | Where-Object Status -eq 'Info').Count
$total = $results.Count
$score = if ($total -gt 0) { [math]::Round((($passCount + $infoCount) / $total) * 100) } else { 0 }
$scoreColor = if ($score -ge 85) { "#2e7d32" } elseif ($score -ge 60) { "#f9a825" } else { "#c62828" }

function Format-Remediation {
    param([string]$Text)
    if (-not $Text) { return "" }
    $escaped = $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
    $escaped = $escaped -replace "`n", "<br>"
    return $escaped
}

# Блок критичных проблем (executive summary)
$critical = $results | Where-Object { $_.Status -eq 'Fail' }
$criticalHtml = ""
if ($critical) {
    $items = ""
    foreach ($c in $critical) {
        $items += "<li><b>[$($c.Category)] $($c.Check)</b> — $($c.Details)</li>"
    }
    $criticalHtml = @"
    <div class="critical-box">
        <h2>🚨 Критичные проблемы, требующие немедленного устранения ($($critical.Count))</h2>
        <ul>$items</ul>
    </div>
"@
}

$categoriesHtml = ""
foreach ($cat in ($results | Select-Object -ExpandProperty Category -Unique)) {
    $rows = ""
    foreach ($r in ($results | Where-Object Category -eq $cat)) {
        $color = $statusColors[$r.Status]
        $bg = $statusBg[$r.Status]
        $riskBlock = if ($r.Risk) { "<div class='risk'><b>Риск:</b> $($r.Risk)</div>" } else { "" }
        $remBlock = if ($r.Remediation) { "<div class='rem'><b>✅ Как устранить:</b><div class='rem-code'>$(Format-Remediation $r.Remediation)</div></div>" } else { "" }
        $rows += @"
        <tr>
            <td class="check-name">$($r.Check)</td>
            <td><span class="badge" style="background:$bg;color:$color;">$($r.Status)</span></td>
            <td class="details">
                <div>$($r.Details)</div>
                $riskBlock
                $remBlock
            </td>
        </tr>
"@
    }
    $categoriesHtml += @"
    <div class="category">
        <h2>$cat</h2>
        <table>
            <thead><tr><th style="width:24%">Проверка</th><th style="width:10%">Статус</th><th>Детали / Риск / Устранение</th></tr></thead>
            <tbody>$rows</tbody>
        </table>
    </div>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Аудит безопасности Windows - $env:COMPUTERNAME</title>
<style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background:#f4f6f8; margin:0; padding:0; color:#2c3e50; }
    header { background:linear-gradient(135deg,#1a237e,#283593); color:white; padding:30px 40px; }
    header h1 { margin:0; font-size:24px; }
    header p { margin:5px 0 0; opacity:0.85; font-size:14px; }
    .container { max-width:1050px; margin:-20px auto 40px; padding:0 20px; }
    .summary { background:white; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.08); padding:25px 30px; display:flex; align-items:center; gap:30px; margin-bottom:25px; flex-wrap:wrap; }
    .score-circle { width:90px; height:90px; border-radius:50%; border:8px solid $scoreColor; display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:bold; color:$scoreColor; flex-shrink:0; }
    .summary-stats { display:flex; gap:25px; flex-wrap:wrap; }
    .stat { text-align:center; }
    .stat .num { font-size:22px; font-weight:bold; }
    .stat .lbl { font-size:12px; color:#78909c; text-transform:uppercase; }
    .critical-box { background:#fff3f3; border:1px solid #ffcdd2; border-left:5px solid #c62828; border-radius:8px; padding:18px 22px; margin-bottom:25px; }
    .critical-box h2 { margin:0 0 10px; font-size:16px; color:#c62828; }
    .critical-box ul { margin:0; padding-left:20px; font-size:13.5px; line-height:1.7; }
    .category { background:white; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.06); margin-bottom:20px; overflow:hidden; }
    .category h2 { margin:0; padding:15px 20px; background:#eceff1; font-size:16px; border-bottom:1px solid #e0e0e0; }
    table { width:100%; border-collapse:collapse; }
    th { text-align:left; padding:10px 20px; font-size:12px; color:#78909c; text-transform:uppercase; border-bottom:1px solid #eee; }
    td { padding:12px 20px; border-bottom:1px solid #f0f0f0; vertical-align:top; font-size:13.5px; }
    .check-name { font-weight:600; }
    .badge { padding:4px 10px; border-radius:12px; font-size:12px; font-weight:600; white-space:nowrap; }
    .risk { margin-top:8px; font-size:12.5px; color:#8d6e00; background:#fffde7; padding:8px 10px; border-radius:6px; border-left:3px solid #f9a825; }
    .rem { margin-top:8px; font-size:12.5px; }
    .rem-code { margin-top:5px; background:#1e272e; color:#d7f5dd; font-family:Consolas,'Courier New',monospace; padding:10px 12px; border-radius:6px; line-height:1.6; white-space:pre-wrap; word-break:break-word; }
    footer { text-align:center; color:#90a4ae; font-size:12px; padding:20px; }
</style>
</head>
<body>
<header>
    <h1>🛡️ Аудит безопасности Windows</h1>
    <p>Хост: $env:COMPUTERNAME &nbsp;|&nbsp; Дата: $(Get-Date -Format 'dd.MM.yyyy HH:mm') &nbsp;|&nbsp; Пользователь: $env:USERNAME</p>
</header>
<div class="container">
    <div class="summary">
        <div class="score-circle">$score%</div>
        <div class="summary-stats">
            <div class="stat"><div class="num" style="color:#2e7d32;">$passCount</div><div class="lbl">Pass</div></div>
            <div class="stat"><div class="num" style="color:#f9a825;">$warnCount</div><div class="lbl">Warning</div></div>
            <div class="stat"><div class="num" style="color:#c62828;">$failCount</div><div class="lbl">Fail</div></div>
            <div class="stat"><div class="num" style="color:#546e7a;">$infoCount</div><div class="lbl">Info</div></div>
        </div>
    </div>
    $criticalHtml
    $categoriesHtml
</div>
<footer>Сгенерировано локальным скриптом аудита PowerShell. Отчёт содержит сведения о конфигурации системы — храните его так же, как остальные конфиденциальные данные.</footer>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`nГотово! Отчёт сохранён: $OutputPath" -ForegroundColor Green
Write-Host "Итоговая оценка: $score% ($passCount pass / $warnCount warning / $failCount fail)" -ForegroundColor Cyan

Invoke-Item $OutputPath
