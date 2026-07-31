[CmdletBinding()]
param(
    [string]$OutputPath = $(Join-Path $PSScriptRoot "SecurityAudit_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"),
    [switch]$ExportJson,
    [switch]$ExportCsv,
    [switch]$NoLaunch,
    [switch]$Quiet,
    [switch]$NoExitCode,
    [switch]$NoElevate,
    [string[]]$Categories = @(),
    [switch]$NoMenu
)

# ============================================================
# АВТОМАТИЧЕСКОЕ ПОВЫШЕНИЕ ПРАВ (UAC)
# Часть проверок (реестр HKLM, BitLocker, TPM, локальные группы и т.д.) требует прав
# администратора. Вместо жёсткого отказа (#Requires) скрипт сам перезапускает себя
# в новом процессе с запросом UAC, передавая все указанные параметры дальше.
# ============================================================
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $NoElevate) {
    Write-Host "Скрипт запущен без прав администратора — запрашиваю повышение прав (UAC)..." -ForegroundColor Yellow
    $argList = [System.Collections.Generic.List[string]]::new()
    $argList.Add("-NoProfile")
    $argList.Add("-ExecutionPolicy"); $argList.Add("Bypass")
    $argList.Add("-File"); $argList.Add("`"$PSCommandPath`"")
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [switch]) {
            if ($value.IsPresent) { $argList.Add("-$key") }
        } elseif ($value -is [array]) {
            if ($value.Count -gt 0) {
                $argList.Add("-$key")
                $argList.Add(($value | ForEach-Object { "`"$_`"" }) -join ",")
            }
        } else {
            $argList.Add("-$key"); $argList.Add("`"$value`"")
        }
    }
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -ErrorAction Stop | Out-Null
        exit 0
    } catch {
        Write-Host "Не удалось запросить повышение прав автоматически (UAC отклонён или недоступен)." -ForegroundColor Red
        Write-Host "Продолжаю без прав администратора — часть проверок будет недоступна. Для полного аудита запустите PowerShell от имени администратора вручную." -ForegroundColor Yellow
    }
}

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreferenceOriginal = $ProgressPreference
$results = New-Object System.Collections.Generic.List[Object]
$scriptStartTime = Get-Date
$currentStep = 0
$ScriptVersion = "1.0"
$ScriptAuthor  = "Kuanyshgali Ishimbayev"

function Show-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   🛡️  WINDOWS SECURITY AUDIT TOOL  —  v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "  ║   Комплексный аудит безопасности Windows на PowerShell" -ForegroundColor DarkCyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "                                        By $ScriptAuthor" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

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

function Write-Section {
    param([string]$Text)
    $script:currentStep++
    if (-not $Quiet) {
        Write-Host " [$script:currentStep/$totalSteps] $Text" -ForegroundColor Yellow
    }
    Write-Progress -Activity "Аудит безопасности Windows" -Status $Text -PercentComplete (($script:currentStep / $totalSteps) * 100)
}

# Выполняет блок проверки в изолированном виде: сбой одной проверки (например, недоступный
# на данной редакции Windows командлет) не должен обрывать выполнение всего скрипта.
# Также пропускает раздел, если пользователь не выбрал его в меню/параметре -Categories.
function Invoke-SafeSection {
    param(
        [string]$SectionName,
        [scriptblock]$Body
    )
    if ($script:SelectedCategories -and ($script:SelectedCategories -notcontains $SectionName)) {
        return
    }
    try {
        & $Body
    } catch {
        Add-Result -Category $SectionName -Check "Выполнение раздела" -Status "Info" `
            -Details "Раздел выполнен частично: $($_.Exception.Message)"
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($item) { return $item.$Name }
    return $null
}

$AllCategories = @(
    "Система", "Пароли", "Учётные записи", "Firewall", "Сеть",
    "Службы", "Обновления", "Защита", "Аудит и логирование"
)

# ============================================================
# ИНТЕРАКТИВНОЕ МЕНЮ ВЫБОРА
# Позволяет выбрать, какие категории проверок запускать, и настроить экспорт,
# не запоминая ключи командной строки. Пропускается, если категории уже заданы
# параметром -Categories, указан -NoMenu, либо включён тихий режим -Quiet
# (сценарий планировщика задач/CI — там интерактив не нужен).
# ============================================================
function Show-AuditMenu {
    $selected = [System.Collections.Generic.List[string]]::new()
    $AllCategories | ForEach-Object { $selected.Add($_) }
    $exportJsonLocal = $ExportJson.IsPresent
    $exportCsvLocal  = $ExportCsv.IsPresent
    $noLaunchLocal   = $NoLaunch.IsPresent

    while ($true) {
        Clear-Host
        Show-Banner
        Write-Host "Категории проверки (введите номер, чтобы включить/выключить):" -ForegroundColor Yellow
        for ($i = 0; $i -lt $AllCategories.Count; $i++) {
            $mark = if ($selected -contains $AllCategories[$i]) { "[x]" } else { "[ ]" }
            "{0} {1}. {2}" -f $mark, ($i + 1), $AllCategories[$i] | Write-Host
        }
        Write-Host ""
        Write-Host "Экспорт и поведение:" -ForegroundColor Yellow
        Write-Host "$(if ($exportJsonLocal) {'[x]'} else {'[ ]'}) J. Дополнительно сохранить JSON"
        Write-Host "$(if ($exportCsvLocal)  {'[x]'} else {'[ ]'}) C. Дополнительно сохранить CSV"
        Write-Host "$(if ($noLaunchLocal)   {'[x]'} else {'[ ]'}) L. Не открывать отчёт автоматически после генерации"
        Write-Host ""
        Write-Host "  A — выбрать все категории      N — снять все категории" -ForegroundColor DarkGray
        Write-Host "  R — запустить аудит с текущими настройками" -ForegroundColor Green
        Write-Host "  Q — выход без запуска" -ForegroundColor DarkGray
        Write-Host "  --------------------------------------------------------------"
        Write-Host "                                        By $ScriptAuthor" -ForegroundColor DarkGray
        Write-Host ""
        $choice = Read-Host "Ваш выбор"

        switch -Regex ($choice.Trim()) {
            '^\d+$' {
                $idx = [int]$choice - 1
                if ($idx -ge 0 -and $idx -lt $AllCategories.Count) {
                    $catName = $AllCategories[$idx]
                    if ($selected -contains $catName) { $selected.Remove($catName) | Out-Null } else { $selected.Add($catName) }
                }
            }
            '^[Jj]$' { $exportJsonLocal = -not $exportJsonLocal }
            '^[Cc]$' { $exportCsvLocal  = -not $exportCsvLocal }
            '^[Ll]$' { $noLaunchLocal   = -not $noLaunchLocal }
            '^[Aa]$' { $selected.Clear(); $AllCategories | ForEach-Object { $selected.Add($_) } }
            '^[Nn]$' { $selected.Clear() }
            '^[Rr]$' {
                if ($selected.Count -eq 0) {
                    Write-Host "Выберите хотя бы одну категорию перед запуском." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                return [PSCustomObject]@{
                    Categories  = @($selected)
                    ExportJson  = $exportJsonLocal
                    ExportCsv   = $exportCsvLocal
                    NoLaunch    = $noLaunchLocal
                }
            }
            '^[Qq]$' {
                Write-Host "Выход без запуска аудита." -ForegroundColor Yellow
                exit 0
            }
            default { }
        }
    }
}

if ($Categories.Count -gt 0) {
    $script:SelectedCategories = @($Categories | Where-Object { $AllCategories -contains $_ })
    if ($script:SelectedCategories.Count -eq 0) { $script:SelectedCategories = $AllCategories }
} elseif (-not $NoMenu -and -not $Quiet) {
    $menuResult = Show-AuditMenu
    $script:SelectedCategories = $menuResult.Categories
    $ExportJson = $menuResult.ExportJson
    $ExportCsv  = $menuResult.ExportCsv
    $NoLaunch   = $menuResult.NoLaunch
} else {
    $script:SelectedCategories = $AllCategories
}
$totalSteps = [math]::Max($script:SelectedCategories.Count, 1)

Clear-Host
Show-Banner
Write-Host "Запуск расширенного аудита безопасности Windows..." -ForegroundColor Cyan
Write-Host "Хост: $env:COMPUTERNAME | Пользователь: $env:USERNAME | $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Выбрано категорий: $($script:SelectedCategories.Count) из $($AllCategories.Count)" -ForegroundColor Cyan

# ============================================================
# 1. СИСТЕМА
# ============================================================
Invoke-SafeSection -SectionName "Система" -Body {
Write-Section "Информация о системе..."
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem

Add-Result -Category "Система" -Check "ОС" -Status "Info" -Details "$($os.Caption) build $($os.BuildNumber), домен/группа: $($cs.Domain)"
Add-Result -Category "Система" -Check "Последняя загрузка" -Status "Info" -Details "$($os.LastBootUpTime)"

if (-not $isAdmin) {
    Add-Result -Category "Система" -Check "Права выполнения аудита" -Status "Warning" `
        -Details "Скрипт выполнялся без прав администратора — часть проверок (реестр HKLM, BitLocker, TPM, группы и др.) могла быть пропущена или дать неполные результаты." `
        -Risk "Без прав администратора часть уязвимостей может остаться незамеченной." `
        -Remediation "Запустите скрипт от имени администратора (или разрешите запрос UAC при следующем запуске) для полного покрытия проверок."
} else {
    Add-Result -Category "Система" -Check "Права выполнения аудита" -Status "Pass" -Details "Выполнено с правами администратора"
}

# Ориентировочная проверка на устаревшие/снятые с поддержки сборки (актуальные даты см. learn.microsoft.com/lifecycle)
$build = [int]$os.BuildNumber
$eolHint = $null
if ($os.Caption -match "Windows 10" -and $build -lt 19045) {
    $eolHint = "Сборка Windows 10 ниже 19045 (22H2) — более ранние версии сняты с поддержки."
} elseif ($os.Caption -match "Windows 11" -and $build -lt 22621) {
    $eolHint = "Сборка Windows 11 ниже 22621 (22H2) может быть снята с поддержки в зависимости от редакции."
} elseif ($os.Caption -match "Server 2012") {
    $eolHint = "Windows Server 2012/2012 R2 вне расширенной поддержки Microsoft (без ESU)."
} elseif ($os.Caption -match "Server 2008") {
    $eolHint = "Windows Server 2008/2008 R2 давно вне поддержки Microsoft."
}
if ($eolHint) {
    Add-Result -Category "Система" -Check "Актуальность версии ОС" -Status "Warning" -Details $eolHint `
        -Risk "Версии ОС вне цикла поддержки не получают обновлений безопасности." `
        -Remediation "Запланируйте обновление до поддерживаемой версии. Сверьте точные даты на https://learn.microsoft.com/lifecycle/products/"
} else {
    Add-Result -Category "Система" -Check "Актуальность версии ОС" -Status "Info" -Details "Build $build — проверьте актуальный статус на learn.microsoft.com/lifecycle при сомнениях."
}

# Свободное место на системном диске (влияет на установку обновлений и хранение логов)
try {
    $sysDisk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction Stop
    if ($sysDisk.Size -gt 0) {
        $freePct = [math]::Round(($sysDisk.FreeSpace / $sysDisk.Size) * 100, 1)
        $freeGB = [math]::Round($sysDisk.FreeSpace / 1GB, 1)
        $status = if ($freePct -ge 15) { "Pass" } elseif ($freePct -ge 5) { "Warning" } else { "Fail" }
        Add-Result -Category "Система" -Check "Свободное место на системном диске" -Status $status `
            -Details "$freeGB ГБ свободно ($freePct% от объёма диска $($env:SystemDrive))" `
            -Risk "При нехватке места обновления безопасности и журналы событий могут не устанавливаться/перезаписываться раньше срока." `
            -Remediation "Освободите место: cleanmgr /sagerun:1, удалите старые файлы обновлений (Dism.exe /Online /Cleanup-Image /StartComponentCleanup), проверьте крупные файлы в WinSxS/Temp."
    }
} catch {}

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

# Установленные антивирусные продукты (в т.ч. сторонние) через Security Center
try {
    $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
    if ($avProducts) {
        $names = ($avProducts | Select-Object -ExpandProperty displayName -Unique) -join ", "
        Add-Result -Category "Система" -Check "Зарегистрированные антивирусные продукты" -Status "Info" -Details $names
    } else {
        Add-Result -Category "Система" -Check "Зарегистрированные антивирусные продукты" -Status "Warning" -Details "Ни один продукт не зарегистрирован в Security Center" `
            -Risk "Отсутствие зарегистрированного антивируса может означать, что защита не установлена или не сообщает о своём статусе." `
            -Remediation "Убедитесь, что Windows Defender включён (Get-MpComputerStatus) либо установлен и активен сторонний антивирус."
    }
} catch {}
}

# ============================================================
# 2. ПАРОЛЬНАЯ ПОЛИТИКА
# ============================================================
Invoke-SafeSection -SectionName "Пароли" -Body {
Write-Section "Парольная политика..."

$secCfgPath = Join-Path $env:TEMP "secpol_audit_$(Get-Random).cfg"
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
$clearText  = Get-SecPolValue "ClearTextPassword"

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
if ($null -ne $clearText) {
    $status = if ($clearText -eq '0') { "Pass" } else { "Fail" }
    Add-Result -Category "Пароли" -Check "Хранение паролей с обратимым шифрованием" -Status $status `
        -Details $(if ($clearText -eq '0') {"Отключено"} else {"Включено — пароли фактически хранятся в открытом виде"}) `
        -Risk "Обратимое шифрование фактически равносильно хранению паролей в открытом тексте — при компрометации контроллера/базы паролей все они раскрываются мгновенно." `
        -Remediation "GPO: Password Policy -> 'Store passwords using reversible encryption' = Disabled"
}
Remove-Item $secCfgPath -ErrorAction SilentlyContinue
}

# ============================================================
# 3. УЧЁТНЫЕ ЗАПИСИ
# ============================================================
Invoke-SafeSection -SectionName "Учётные записи" -Body {
Write-Section "Учётные записи..."

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

    $dangerousMembers = $admins | Where-Object { $_.Name -match 'Everyone|ANONYMOUS LOGON|Все|АНОНИМНЫЙ ВХОД' }
    if ($dangerousMembers) {
        Add-Result -Category "Учётные записи" -Check "Опасные участники группы Administrators" -Status "Fail" `
            -Details "Обнаружены: $($dangerousMembers.Name -join ', ')" `
            -Risk "Группы Everyone/ANONYMOUS LOGON в составе локальных администраторов дают полный контроль над системой практически без аутентификации." `
            -Remediation "Немедленно удалите: Remove-LocalGroupMember -Group Administrators -Member '<имя>'"
    }
} catch {}

$restrictAnon = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
$status = if ($restrictAnon -eq 1) { "Pass" } else { "Warning" }
Add-Result -Category "Учётные записи" -Check "Анонимное перечисление учётных записей SAM" -Status $status `
    -Details $(if ($restrictAnon -eq 1) {"Запрещено"} else {"Разрешено (значение по умолчанию/не задано)"}) `
    -Risk "Анонимные пользователи могут перечислить локальные учётные записи и группы — полезно атакующему для разведки." `
    -Remediation "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1 -PropertyType DWORD -Force`nЛибо GPO: Local Policies -> Security Options -> 'Network access: Do not allow anonymous enumeration of SAM accounts' = Enabled"

$limitBlank = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
$status = if ($limitBlank -eq 1 -or $null -eq $limitBlank) { "Pass" } else { "Fail" }
Add-Result -Category "Учётные записи" -Check "Ограничение входа с пустым паролем по сети" -Status $status `
    -Details $(if ($limitBlank -eq 0) {"Отключено — учётки с пустым паролем доступны по сети!"} else {"Включено"}) `
    -Risk "Учётные записи с пустым паролем могут быть использованы для удалённого входа." `
    -Remediation "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -Value 1 -PropertyType DWORD -Force"

# LAPS (Local Administrator Password Solution) — классический и встроенный Windows LAPS
$lapsLegacy = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "AdmPwdEnabled"
$lapsWindows = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" "BackupDirectory"
if ($lapsLegacy -eq 1 -or $lapsWindows -ge 1) {
    Add-Result -Category "Учётные записи" -Check "LAPS (управление паролями локального администратора)" -Status "Pass" -Details "Настроен и активен"
} elseif ($cs.PartOfDomain) {
    Add-Result -Category "Учётные записи" -Check "LAPS (управление паролями локального администратора)" -Status "Warning" `
        -Details "Не обнаружено на машине, входящей в домен" `
        -Risk "Без LAPS локальный пароль администратора часто одинаков на многих машинах — компрометация одной раскрывает доступ ко всем." `
        -Remediation "Разверните встроенный Windows LAPS (Server 2019+/Win10 2m2004+ с апрельским обновлением 2023): GPO 'Computer Configuration -> Administrative Templates -> System -> LAPS' -> Enabled. Подробности: https://learn.microsoft.com/windows-server/identity/laps/laps-overview"
} else {
    Add-Result -Category "Учётные записи" -Check "LAPS (управление паролями локального администратора)" -Status "Info" -Details "Автономная машина вне домена — LAPS обычно не применяется"
}
}

# ============================================================
# 4. FIREWALL
# ============================================================
Invoke-SafeSection -SectionName "Firewall" -Body {
Write-Section "Брандмауэр Windows..."

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

    if ($fwProfile.Name -eq 'Public' -and $fwProfile.DefaultOutboundAction -eq 'Allow' -and $fwProfile.NotifyOnListen -eq $false) {
        Add-Result -Category "Firewall" -Check "Уведомления о блокировках (Public)" -Status "Info" `
            -Details "Уведомления при блокировке нового приложения отключены на публичном профиле" `
            -Remediation "Set-NetFirewallProfile -Profile Public -NotifyOnListen True (по желанию, для видимости новых сетевых приложений)"
    }
}

$openInbound = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { $_.Profile -match 'Public|Any' }
$status = if ($openInbound.Count -gt 15) { "Warning" } else { "Info" }
Add-Result -Category "Firewall" -Check "Открытые входящие правила (Public/Any)" -Status $status `
    -Details "$($openInbound.Count) активных правил разрешения" `
    -Risk "Каждое открытое входящее правило на публичном профиле — потенциальный вектор атаки из недоверенной сети." `
    -Remediation "Просмотреть правила: Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object {`$_.Profile -match 'Public'} | Format-Table DisplayName,Profile. Отключить ненужные: Disable-NetFirewallRule -DisplayName '<имя правила>'"

$rdpDeny = Get-RegValue "HKLM:\System\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
if ($null -ne $rdpDeny) {
    $rdpEnabled = ($rdpDeny -eq 0)
    $status = if ($rdpEnabled) { "Warning" } else { "Pass" }
    Add-Result -Category "Firewall" -Check "Удалённый рабочий стол (RDP)" -Status $status `
        -Details $(if ($rdpEnabled) {"Включён"} else {"Отключён"}) `
        -Risk "Открытый RDP — один из самых частых векторов первичного доступа при атаках шифровальщиков." `
        -Remediation "Если не нужен: Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1. Если нужен: ограничьте доступ через VPN/бастион, разрешите только доверенные IP в firewall, включите NLA и MFA."
    if ($rdpEnabled) {
        $nla = Get-RegValue "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
        $status = if ($nla -eq 1) { "Pass" } else { "Fail" }
        Add-Result -Category "Firewall" -Check "Network Level Authentication (NLA) для RDP" -Status $status `
            -Details $(if ($nla -eq 1) {"Включена"} else {"Отключена"}) `
            -Risk "Без NLA аутентификация происходит после установки полной RDP-сессии — увеличивает поверхность атаки на уязвимости протокола (например, BlueKeep)." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"

        $restrictedAdmin = Get-RegValue "HKLM:\System\CurrentControlSet\Control\Lsa" "DisableRestrictedAdmin"
        if ($restrictedAdmin -eq 0) {
            Add-Result -Category "Firewall" -Check "RDP Restricted Admin Mode" -Status "Pass" -Details "Разрешён"
        } else {
            Add-Result -Category "Firewall" -Check "RDP Restricted Admin Mode" -Status "Info" -Details "Не включён явно" `
                -Remediation "New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdmin -Value 0 -PropertyType DWORD -Force  (снижает риск передачи хеша пароля при администрировании через RDP)"
        }
    }
}
}

# ============================================================
# 5. СЕТЕВЫЕ ПРОТОКОЛЫ
# ============================================================
Invoke-SafeSection -SectionName "Сеть" -Body {
Write-Section "Сетевые протоколы (SMB/NTLM/LLMNR/TLS)..."

try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    $status = if ($smb1.State -eq 'Enabled') { "Fail" } else { "Pass" }
    Add-Result -Category "Сеть" -Check "Протокол SMBv1" -Status $status -Details "$($smb1.State)" `
        -Risk "SMBv1 — устаревший и небезопасный протокол, используемый в атаках WannaCry/NotPetya (эксплойт EternalBlue)." `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart  (после — перезагрузка)"
} catch {}

$smbSigningServer = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature"
$status = if ($smbSigningServer -eq 1) { "Pass" } else { "Warning" }
Add-Result -Category "Сеть" -Check "Обязательная подпись SMB (сервер)" -Status $status `
    -Details $(if ($smbSigningServer -eq 1) {"Требуется"} else {"Не требуется"}) `
    -Risk "Без обязательной подписи SMB возможны атаки relay/man-in-the-middle (например, NTLM relay через SMB)." `
    -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force`nGPO: 'Microsoft network server: Digitally sign communications (always)' = Enabled"

$smbSigningClient = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
$status = if ($smbSigningClient -eq 1) { "Pass" } else { "Warning" }
Add-Result -Category "Сеть" -Check "Обязательная подпись SMB (клиент)" -Status $status `
    -Details $(if ($smbSigningClient -eq 1) {"Требуется"} else {"Не требуется"}) `
    -Risk "Без подписи на стороне клиента исходящие SMB-соединения также уязвимы к relay-атакам." `
    -Remediation "Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force`nGPO: 'Microsoft network client: Digitally sign communications (always)' = Enabled"

try {
    $smbServerCfg = Get-SmbServerConfiguration -ErrorAction Stop
    $status = if ($smbServerCfg.EncryptData) { "Pass" } else { "Info" }
    Add-Result -Category "Сеть" -Check "Шифрование SMB (сервер)" -Status $status `
        -Details $(if ($smbServerCfg.EncryptData) {"Включено"} else {"Отключено"}) `
        -Risk "Без шифрования SMB-трафик (включая содержимое файлов) может быть перехвачен в сети." `
        -Remediation "Set-SmbServerConfiguration -EncryptData `$true -Force  (требуется SMB3, клиенты Windows 8/Server 2012+)"
} catch {}

$lmCompat = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
$status = if ($lmCompat -ge 5) { "Pass" } elseif ($lmCompat -ge 3) { "Warning" } else { "Fail" }
Add-Result -Category "Сеть" -Check "Уровень совместимости NTLM (LM Compatibility Level)" -Status $status `
    -Details "Текущий уровень: $lmCompat (0-5, рекомендуется 5 — только NTLMv2, отказ от LM и NTLM)" `
    -Risk "Низкий уровень допускает использование устаревших и легко взламываемых протоколов LM/NTLMv1." `
    -Remediation "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -PropertyType DWORD -Force`nGPO: 'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM'"

$wdigest = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
$status = if ($wdigest -eq 0 -or $null -eq $wdigest) { "Pass" } else { "Fail" }
Add-Result -Category "Сеть" -Check "WDigest (хранение паролей в открытом виде в LSASS)" -Status $status `
    -Details $(if ($wdigest -eq 1) {"Включено — пароли доступны в открытом виде в памяти процесса LSASS"} else {"Отключено (по умолчанию с Windows 8.1/Server 2012 R2 + KB2871997)"}) `
    -Risk "Если WDigest хранит пароль в открытом виде в памяти, инструменты типа Mimikatz могут извлечь его напрямую из LSASS." `
    -Remediation "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -PropertyType DWORD -Force"

$ntlmAudit = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AuditReceivingNTLMTraffic"
if ($null -eq $ntlmAudit -or $ntlmAudit -eq 0) {
    Add-Result -Category "Сеть" -Check "Аудит NTLM-трафика" -Status "Info" -Details "Аудит входящего NTLM-трафика не включён" `
        -Remediation "GPO: Security Options -> 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' = Enable auditing for all accounts (полезно перед последующим ограничением NTLM)"
}

$llmnr = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
$status = if ($llmnr -eq 0) { "Pass" } else { "Warning" }
Add-Result -Category "Сеть" -Check "LLMNR (Link-Local Multicast Name Resolution)" -Status $status `
    -Details $(if ($llmnr -eq 0) {"Отключён"} else {"Включён (значение по умолчанию)"}) `
    -Risk "LLMNR/NBT-NS подвержены атакам спуфинга и перехвата хешей (например, инструмент Responder), что позволяет получить учётные данные из локальной сети." `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -PropertyType DWORD -Force`nGPO: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> 'Turn off multicast name resolution' = Enabled"

# Устаревшие протоколы шифрования транспорта (SSL/TLS) через SCHANNEL
$legacyProtocols = @(
    @{ Name = "SSL 2.0" ; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" }
    @{ Name = "SSL 3.0" ; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" }
    @{ Name = "TLS 1.0" ; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" }
    @{ Name = "TLS 1.1" ; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" }
)
foreach ($proto in $legacyProtocols) {
    $enabled = Get-RegValue $proto.Path "Enabled"
    if ($enabled -eq 0) {
        Add-Result -Category "Сеть" -Check "Устаревший протокол $($proto.Name)" -Status "Pass" -Details "Явно отключён"
    } else {
        Add-Result -Category "Сеть" -Check "Устаревший протокол $($proto.Name)" -Status "Warning" `
            -Details "Не отключён явно (используется поведение по умолчанию для данной версии ОС)" `
            -Risk "$($proto.Name) считается небезопасным (известны атаки POODLE, BEAST и др.) и не должен использоваться." `
            -Remediation "New-Item -Path '$($proto.Path)' -Force; New-ItemProperty -Path '$($proto.Path)' -Name Enabled -Value 0 -PropertyType DWORD -Force; New-ItemProperty -Path '$($proto.Path)' -Name DisabledByDefault -Value 1 -PropertyType DWORD -Force  (аналогично создать ветку \Client). Перезагрузка обязательна."
    }
}

$winrmSvc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
    $allowUnencrypted = (Get-Item -Path WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value
    $status = if ($allowUnencrypted -eq 'false') { "Pass" } else { "Warning" }
    Add-Result -Category "Сеть" -Check "WinRM — незашифрованный трафик" -Status $status `
        -Details $(if ($allowUnencrypted -eq 'true') {"Разрешён небезопасный (незашифрованный) трафик"} else {"Только зашифрованный"}) `
        -Risk "Незашифрованный WinRM-трафик может быть перехвачен в локальной сети (учётные данные, команды)." `
        -Remediation "Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value `$false"
}
}

# ============================================================
# 6. СЛУЖБЫ
# ============================================================
Invoke-SafeSection -SectionName "Службы" -Body {
Write-Section "Службы..."

$riskyServices = @(
    @{ Name = "RemoteRegistry"; Display = "Удалённый реестр" }
    @{ Name = "TlntSvr";        Display = "Telnet Server" }
    @{ Name = "SNMP";           Display = "SNMP Service" }
    @{ Name = "SSDPSRV";        Display = "SSDP Discovery" }
    @{ Name = "simptcp";        Display = "Simple TCP/IP Services" }
    @{ Name = "FTPSVC";         Display = "FTP Server (IIS)" }
    @{ Name = "WebClient";      Display = "WebClient (WebDAV)" }
    @{ Name = "Fax";            Display = "Служба факсов" }
    @{ Name = "RemoteAccess";   Display = "Маршрутизация и удалённый доступ (RRAS)" }
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

# PrintNightmare — ограничения Point and Print
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq 'Running') {
    $restrictDriver = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators"
    $status = if ($restrictDriver -eq 1) { "Pass" } else { "Warning" }
    Add-Result -Category "Службы" -Check "Point and Print — установка драйверов только администраторами" -Status $status `
        -Details $(if ($restrictDriver -eq 1) {"Ограничено администраторами"} else {"Не ограничено явно (риск PrintNightmare)"}) `
        -Risk "Уязвимости класса PrintNightmare (CVE-2021-34527 и связанные) позволяют получить SYSTEM-права через установку вредоносного драйвера печати непривилегированным пользователем." `
        -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Force; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name RestrictDriverInstallationToAdministrators -Value 1 -PropertyType DWORD -Force`nЕсли служба печати не нужна на сервере: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled"
}

# Sysmon — расширенное журналирование (опционально, не входит в стандартную поставку Windows)
$sysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if (-not $sysmon) {
    Add-Result -Category "Службы" -Check "Sysmon (расширенный мониторинг событий)" -Status "Info" `
        -Details "Не установлен" `
        -Remediation "Опционально: разверните Sysinternals Sysmon с конфигурацией на базе SwiftOnSecurity/olafhartong для детального журналирования процессов, сетевых соединений и изменений реестра — существенно повышает возможности расследования инцидентов."
} else {
    Add-Result -Category "Службы" -Check "Sysmon (расширенный мониторинг событий)" -Status "Pass" -Details "Установлен: статус $($sysmon.Status)"
}
}

# ============================================================
# 7. ОБНОВЛЕНИЯ
# ============================================================
Invoke-SafeSection -SectionName "Обновления" -Body {
Write-Section "Обновления Windows..."

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

$deferQuality = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" "DeferQualityUpdatesPeriodInDays"
if ($deferQuality -gt 30) {
    Add-Result -Category "Обновления" -Check "Отсрочка обновлений безопасности" -Status "Warning" `
        -Details "Обновления качества (включая патчи безопасности) отложены на $deferQuality дн." `
        -Risk "Длительная отсрочка critical/security-обновлений увеличивает окно уязвимости к известным эксплойтам." `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate' -Name DeferQualityUpdatesPeriodInDays -Value 7"
}

$doMode = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode"
if ($doMode -eq 3) {
    Add-Result -Category "Обновления" -Check "Delivery Optimization — обмен через интернет" -Status "Info" `
        -Details "Режим 3: загрузка/раздача обновлений с/на узлы через интернет (не только локальную сеть)" `
        -Risk "Раздача обновлений внешним хостам через интернет — минимальный риск, но увеличивает исходящий трафик и поверхность взаимодействия с внешними узлами." `
        -Remediation "Ограничить локальной сетью при необходимости: Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name DODownloadMode -Value 1"
}
}

# ============================================================
# 8. ЗАЩИТА (Defender, UAC, Credential Guard, LSA, BitLocker)
# ============================================================
Invoke-SafeSection -SectionName "Защита" -Body {
Write-Section "Defender, UAC, Credential Guard, BitLocker..."

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

    $status = if ($mp.IsTamperProtected) { "Pass" } else { "Warning" }
    Add-Result -Category "Защита" -Check "Защита от несанкционированного изменения (Tamper Protection)" -Status $status `
        -Details $(if ($mp.IsTamperProtected) {"Включена"} else {"Отключена"}) `
        -Risk "Без Tamper Protection вредоносное ПО с правами администратора может отключить Defender." `
        -Remediation "Включите через Windows Security -> Защита от вирусов и угроз -> Параметры защиты от вирусов и угроз -> Защита от несанкционированного доступа. Массово — через Intune/MDM (не рекомендуется через реестр напрямую)."

    $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($mpPref) {
        $status = if ($mpPref.MAPSReporting -ne 0) { "Pass" } else { "Warning" }
        Add-Result -Category "Защита" -Check "Облачная защита Defender (MAPS)" -Status $status `
            -Details $(if ($mpPref.MAPSReporting -ne 0) {"Включена"} else {"Отключена"}) `
            -Risk "Без облачной защиты обнаружение новых/неизвестных угроз (zero-day) значительно медленнее." `
            -Remediation "Set-MpPreference -MAPSReporting Advanced"

        $status = switch ($mpPref.EnableControlledFolderAccess) { 1 {"Pass"} 2 {"Warning"} default {"Warning"} }
        Add-Result -Category "Защита" -Check "Controlled Folder Access (защита от шифровальщиков)" -Status $status `
            -Details "Режим: $($mpPref.EnableControlledFolderAccess) (0=выкл, 1=вкл, 2=аудит)" `
            -Risk "Без контролируемого доступа к папкам процессы-шифровальщики могут беспрепятственно изменять/шифровать личные файлы." `
            -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled  (протестируйте в режиме AuditMode перед полным включением, чтобы не заблокировать легитимные приложения)"

        $asrCount = ($mpPref.AttackSurfaceReductionRules_Ids | Measure-Object).Count
        $status = if ($asrCount -ge 5) { "Pass" } elseif ($asrCount -ge 1) { "Warning" } else { "Warning" }
        Add-Result -Category "Защита" -Check "Правила сокращения поверхности атаки (ASR)" -Status $status `
            -Details "$asrCount правил настроено" `
            -Risk "Без правил ASR не блокируются типовые техники атак (макросы Office, запуск скриптов из вложений, эксплойты через LSASS и др.)." `
            -Remediation "Настройте базовый набор правил ASR, например: Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled. Список правил: https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
    }
} else {
    Add-Result -Category "Защита" -Check "Windows Defender" -Status "Info" -Details "Get-MpComputerStatus недоступен — вероятно, используется сторонний антивирус, либо Defender неактивен."
}

$uac = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
if ($null -ne $uac) {
    $status = if ($uac -eq 1) { "Pass" } else { "Fail" }
    Add-Result -Category "Защита" -Check "Контроль учётных записей (UAC)" -Status $status `
        -Details $(if ($uac -eq 1) {"Включён"} else {"Отключён"}) `
        -Risk "Без UAC любой процесс (в т.ч. вредоносный) может тихо получить права администратора." `
        -Remediation "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -PropertyType DWORD -Force  (требуется перезагрузка)"
}

$autoLogon = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
if ($autoLogon -eq "1") {
    Add-Result -Category "Защита" -Check "Автоматический вход в систему" -Status "Fail" `
        -Details "Включён (пароль хранится в реестре в открытом виде)" `
        -Risk "Любой, кто получит доступ к реестру или физически к диску, может извлечь пароль учётной записи в открытом виде." `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0`nRemove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue"
}

# LSA Protection (RunAsPPL) — защита процесса LSASS от дампа учётных данных
$runAsPPL = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
$status = if ($runAsPPL -eq 1) { "Pass" } else { "Warning" }
Add-Result -Category "Защита" -Check "LSA Protection (RunAsPPL)" -Status $status `
    -Details $(if ($runAsPPL -eq 1) {"Включена"} else {"Отключена"}) `
    -Risk "Без защиты LSA процесс lsass.exe может быть считан инструментами типа Mimikatz для извлечения хешей и паролей из памяти." `
    -Remediation "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -PropertyType DWORD -Force  (перед включением проверьте совместимость драйверов/агентов, работающих с LSASS; требуется перезагрузка)"

# Credential Guard
try {
    $dg = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard -ErrorAction Stop
    $cgRunning = $dg.SecurityServicesRunning -contains 1
    $status = if ($cgRunning) { "Pass" } else { "Warning" }
    Add-Result -Category "Защита" -Check "Credential Guard" -Status $status `
        -Details $(if ($cgRunning) {"Запущен"} else {"Не запущен"}) `
        -Risk "Без Credential Guard учётные данные домена, хранимые в LSASS, менее защищены от кражи с помощью техник pass-the-hash/pass-the-ticket." `
        -Remediation "Требуются: UEFI + Secure Boot + виртуализация (Hyper-V). Включение: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor; затем GPO 'Turn On Virtualization Based Security' -> Credential Guard = Enabled with UEFI lock. Подробности: https://learn.microsoft.com/windows/security/identity-protection/credential-guard/"
} catch {
    Add-Result -Category "Защита" -Check "Credential Guard" -Status "Info" -Details "Недоступно на этой редакции/конфигурации Windows (обычно требуется Windows 10/11 Enterprise/Education или Server)"
}

# PowerShell v2 — устаревший движок без AMSI/логирования, стоит удалить
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
    $status = if ($psv2.State -eq 'Disabled') { "Pass" } else { "Warning" }
    Add-Result -Category "Защита" -Check "Компонент Windows PowerShell v2" -Status $status -Details "$($psv2.State)" `
        -Risk "PowerShell v2 не поддерживает AMSI и современное журналирование — атакующие используют его, чтобы обойти защитные механизмы более новых версий (`powershell -version 2`)." `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
} catch {}

try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $status = if ($bl.ProtectionStatus -eq 'On') { "Pass" } else { "Warning" }
    Add-Result -Category "Защита" -Check "Шифрование диска BitLocker ($env:SystemDrive)" -Status $status `
        -Details "Статус защиты: $($bl.ProtectionStatus)" `
        -Risk "Без шифрования диска данные доступны при физическом доступе к устройству (кража/утеря ноутбука)." `
        -Remediation "Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector. Обязательно сохраните ключ восстановления (AD, Azure AD или распечатка)."

    $otherVolumes = Get-BitLockerVolume | Where-Object { $_.MountPoint -ne $env:SystemDrive -and $_.VolumeType -eq 'Data' }
    foreach ($vol in $otherVolumes) {
        $status = if ($vol.ProtectionStatus -eq 'On') { "Pass" } else { "Warning" }
        Add-Result -Category "Защита" -Check "Шифрование BitLocker ($($vol.MountPoint))" -Status $status `
            -Details "Статус защиты: $($vol.ProtectionStatus)" `
            -Risk "Незашифрованные дополнительные тома так же доступны при физическом доступе, как и системный диск." `
            -Remediation "Enable-BitLocker -MountPoint $($vol.MountPoint) -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector"
    }
} catch {
    Add-Result -Category "Защита" -Check "Шифрование диска BitLocker" -Status "Info" -Details "Недоступно на этой редакции/конфигурации Windows"
}
}

# ============================================================
# 9. АУДИТ И ЛОГИРОВАНИЕ
# ============================================================
Invoke-SafeSection -SectionName "Аудит и логирование" -Body {
Write-Section "Аудит и логирование..."

$auditLogon = auditpol /get /subcategory:"Logon" 2>$null | Select-String "Success and Failure|Success|Failure|No Auditing"
if ($auditLogon) {
    $line = $auditLogon.Line
    $status = if ($line -match "No Auditing") { "Fail" } elseif ($line -match "Success and Failure") { "Pass" } else { "Warning" }
    Add-Result -Category "Аудит и логирование" -Check "Аудит событий входа в систему (Logon)" -Status $status `
        -Details ($line.Trim() -replace '\s{2,}', ' ') `
        -Risk "Без аудита входов невозможно расследовать попытки несанкционированного доступа постфактум." `
        -Remediation "auditpol /set /subcategory:`"Logon`" /success:enable /failure:enable`nGPO: Advanced Audit Policy Configuration -> Logon/Logoff -> Audit Logon = Success and Failure"
}

$auditProcess = auditpol /get /subcategory:"Process Creation" 2>$null | Select-String "Success and Failure|Success|Failure|No Auditing"
if ($auditProcess) {
    $line = $auditProcess.Line
    $status = if ($line -match "No Auditing") { "Warning" } else { "Pass" }
    Add-Result -Category "Аудит и логирование" -Check "Аудит создания процессов (Process Creation)" -Status $status `
        -Details ($line.Trim() -replace '\s{2,}', ' ') `
        -Risk "Без журналирования создания процессов сложно отследить, какие программы запускались во время инцидента." `
        -Remediation "auditpol /set /subcategory:`"Process Creation`" /success:enable"

    $cmdLineAudit = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled"
    $status = if ($cmdLineAudit -eq 1) { "Pass" } else { "Warning" }
    Add-Result -Category "Аудит и логирование" -Check "Включение командной строки в события создания процессов" -Status $status `
        -Details $(if ($cmdLineAudit -eq 1) {"Включено"} else {"Отключено"}) `
        -Risk "Без параметров командной строки в событии 4688 расследование инцидентов сильно затрудняется (не видно, что именно было выполнено)." `
        -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force; New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWORD -Force`nGPO: 'Include command line in process creation events' = Enabled"
}

$psLogging = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
$status = if ($psLogging -eq 1) { "Pass" } else { "Warning" }
Add-Result -Category "Аудит и логирование" -Check "PowerShell Script Block Logging" -Status $status `
    -Details $(if ($psLogging -eq 1) {"Включено"} else {"Отключено"}) `
    -Risk "Без логирования блоков скриптов сложно обнаружить вредоносные PowerShell-скрипты (частый инструмент атакующих после получения доступа)." `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -PropertyType DWORD -Force`nGPO: Administrative Templates -> Windows Components -> Windows PowerShell -> 'Turn on PowerShell Script Block Logging' = Enabled"

$psModuleLogging = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
$status = if ($psModuleLogging -eq 1) { "Pass" } else { "Info" }
Add-Result -Category "Аудит и логирование" -Check "PowerShell Module Logging" -Status $status `
    -Details $(if ($psModuleLogging -eq 1) {"Включено"} else {"Отключено"}) `
    -Risk "Дополняет Script Block Logging — без него часть выполняемых командлетов может остаться незафиксированной." `
    -Remediation "GPO: 'Turn on Module Logging' = Enabled, Module Names = *"

$psTranscription = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
if ($psTranscription -ne 1) {
    Add-Result -Category "Аудит и логирование" -Check "PowerShell Transcription" -Status "Info" -Details "Отключено" `
        -Remediation "GPO: 'Turn on PowerShell Transcription' = Enabled с указанием защищённой (только для записи для обычных пользователей) папки для транскриптов."
}

foreach ($logName in @('Security','Application','System')) {
    $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if ($log) {
        $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB)
        $minSize = if ($logName -eq 'Security') { 196 } else { 64 }
        $status = if ($sizeMB -ge $minSize) { "Pass" } else { "Warning" }
        Add-Result -Category "Аудит и логирование" -Check "Максимальный размер журнала: $logName" -Status $status `
            -Details "$sizeMB МБ" `
            -Risk "Маленький журнал перезаписывается быстро — при активной атаке важные события могут быть потеряны до расследования." `
            -Remediation "Limit-EventLog -LogName $logName -MaximumSize $(if ($logName -eq 'Security') {'512MB'} else {'128MB'}) (рекомендуется больше в зависимости от активности системы, либо централизованный сбор логов через SIEM/Windows Event Forwarding)"
    }
}
}

# ============================================================
# ФОРМИРОВАНИЕ ОТЧЁТОВ (HTML / JSON / CSV)
# ============================================================
Write-Progress -Activity "Аудит безопасности Windows" -Completed
Write-Host "Формирование отчёта..." -ForegroundColor Yellow

$statusColors = @{ Pass = "#2e7d32"; Warning = "#f9a825"; Fail = "#c62828"; Info = "#546e7a" }
$statusBg     = @{ Pass = "#e8f5e9"; Warning = "#fff8e1"; Fail = "#ffebee"; Info = "#eceff1" }

$passCount = ($results | Where-Object Status -eq 'Pass').Count
$warnCount = ($results | Where-Object Status -eq 'Warning').Count
$failCount = ($results | Where-Object Status -eq 'Fail').Count
$infoCount = ($results | Where-Object Status -eq 'Info').Count
$total = $results.Count

# Взвешенный расчёт: Info не участвует (нейтральная информация), Warning считается наполовину.
$scored = $results | Where-Object { $_.Status -in @('Pass','Warning','Fail') }
$scoreTotal = $scored.Count
if ($scoreTotal -gt 0) {
    $scoreValue = ($scored | ForEach-Object {
        switch ($_.Status) { 'Pass' {1} 'Warning' {0.5} 'Fail' {0} }
    } | Measure-Object -Sum).Sum
    $score = [math]::Round(($scoreValue / $scoreTotal) * 100)
} else {
    $score = 0
}
$scoreColor = if ($score -ge 85) { "#2e7d32" } elseif ($score -ge 60) { "#f9a825" } else { "#c62828" }

# ---- История запусков и тренд (сравнение с предыдущей проверкой на этой машине) ----
$historyPath = Join-Path (Split-Path $OutputPath -Parent) "SecurityAudit_History_$($env:COMPUTERNAME).json"
$history = @()
if (Test-Path $historyPath) {
    try { $history = @(Get-Content $historyPath -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $history = @() }
}
$previousRun = $history | Select-Object -Last 1
$trendHtml = ""
if ($previousRun) {
    $delta = $score - [int]$previousRun.Score
    $prevDate = $previousRun.Date
    if ($delta -gt 0) {
        $trendHtml = "<div class='trend trend-up'>▲ +$delta% с прошлой проверки ($prevDate)</div>"
    } elseif ($delta -lt 0) {
        $trendHtml = "<div class='trend trend-down'>▼ $delta% с прошлой проверки ($prevDate)</div>"
    } else {
        $trendHtml = "<div class='trend trend-flat'>= без изменений с прошлой проверки ($prevDate)</div>"
    }
} else {
    $trendHtml = "<div class='trend trend-flat'>Первая проверка на этой машине — истории пока нет</div>"
}
$history += [PSCustomObject]@{ Date = (Get-Date -Format 'dd.MM.yyyy HH:mm'); Score = $score; Pass = $passCount; Warning = $warnCount; Fail = $failCount }
if ($history.Count -gt 30) { $history = $history | Select-Object -Last 30 }
try { $history | ConvertTo-Json -Depth 3 | Out-File -FilePath $historyPath -Encoding UTF8 } catch {}

function Format-Remediation {
    param([string]$Text)
    if (-not $Text) { return "" }
    $escaped = $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
    $escaped = $escaped -replace "`n", "<br>"
    return $escaped
}

function Format-Html {
    param([string]$Text)
    if (-not $Text) { return "" }
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')
}

# Блок критичных проблем (executive summary)
$critical = $results | Where-Object { $_.Status -eq 'Fail' }
$criticalHtml = ""
if ($critical) {
    $items = ""
    foreach ($c in $critical) {
        $items += "<li><b>[$(Format-Html $c.Category)] $(Format-Html $c.Check)</b> — $(Format-Html $c.Details)</li>"
    }
    $criticalHtml = @"
    <div class="critical-box">
        <h2>🚨 Критичные проблемы, требующие немедленного устранения ($($critical.Count))</h2>
        <ul>$items</ul>
    </div>
"@
}

function Get-SeverityOrder {
    param([string]$Status)
    switch ($Status) { 'Fail' {0} 'Warning' {1} 'Info' {2} 'Pass' {3} default {4} }
}

function Get-CategoryBarSvg {
    param($CatResults)
    $counts = @{
        Fail    = ($CatResults | Where-Object Status -eq 'Fail').Count
        Warning = ($CatResults | Where-Object Status -eq 'Warning').Count
        Pass    = ($CatResults | Where-Object Status -eq 'Pass').Count
        Info    = ($CatResults | Where-Object Status -eq 'Info').Count
    }
    $total = $CatResults.Count
    if ($total -eq 0) { return "" }
    $width = 110
    $x = 0
    $segments = ""
    foreach ($st in @('Fail','Warning','Pass','Info')) {
        if ($counts[$st] -gt 0) {
            $segWidth = [math]::Round(($counts[$st] / $total) * $width, 1)
            $segments += "<rect x='$x' y='0' width='$segWidth' height='8' fill='$($statusColors[$st])' />"
            $x += $segWidth
        }
    }
    return "<svg class='cat-bar' width='$width' height='8' viewBox='0 0 $width 8'>$segments</svg>"
}

$categoriesHtml = ""
$tocHtml = ""
$catIndex = 0
foreach ($cat in ($results | Select-Object -ExpandProperty Category -Unique)) {
    $catIndex++
    $catId = "cat-$catIndex"
    $catResults = $results | Where-Object Category -eq $cat | Sort-Object { Get-SeverityOrder $_.Status }
    $catFail = ($catResults | Where-Object Status -eq 'Fail').Count
    $catWarn = ($catResults | Where-Object Status -eq 'Warning').Count
    $openAttr = if ($catFail -gt 0 -or $catWarn -gt 0) { " open" } else { "" }

    $badgesHtml = ""
    if ($catFail -gt 0) { $badgesHtml += "<span class='cat-badge' style='background:$($statusBg.Fail);color:$($statusColors.Fail);'>$catFail Fail</span>" }
    if ($catWarn -gt 0) { $badgesHtml += "<span class='cat-badge' style='background:$($statusBg.Warning);color:$($statusColors.Warning);'>$catWarn Warning</span>" }
    $barSvg = Get-CategoryBarSvg -CatResults $catResults

    $tocHtml += "<a href='#$catId' class='toc-link'>$(Format-Html $cat)$(if ($catFail -gt 0) {" <b class='toc-fail'>($catFail)</b>"})</a>"

    $rows = ""
    foreach ($r in $catResults) {
        $color = $statusColors[$r.Status]
        $bg = $statusBg[$r.Status]
        $riskBlock = if ($r.Risk) { "<div class='risk'><b>Риск:</b> $(Format-Html $r.Risk)</div>" } else { "" }
        $remBlock = if ($r.Remediation) { "<div class='rem'><div class='rem-header'><b>✅ Как устранить:</b><button class='copy-btn' onclick='copyRemediation(this)'>📋 Копировать</button></div><div class='rem-code'>$(Format-Remediation (Format-Html $r.Remediation))</div></div>" } else { "" }
        $rows += @"
        <tr class="row" data-status="$($r.Status)" data-text="$((Format-Html ($r.Check + ' ' + $r.Details)).ToLower())">
            <td class="check-name">$(Format-Html $r.Check)</td>
            <td><span class="badge" style="background:$bg;color:$color;">$($r.Status)</span></td>
            <td class="details">
                <div>$(Format-Html $r.Details)</div>
                $riskBlock
                $remBlock
            </td>
        </tr>
"@
    }
    $categoriesHtml += @"
    <details class="category" id="$catId"$openAttr>
        <summary><h2>$(Format-Html $cat) $badgesHtml $barSvg</h2></summary>
        <table>
            <thead><tr><th style="width:24%">Проверка</th><th style="width:10%">Статус</th><th>Детали / Риск / Устранение</th></tr></thead>
            <tbody>$rows</tbody>
        </table>
    </details>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Аудит безопасности Windows - $env:COMPUTERNAME</title>
<style>
    :root { --bg:#f4f6f8; --card:#ffffff; --text:#2c3e50; --muted:#78909c; --border:#eee; }
    body.dark { --bg:#12181f; --card:#1b2531; --text:#dce3ea; --muted:#8fa3b3; --border:#2a3644; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background:var(--bg); margin:0; padding:0; color:var(--text); transition:background .2s,color .2s; }
    header { background:linear-gradient(135deg,#1a237e,#283593); color:white; padding:30px 40px; display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:15px; }
    header h1 { margin:0; font-size:24px; }
    header p { margin:5px 0 0; opacity:0.85; font-size:14px; }
    .toolbar { display:flex; gap:10px; flex-wrap:wrap; }
    .toolbar button { background:rgba(255,255,255,0.15); color:white; border:1px solid rgba(255,255,255,0.4); border-radius:6px; padding:6px 12px; font-size:12.5px; cursor:pointer; }
    .toolbar button:hover { background:rgba(255,255,255,0.3); }
    .container { max-width:1050px; margin:-20px auto 40px; padding:0 20px; }
    .summary { background:var(--card); border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.08); padding:25px 30px; display:flex; align-items:center; gap:30px; margin-bottom:25px; flex-wrap:wrap; }
    .score-circle { width:90px; height:90px; border-radius:50%; border:8px solid $scoreColor; display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:bold; color:$scoreColor; flex-shrink:0; }
    .summary-stats { display:flex; gap:25px; flex-wrap:wrap; }
    .stat { text-align:center; }
    .stat .num { font-size:22px; font-weight:bold; }
    .stat .lbl { font-size:12px; color:var(--muted); text-transform:uppercase; }
    .filter-search { display:flex; gap:10px; flex-wrap:wrap; margin-left:auto; align-items:center; }
    .filter-search input { padding:8px 12px; border-radius:6px; border:1px solid #cfd8dc; font-size:13px; min-width:180px; }
    .filter-btn { border:1px solid #cfd8dc; background:var(--card); color:var(--text); border-radius:6px; padding:6px 12px; font-size:12.5px; cursor:pointer; }
    .filter-btn.active { background:#283593; color:white; border-color:#283593; }
    .critical-box { background:#fff3f3; border:1px solid #ffcdd2; border-left:5px solid #c62828; border-radius:8px; padding:18px 22px; margin-bottom:25px; }
    .critical-box h2 { margin:0 0 10px; font-size:16px; color:#c62828; }
    .critical-box ul { margin:0; padding-left:20px; font-size:13.5px; line-height:1.7; }
    .category { background:var(--card); border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.06); margin-bottom:20px; overflow:hidden; }
    .category summary { cursor:pointer; list-style:none; }
    .category summary::-webkit-details-marker { display:none; }
    .category h2 { margin:0; padding:15px 20px; background:#eceff1; font-size:16px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    body.dark .category h2 { background:#232f3d; }
    .cat-badge { font-size:11px; padding:3px 8px; border-radius:10px; font-weight:600; }
    table { width:100%; border-collapse:collapse; }
    th { text-align:left; padding:10px 20px; font-size:12px; color:var(--muted); text-transform:uppercase; border-bottom:1px solid var(--border); }
    td { padding:12px 20px; border-bottom:1px solid var(--border); vertical-align:top; font-size:13.5px; }
    .check-name { font-weight:600; }
    .badge { padding:4px 10px; border-radius:12px; font-size:12px; font-weight:600; white-space:nowrap; }
    .risk { margin-top:8px; font-size:12.5px; color:#8d6e00; background:#fffde7; padding:8px 10px; border-radius:6px; border-left:3px solid #f9a825; }
    .rem { margin-top:8px; font-size:12.5px; }
    .rem-header { display:flex; align-items:center; gap:10px; justify-content:space-between; }
    .copy-btn { border:1px solid #cfd8dc; background:var(--card); color:var(--text); border-radius:5px; padding:2px 8px; font-size:11px; cursor:pointer; }
    .copy-btn:hover { background:#283593; color:white; }
    .rem-code { margin-top:5px; background:#1e272e; color:#d7f5dd; font-family:Consolas,'Courier New',monospace; padding:10px 12px; border-radius:6px; line-height:1.6; white-space:pre-wrap; word-break:break-word; }
    footer { text-align:center; color:#90a4ae; font-size:12px; padding:20px; }
    .row.hidden { display:none; }
    .cat-bar { vertical-align:middle; margin-left:auto; border-radius:4px; overflow:hidden; }
    .toc { background:var(--card); border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.06); padding:14px 20px; margin-bottom:20px; display:flex; gap:16px; flex-wrap:wrap; font-size:13px; }
    .toc-link { color:var(--text); text-decoration:none; padding:4px 8px; border-radius:5px; }
    .toc-link:hover { background:#eceff1; }
    body.dark .toc-link:hover { background:#232f3d; }
    .toc-fail { color:#c62828; }
    .trend { font-size:12.5px; color:var(--muted); margin-top:6px; }
    .trend-up { color:#2e7d32; }
    .trend-down { color:#c62828; }
    @media print {
        .toolbar, .filter-search { display:none; }
        .category { break-inside: avoid; }
    }
</style>
</head>
<body>
<header>
    <div>
        <h1>🛡️ Аудит безопасности Windows <span style="font-size:13px;font-weight:normal;opacity:.75;">v$ScriptVersion</span></h1>
        <p>Хост: $env:COMPUTERNAME &nbsp;|&nbsp; Дата: $(Get-Date -Format 'dd.MM.yyyy HH:mm') &nbsp;|&nbsp; Пользователь: $env:USERNAME &nbsp;|&nbsp; By $ScriptAuthor</p>
    </div>
    <div class="toolbar">
        <button onclick="window.print()">🖨️ Печать / PDF</button>
        <button onclick="toggleTheme()">🌓 Тема</button>
        <button onclick="toggleAll(true)">⬇️ Развернуть всё</button>
        <button onclick="toggleAll(false)">⬆️ Свернуть всё</button>
    </div>
</header>
<div class="container">
    <div class="summary">
        <div>
            <div class="score-circle">$score%</div>
            $trendHtml
        </div>
        <div class="summary-stats">
            <div class="stat"><div class="num" style="color:#2e7d32;">$passCount</div><div class="lbl">Pass</div></div>
            <div class="stat"><div class="num" style="color:#f9a825;">$warnCount</div><div class="lbl">Warning</div></div>
            <div class="stat"><div class="num" style="color:#c62828;">$failCount</div><div class="lbl">Fail</div></div>
            <div class="stat"><div class="num" style="color:#546e7a;">$infoCount</div><div class="lbl">Info</div></div>
        </div>
        <div class="filter-search">
            <input type="text" id="searchBox" placeholder="Поиск по проверкам..." oninput="applyFilters()">
            <button class="filter-btn active" data-status="all" onclick="setStatusFilter('all', this)">Все</button>
            <button class="filter-btn" data-status="Fail" onclick="setStatusFilter('Fail', this)">Fail</button>
            <button class="filter-btn" data-status="Warning" onclick="setStatusFilter('Warning', this)">Warning</button>
            <button class="filter-btn" data-status="Pass" onclick="setStatusFilter('Pass', this)">Pass</button>
            <button class="filter-btn" data-status="Info" onclick="setStatusFilter('Info', this)">Info</button>
        </div>
    </div>
    <div class="toc">$tocHtml</div>
    $criticalHtml
    $categoriesHtml
</div>
<footer>Сгенерировано локальным скриптом аудита PowerShell. Отчёт содержит сведения о конфигурации системы — храните его так же, как остальные конфиденциальные данные.<br>Windows Security Audit Tool v$ScriptVersion &nbsp;|&nbsp; By $ScriptAuthor</footer>
<script>
    var currentStatusFilter = 'all';
    function setStatusFilter(status, btn) {
        currentStatusFilter = status;
        var buttons = document.querySelectorAll('.filter-btn');
        for (var i = 0; i < buttons.length; i++) { buttons[i].classList.remove('active'); }
        btn.classList.add('active');
        applyFilters();
    }
    function applyFilters() {
        var q = document.getElementById('searchBox').value.toLowerCase();
        var rows = document.querySelectorAll('.row');
        rows.forEach(function(row) {
            var statusMatch = (currentStatusFilter === 'all') || (row.getAttribute('data-status') === currentStatusFilter);
            var textMatch = row.getAttribute('data-text').indexOf(q) !== -1;
            if (statusMatch && textMatch) { row.classList.remove('hidden'); } else { row.classList.add('hidden'); }
        });
    }
    function copyRemediation(btn) {
        var codeBlock = btn.closest('.rem').querySelector('.rem-code');
        var text = codeBlock.innerText;
        var restoreLabel = btn.innerText;
        function showCopied() {
            btn.innerText = '✅ Скопировано';
            setTimeout(function() { btn.innerText = restoreLabel; }, 1500);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(showCopied, function() { fallbackCopy(text, showCopied); });
        } else {
            fallbackCopy(text, showCopied);
        }
    }
    function fallbackCopy(text, done) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(ta);
        if (done) { done(); }
    }
    function toggleTheme() {
        document.body.classList.toggle('dark');
    }
    function toggleAll(openState) {
        document.querySelectorAll('details.category').forEach(function(d) { d.open = openState; });
    }
    var _openStateBeforePrint = [];
    window.addEventListener('beforeprint', function() {
        _openStateBeforePrint = [];
        document.querySelectorAll('details.category').forEach(function(d) { _openStateBeforePrint.push(d.open); d.open = true; });
    });
    window.addEventListener('afterprint', function() {
        document.querySelectorAll('details.category').forEach(function(d, i) { d.open = _openStateBeforePrint[i]; });
    });
</script>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`nГотово! HTML-отчёт сохранён: $OutputPath" -ForegroundColor Green

$producedFiles = @($OutputPath)

if ($ExportJson) {
    $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, "json")
    $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "JSON-отчёт сохранён: $jsonPath" -ForegroundColor Green
    $producedFiles += $jsonPath
}

if ($ExportCsv) {
    $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, "csv")
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV-отчёт сохранён: $csvPath" -ForegroundColor Green
    $producedFiles += $csvPath
}

$duration = (Get-Date) - $scriptStartTime
Write-Host "Итоговая оценка: $score% (взвешенно: Pass=1, Warning=0.5, Fail=0)" -ForegroundColor Cyan
Write-Host "$passCount pass / $warnCount warning / $failCount fail / $infoCount info — выполнено за $([math]::Round($duration.TotalSeconds,1)) сек." -ForegroundColor Cyan
Write-Host ""
Write-Host "Windows Security Audit Tool v$ScriptVersion — By $ScriptAuthor" -ForegroundColor DarkGray

$ProgressPreference = $ProgressPreferenceOriginal

if (-not $NoLaunch) {
    Invoke-Item $OutputPath
}

if (-not $NoExitCode) {
    if ($failCount -gt 0) { exit 1 } else { exit 0 }
}
