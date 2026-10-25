#Requires -Version 5.1
<#
EgressScope shutdown-lab（仅限一次性 Windows 虚拟机）

危险 / DANGER
  1. 先在虚拟机中创建快照，再运行本脚本。
  2. 仅可在你拥有或明确获授权审计的设备上运行。
  3. prepare 阶段会在 20 秒后真正重启、关机或注销这台机器。
  4. 本脚本不安装应用、不关闭安全控件、不使用 -Force 强制关机。

用法（在虚拟机内）：
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\shutdown_lab.ps1 `
    -Exe C:\path\EgressScope.exe -Phase prepare -Mode restart -ConfirmReboot

  脚本会登记一个 HKCU RunOnce 项；下次登录后自动执行 -Phase verify，
  写出 <Home>\lab-report.json 与 lab-report.txt（UTF-8 BOM），退出码 0 表示通过。

  -Mode shutdown 时机器会保持关机，请手动开机并在登录后等待 verify 完成。
  RunOnce 属于当前用户（HKCU）；重启后请用同一个 Windows 用户登录。
  prepare 之后请勿移动或删除本脚本、实验目录与 RunOnce 项，否则 verify 无法运行。

说明：PowerShell 的 $HOME 是只读自动变量，因此命令行参数 -Home 通过 Alias
映射到内部变量 $LabHome；对外用法仍是 -Home。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [ValidateSet("prepare","verify")][string]$Phase = "prepare",
    [ValidateSet("restart","shutdown","logoff")][string]$Mode = "restart",
    [Alias("Home")][string]$LabHome = "$env:LOCALAPPDATA\EgressScope-shutdown-lab",
    [int]$ProxyPort = 18899,
    [int]$WebPort = 18898,
    [switch]$ConfirmReboot
)

$ErrorActionPreference = "Stop"

$script:InternetValueNames = @("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")
$script:RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$script:RunOnceKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$script:RunOnceName = "EgressScopeShutdownLabVerify"
$script:WinInetReady = $false
$script:AppProcess = $null
$script:ProxyTakenOver = $false
$script:BackupCreated = $false
$script:StateCreated = $false
$script:RunOnceCreated = $false
$script:OriginalRegistry = $null
$script:ExePath = $Exe
$script:ProxyPort = $ProxyPort
$script:WebPort = $WebPort

$script:ExePath = [Environment]::ExpandEnvironmentVariables([string]$Exe)
$script:LabHome = [Environment]::ExpandEnvironmentVariables([string]$LabHome)
if ([string]::IsNullOrWhiteSpace($script:LabHome)) {
    Write-Host "拒绝执行：-Home 不能为空。"
    exit 1
}
try {
    $script:LabHome = [System.IO.Path]::GetFullPath($script:LabHome)
} catch {
    Write-Host "拒绝执行：-Home 路径无效。"
    exit 1
}
if ($script:LabHome.Length -gt 3) {
    $script:LabHome = $script:LabHome.TrimEnd("\")
}

$script:StatePath = Join-Path $script:LabHome "lab-state.json"
$script:ReportJson = Join-Path $script:LabHome "lab-report.json"
$script:ReportText = Join-Path $script:LabHome "lab-report.txt"
$script:LabLog = Join-Path $script:LabHome "lab.log"
$script:DataDir = Join-Path $script:LabHome "data"
$script:ConfigPath = Join-Path $script:DataDir "config.json"
$script:BackupPath = Join-Path $script:DataDir "proxy-backup.json"
$script:AppLog = Join-Path $script:DataDir "logs\egressscope.log"
$script:ScriptPath = $PSCommandPath
if (-not $script:ScriptPath) {
    $script:ScriptPath = $MyInvocation.MyCommand.Definition
}
if ($script:ScriptPath) {
    try { $script:ScriptPath = (Resolve-Path -LiteralPath $script:ScriptPath).Path } catch { }
}
$script:VerifyCommand = ""

function Write-LabLog([string]$Message) {
    try {
        $dir = Split-Path -Parent $script:LabLog
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Phase, $Message
        Add-Content -LiteralPath $script:LabLog -Value $line -Encoding UTF8
        Write-Host $line
    } catch {
        Write-Host ("lab log write failed: " + $_.Exception.Message)
    }
}

function Write-Utf8File([string]$Path, [string]$Text, [bool]$Bom) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $encoding = New-Object System.Text.UTF8Encoding($Bom)
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}

function Get-EpochSeconds {
    $utcNow = (Get-Date).ToUniversalTime()
    $epoch = New-Object DateTime(1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc))
    return [int](($utcNow - $epoch).TotalSeconds)
}

function Get-BagValue($Bag, [string]$Name) {
    if ($null -eq $Bag) { return $null }
    if ($Bag -is [System.Collections.IDictionary]) {
        if ($Bag.Contains($Name)) { return $Bag[$Name] }
        return $null
    }
    $prop = $Bag.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-RegistryValue([string]$KeyPath, [string]$Name) {
    $item = Get-ItemProperty -LiteralPath $KeyPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $prop = $item.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-InternetSettingsSnapshot {
    $values = [ordered]@{}
    foreach ($name in $script:InternetValueNames) {
        $values[$name] = Get-RegistryValue $script:RegPath $name
    }
    return $values
}

function Set-InternetSettingsValue([string]$Name, $Value) {
    if ($null -eq $Value) {
        if ($null -ne (Get-RegistryValue $script:RegPath $Name)) {
            Remove-ItemProperty -LiteralPath $script:RegPath -Name $Name -ErrorAction Stop
        }
        return
    }
    if ($Name -eq "ProxyEnable") {
        Set-ItemProperty -LiteralPath $script:RegPath -Name $Name -Value ([int]$Value) -Type DWord -ErrorAction Stop
    } else {
        Set-ItemProperty -LiteralPath $script:RegPath -Name $Name -Value ([string]$Value) -Type String -ErrorAction Stop
    }
}

function Restore-InternetSettings($Values) {
    foreach ($name in $script:InternetValueNames) {
        $value = Get-BagValue $Values $name
        Set-InternetSettingsValue $name $value
    }
    Refresh-WinInet
}

function Initialize-WinInet {
    if ($script:WinInetReady) { return }
    $source = @'
using System;
using System.Runtime.InteropServices;
public static class ShutdownLabWinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int option, IntPtr buffer, int length);
}
'@
    Add-Type -TypeDefinition $source -ErrorAction Stop | Out-Null
    $script:WinInetReady = $true
}

function Refresh-WinInet {
    Initialize-WinInet
    [ShutdownLabWinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
    [ShutdownLabWinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
}

function Test-ProxyServerPointsAtPort([string]$Server, [int]$Port) {
    if ([string]::IsNullOrWhiteSpace($Server) -or $Port -le 0) { return $false }
    foreach ($part in $Server.Split(";")) {
        $piece = $part.Trim()
        if (-not $piece) { continue }
        $scheme = "http"
        $addr = $piece
        if ($piece.Contains("=")) {
            $scheme = $piece.Split("=", 2)[0].Trim().ToLowerInvariant()
            $addr = $piece.Split("=", 2)[1].Trim()
        }
        if ($scheme -ne "http" -and $scheme -ne "https") { continue }
        $match = [regex]::Match($addr, '^(?i)(?:https?://)?(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)/?$')
        if ($match.Success -and [int]$match.Groups[1].Value -eq $Port) {
            return $true
        }
    }
    return $false
}

function ConvertTo-CommandLineArgument([string]$Value) {
    if ($null -eq $Value) { return '""' }
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Test-TcpPortFree([int]$Port) {
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $listener) { $listener.Stop() }
    }
}

function Test-TcpPortListening([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(600)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Wait-ForListener([int]$Port, [datetime]$Deadline, $ProcessHandle) {
    while ((Get-Date) -lt $Deadline) {
        if (Test-TcpPortListening $Port) { return $true }
        if ($null -ne $ProcessHandle -and $ProcessHandle.HasExited) { return $false }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Test-LogPattern([string]$Path, [string]$Pattern, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        if (Test-Path -LiteralPath $Path) {
            try {
                if (Select-String -LiteralPath $Path -Pattern $Pattern -SimpleMatch -Quiet -ErrorAction Stop) {
                    return $true
                }
            } catch { }
        }
        if ((Get-Date) -ge $deadline) { return $false }
        Start-Sleep -Milliseconds 500
    }
}

function Wait-ForSessionSettle {
    $started = Get-Date
    $deadline = $started.AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $explorer = @(Get-Process -Name "explorer" -ErrorAction SilentlyContinue)
        if ($explorer.Count -gt 0) { break }
        Start-Sleep -Milliseconds 750
    }
    Start-Sleep -Seconds 2
    Write-LabLog ("session settle wait: {0:N1}s" -f ((Get-Date) - $started).TotalSeconds)
}

function Remove-VerifyRunOnce {
    try {
        Remove-ItemProperty -LiteralPath $script:RunOnceKey -Name $script:RunOnceName -ErrorAction SilentlyContinue
    } catch { }
}

function Stop-LabApp {
    if ($null -ne $script:AppProcess) {
        try {
            if (-not $script:AppProcess.HasExited) {
                Stop-Process -Id $script:AppProcess.Id -Force -ErrorAction SilentlyContinue
                Write-LabLog ("stopped lab app pid {0}" -f $script:AppProcess.Id)
            }
        } catch { }
    }
}

function Undo-Prepare {
    if ($script:RunOnceCreated) {
        Remove-VerifyRunOnce
        Write-LabLog "removed the RunOnce verify entry"
    }
    Stop-LabApp
    $restored = $true
    if ($script:ProxyTakenOver) {
        try {
            Restore-InternetSettings $script:OriginalRegistry
            Write-LabLog "prepare rollback restored the original proxy settings"
        } catch {
            $restored = $false
            Write-LabLog ("prepare rollback could not restore the proxy: " + $_.Exception.Message)
        }
    }
    if ($restored) {
        if ($script:BackupCreated -and (Test-Path -LiteralPath $script:BackupPath)) {
            Remove-Item -LiteralPath $script:BackupPath -Force -ErrorAction SilentlyContinue
        }
        if ($script:StateCreated -and (Test-Path -LiteralPath $script:StatePath)) {
            Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-LabLog ("kept state and backup for manual recovery: {0}" -f $script:StatePath)
    }
}

function Invoke-Prepare {
    Write-LabLog ("prepare: mode={0} proxy={1} web={2} home={3}" -f $Mode, $script:ProxyPort, $script:WebPort, $script:LabHome)
    Write-LabLog "DANGER: this phase restarts/shuts down/logs off this machine"

    if (-not $ConfirmReboot) {
        throw "拒绝执行：prepare 必须显式传入 -ConfirmReboot；请先为虚拟机创建快照。"
    }
    if (Test-Path -LiteralPath $script:StatePath) {
        throw ("拒绝执行：{0} 已存在。请换一个 -Home，或先手动清理该实验目录。" -f $script:StatePath)
    }
    $existingRunOnce = Get-ItemProperty -LiteralPath $script:RunOnceKey -Name $script:RunOnceName -ErrorAction SilentlyContinue
    if ($null -ne $existingRunOnce) {
        throw "拒绝执行：HKCU RunOnce 中已存在 EgressScopeShutdownLabVerify，可能有未完成的实验。"
    }
    if (-not (Test-Path -LiteralPath $script:ExePath -PathType Leaf)) {
        throw ("拒绝执行：找不到 -Exe 文件：{0}" -f $script:ExePath)
    }
    $script:ExePath = (Resolve-Path -LiteralPath $script:ExePath).Path
    if ($script:ProxyPort -lt 1024 -or $script:ProxyPort -gt 65535 -or $script:WebPort -lt 1024 -or $script:WebPort -gt 65535) {
        throw "拒绝执行：端口必须位于 1024-65535。"
    }
    if ($script:ProxyPort -eq $script:WebPort) {
        throw "拒绝执行：-ProxyPort 与 -WebPort 不能相同。"
    }

    $processNames = @("EgressScope")
    $leafName = [System.IO.Path]::GetFileNameWithoutExtension($script:ExePath)
    if ($leafName -and $leafName -ne "EgressScope") {
        $processNames += $leafName
    }
    $running = @()
    foreach ($name in $processNames) {
        $running += @(Get-Process -Name $name -ErrorAction SilentlyContinue)
    }
    if ($running.Count -gt 0) {
        $pids = ($running | ForEach-Object { $_.Id }) -join ", "
        throw ("拒绝执行：检测到 EgressScope 进程（pid {0}）。本实验不得干扰真实安装。" -f $pids)
    }
    $schtasks = Join-Path $env:SystemRoot "System32\schtasks.exe"
    if (-not (Test-Path -LiteralPath $schtasks)) { $schtasks = "schtasks.exe" }
    foreach ($taskName in @("EgressScope Proxy Recovery", "EgressScope Audit")) {
        $taskFound = $false
        try {
            $null = & $schtasks /Query /TN $taskName 2>&1
            $taskFound = ($LASTEXITCODE -eq 0)
        } catch {
            $taskFound = $false
        }
        if ($taskFound) {
            throw ("拒绝执行：检测到计划任务「{0}」。它可能属于真实安装，本实验不得干扰。" -f $taskName)
        }
    }
    if (Test-Path -LiteralPath $script:BackupPath) {
        throw ("拒绝执行：实验目录中已有 proxy-backup.json：{0}。请使用全新的 -Home。" -f $script:BackupPath)
    }
    if (-not (Test-TcpPortFree $script:ProxyPort)) {
        throw ("拒绝执行：TCP 端口 {0} 已被占用。" -f $script:ProxyPort)
    }
    if (-not (Test-TcpPortFree $script:WebPort)) {
        throw ("拒绝执行：TCP 端口 {0} 已被占用。" -f $script:WebPort)
    }

    New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null
    Write-Utf8File $script:ConfigPath '{"autostart_enabled": false}' $false
    if (Test-Path -LiteralPath $script:AppLog) {
        Remove-Item -LiteralPath $script:AppLog -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $script:AppLog) {
            throw ("无法清理旧的应用日志：{0}。请关闭占用它的进程后重试。" -f $script:AppLog)
        }
        Write-LabLog "reset the lab app log so verify cannot match an old restore line"
    }

    $script:OriginalRegistry = Get-InternetSettingsSnapshot
    Write-LabLog ("original proxy: enable={0} server={1} override={2} pac={3}" -f `
        (Get-BagValue $script:OriginalRegistry "ProxyEnable"), `
        (Get-BagValue $script:OriginalRegistry "ProxyServer"), `
        (Get-BagValue $script:OriginalRegistry "ProxyOverride"), `
        (Get-BagValue $script:OriginalRegistry "AutoConfigURL"))

    $appArguments = @(
        "--headless",
        "--home", (ConvertTo-CommandLineArgument $script:LabHome),
        "--proxy-port", [string]$script:ProxyPort,
        "--web-port", [string]$script:WebPort
    )
    $script:AppProcess = Start-Process -FilePath $script:ExePath -ArgumentList $appArguments -WindowStyle Hidden -PassThru
    Write-LabLog ("started lab app pid {0}" -f $script:AppProcess.Id)
    $listenDeadline = (Get-Date).AddSeconds(30)
    if (-not (Wait-ForListener $script:ProxyPort $listenDeadline $script:AppProcess)) {
        throw ("实验应用未在 30 秒内监听代理端口 127.0.0.1:{0}。" -f $script:ProxyPort)
    }
    if (-not (Wait-ForListener $script:WebPort $listenDeadline $script:AppProcess)) {
        throw ("实验应用未在 30 秒内监听面板端口 127.0.0.1:{0}。" -f $script:WebPort)
    }
    Start-Sleep -Milliseconds 500
    if ($script:AppProcess.HasExited) {
        throw ("实验应用提前退出，退出码 {0}。" -f $script:AppProcess.ExitCode)
    }
    $hookSeen = Test-LogPattern $script:AppLog "shutdown/logoff proxy restore hook installed" 8
    if (-not $hookSeen) {
        Write-LabLog "WARN: app log does not show the shutdown hook; verify may fail and the safety net will restore the proxy"
    }

    $backup = [ordered]@{
        created_at = Get-EpochSeconds
        managed = $true
        host = "127.0.0.1"
        port = $script:ProxyPort
        values = [ordered]@{
            ProxyEnable = Get-BagValue $script:OriginalRegistry "ProxyEnable"
            ProxyServer = Get-BagValue $script:OriginalRegistry "ProxyServer"
            ProxyOverride = Get-BagValue $script:OriginalRegistry "ProxyOverride"
            AutoConfigURL = Get-BagValue $script:OriginalRegistry "AutoConfigURL"
        }
    }
    $script:BackupCreated = $true
    Write-Utf8File $script:BackupPath ($backup | ConvertTo-Json -Depth 6) $false
    Write-LabLog ("wrote simulated proxy backup: {0}" -f $script:BackupPath)

    $script:ProxyTakenOver = $true
    Set-InternetSettingsValue "ProxyEnable" 1
    Set-InternetSettingsValue "ProxyServer" ("127.0.0.1:{0}" -f $script:ProxyPort)
    $overrideRaw = [string](Get-BagValue $script:OriginalRegistry "ProxyOverride")
    $overrideParts = @()
    if ($overrideRaw) {
        $overrideParts = @($overrideRaw.Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    foreach ($token in @("localhost", "127.0.0.1", "<local>")) {
        $present = $false
        foreach ($part in $overrideParts) {
            if ($part.Equals($token, [System.StringComparison]::OrdinalIgnoreCase)) { $present = $true; break }
        }
        if (-not $present) { $overrideParts += $token }
    }
    Set-InternetSettingsValue "ProxyOverride" ($overrideParts -join ";")
    Refresh-WinInet
    Write-LabLog ("lab proxy enabled: 127.0.0.1:{0}" -f $script:ProxyPort)

    $script:VerifyCommand = "powershell.exe " + (@(
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", (ConvertTo-CommandLineArgument $script:ScriptPath),
        "-Phase", "verify",
        "-Mode", $Mode,
        "-Exe", (ConvertTo-CommandLineArgument $script:ExePath),
        "-Home", (ConvertTo-CommandLineArgument $script:LabHome),
        "-ProxyPort", [string]$script:ProxyPort,
        "-WebPort", [string]$script:WebPort
    ) -join " ")

    $state = [ordered]@{
        schema = 1
        phase = "prepare"
        mode = $Mode
        prepared_at = (Get-Date).ToString("o")
        script = $script:ScriptPath
        exe = $script:ExePath
        home = $script:LabHome
        proxy_port = $script:ProxyPort
        web_port = $script:WebPort
        app_pid = $script:AppProcess.Id
        app_log = $script:AppLog
        backup_path = $script:BackupPath
        original_registry = $script:OriginalRegistry
        runonce_name = $script:RunOnceName
        runonce_command = $script:VerifyCommand
        hook_seen = [bool]$hookSeen
    }
    $script:StateCreated = $true
    Write-Utf8File $script:StatePath ($state | ConvertTo-Json -Depth 8) $true
    Write-LabLog ("state written: {0}" -f $script:StatePath)

    if (-not (Test-Path -LiteralPath $script:RunOnceKey)) {
        New-Item -Path $script:RunOnceKey -Force | Out-Null
    }
    $script:RunOnceCreated = $true
    New-ItemProperty -LiteralPath $script:RunOnceKey -Name $script:RunOnceName -Value $script:VerifyCommand -PropertyType String -Force | Out-Null
    Write-LabLog ("RunOnce registered: {0}" -f $script:VerifyCommand)

    $shutdownExe = Join-Path $env:SystemRoot "System32\shutdown.exe"
    if (-not (Test-Path -LiteralPath $shutdownExe)) { $shutdownExe = "shutdown.exe" }
    $shutdownArgs = switch ($Mode) {
        "restart" { @("/r", "/t", "20") }
        "shutdown" { @("/s", "/t", "20") }
        "logoff" { @("/l") }
    }
    Write-LabLog ("triggering {0}: {1} {2}" -f $Mode, $shutdownExe, ($shutdownArgs -join " "))
    $triggerOutput = & $shutdownExe @shutdownArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("shutdown.exe 失败（退出码 {0}）：{1}" -f $LASTEXITCODE, ($triggerOutput -join " "))
    }
    Write-LabLog "trigger accepted; Windows will sign out shortly. Verify runs at the next logon."
    exit 0
}

function Format-RegistryValue($Value) {
    if ($null -eq $Value) { return "(未设置)" }
    $text = [string]$Value
    if (-not $text) { return "(空)" }
    return $text
}

function Write-VerifyFailureReport([string]$Message) {
    $now = (Get-Date).ToString("o")
    $final = $null
    try { $final = Get-InternetSettingsSnapshot } catch { }
    $report = [ordered]@{
        ok = $false
        phase = "verify"
        mode = $Mode
        timestamp = $now
        home = $script:LabHome
        checks = @(
            [ordered]@{ name = "verify_completed"; ok = $false; detail = $Message }
        )
        original_registry = $null
        final_registry = $final
        backup_present = (Test-Path -LiteralPath $script:BackupPath)
        log_matched = $false
        log_excerpt = @()
        safety_restored = $false
        error = $Message
    }
    try {
        Write-Utf8File $script:ReportJson ($report | ConvertTo-Json -Depth 8) $true
    } catch { }
    try {
        $lines = @(
            "EgressScope 关机实验报告（verify）",
            "",
            "结论: 未通过（实验未完成）",
            ("时间: " + $now),
            ("模式: " + $Mode),
            ("错误: " + $Message),
            ("实验目录: " + $script:LabHome),
            "",
            "没有删除任何用户数据。请检查 lab.log 与实验目录。"
        )
        Write-Utf8File $script:ReportText ($lines -join [Environment]::NewLine) $true
    } catch { }
}

function Invoke-Verify {
    Write-LabLog ("verify: mode={0} home={1}" -f $Mode, $script:LabHome)
    Remove-VerifyRunOnce
    Write-LabLog "removed the RunOnce entry to prevent a verify loop"

    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        throw ("找不到实验状态文件：{0}。请从 prepare 阶段重新开始。" -f $script:StatePath)
    }
    $state = Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $mode = [string]$state.mode
    if (-not $mode) { $mode = $Mode }
    $proxyPort = [int]$state.proxy_port
    if ($proxyPort -le 0) { $proxyPort = $script:ProxyPort }
    $original = $state.original_registry
    $appLog = [string]$state.app_log
    if (-not $appLog) { $appLog = $script:AppLog }
    $backupPath = [string]$state.backup_path
    if (-not $backupPath) { $backupPath = $script:BackupPath }
    $stateExe = [string]$state.exe

    Write-LabLog ("verify: restored from state, mode={0} proxy={1}" -f $mode, $proxyPort)
    Wait-ForSessionSettle

    $final = Get-InternetSettingsSnapshot
    $pointsAtLab = Test-ProxyServerPointsAtPort ([string](Get-BagValue $final "ProxyServer")) $proxyPort
    $backupPresent = Test-Path -LiteralPath $backupPath
    $logMatched = $false
    $logExcerpt = @()
    if (Test-Path -LiteralPath $appLog) {
        try {
            $restoreMatches = @(Select-String -LiteralPath $appLog -Pattern "restored during OS shutdown/logoff" -SimpleMatch -ErrorAction Stop)
            $logMatched = $restoreMatches.Count -gt 0
            foreach ($item in $restoreMatches) {
                $logExcerpt += ("MATCH: " + $item.Line.Trim())
            }
            if ($logExcerpt.Count -eq 0) {
                $logExcerpt = @(Get-Content -LiteralPath $appLog -Tail 20 -Encoding UTF8 -ErrorAction SilentlyContinue)
            }
            if ($logExcerpt.Count -gt 40) {
                $logExcerpt = @($logExcerpt[0..39])
            }
        } catch {
            Write-LabLog ("could not read the app log: " + $_.Exception.Message)
        }
    } else {
        Write-LabLog ("app log not found: {0}" -f $appLog)
    }

    $labPids = @()
    $processCheckAvailable = $true
    try {
        $leaf = [System.IO.Path]::GetFileName($stateExe)
        if ($leaf) {
            $filter = "Name = '{0}'" -f $leaf.Replace("'", "''")
            $cimProcesses = @(Get-CimInstance -ClassName Win32_Process -Filter $filter -ErrorAction Stop)
            foreach ($process in $cimProcesses) {
                $commandLine = [string]$process.CommandLine
                if ($commandLine -and $commandLine.IndexOf($script:LabHome, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $labPids += [int]$process.ProcessId
                }
            }
        }
    } catch {
        $processCheckAvailable = $false
    }

    $originalEnable = Get-BagValue $original "ProxyEnable"
    $finalEnable = Get-BagValue $final "ProxyEnable"
    $finalEnabled = ($null -ne $finalEnable) -and ([int]$finalEnable -ne 0)
    $activeLabProxy = $finalEnabled -and $pointsAtLab
    $enableOk = $true
    if ($null -ne $originalEnable -and [int]$originalEnable -eq 0) {
        $enableOk = (($null -ne $finalEnable -and [int]$finalEnable -eq 0) -or (-not $pointsAtLab))
    }

    $checks = @(
        [ordered]@{
            name = "registry_proxy_points_away_from_lab"
            ok = (-not $activeLabProxy)
            detail = ("final ProxyEnable={0}; final ProxyServer={1}; lab port={2}" -f (Format-RegistryValue $finalEnable), (Format-RegistryValue (Get-BagValue $final "ProxyServer")), $proxyPort)
        },
        [ordered]@{
            name = "proxy_enable_zero_when_originally_disabled"
            ok = $enableOk
            detail = ("original ProxyEnable={0}; final ProxyEnable={1}" -f (Format-RegistryValue $originalEnable), (Format-RegistryValue $finalEnable))
        },
        [ordered]@{
            name = "backup_file_removed"
            ok = (-not $backupPresent)
            detail = $backupPath
        },
        [ordered]@{
            name = "restore_logged"
            ok = $logMatched
            detail = $appLog
        },
        [ordered]@{
            name = "no_lab_app_process"
            ok = (($labPids.Count -eq 0) -or (-not $processCheckAvailable))
            detail = $(if ($processCheckAvailable) { "pids=" + (($labPids | ForEach-Object { [string]$_ }) -join ",") } else { "Win32_Process query unavailable; skipped" })
        }
    )

    $ok = $true
    foreach ($item in $checks) {
        if (-not $item["ok"]) { $ok = $false }
    }

    $safetyRestored = $false
    $safetyError = ""
    if ($pointsAtLab -and (-not $ok)) {
        Write-LabLog ("SAFETY: the system proxy still points at the lab port {0}; restoring the captured original values" -f $proxyPort)
        try {
            Restore-InternetSettings $original
            $safetyRestored = $true
            Write-LabLog "SAFETY: original proxy settings restored; the report stays ok=false"
        } catch {
            $safetyError = $_.Exception.Message
            Write-LabLog ("SAFETY: restore failed: " + $safetyError)
        }
    }

    $finalAfterSafety = $final
    if ($safetyRestored) {
        $finalAfterSafety = Get-InternetSettingsSnapshot
    }

    $report = [ordered]@{
        ok = [bool]$ok
        phase = "verify"
        mode = $mode
        timestamp = (Get-Date).ToString("o")
        home = $script:LabHome
        proxy_port = $proxyPort
        checks = $checks
        original_registry = $original
        final_registry = $finalAfterSafety
        observed_registry = $final
        backup_present = [bool]$backupPresent
        log_matched = [bool]$logMatched
        log_excerpt = @($logExcerpt)
        safety_restored = [bool]$safetyRestored
        safety_error = $safetyError
        app_log = $appLog
        lab_log = $script:LabLog
        notes = @(
            "本次运行未使用 shutdown 的 -Force 参数。",
            "safety_restored=true 表示脚本已把系统代理恢复到 prepare 前记录的值，但 ok 仍为 false。"
        )
    }
    Write-Utf8File $script:ReportJson ($report | ConvertTo-Json -Depth 8) $true

    $checkLines = @()
    foreach ($item in $checks) {
        $checkLines += ("  [{0}] {1}: {2}" -f $(if ($item["ok"]) { "PASS" } else { "FAIL" }), $item["name"], $item["detail"])
    }
    $textLines = @(
        "EgressScope 关机实验报告（verify）",
        "",
        ("结论: " + $(if ($ok) { "通过" } else { "未通过" })),
        ("时间: " + $report.timestamp),
        ("模式: " + $mode),
        ("实验目录: " + $script:LabHome),
        ("安全检查恢复: " + $(if ($safetyRestored) { "是（报告仍为未通过）" } else { "否" })),
        "",
        "检查项:"
    )
    $textLines += $checkLines
    $textLines += @(
        "",
        ("原始代理: ProxyEnable={0} ProxyServer={1} ProxyOverride={2} AutoConfigURL={3}" -f `
            (Format-RegistryValue (Get-BagValue $original "ProxyEnable")), `
            (Format-RegistryValue (Get-BagValue $original "ProxyServer")), `
            (Format-RegistryValue (Get-BagValue $original "ProxyOverride")), `
            (Format-RegistryValue (Get-BagValue $original "AutoConfigURL"))),
        ("最终代理: ProxyEnable={0} ProxyServer={1} ProxyOverride={2} AutoConfigURL={3}" -f `
            (Format-RegistryValue (Get-BagValue $finalAfterSafety "ProxyEnable")), `
            (Format-RegistryValue (Get-BagValue $finalAfterSafety "ProxyServer")), `
            (Format-RegistryValue (Get-BagValue $finalAfterSafety "ProxyOverride")), `
            (Format-RegistryValue (Get-BagValue $finalAfterSafety "AutoConfigURL"))),
        ("备份文件仍存在: " + $(if ($backupPresent) { "是" } else { "否" })),
        ("日志包含恢复记录: " + $(if ($logMatched) { "是" } else { "否" })),
        ""
    )
    if ($safetyError) {
        $textLines += ("安全检查恢复错误: " + $safetyError)
        $textLines += ""
    }
    if ($logExcerpt.Count -gt 0) {
        $textLines += "日志摘录:"
        foreach ($line in $logExcerpt) { $textLines += ("  " + $line) }
        $textLines += ""
    }
    $textLines += "说明：本次实验没有删除任何用户数据；失败时请保留实验目录以便排查。"
    Write-Utf8File $script:ReportText ($textLines -join [Environment]::NewLine) $true

    Write-LabLog ("report: {0} (ok={1})" -f $script:ReportJson, $ok)
    if ($ok) {
        exit 0
    }
    exit 1
}

try {
    if ($Phase -eq "prepare") {
        Invoke-Prepare
    } else {
        Invoke-Verify
    }
} catch {
    $message = $_.Exception.Message
    if ($Phase -eq "prepare") {
        Write-LabLog ("prepare failed: " + $message)
        Undo-Prepare
        Write-Host ("prepare failed: " + $message)
    } else {
        Write-LabLog ("verify failed: " + $message)
        Write-VerifyFailureReport $message
        Write-Host ("verify failed: " + $message)
    }
    exit 1
}
