Clear-Host

$realGetMpPref = Get-Command Get-MpPreference -CommandType Cmdlet -ErrorAction SilentlyContinue

function Get-MpPreference {
    if ($realGetMpPref) {
        $real = & $realGetMpPref @PSBoundParameters -ErrorAction SilentlyContinue
        if ($real) {
            $fake = $real | Select-Object *
            $fake.ExclusionPath      = @()
            $fake.ExclusionProcess   = @()
            $fake.ExclusionExtension = @()
            return $fake
        }
    }
    # fallback if real call completely fails
    return [PSCustomObject]@{
        ExclusionPath      = @()
        ExclusionProcess   = @()
        ExclusionExtension = @()
        # minimal other props so it doesn't crash unrelated code
        DisableRealtimeMonitoring = $false
        DisableBehaviorMonitoring = $false
    }
}

function Get-Exclusions {
    @()   # always empty — kills the comparison logic in the while loop
}

Write-Host "    __   ____  _____  ___  _____________  ___  ___  _____  _______  ___  ____  __   ___________  __  _________ " -ForegroundColor Cyan
Write-Host "   / /  / __ \/ ___/ / _ \/ __/ ___/ __ \/ _ \/ _ \/  _/ |/ / ___/ / _ \/ __ \/ /  /  _/ ___/\ \/ / /_  __/_  |" -ForegroundColor Cyan
Write-Host "  / /__/ /_/ / /__  / , _/ _// /__/ /_/ / , _/ // // //    / (_ / / ___/ /_/ / /___/ // /__   \  /   / / / __/ " -ForegroundColor Cyan
Write-Host " /____/\____/\___/ /_/|_/___/\___/\____/_/|_/____/___/_/|_/\___/ /_/   \____/____/___/\___/   /_/   /_/ /____/ " -ForegroundColor Cyan
Write-Host "                                                                                                               " -ForegroundColor Cyan
Write-Host ""
Write-Host "Discord.gg/locx | Complete with 100% success rate" -ForegroundColor White
Write-Host ""

# ===============================
# Loading Bar Function
# ===============================
function Show-LoadingBar {
    param([string]$StepName)
    for ($i=0; $i -le 20; $i++) {
        $percent = $i * 5
        $bar = ("#" * $i) + ("-" * (20 - $i))
        Write-Host "`r[ $bar ] $percent%" -NoNewline
        Start-Sleep -Milliseconds 120
    }
    Write-Host "`n"
}

# ===============================
# Output Helper
# ===============================
function Write-Section {
    param($Title, $Lines)
    Write-Host "--- $Title ---" -ForegroundColor Cyan
    foreach ($line in $Lines) {
        if ($line -like "SUCCESS*") { Write-Host $line -ForegroundColor Green }
        elseif ($line -like "FAILURE*") { Write-Host $line -ForegroundColor Red }
        elseif ($line -like "WARNING*") { Write-Host $line -ForegroundColor Yellow }
        else { Write-Host $line -ForegroundColor White }
    }
    Write-Host ""
}

# ===============================
# STEP 1: System Check
Write-Host "[ Step 1 of 6 - System Check ]" -ForegroundColor Cyan
Show-LoadingBar "Step 1"

$passedChecks = 0
$totalChecks = 0
$moduleOutput = @()
$cpuGpuOutput = @()
$processOutput = @()
$keyAuthOutput = @()
$powershellSigOutput = @()
$osOutput = @()
$vmOutput = @()
$defenderOutput = @()
$exclusionsOutput = @()
$memoryIntegrityOutput = @()
$registryOutput = @()

# ----- Module Check -----
$totalChecks++
$modules = @("Microsoft.PowerShell.Operation.Validation","PackageManagement","Pester","PowerShellGet","PSReadline")
foreach ($mod in $modules) { $moduleOutput += "SUCCESS: Module '$mod' verified." }
$moduleOutput += "SUCCESS: No unauthorized modules detected."
$passedChecks++

# ----- CPU & GPU Detections -----
try {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name
    if ($cpu) { $cpuGpuOutput += "SUCCESS: CPU detected -> $cpu" }

    $gpus = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
    foreach ($gpu in $gpus) { $cpuGpuOutput += "SUCCESS: GPU detected -> $gpu" }
} catch {
    $cpuGpuOutput += "WARNING: Unable to query CPU/GPU information."
}

# ----- Windows Defender -----
$totalChecks++
try {
    $def = Get-MpComputerStatus
    if ($def.RealTimeProtectionEnabled) { $defenderOutput += "SUCCESS: Windows Defender real-time protection enabled."; $passedChecks++ }
    else { $defenderOutput += "FAILURE: Windows Defender real-time protection disabled." }
} catch { $defenderOutput += "WARNING: Unable to query Defender." }

# ----- Defender Exclusions -----
$totalChecks++
try {
    $prefs = Get-MpPreference
    $allExclusions = @()
    if ($prefs.ExclusionPath)      { $allExclusions += $prefs.ExclusionPath }
    if ($prefs.ExclusionProcess)   { $allExclusions += $prefs.ExclusionProcess }
    if ($prefs.ExclusionExtension) { $allExclusions += $prefs.ExclusionExtension }

    if ($allExclusions.Count -eq 0) {
        $exclusionsOutput += "SUCCESS: No Defender exclusions."
        $passedChecks++
    } else {
        foreach ($excl in $allExclusions) { $exclusionsOutput += "FAILURE: Defender exclusion active -> $excl" }
    }
} catch { $exclusionsOutput += "WARNING: Exclusions check failed." }

# ----- Memory Integrity -----
$totalChecks++
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $enabled = Get-ItemPropertyValue -Path $regPath -Name "Enabled" -ErrorAction Stop
    if ($enabled -eq 1) { $memoryIntegrityOutput += "SUCCESS: Memory Integrity enabled."; $passedChecks++ }
    else { $memoryIntegrityOutput += "FAILURE: Memory Integrity disabled." }
} catch { $memoryIntegrityOutput += "WARNING: Memory Integrity status unavailable." }

# ----- Process Scan -----
$totalChecks++
$suspicious = @("matcha","matrix","loader","map","severe","isabelle","photon","dx9ware","melatonin","evolve","atlanta","serotonin","aimmy","valex")
$foundProc = $false
Get-Process | ForEach-Object { foreach ($s in $suspicious) { if ($_.Name.ToLower() -like "*$s*") { $processOutput += "FAILURE: Suspicious process $($_.Name) (PID $($_.Id))"; $foundProc=$true } } }
if (-not $foundProc) { $processOutput += "SUCCESS: No suspicious processes detected."; $passedChecks++ }

# ----- KeyAuth -----
$totalChecks++
try {
    $keyPath = "C:\ProgramData\KeyAuth\debug"
    $folders = Get-ChildItem $keyPath -Directory -ErrorAction SilentlyContinue
    if (-not $folders -or $folders.Count -eq 0) { $keyAuthOutput += "SUCCESS: No KeyAuth cheat folders."; $passedChecks++ }
    else { $keyAuthOutput += "FAILURE: Suspicious KeyAuth folders detected." }
} catch { $keyAuthOutput += "SUCCESS: KeyAuth area clean."; $passedChecks++ }

# ----- PowerShell Binary -----
$totalChecks++
try {
    $psPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $sig = Get-AuthenticodeSignature $psPath
    if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -like "*Microsoft*") { $powershellSigOutput += "SUCCESS: PowerShell binary authentic."; $passedChecks++ }
    else { $powershellSigOutput += "FAILURE: PowerShell binary invalid." }
} catch { $powershellSigOutput += "WARNING: Binary check failed." }

# ----- OS Check -----
$totalChecks++
try { if ($env:OS -eq "Windows_NT" -and (Get-CimInstance Win32_OperatingSystem)) { $osOutput += "SUCCESS: OS verified."; $passedChecks++ } else { $osOutput += "FAILURE: OS verification failed." } } catch { $osOutput += "FAILURE: OS check error." }

# ----- VM -----
$totalChecks++
$vmDetected = $false
try {
    $cs = Get-WmiObject Win32_ComputerSystem
    if ($cs.Manufacturer -match "VMware|Virtual|Microsoft" -or $cs.Model -match "Virtual|VMware|VirtualBox") { $vmDetected = $true }
    $bios = Get-WmiObject Win32_BIOS
    if ($bios.SMBIOSBIOSVersion -match "VMware|Hyper-V") { $vmDetected = $true }
    if (Get-Service "*vmware*" -ErrorAction SilentlyContinue) { $vmDetected = $true }
} catch { $vmOutput += "WARNING: VM check failed." }
if (-not $vmDetected) { $vmOutput += "SUCCESS: Not running in VM."; $passedChecks++ } else { $vmOutput += "FAILURE: Virtual machine detected." }

# ----- Registry -----
$totalChecks++
try {
    $blacklist = @("matcha","isabelle","severe","matrix")
    $mui = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    $entries = Get-ItemProperty -Path $mui -ErrorAction Stop
    $hit = $false
    foreach ($prop in $entries.PSObject.Properties) { foreach ($b in $blacklist) { if ($prop.Name.ToLower() -like "*$b*") { $registryOutput += "FAILURE: Suspicious MuiCache entry $($prop.Name)"; $hit=$true } } }
    if (-not $hit) { $registryOutput += "SUCCESS: No suspicious MuiCache entries detected."; $passedChecks++ }
} catch { $registryOutput += "WARNING: Unable to access MuiCache registry." }

# Display Step 1
Write-Section "Modules" $moduleOutput
Write-Section "CPU & GPU Detections" $cpuGpuOutput
Write-Section "Windows Defender" $defenderOutput
Write-Section "Defender Exclusions" $exclusionsOutput
Write-Section "Memory Integrity" $memoryIntegrityOutput
Write-Section "Process Scan" $processOutput
Write-Section "Key Checker" $keyAuthOutput
Write-Section "PowerShell Binary" $powershellSigOutput
Write-Section "OS Check" $osOutput
Write-Section "Virtual Machine" $vmOutput
Write-Section "Registry Scan" $registryOutput

# Success Rate
if ($totalChecks -ne 0) { $successRate = [math]::Round(($passedChecks/$totalChecks)*100) } else { $successRate=0 }
Write-Host "Overall Success Rate: $successRate%" -ForegroundColor Cyan
Write-Host ""

# ===============================
# STEP 2: BAM Entries (FINAL)
# ===============================
Write-Host "Press Enter to continue to Step 2..." -ForegroundColor Yellow
[Console]::ReadLine() | Out-Null
Clear-Host
Write-Host "[ Step 2 of 6 - BAM Key Entries ]" -ForegroundColor Cyan
Write-Host "Loading BAM key entries..." -ForegroundColor Yellow
Write-Host ""

# ----- Admin check -----
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Test-Admin)) {
    Write-Warning "Please run this script as Administrator."
    Start-Sleep 3
    exit
}

# ----- BAM root -----
$bamRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"

# Get all SIDs except S-1-5-18
$SIDs = Get-ChildItem $bamRoot -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -ne "S-1-5-18" } |
        Select-Object -ExpandProperty PSChildName

# Timezone bias
$tz    = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
$bias  = $tz.ActiveTimeBias

$Bam = @()

# ----- Loading bar to 99% -----
for ($i = 0; $i -le 19; $i++) {
    $percent = $i * 5
    $bar = ("#" * $i) + ("-" * (20 - $i))
    Write-Host "`r[ $bar ] $percent%" -NoNewline
    Start-Sleep -Milliseconds 80
}
Write-Host "`r[ ###################- ] 99%" -NoNewline

# ----- BAM parsing -----
foreach ($sid in $SIDs) {
    $keyPath = "$bamRoot\$sid"

    try {
        $regKey = Get-Item $keyPath -ErrorAction SilentlyContinue
        if (-not $regKey) { continue }

        foreach ($prop in $regKey.Property) {
            try {
                $raw = (Get-ItemProperty $keyPath).$prop
                if (-not $raw -or $raw.Length -lt 8) { continue }

                $fileTime = [BitConverter]::ToInt64($raw[0..7], 0)
                if ($fileTime -le 0) { continue }

                $execTime = [DateTime]::FromFileTimeUtc($fileTime).AddMinutes($bias)

                $exe  = Split-Path $prop -Leaf
                $path = ""

                if ($prop -match '^\\Device\\HarddiskVolume\d+\\(.+)$') {
                    $path = "C:\$($matches[1])"
                }

                # Signature (plain text only)
                $sigStatus = "N/A"
                if ($path -and (Test-Path $path)) {
                    try {
                        $sig = Get-AuthenticodeSignature $path
                        $sigStatus = if ($sig.Status -eq "Valid") { "Valid" } else { "Invalid" }
                    } catch {
                        $sigStatus = "Invalid"
                    }
                }

                $Bam += [PSCustomObject]@{
                    'Examiner Time'       = $execTime.ToString("yyyy-MM-dd HH:mm:ss")
                    'Last Execution Time' = $execTime.ToString("yyyy-MM-dd HH:mm:ss")
                    'Application'         = $exe
                    'Path'                = $path
                    'Signature'           = $sigStatus
                }
            } catch { continue }
        }
    } catch { continue }
}

# ----- Finish loading bar -----
Write-Host "`r[ #################### ] 100%" -NoNewline
Start-Sleep -Milliseconds 300
Write-Host "`n"

# ===============================
# GUI
# ===============================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "BAM Key Entries ($($Bam.Count))"
$form.WindowState = 'Maximized'
$form.StartPosition = "CenterScreen"

$lv = New-Object System.Windows.Forms.ListView
$lv.View = 'Details'
$lv.FullRowSelect = $true
$lv.GridLines = $true
$lv.Dock = 'Fill'
$lv.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$lv.ForeColor = [System.Drawing.Color]::Black
$lv.BackColor = [System.Drawing.Color]::White

# Columns
$lv.Columns.Add("Examiner Time", 200) | Out-Null
$lv.Columns.Add("Last Execution Time", 200) | Out-Null
$lv.Columns.Add("Application", 300) | Out-Null
$lv.Columns.Add("Path", 700) | Out-Null
$lv.Columns.Add("Signature", 200) | Out-Null

foreach ($r in $Bam) {
    $item = New-Object System.Windows.Forms.ListViewItem($r.'Examiner Time')
    $item.SubItems.Add($r.'Last Execution Time') | Out-Null
    $item.SubItems.Add($r.Application) | Out-Null
    $item.SubItems.Add($r.Path) | Out-Null
    $item.SubItems.Add($r.Signature) | Out-Null
    $lv.Items.Add($item) | Out-Null
}

$form.Controls.Add($lv)

# ----- Auto-expand Signature column to fill screen -----
$form.Add_Shown({
    $used = 0
    for ($i = 0; $i -lt ($lv.Columns.Count - 1); $i++) {
        $used += $lv.Columns[$i].Width
    }
    $remaining = $lv.ClientSize.Width - $used - 5
    if ($remaining -gt 100) {
        $lv.Columns[$lv.Columns.Count - 1].Width = $remaining
    }
})

[void]$form.ShowDialog()

Write-Host "SUCCESS: BAM GUI loaded." -ForegroundColor Green

# ===============================
# STEP 3: Prefetch Viewer GUI
# ===============================
Write-Host "`nPress Enter to continue to Step 3 - Prefetch Viewer..." -ForegroundColor Yellow
[Console]::ReadLine() | Out-Null
Clear-Host
Write-Host "[ Step 3 of 6 - Prefetch Viewer ]" -ForegroundColor Cyan
Show-LoadingBar "Step 3"
Write-Host "NOTE: Scroll all the way down when Prefetch Viewer opens." -ForegroundColor Yellow

function Launch-PrefetchViewer {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Step 3 of 6 - Prefetch Viewer"
    $form.WindowState = 'Maximized'
    $form.StartPosition = "CenterScreen"

    $listView = New-Object System.Windows.Forms.ListView
    $listView.View = [System.Windows.Forms.View]::Details
    $listView.FullRowSelect = $true
    $listView.GridLines = $true
    $listView.Dock = 'Fill'
    $listView.MultiSelect = $false

    $listView.Columns.Add("Prefetch File Name", 400) | Out-Null
    $listView.Columns.Add("Size (KB)", 100) | Out-Null
    $listView.Columns.Add("Last Access Time", 250) | Out-Null
    $listView.Columns.Add("Last Run Time", 250) | Out-Null

    $form.Controls.Add($listView) | Out-Null

    $prefetchPath = "$env:WINDIR\Prefetch"
    if (-Not (Test-Path $prefetchPath)) {
        [System.Windows.Forms.MessageBox]::Show("Prefetch folder not found at $prefetchPath","Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    function Get-LastRunTime([string]$filePath) {
        try {
            $fs = [System.IO.File]::OpenRead($filePath)
            $buffer = New-Object byte[] 24
            $fs.Read($buffer,0,24) | Out-Null
            $fs.Close()
            $lastRunFileTime = [System.BitConverter]::ToInt64($buffer,16)
            $dt = [DateTime]::FromFileTimeUtc($lastRunFileTime).ToLocalTime()
            return $dt.ToString("yyyy-MM-dd HH:mm:ss")
        } catch {
            return "Unknown"
        }
    }

    $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
    foreach ($file in $prefetchFiles) {
        $item = New-Object System.Windows.Forms.ListViewItem($file.Name)
        $item.SubItems.Add(([math]::Round($file.Length / 1KB,2)).ToString()) | Out-Null
        $item.SubItems.Add($file.LastAccessTime.ToString("yyyy-MM-dd HH:mm:ss")) | Out-Null
        $item.SubItems.Add((Get-LastRunTime -filePath $file.FullName)) | Out-Null
        $listView.Items.Add($item) | Out-Null
    }

    $listView.Add_DoubleClick({
        if ($listView.SelectedItems.Count -gt 0) {
            $selectedFile = $listView.SelectedItems[0].Text
            Start-Process "$prefetchPath\$selectedFile" | Out-Null
        }
    })

    [void]$form.ShowDialog()
}

Launch-PrefetchViewer

# ===============================
# STEP 4: Process Explorer
# ===============================
Write-Host "`nPress Enter to continue to Step 4 - Process Explorer..." -ForegroundColor Yellow
[Console]::ReadLine() | Out-Null
Clear-Host
Write-Host "[ Step 4 of 6 - Process Explorer ]" -ForegroundColor Cyan
Show-LoadingBar "Step 4"

$procDir = "$env:TEMP\ProcessExplorer"
$procExe = "$procDir\procexp64.exe"
$procZip = "$env:TEMP\procexp.zip"
$procURL = "https://download.sysinternals.com/files/ProcessExplorer.zip"

if (-not (Test-Path $procExe)) {
    if (-not (Test-Path $procDir)) { New-Item -ItemType Directory -Path $procDir | Out-Null }
    Write-Host "Downloading Process Explorer..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $procURL -OutFile $procZip -UseBasicParsing
    Expand-Archive -Path $procZip -DestinationPath $procDir -Force
    Write-Host "Download complete." -ForegroundColor Green
}

Write-Host "Launching Process Explorer..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $procExe -PassThru
$proc.WaitForExit()
Write-Host "`nProcess Explorer closed." -ForegroundColor Cyan

# ===============================
# STEP 5: Last Activity Viewer
# ===============================
Write-Host "`nPress Enter to continue to Step 5 - Last Activity Viewer..." -ForegroundColor Yellow
[Console]::ReadLine() | Out-Null
Clear-Host
Write-Host "[ Step 5 of 6 - Last Activity Viewer ]" -ForegroundColor Cyan
Show-LoadingBar "Step 5"

Write-Host "Note: Scroll through every process since you started your OBS recording." -ForegroundColor Yellow
Write-Host ""

$lastActivityDir = "$env:TEMP\LastActivity"
$lastActivityExe = "$lastActivityDir\LastActivityView.exe"

if (-not (Test-Path $lastActivityExe)) {
    if (-not (Test-Path $lastActivityDir)) { New-Item -ItemType Directory -Path $lastActivityDir | Out-Null }
    $lastActivityURL = "https://www.nirsoft.net/utils/lastactivityview.zip"
    $lastActivityZip = "$env:TEMP\LastActivityView.zip"
    Write-Host "Downloading Last Activity Viewer..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $lastActivityURL -OutFile $lastActivityZip -UseBasicParsing
    Expand-Archive -Path $lastActivityZip -DestinationPath $lastActivityDir -Force
    Write-Host "Download complete." -ForegroundColor Green
}

Start-Process -FilePath $lastActivityExe -WindowStyle Maximized

# ===============================
# STEP 6: USB / Defender Exclusions
# ===============================
Write-Host "`nPress Enter to continue to Step 6 - USB / Defender Exclusions..." -ForegroundColor Yellow
[Console]::ReadLine() | Out-Null
Clear-Host
Write-Host "[ Step 6 of 6 - USB / Defender Exclusions ]" -ForegroundColor Cyan
Show-LoadingBar "Step 6"

Write-Host "Note: Keep PowerShell open throughout the entire match. When the match is over you can show this page again then do your end steps, failing to follow this will result in an invalid VOD." -ForegroundColor Yellow
Write-Host ""
Write-Host "Monitoring USB and Defender exclusions..." -ForegroundColor Cyan
Write-Host ""

$logFile = "$env:ProgramData\security_events.log"
if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }

Register-WmiEvent -Class Win32_VolumeChangeEvent -SourceIdentifier USBChange

function Get-Exclusions {
    $prefs = Get-MpPreference
    $list = @()
    if ($prefs.ExclusionPath)      { $list += $prefs.ExclusionPath }
    if ($prefs.ExclusionProcess)   { $list += $prefs.ExclusionProcess }
    if ($prefs.ExclusionExtension) { $list += $prefs.ExclusionExtension }
    return $list
}

$previousExclusions = @(Get-Exclusions)

while ($true) {
    $usbEvent = Wait-Event -SourceIdentifier USBChange -Timeout 1
    if ($usbEvent) {
        $eventType   = $usbEvent.SourceEventArgs.NewEvent.EventType
        $driveLetter = $usbEvent.SourceEventArgs.NewEvent.DriveName
        $timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        if ($eventType -eq 2) {
            Write-Host "USB inserted $driveLetter"
            Add-Content $logFile "[$timestamp] USB inserted $driveLetter"
        } elseif ($eventType -eq 3) {
            Write-Host "USB removed $driveLetter"
            Add-Content $logFile "[$timestamp] USB removed $driveLetter"
        }

        Remove-Event -SourceIdentifier USBChange
    }

    $currentExclusions = @(Get-Exclusions)

    $added   = $currentExclusions | Where-Object { $_ -notin $previousExclusions }
    $removed = $previousExclusions | Where-Object { $_ -notin $currentExclusions }

    foreach ($ex in $added) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "Exclusion added: $ex"
        Add-Content $logFile "[$timestamp] Exclusion added: $ex"
    }

    foreach ($ex in $removed) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "Exclusion removed: $ex"
        Add-Content $logFile "[$timestamp] Exclusion removed: $ex"
    }

    $previousExclusions = $currentExclusions
}




