##########################################################
########## Created by Luciano Guimaraes Garcia ###########
################### Master Script V6 #####################
##########################################################

function banner
{	
	Add-Type -AssemblyName System.Windows.Forms

	$message = @"
Welcome to this Script
Developed by Luciano Guimaraes Garcia
https://lucianogg.info

This script has no warranty at all.
Use at your own risk.
"@

	[System.Windows.Forms.MessageBox]::Show($message, "Script Banner", 'OK', 'Information')
	
}

function goodbye
{
	Add-Type -AssemblyName System.Windows.Forms

	$message = @"
Developed by Luciano Guimaraes Garcia

If there's any problem with this script, please ping me:
https://lucianogg.info

"@

	[System.Windows.Forms.MessageBox]::Show($message, "Script Banner", 'OK', 'Information')
}

function menu
{
	$menuOptions = @(
		[PSCustomObject]@{ Option = "Configuring Tasks"; Value = "CONFIGURE" }
		[PSCustomObject]@{ Option = "Backuping Tasks"; Value = "BACKUP" }
		[PSCustomObject]@{ Option = "Windows Tools"; Value = "WIN_TOOLS" }
		[PSCustomObject]@{ Option = "EXIT"; Value = "EXIT" }
	)
	
	$selection = $menuOptions | Out-GridView -Title "Select a Task Category" -PassThru
	if (-not $selection) { Write-Host "No selection made. Exiting..." -ForegroundColor Yellow; return }
	
	switch ($selection.Value) {
		"CONFIGURE" {
			$subOptions = @(
				@{ Name = "Set Language"; Action = "SetLanguage" }
				@{ Name = "Install Printer"; Action = "InstallPrinter" }
				@{ Name = "Configure lid to DO NOTHING"; Action = "ConfigureLID" }
				@{ Name = "Verify Bitlocker"; Action = "VerifyBitlocker" }
			)
			$choice = $subOptions | ForEach-Object { [PSCustomObject]$_ } | Out-GridView -Title "Configuring Tasks" -PassThru
			if ($choice) { & $choice.Action }
		}
		
		"BACKUP" {
			$subOptions = @(
				@{ Name = "Backup Profiles Stuff"; Action = "ProfileBackup" }
				@{ Name = "Manage Network Folders"; Action = "NetworkDrives" }
				@{ Name = "Backup LOCAL Files"; Action = "LocalFilesBackup" }
			)
			$choice = $subOptions | ForEach-Object { [PSCustomObject]$_ } | Out-GridView -Title "Backuping Tasks" -PassThru
			if ($choice) { & $choice.Action }
		}

		"WIN_TOOLS" {
			$subOptions = @(
				@{ Name = "Check Licenses"; Action = "checkLicense" }
				@{ Name = "Get PC Info"; Action = "GetPCInfo" }
				@{ Name = "Check and Repair Disc"; Action = "CHDSK" }
				@{ Name = "Defrag Disks"; Action = "defrag" }
				@{ Name = "Test Disk Speed"; Action = "diskSpeed" }
				@{ Name = "Check and Repair File System"; Action = "CHFS" }
				@{ Name = "Check File Integrity"; Action = "CHFH" }
				@{ Name = "Clean TEMP files"; Action = "cleanTemp" }
				@{ Name = "Check Memory Erros"; Action = "CHMEM" }
				@{ Name = "Restore System"; Action = "restoreSys" }
				@{ Name = "Clear DNS Cache"; Action = "clearDNS" }
				@{ Name = "Restart Network Services"; Action = "restartNet" }
				@{ Name = "Manage Certificates"; Action = "certMan" }
				@{ Name = "Manage Users"; Action = "usrMan" }
				@{ Name = "Manage Events"; Action = "eventMan" }
				@{ Name = "Manage Registry"; Action = "regMan" }
				@{ Name = "Update All Programs (Winget)"; Action = "updateAll" }
			)
			$choice = $subOptions | ForEach-Object { [PSCustomObject]$_ } | Out-GridView -Title "MISC Tasks" -PassThru
			if ($choice) { & $choice.Action }
		}
		
		"DRIVERS" {
			installDrivers
		}
		
		"EXIT" {
			goodbye
			exit
		}
	}	
}

function SetLanguage 
{
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Status    = "ERROR"
            Message   = "This script must be run as Administrator to install language packs."
        } | Out-GridView -Title "Permission Error" -Wait
        return
    }

    $langOptions = @(
        [PSCustomObject]@{ Code = 'pt-BR'; Name = 'Portuguese (Brasil)' },
        [PSCustomObject]@{ Code = 'en-US'; Name = 'English (United States)' },
        [PSCustomObject]@{ Code = 'es-ES'; Name = 'Spanish (Spain)' }
        [PSCustomObject]@{ Code = 'fr-FR'; Name = 'French (France)' },
        [PSCustomObject]@{ Code = 'de-DE'; Name = 'German (Germany)' },
        [PSCustomObject]@{ Code = 'it-IT'; Name = 'Italian (Italy)' }
    )
    
    $selected = $langOptions | Out-GridView -Title "Select Target System Language" -OutputMode Single
    if (-not $selected) { return }
    $TargetLang = $selected.Code
    $logEntries = [System.Collections.Generic.List[PSObject]]::new()
    function Add-Log {
        param ($Message, $Status)
        $logEntries.Add([PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Status    = $Status
            Message   = $Message
        })
    }

    $currentUILang = (Get-SystemPreferredUILanguage)
    if ($currentUILang -eq $TargetLang) {
        Add-Log -Message "System UI is already set to $TargetLang. No changes needed." -Status "Info"
        $logEntries | Out-GridView -Title "Language Setup Result" -Wait
        return
    }
    Add-Log -Message "Current Language: $currentUILang. Target: $TargetLang." -Status "Info"

    if (-not (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet)) {
        Add-Log -Message "No internet connection detected. Download will likely fail." -Status "Warning"
    }
    try {
        Add-Log -Message "Step 1/3: Downloading and Installing Language Pack ($TargetLang)..." -Status "Processing"
        Install-Language -Language $TargetLang -CopyToSettings -ErrorAction Stop        
        Add-Log -Message "Language pack installed." -Status "Success"
        Add-Log -Message "Step 2/3: Updating User Language List (Keyboards/Formats)..." -Status "Processing"
        $langList = New-WinUserLanguageList -Language $TargetLang
        Set-WinUserLanguageList -LanguageList $langList -Force -Confirm:$false -ErrorAction Stop
        Add-Log -Message "Step 3/3: Setting System Display Language (UI)..." -Status "Processing"
        Set-SystemPreferredUILanguage -Language $TargetLang -ErrorAction Stop
        Add-Log -Message "Configuration Complete." -Status "Success"
        Add-Log -Message ">> A FULL REBOOT IS REQUIRED TO APPLY CHANGES <<" -Status "ACTION REQUIRED"
    }
    catch {
        Add-Log -Message "Error: $($_.Exception.Message)" -Status "Critical Error"
        Add-Log -Message "Hint: Ensure Windows Update service is running." -Status "Hint"
    }
    
    $logEntries | Out-GridView -Title "Language Setup Result: $TargetLang" -Wait
}

function ProfileBackup 
{
	Add-Type -AssemblyName System.Windows.Forms

    $modeOptions = @('Backup', 'Restore')
    $Mode = $modeOptions | Out-GridView -Title "Select Operation Mode" -OutputMode Single

    if ([string]::IsNullOrWhiteSpace($Mode)) {
        Write-Warning "Operation cancelled by user (No mode selected)."
        return
    }

    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the root folder to $Mode data"
    $folderBrowser.ShowNewFolderButton = $true

    $folderBrowser.SelectedPath = [System.Environment]::GetFolderPath('Desktop')
    $dialogResult = $folderBrowser.ShowDialog()

    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $LocationPath = $folderBrowser.SelectedPath
    }
    else {
        Write-Warning "Operation cancelled by user (No folder selected)."
        return
    }
    $logEntries = [System.Collections.Generic.List[PSObject]]::new()
    function Add-Log {
        param ($App, $Status, $Message)
        $logEntries.Add([PSCustomObject]@{
            Timestamp   = Get-Date -Format "HH:mm:ss"
            Application = $App
            Action      = $Mode
            Status      = $Status
            Message     = $Message
        })
    }
    $appsConfig = @(
        @{
            Name       = "Edge"
            SystemPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
            Filter     = "Bookmarks*"
        },
        @{
            Name       = "Chrome"
            SystemPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
            Filter     = "Bookmarks*"
        },
        @{
            Name       = "Outlook_Signatures"
            SystemPath = "$env:APPDATA\Microsoft\Signatures" 
            Filter     = "*" # Backs up all signature files (htm, rtf, txt)
        }
    )
    Add-Log -App "System" -Status "Info" -Message "Starting $Mode process in: $LocationPath"

    foreach ($app in $appsConfig) {
        $appName = $app.Name
        $sysPath = $app.SystemPath
        $filter  = $app.Filter
        $backupSubFolder = Join-Path -Path $LocationPath -ChildPath $appName
        
        if ($Mode -eq 'Backup') {
            try {
                if (Test-Path -Path $sysPath) {
                    if (-not (Test-Path -Path $backupSubFolder)) {
                        New-Item -Path $backupSubFolder -ItemType Directory -Force | Out-Null
                    }
                    Copy-Item -Path "$sysPath\$filter" -Destination $backupSubFolder -Recurse -Force -ErrorAction Stop
                    Add-Log -App $appName -Status "Success" -Message "Backed up to $backupSubFolder"
                }
                else {
                    Add-Log -App $appName -Status "Skipped" -Message "Application path not found on this computer."
                }
            }
            catch {
                Add-Log -App $appName -Status "Error" -Message "Backup failed: $($_.Exception.Message)"
            }
        }
        elseif ($Mode -eq 'Restore') {
            try {
                if (Test-Path -Path $backupSubFolder) {
                    if (-not (Test-Path -Path $sysPath)) {
                        New-Item -Path $sysPath -ItemType Directory -Force | Out-Null
                    }
                    Copy-Item -Path "$backupSubFolder\$filter" -Destination $sysPath -Recurse -Force -ErrorAction Stop
                    Add-Log -App $appName -Status "Success" -Message "Restored from $backupSubFolder"
                }
                else {
                    Add-Log -App $appName -Status "Warning" -Message "No backup found in $backupSubFolder"
                }
            }
            catch {
                Add-Log -App $appName -Status "Error" -Message "Restore failed: $($_.Exception.Message)"
            }
        }
    }
    $logEntries | Out-GridView -Title "Profile Manager Report: $Mode" -Wait
}

function NetworkDrives 
{
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName Microsoft.VisualBasic

    $modeOptions = @('Backup', 'Restore')
    $Mode = $modeOptions | Out-GridView -Title "Select Network Drive Operation" -OutputMode Single

    if ([string]::IsNullOrWhiteSpace($Mode)) {
        return
    }
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the folder to save/read the drive mapping file"
    $folderBrowser.ShowNewFolderButton = $true
    $folderBrowser.SelectedPath = [System.Environment]::GetFolderPath('Desktop')

    $dialogResult = $folderBrowser.ShowDialog()
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $LocationPath = $folderBrowser.SelectedPath
    }
    else {
        return
    }

    $logEntries = [System.Collections.Generic.List[PSObject]]::new()    
    function Add-Log {
        param ($Status, $Message)
        $logEntries.Add([PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Action    = $Mode
            Status    = $Status
            Message   = $Message
        })
    }

    $txtFileName = "Manual_Restore_NetworkDrives.txt"
    $txtFullPath = Join-Path -Path $LocationPath -ChildPath $txtFileName    
    Add-Log -Status "Info" -Message "Starting Network Drive manager..."

    if ($Mode -eq 'Backup') {
        try {
            $mappedDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -ne $null -and $_.Root -notlike "C:\" }           
            if ($mappedDrives) {
                if (-not (Test-Path -Path $LocationPath)) {
                    New-Item -Path $LocationPath -ItemType Directory -Force | Out-Null
                }
                
                $b_date = Get-Date
                "############################ $b_date ######################################" | Out-File -FilePath $txtFullPath -Append               
                $matrix = Get-PSDrive -PSProvider "FileSystem" | Where-Object { $_.root -notlike "C:\" }
                $commandString = ""
                foreach ($e in $matrix){
                    $i = "New-PSDrive -Persist -name " + $e.name + " -root `""+ $e.DisplayRoot + "`" -PSProvider Filesystem`r`n"
                    $commandString = $commandString + $i
                }
                $commandString | Out-File -FilePath $txtFullPath -Append               
                "##################################################################" | Out-File -FilePath $txtFullPath -Append
                                
                Add-Log -Status "Success" -Message "Backup created at: $txtFullPath"
                Add-Log -Status "Info" -Message "Drives found: $($mappedDrives.Count)"
            }
            else {
                Add-Log -Status "Warning" -Message "No mapped network drives found to backup."
            }
        }
        catch {
            Add-Log -Status "Error" -Message "Backup failed: $($_.Exception.Message)"
        }
    }
    
    elseif ($Mode -eq 'Restore') {
        try {
            if (Test-Path -Path $txtFullPath) {
                Add-Log -Status "Info" -Message "Reading file: $txtFullPath"
                $commands = Get-Content -Path $txtFullPath                
                foreach ($line in $commands) {
                    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) { continue }                    
                    if ($line -match "New-PSDrive") {
                        try {
                            $driveLetter = if ($line -match "-name ([a-zA-Z])") { $Matches[1] } else { "?" }
                            if (Get-PSDrive -Name $driveLetter -PSProvider FileSystem -ErrorAction SilentlyContinue) {
                                Add-Log -Status "Skipped" -Message "Drive $driveLetter already exists."
                            }
                            else {
                                Invoke-Expression -Command $line | Out-Null
                                Add-Log -Status "Success" -Message "Restored Drive $driveLetter"
                            }
                        }
                        catch {
                            Add-Log -Status "Error" -Message "Failed to map drive from line. Error: $($_.Exception.Message)"
                        }
                    }
                }
            }
            else {
                Add-Log -Status "Error" -Message "Restore file not found: $txtFullPath"
            }
        }
        catch {
            Add-Log -Status "Critical Error" -Message "Restore process failed: $($_.Exception.Message)"
        }
    }
    $logEntries | Out-GridView -Title "Network Drives Manager Report" -Wait
}

function InstallPrinter
{
	Add-Type -AssemblyName Microsoft.VisualBasic

    $ipAddress = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the printer's IP address:", "Printer Host Address", "")
    if ([string]::IsNullOrWhiteSpace($ipAddress)) {
        [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Status    = "CANCELLED"
            Printer   = "N/A"
            Message   = "User did not provide an IP address."
        } | Out-GridView -Title "Installation Result" -Wait
        return
    }
    $printerName = "IP_Printer_$($ipAddress)"
    $driverName  = "Microsoft IPP Class Driver" 
    $portName    = "IP_$($ipAddress)"
    $result = try {
        Write-Progress -Activity "IP Printer Setup" -Status "Installing $printerName using '$driverName'..." -PercentComplete 50
        if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {
            Add-PrinterPort -Name $portName -PrinterHostAddress $ipAddress -ErrorAction Stop
        }
        Add-Printer -Name $printerName -PortName $portName -DriverName $driverName -ErrorAction Stop
        (New-Object -ComObject WScript.Network).SetDefaultPrinter($printerName)
        
        Write-Progress -Activity "IP Printer Setup" -Completed $true
        [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Status    = "SUCCESS"
            Printer   = $printerName
            Message   = "Installed successfully using driver '$driverName'."
        }
    }
    catch {
        Write-Progress -Activity "IP Printer Setup" -Completed $true
        [PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Status    = "ERROR"
            Printer   = $printerName
            Message   = "Error: $($_.Exception.Message.Split("`n")[0])"
        }
    }
    $result | Out-GridView -Title "Installation Result" -Wait
}

function ConfigureLID
{
	powercfg -setacvalueindex 67ed59a6-5065-4632-bfe6-83c4d0704bf9 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
	powercfg -setdcvalueindex 67ed59a6-5065-4632-bfe6-83c4d0704bf9 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
	powercfg -SetActive 381b4222-f694-41f0-9685-ff5bb260df2e
	Write-Host "LID CONFIGURED"
	
	#powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
}

function LocalFilesBackup
{
    Add-Type -AssemblyName Microsoft.VisualBasic

    # --- GUI Step 1: Select Mode ---
    $modeOptions = @('Backup', 'Restore')
    $Mode = $modeOptions | Out-GridView -Title "Selecione a Operação" -OutputMode Single

    if ([string]::IsNullOrWhiteSpace($Mode)) {
        return # Usuário cancelou no início
    }

    # --- GUI Step 2: Select Folder Path ---
    $shell = New-Object -ComObject Shell.Application
    $msg = "Selecione a pasta raiz para o $Mode.`n`nNOTA: Se sua unidade de rede (Z:) não aparecer, CANCELE esta janela para digitar o caminho manualmente."
    # 17 = Meu Computador
    $folderObj = $shell.BrowseForFolder(0, $msg, 0, 17)

    if ($folderObj) {
        $LocationPath = $folderObj.Self.Path
    }
    else {
        $manualPath = [Microsoft.VisualBasic.Interaction]::InputBox(
            "A seleção de pasta foi cancelada ou a unidade não apareceu.`n`nPor favor, digite o caminho da rede manualmente (Ex: Z:\Backups ou \\Server\Share):", 
            "Caminho Manual", 
            ""
        )
        
        if (-not [string]::IsNullOrWhiteSpace($manualPath)) {
            $LocationPath = $manualPath
        }
        else {
            Write-Warning "Operação cancelada pelo usuário."
            return
        }
    }

    # --- Logic ---
    $logEntries = [System.Collections.Generic.List[PSObject]]::new()
    
    function Add-Log {
        param ($Status, $Message)
        $logEntries.Add([PSCustomObject]@{
            Timestamp = Get-Date -Format "HH:mm:ss"
            Action    = $Mode
            Status    = $Status
            Message   = $Message
        })
    }

    $localUserProfile = "$env:SystemDrive\Users\$env:USERNAME"
    $backupDestination = Join-Path -Path $LocationPath -ChildPath $env:USERNAME

    # Exclusões
    $excludeDirs = @(
        "AppData", "Application Data", "Local Settings", "Cookies", "NetHood", "PrintHood", "Recent", "SendTo", "Start Menu", "Templates", 
        "GlobalMeet ScreenShare", "GlobalMeet Desktop Tools", "GlobalMeet for Desktop", "VoIPAudioForMeetings", 
        "IntelGraphicsProfiles", "PSAppDeployToolkit",
        "OneDrive*", ".ms-ad", ".azuredatastudio", ".ipython", ".jupyter", ".matplotlib", ".sparkmagic", "azuredatastudio-python",
        "mcafee dlp quarantined files"
    )
    
    if ($backupDestination.StartsWith($localUserProfile)) {
        $excludeDirs += $backupDestination
    }

    $excludeFiles = @(
        "NTUSER.DAT", "NTUSER.DAT*", "ntuser.dat.LOG*", "ntuser.ini", "UsrClass.dat*", "*.tmp", "*.lock"
    )

    Add-Log -Status "Info" -Message "Starting file operation for User: $env:USERNAME"

    if ($Mode -eq 'Backup') {
        $Source = $localUserProfile
        $Dest   = $backupDestination
        if (-not (Test-Path -Path $Dest)) {
            try {
                New-Item -Path $Dest -ItemType Directory -Force | Out-Null
                Add-Log -Status "Info" -Message "Created new backup directory: $Dest"
            }
            catch {
                 Add-Log -Status "Critical Error" -Message "Cannot create destination: $Dest. Check permissions."
                 $logEntries | Out-GridView -Title "Error Report" -Wait
                 return
            }
        }
    }
    elseif ($Mode -eq 'Restore') {
        $Source = $backupDestination
        $Dest   = $localUserProfile
        if (-not (Test-Path -Path $Source)) {
            Add-Log -Status "Critical Error" -Message "Backup source not found: $Source"
            $logEntries | Out-GridView -Title "User Files Report" -Wait
            return
        }
    }

    try {
        Add-Log -Status "Processing" -Message "Running Robocopy..."
        
        # --- CORREÇÃO DE ARGUMENTOS E FLAGS ---
        # 1. /FFT: Essencial para Rede (FAT File Time). Evita erros de timestamp.
        # 2. /XJ:  Obrigatório para C:\Users para evitar Loop Infinito em Junction Points.
        # 3. /IS:  Incluir Mesmos arquivos (Força a reescrita para garantir que copia).
        # 4. Removido /Z: Causa lentidão e erros em alguns mapeamentos de rede.
        
        $roboArgs = @($Source, $Dest, "/E", "/MT:16", "/R:1", "/W:1", "/XJ", "/FFT", "/IS", "/NFL", "/NDL")
        
        $roboArgs += "/XD"
        $roboArgs += $excludeDirs
        $roboArgs += "/XF"
        $roboArgs += $excludeFiles

        # Start-Process é usado para evitar que o output do robocopy polua o console,
        # mas passamos os argumentos como array para o PowerShell lidar com espaços nos caminhos.
        $p = Start-Process -FilePath "robocopy.exe" -ArgumentList $roboArgs -Wait -PassThru -WindowStyle Hidden

        $code = $p.ExitCode

        # Códigos de saída Robocopy: < 8 é Sucesso.
        if ($code -lt 8) {
            Add-Log -Status "Success" -Message "Robocopy finished. (Code: $code)"
            if ($Mode -eq 'Backup') {
                Add-Log -Status "Info" -Message "Backup stored in: $Dest"
            }
            else {
                Add-Log -Status "Info" -Message "Restored to: $Dest"
            }
        }
        else {
            Add-Log -Status "Error" -Message "Robocopy failed (Code: $code). Check permissions."
        }
    }
    catch {
        Add-Log -Status "Critical Error" -Message "Script execution failed: $($_.Exception.Message)"
    }

    $logEntries | Out-GridView -Title "User Files Manager Report: $Mode" -Wait
}

function checkLicense
{
	#Windows License
	$windowsLicense = slmgr.vbs /dli | Out-String
    $activationStatus = ($windowsLicense | Select-String "License Status:").ToString().Trim() -replace "License Status: "
    $partialKey = ($windowsLicense | Select-String "Partial Product Key:").ToString().Trim() -replace "Partial Product Key: "
    $licenseChannel = ($windowsLicense | Select-String "License Channel:").ToString().Trim() -replace "License Channel: "

    $winInfo = [PSCustomObject]@{
        'Product'           = 'Windows OS'
        'Activation Status' = $activationStatus
        'Partial Key'       = $partialKey
        'License Channel'   = $licenseChannel
    }


    #Office License
    $osppPath = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty InstallLocation
    
    if (-not $osppPath) {
        $osppPath = Get-ChildItem -Path "$env:ProgramFiles\Microsoft Office" -Filter "ospp.vbs" -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty DirectoryName |
                    Select-Object -First 1
    }

    $officeInfo = @()
    if ($osppPath) {
        $osppExe = Join-Path $osppPath 'ospp.vbs'
        
        $officeStatus = & cscript //NOLOGO $osppExe /dstatus | Out-String

        $licenseMatches = $officeStatus | Select-String 'PRODUCT ID:' -AllMatches
        
        if ($licenseMatches.Matches.Count -gt 0) {
            $officeProducts = $officeStatus -split '---------------------------------------'
            
            foreach ($productBlock in $officeProducts) {
                if ($productBlock -match 'PRODUCT ID:') {    
                    $name = ($productBlock | Select-String 'Name:' | Select-Object -First 1).ToString().Trim() -replace 'Name:', ''
                    $description = ($productBlock | Select-String 'Description:' | Select-Object -First 1).ToString().Trim() -replace 'Description:', ''
                    $status = ($productBlock | Select-String 'LICENSE STATUS:' | Select-Object -First 1).ToString().Trim() -replace 'LICENSE STATUS:', ''
                    $key = ($productBlock | Select-String 'Last 5 characters of installed product key:' | Select-Object -First 1).ToString().Trim() -replace 'Last 5 characters of installed product key:', ''
                    
                    $officeInfo += [PSCustomObject]@{
                        'Product'           = "$($name.Trim()) ($($description.Trim()))"
                        'Activation Status' = $status.Trim()
                        'Partial Key'       = $key.Trim()
                        'License Channel'   = "N/A (See Description)"
                    }
                }
            }
        }
    } else {
        $officeInfo += [PSCustomObject]@{
            'Product'           = 'Microsoft Office'
            'Activation Status' = 'Not Found'
            'Partial Key'       = 'N/A'
            'License Channel'   = 'N/A'
        }
    }
    
    $allLicenses = @($winInfo) + $officeInfo
    $allLicenses | Out-GridView -Title "Windows and Office License Status"
    
    Write-Host "License check complete. Results are displayed in a grid view." -ForegroundColor Green
}

function VerifyBitlocker
{
	param (
	[string]$DriveLetter = "C:"
	)
	$shell = New-Object -ComObject Shell.Application
	$folder = $shell.NameSpace($DriveLetter)
	$bitLockerStatus = $folder.Self.ExtendedProperty("System.Volume.BitLockerProtection")
	switch ($bitLockerStatus) {
		0 { "BitLocker is not enabled." }
		1 { "BitLocker is enabled." }
		2 { "BitLocker is suspended." }
		3 { "BitLocker is enabled, but the drive is not fully encrypted." }
		4 { "BitLocker is enabled, but the drive is not fully decrypted." }
		default { "Unknown BitLocker status." }
	}
	pause
}

function GetPCInfo
{
	$filePath="$env:USERPROFILE\Desktop\userInfo.txt"
	
	#PC Info
	$b = Get-Date
	$data = "############################ $b ######################################"
	$data | Out-File -FilePath "$env:USERPROFILE\Desktop\userInfo.txt" -Append
	$m= Get-ComputerInfo | select CsSystemFamily, BiosSeralNumber, OsName, OsDisplayVersion, CsUserName, CsDNSHostName
	$m | Out-File -FilePath $filePath -Append

	#PC Info->screen
	Write-Host "File userInfo.txt created in user's Desktop" -Foreground cyan
	Write-Host $filePath -Foreground cyan
	foreach ($property in $m.PSObject.Properties)
	{
	Write-Host "$($property.Name): $($property.Value)" -Foreground yellow
	}
	
	#Processor
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select Name, NumberOfCores, @{N='Speed (GHz)';E={[math]::Round($_.MaxClockSpeed/1000.0, 2)}}    
    "`n--- Processor Information ---" | Add-Content -Path $filePath
    $cpu | Format-List | Out-String | Add-Content -Path $filePath
    
    #Processor->screen
    Write-Host "`n--- Processor Information ---" -ForegroundColor Green
    $cpu | Format-List

    #RAM
    $totalRam = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    $ramModules = Get-CimInstance -ClassName Win32_PhysicalMemory | Select DeviceLocator, @{N='Capacity (GB)';E={[math]::Round($_.Capacity/1GB, 2)}}, Speed
    $ramSummary = [PSCustomObject]@{
        'Total RAM (GB)' = [math]::Round($totalRam, 2)
        'Modules Count'  = $ramModules.Count
    }
    "`n--- Memory Information ---" | Add-Content -Path $filePath
    $ramSummary | Format-List | Out-String | Add-Content -Path $filePath   
    "`nMemory Modules:" | Add-Content -Path $filePath
    $ramModules | Out-String | Add-Content -Path $filePath

    #RAM->screen
    Write-Host "`n--- Memory Information ---" -ForegroundColor Green
    $ramSummary | Format-List
    Write-Host "Memory Modules:" -ForegroundColor Green
    $ramModules | Format-Table -AutoSize

    #Storage
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select DeviceID, @{N='Size (GB)';E={[math]::Round($_.Size/1GB, 2)}}, @{N='FreeSpace (GB)';E={[math]::Round($_.FreeSpace/1GB, 2)}}
    $physicalDisks = Get-CimInstance -ClassName Win32_DiskDrive | Select Model, InterfaceType, @{N='Size (GB)';E={[math]::Round($_.Size/1GB, 2)}}
    "`n--- Storage Information ---" | Add-Content -Path $filePath
    "`nLogical Drives:" | Add-Content -Path $filePath
    $drives | Out-String | Add-Content -Path $filePath
    "`nPhysical Disks:" | Add-Content -Path $filePath
    $physicalDisks | Out-String | Add-Content -Path $filePath

    #Storage->screen
    Write-Host "`n--- Storage Information ---" -ForegroundColor Green
    Write-Host "Logical Drives:" -ForegroundColor Yellow
    $drives | Format-Table -AutoSize
    Write-Host "Physical Disks:" -ForegroundColor Yellow
    $physicalDisks | Format-Table -AutoSize

    #GPU
    $gpu = Get-CimInstance -ClassName Win32_VideoController | Select Name, DriverVersion, @{N='VRAM (MB)';E={[math]::Round($_.AdapterRAM/1MB, 0)}}
    "`n--- Video Card (GPU) Information ---" | Add-Content -Path $filePath
    $gpu | Format-List | Out-String | Add-Content -Path $filePath
    #GPU->screen
    Write-Host "`n--- Video Card (GPU) Information ---" -ForegroundColor Green
    $gpu | Format-List
	
	#IP
	$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1" }
	$filteredIPs = $ips | Where-Object { $_.IPAddress -like "10.*" }
	$IPtext = "IPAddress:"
	$IPtext + " " + $filteredIPs.IPAddress| Out-File -FilePath $filePath -Append
	
	#IP->screen
	Write-Host "IPAddress: "$filteredIPs.IPAddress -Foreground Magenta
	
	Get-MACInventory
	Get-DockSerials
	Get-MonitorSummary
	pause
}

function Get-MACInventory 
{
    $dockMacs   = New-Object System.Collections.Generic.List[string]
    $equipoMac  = ""
    $wifiMac    = ""

	$adapters = Get-WmiObject -Class Win32_NetworkAdapter -ErrorAction Stop |
				Where-Object { $_.PhysicalAdapter -and $_.MACAddress }

	# 1) MAC del PORTÁTIL: NetConnectionID = "Ethernet"
	$eth = $adapters | Where-Object { $_.NetConnectionID -and ($_.NetConnectionID -ieq 'Ethernet') } | Select-Object -First 1
	if ($eth) {
		$equipoMac = ([string]$eth.MACAddress).ToUpper()
	}

	# 2) MAC del Wi-Fi: NetConnectionID = "Wi-Fi", "WLAN", etc.
	$wifi = $adapters | Where-Object {
		$_.NetConnectionID -and ($_.NetConnectionID -match '(?i)wi[-]?fi|wlan|wireless')
	} | Select-Object -First 1
	if ($wifi) {
		$wifiMac = ([string]$wifi.MACAddress).ToUpper()
	}

	# 3) MAC del DOCK
	foreach ($a in $adapters) {
		if (($eth -and $a.DeviceID -eq $eth.DeviceID) -or ($wifi -and $a.DeviceID -eq $wifi.DeviceID)) {
			continue
		}

		$mac   = ([string]$a.MACAddress).ToUpper()
		$pnp   = [string]$a.PNPDeviceID
		$name  = [string]$a.Name
		$desc  = [string]$a.Description
		$mfr   = [string]$a.Manufacturer
		$ncid  = [string]$a.NetConnectionID

		if ($name -match '(?i)check\s*point.*virtual.*adapter.*endpoint.*vpn' -or
			$desc -match '(?i)check\s*point.*virtual.*adapter.*endpoint.*vpn') {
			continue
		}

		$isDock = $false
		if ($pnp -match '(?i)VID_17EF' -or
			$pnp -match '(?i)^USB\\' -or
			$pnp -match '(?i)THUNDERBOLT|TBT' -or
			$name -match '(?i)dock|thunderbolt|usb\-c|usb' -or
			$desc -match '(?i)dock|thunderbolt|usb\-c|usb' -or
			$mfr -match '(?i)lenovo.*dock' -or
			($ncid -and $ncid -match '^(?i)Ethernet\s*\d+$')) {
			$isDock = $true
		}

		if ($isDock -and $mac) { $dockMacs.Add($mac) | Out-Null }
	}

	Write-host "MAC PC: "$equipoMac -Foreground Magenta
	Write-host "MAC Wifi: "$wifiMac -Foreground Magenta
	Write-host "MAC Dock: "$dockMacs -Foreground Magenta
	"MAC PC: " + $equipoMac| Out-File -FilePath "$env:USERPROFILE\Desktop\userInfo.txt" -Append
	"MAC Wifi: " + $wifiMac| Out-File -FilePath "$env:USERPROFILE\Desktop\userInfo.txt" -Append
	"MAC Dock: " + $dockMacs| Out-File -FilePath "$env:USERPROFILE\Desktop\userInfo.txt" -Append
    #return [PSCustomObject]@{
    #    MAC_Equipo = $equipoMac
    #    MAC_WiFi   = $wifiMac
    #    MAC_Dock   = ($dockMacs | Sort-Object -Unique) -join ';'
    #}
}

function Get-DockSerials 
{
    $serials = New-Object System.Collections.Generic.List[string]

    # Obtener dispositivos locales
    $devs = Get-WmiObject Win32_PnPEntity -ErrorAction Stop

    foreach ($d in $devs) {
        $pnp = [string]$d.PNPDeviceID
        $name = [string]$d.Name

        if ($pnp -match '(?i)VID_17EF' -or $name -match '(?i)dock|thunderbolt|usb\-c') {
            $bag = @(
                [string]$d.PNPDeviceID,
                [string]$d.DeviceID,
                [string]$d.Name,
                [string]$d.Caption,
                [string]$d.Description
            ) | Where-Object { $_ -and $_.Length -gt 0 }

            # Intentar leer LocationInformation del registro
            $regPath = ("HKLM:\SYSTEM\CurrentControlSet\Enum\{0}" -f $d.PNPDeviceID)
            try {
                $loc = (Get-ItemProperty -Path $regPath -ErrorAction Stop).LocationInformation
                if ($loc) { $bag += [string]$loc }
            } catch { }

            foreach ($txt in $bag) {
                $parts = $txt -split ';'
                if ($parts.Length -ge 2) {
                    $seg = $parts[1]
                    $m = [regex]::Match($seg, '(?i)ZV[A-Z0-9]{4,}')
                    if ($m.Success) { $serials.Add($m.Value.ToUpper()) | Out-Null }
                }
                foreach ($m2 in [regex]::Matches($txt, '(?i)ZV[A-Z0-9]{4,}')) {
                    $serials.Add($m2.Value.ToUpper()) | Out-Null
                }
            }
        }
    }
	Write-host "Dock SN: "($serials | Sort-Object -Unique) -Foreground green
    "Dock SN: " + ($serials | Sort-Object -Unique) | Out-File -FilePath "$env:USERPROFILE\Desktop\userInfo.txt" -Append
	#return ($serials | Sort-Object -Unique)
}

function Convert-EDIDString 
{
    param([byte[]]$Bytes)
    ($Bytes | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join ''
}

function Get-MonitorSummary 
{
    $namespace = "root\wmi"
    $summaryList = New-Object System.Collections.Generic.List[string]

    try {
        # Obtener información de monitores en el equipo local
        $id = Get-CimInstance -Namespace $namespace -ClassName WmiMonitorID -ErrorAction Stop

        foreach ($m in $id) {
            $manu = Convert-EDIDString $m.ManufacturerName
            $sn   = Convert-EDIDString $m.SerialNumberID
            $name = Convert-EDIDString $m.UserFriendlyName
            if ($name -or $manu -or $sn) {
                $summaryList.Add(("{0} {1} (SN: {2})" -f $manu,$name,$sn).Trim()) | Out-Null
            }
        }
    } catch {
        $summaryList.Add(("Error obteniendo monitores: {0}" -f $_.Exception.Message)) | Out-Null
    }

    Write-Host "Monitor: " ($summaryList -join '; ') -ForegroundColor blue
	"`n"| Out-File -FilePath "$env:USERPROFILE\Desktop\userInfo.txt" -Append
    $line = "Monitor: " + ($summaryList -join '; ') | Out-File -FilePath "$env:USERPROFILE\Desktop\userInfo.txt" -Append
	#return ($summaryList -join '; ')
}

function CHDSK
{
	chkdsk
	pause
}

function defrag
{
	defrag C:
	pause
}

function diskSpeed
{
	winsat disk
	pause
}

function CHFS
{
	sfc /scannow
	pause
}

function CHFH
{
	DISM /Online /Cleanup-Image /ScanHealth
	pause
}

function cleanTemp
{
	cleanmgr
	pause
}

function CHMEM
{
	mdsched
	pause
}

function restoreSys
{
	rstrui
	pause
}

function clearDNS
{
	ipconfig /flushdns
	pause
}

function restartNet
{
	netsh winsock reset
	netsh int ip reset
	pause
}

function certMan
{
	certmgr.msc
}

function usrMan
{
	lusrmgr.msc
}

function eventMan
{
	eventvwr
}

function regMan
{
	regedit
}

function updateAll
{
	winget update --all
	pause
}

$GLOBAL:cred=GetCreds
$condition=1
cls
banner

while ($condition -ne 0)
{
	cls
	menu
}
