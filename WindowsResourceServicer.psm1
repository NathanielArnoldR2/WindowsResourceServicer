Import-Module @(
 "Dism"
 "Storage"
)

$OSData = $null

$scripts = @{}
$scripts.DC = {
  . C:\CT\Modules\import.ps1

  Set-IPConfiguration -IPAddress    172.16.0.10 `
                      -PrefixLength 16 `
                      -DNSAddresses 172.16.0.10

  Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools

  Register-ConfigTask -Name DomainAdminHandOff -Task {
    Set-ScheduledTask -TaskName DomainAdminTasks `
                      -User WSUSEnv\Administrator `
                      -Password 'Pa$$w0rd' `
                      -Trigger (New-ScheduledTaskTrigger -At (Get-Date).AddMinutes(1) -Once)

    . C:\CT\Modules\import.ps1
    Write-ErrorLog
  } -AtStartup

  Register-ConfigTask -Name DomainAdminTasks -Task {
    . C:\CT\Modules\import.ps1

    Wait-Domain

    $cliOU = New-ADOrganizationalUnit -Name "WSUS Clients" -PassThru |
               ForEach-Object DistinguishedName

    New-GPO -Name "WSUS Client Policy" |
      New-GPLink -Target $cliOU

    #region Enforce Automatic Updates from WSUS Server.
    Set-GPRegistryValue -Name "WSUS Client Policy" `
                        -Key HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate `
                        -ValueName WUServer `
                        -Value http://WSUS.WSUSEnv.int:8530/ `
                        -Type String

    Set-GPRegistryValue -Name "WSUS Client Policy" `
                        -Key HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate `
                        -ValueName WUStatusServer `
                        -Value http://WSUS.WSUSEnv.int:8530/ `
                        -Type String

    Set-GPRegistryValue -Name "WSUS Client Policy" `
                        -Key HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate `
                        -ValueName DoNotConnectToWindowsUpdateInternetLocations `
                        -Value 1 `
                        -Type DWord

    Set-GPRegistryValue -Name "WSUS Client Policy" `
                        -Key HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU `
                        -ValueName NoAutoUpdate `
                        -Value 0 `
                        -Type DWord

    Set-GPRegistryValue -Name "WSUS Client Policy" `
                        -Key HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU `
                        -ValueName AUOptions `
                        -Value 2 `
                        -Type DWord

    Set-GPRegistryValue -Name "WSUS Client Policy" `
                        -Key HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU `
                        -ValueName UseWUServer `
                        -Value 1 `
                        -Type DWord

    Set-GPRegistryValue -Name "WSUS Client Policy" `
                        -Key HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU `
                        -ValueName DetectionFrequencyEnabled `
                        -Value 1 `
                        -Type DWord

    Set-GPRegistryValue -Name "WSUS Client Policy" `
                        -Key HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU `
                        -ValueName DetectionFrequency `
                        -Value 1 `
                        -Type DWord
    #endregion

    # For my own sanity, display of member computers will not lock automatically.
    Set-GPRegistryValue -Name "Default Domain Policy" `
                        -Key HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E `
                        -ValueName ACSettingIndex `
                        -Value 0 `
                        -Type DWord

    Remove-SetupPaths

    Write-ErrorLog

    Invoke-FinAckHandshake
  }

  # Our entry point into the tasks.
  Enable-ScheduledTask -TaskName DomainAdminHandOff | Out-Null

  Set-AutoLogon -Domain WSUSEnv -User Administrator -Password 'Pa$$w0rd'

  $pwd = ConvertTo-SecureString -String 'Pa$$w0rd' -AsPlainText -Force
  Install-ADDSForest -DomainName WSUSEnv.int -SafeModeAdministratorPassword $pwd -Force # Automatic restart.

  Write-ErrorLog
}
$scripts.WSUS = {
  . C:\CT\Modules\import.ps1

  Set-IPConfiguration -TargetByNeighbor DC `
                      -IPAddress        172.16.0.11 `
                      -PrefixLength     16 `
                      -DNSAddresses     172.16.0.10

  Join-Domain -Domain WSUSEnv.int -User Administrator -Password 'Pa$$w0rd'

  Disable-LocalUsers

  Set-AutoLogon -Domain WSUSEnv -User Administrator -Password 'Pa$$w0rd'

  Register-ConfigTask -Name DomainAdminHandOff -Task {
    Set-ScheduledTask -TaskName WindowsUpdateLoop `
                      -User WSUSEnv\Administrator `
                      -Password 'Pa$$w0rd' `

    . C:\CT\Modules\import.ps1
    Write-ErrorLog

    Enable-ScheduledTask -TaskName WindowsUpdateLoop
    Start-ScheduledTask -TaskName WindowsUpdateLoop
  } -AtStartup

  Register-ConfigTask -Name WindowsUpdateLoop -Task {
    function Write-Log ($Message) {
      (Get-Date).ToString("hh:mm:ss"),$Message -join " | " |
        Out-File $env:TMP\WindowsUpdateLoop.log -Append
    }

    Write-Log "Starting iteration."

    $updateSession = New-Object -ComObject Microsoft.Update.Session

    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")

    Write-Log "Synchronous search found $($searchResults.Updates.Count) missing update(s)."

    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

    for ($i = 0; $i -lt $searchResult.Updates.Count; $i++) {
      $update = $searchResult.Updates.Item($i)

      if (-not $update.IsDownloaded) {
        $updatesToDownload.Add($update)
      }
    }

    if ($updatesToDownload.Count -gt 0) {
      $downloader = $updateSession.CreateUpdateDownloader()
      $downloader.Updates = $updatestoDownload

      Write-Log "Downloading $($updatesToDownload.Count) update(s)."
      $downloader.Download()
    }

    $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl

    for ($i = 0; $i -lt $searchResult.Updates.Count; $i++) {
      $update = $searchResult.Updates.Item($i)

      if ($update.IsDownloaded) {
        $updatesToInstall.Add($update)
      }
    }

    if ($updatesToInstall.Count -gt 0) {
      $installer = $updateSession.CreateUpdateInstaller()
      $installer.Updates = $updatesToInstall

      Write-Log "Installing $($updatesToInstall.Count) update(s)."
      $installer.Install()
    }

    . C:\CT\Modules\import.ps1

    if ($searchResult.Updates.Count -eq 0) {
      Write-Log "Ending update loop."
      Unregister-ScheduledTask -TaskName WindowsUpdateLoop -Confirm:$false

      Set-ScheduledTask -TaskName InstallConfigWSUS `
                        -User WSUSEnv\Administrator `
                        -Password 'Pa$$w0rd' `
                        -Trigger (New-ScheduledTaskTrigger -At (Get-Date).AddMinutes(1) -Once)

      return
    }

    Write-Log "Restarting."
    Write-ErrorLog

    Restart-Computer -Force
  } -AtStartup -NoAutoUnregister

  Register-ConfigTask -Name InstallConfigWSUS -Task {

    . C:\CT\Modules\import.ps1

    #region Install & Configure WSUS
    Install-WindowsFeature UpdateServices -IncludeManagementTools

    Set-VolumeDriveLetter WSUSData E

    New-Item -Path E:\WSUS -ItemType Directory | Out-Null

    $wsusUtil = "C:\Program Files\Update Services\Tools\wsusutil.exe"
    & $wsusUtil postinstall CONTENT_DIR=E:\WSUS

    $wsusConfig = Get-WsusServer |
                    ForEach-Object GetConfiguration

    $wsusConfig.MURollupOptin = $false
    $wsusConfig.AllUpdateLanguagesEnabled = $false
    $wsusConfig.SetEnabledUpdateLanguages("en")

    # I do not believe that Express Packages are compatible with offline
    # application.
    #$wsusConfig.DownloadExpressPackages = $true

    $wsusConfig.Save()

    $subscription = Get-WsusServer |
                      ForEach-Object GetSubscription

    $subscription.StartSynchronizationForCategoryOnly()

    do {
      Start-Sleep -Seconds 5
    } until ($subscription.GetSynchronizationStatus() -eq "NotProcessing")
    #endregion

    #region Configure Products & Classifications
    $myProducts = $ScriptParameters.Products.Split("|")

    Get-WsusProduct |
      Set-WsusProduct -Disable

    Get-WsusProduct |
      Where-Object {
        $_.Product.Title -in $myProducts
      } |
      Set-WsusProduct

    if ($ScriptParameters.Classifications -is [string]) {
      $myClassifications = $ScriptParameters.Classifications.Split("|")

      Get-WsusClassification |
        Set-WsusClassification -Disable

      Get-WsusClassification |
        Where-Object {
          $_.Classification.Title -in $myClassifications
        } |
        Set-WsusClassification
    }

    $subscription.StartSynchronization()

    do {
      Start-Sleep -Seconds 5
    } until ($subscription.GetSynchronizationStatus() -eq "NotProcessing")
    #endregion

    # Decline superseded updates (the great majority).
    Get-WsusUpdate |
      Where-Object {$_.Update.IsSuperseded -eq $true} |
      ForEach-Object {$_.Update.Decline()}

    $cliDn = "OU=WSUS Clients,DC=WSUSEnv,DC=int"

    Invoke-Command -ComputerName DC -ArgumentList $cliDn -ScriptBlock {
      param($cliDn)

      & redircmp.exe $cliDn
    } | Out-Null

    Invoke-FinAckHandshake # Okay to Start Clients

    Wait-HostPoke # Okay to Query Client Status

    $clients = Invoke-Command -ComputerName DC -ArgumentList $cliDn -ScriptBlock {
      param($cliDn)

      Get-ADComputer -SearchBase $cliDn -Filter * -Properties Description |
        Select-Object Name,Description
    }

    #region Query Client Status
    :everyMinute while ($true) {
      Start-Sleep -Seconds 60

      foreach ($client in $clients) {
        $clientReported = @(
          Get-WsusComputer |
          Where-Object FullDomainName -like "$($client.Name).*" |
          Where-Object LastReportedStatusTime -gt (Get-Date 7/4/1776)
        ).Count -eq 1

        if (-not $clientReported) {
          continue everyMinute
        }
      }

      break
    }
    #endregion

    Invoke-FinAckHandshake # Okay to Stop Clients

    Wait-HostPoke # Okay to Approve Updates.

    # And this will rule out *all* unnecessary updates.
    Get-WsusUpdate |
      Where-Object ComputersNeedingThisUpdate -eq 0 |
      ForEach-Object {$_.Update.Decline()}

    #region Approve & Download Updates
    Get-WsusUpdate |
      Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

    do {
      Start-Sleep -Seconds 60

      $unreadyUpdateCount = @(
        Get-WsusUpdate -Approval Approved |
          Where-Object {$_.Update.State -ne "Ready"}
      ).Count
    } until ($unreadyUpdateCount -eq 0)
    #endregion

    #region Export Updates to Path
    $uriWebComponent = "http://" + ([System.Net.Dns]::GetHostName()).ToLower() + ":8530/Content/"

    $shObj = New-Object -ComObject Shell.Application
    $scratchPath = New-Item -Path E:\Scratch -ItemType Directory |
                     ForEach-Object FullName

    $scratchObj = $shObj.Namespace($scratchPath)

    foreach ($client in $clients) {
      $exportPath = New-Item -Path E:\Export `
                             -Name $client.Description `
                             -ItemType Directory `
                             -Force |
                      ForEach-Object FullName

      $computerId = Get-WsusComputer |
                      Where-Object FullDomainName -like "$($client.Name).*" |
                      ForEach-Object Id

      # We must take care to filter out NotApplicable updates; otherwise, every
      # update is assumed to be associated with every client.
      $updateItems = @(
        Get-WsusServer |
          ForEach-Object GetComputerTarget $computerId |
          ForEach-Object GetUpdateInstallationInfoPerUpdate |
          Where-Object UpdateInstallationState -ne NotApplicable | # All updates included otherwise.
          ForEach-Object UpdateId |
          ForEach-Object {
            Get-WsusUpdate -UpdateId $_
          } |
          ForEach-Object Update
      )

      foreach ($item in $updateItems) {
        $kb = $item.KnowledgebaseArticles[0]

        # Express package files are incompatible with offline application.
        $updateFiles = @(
          $item |
            ForEach-Object GetInstallableItems |
            ForEach-Object Files |
            Where-Object Type -ne Express
        )

        foreach ($file in $updateFiles) {
          $cabPath = Join-Path `
          -Path "E:\WSUS\WsusContent" `
          -ChildPath $file.FileUri.ToString().Replace($uriWebComponent, "")

          if (-not $ScriptParameters.ExtractMspFiles) {
            $fileDestination = Join-Path -Path $exportPath -ChildPath $file.Name

            Copy-Item -LiteralPath $cabPath -Destination $fileDestination
          }
          elseif ($ScriptParameters.ExtractMspFiles) {
            Get-ChildItem -LiteralPath $scratchPath -Force |
              Remove-Item -Force -Recurse

            $msp = $shObj.Namespace($cabPath).Items() |
                     Where-Object Path -like *.msp

            $scratchObj.CopyHere($msp)

            Get-ChildItem -LiteralPath $scratchPath |
              ForEach-Object {
                $_ |
                  Copy-Item -Destination (Join-Path -Path $exportPath -ChildPath "KB$kb-$($_.Name)")
              }
          }
        }
      }
    }
    #endregion

    Remove-SetupPaths

    Write-ErrorLog

    Invoke-FinAckHandshake # Has Downloaded/Exported Updates. Okay to Stop.
  }

  # Our entry point into the tasks.
  Enable-ScheduledTask -TaskName DomainAdminHandOff | Out-Null

  Write-ErrorLog

  Restart-Computer -Force
}
$scripts.Client = {
  . C:\CT\Modules\import.ps1

  Set-IPConfiguration -IPAddress        $ScriptParameters.IPAddress `
                      -PrefixLength     16 `
                      -DNSAddresses     172.16.0.10

  if ($ScriptParameters.UpdateMode -eq "Office") {
    Install-CTPackage $ScriptParameters.Description @{
      AdminFile = "mock activated"
      IncludeUpdates = $false
    }
  }

  Join-Domain -Domain WSUSEnv.int -User Administrator -Password 'Pa$$w0rd'

  Disable-LocalUsers

  Set-AutoLogon -Domain WSUSEnv -User Administrator -Password 'Pa$$w0rd'

  Register-ConfigTask -Name DomainAdminHandOff -Task {
    Set-ScheduledTask -TaskName DomainAdminTasks `
                      -User WSUSEnv\Administrator `
                      -Password 'Pa$$w0rd' `
                      -Trigger (New-ScheduledTaskTrigger -At (Get-Date).AddMinutes(1) -Once)

    . C:\CT\Modules\import.ps1
    Write-ErrorLog
  } -AtStartup

  Register-ConfigTask -Name DomainAdminTasks -Task {
    . C:\CT\Modules\import.ps1

    # Initial application of Group Policy after domain join failed w/ Event ID
    # 1058. This loop will catch this circumstance by noting the absence of a
    # key that should be generated by successful application of Group Policy,
    # and will run consecutive gpupdates until said key is confirmed to exist.
    while (-not (Test-Path -LiteralPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate)) {
      & gpupdate /force
      Start-Sleep -Seconds 5
    }

    # Permit inventory of updates for Microsoft Office products.
    if ($ScriptParameters.UpdateMode -eq "Office") {
      (New-Object -ComObject Microsoft.Update.ServiceManager).
        AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"") | Out-Null
    }

    # Runs a synchronous update detection cycle. Practical testing suggests
    # this is far more likely to be effective than wuauclt commands.
    (New-Object -ComObject Microsoft.Update.Session).
      CreateUpdateSearcher().
      Search("IsInstalled=0 and Type='Software'") | Out-Null

    Invoke-Command -ComputerName DC -ScriptBlock {
      param($ComputerName, $Description)

      Set-ADComputer $ComputerName -Description $Description
    } -ArgumentList @(
      [System.Net.Dns]::GetHostName()
      $ScriptParameters.Description
    )

    Remove-SetupPaths

    Write-ErrorLog

    Invoke-FinAckHandshake
  }

  # Our entry point into the tasks.
  Enable-ScheduledTask -TaskName DomainAdminHandOff | Out-Null

  Write-ErrorLog

  Restart-Computer -Force
}
$scripts.ResourceServicer = {
  . C:\CT\Modules\import.ps1

  Register-ConfigTask -Name Servicing -Task {
    . C:\CT\Modules\import.ps1

    Start-Transcript -LiteralPath C:\Users\Public\Desktop\Transcript.txt

    Invoke-WRSWorkflow_ISOtoWIM `
    -Source "C:\res\ISO" `
    -Destination "C:\res\WIM (Pristine)" `
    -Verbose

    Invoke-WRSWorkflow_WIMPartitioning `
    -Source "C:\res\WIM (Pristine)" `
    -Destination "C:\res\WIM (Partitioned)" `
    -Verbose

    Invoke-WRSWorkflow_WIMUpdating `
    -WIM "C:\res\WIM (Partitioned)" `
    -Updates "C:\res\Updates" `
    -Scratch "C:\scratch" `
    -Verbose `

    Invoke-WRSWorkflow_WIMtoVHD `
    -Source "C:\res\WIM (Partitioned)" `
    -Destination "C:\res\VHD" `
    -Scratch "C:\scratch" `
    -Verbose

    Stop-Transcript

    Remove-SetupPaths

    Write-ErrorLog

    Invoke-FinAckHandshake
  } -AtStartup

  Set-AutoLogon -User StudentAdmin -Password 'Pa$$w0rd' -Persist

  Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online -NoRestart

  Enable-ScheduledTask -TaskName Servicing

  Write-ErrorLog

  Restart-Computer -Force
}

function Write-Warning ($Message) {
  Microsoft.PowerShell.Utility\Write-Warning -Message "[$([datetime]::Now.ToString("HH:mm"))] $($Message)"
}

function Write-Verbose ($Message) {
  Microsoft.PowerShell.Utility\Write-Verbose -Message "[$([datetime]::Now.ToString("HH:mm"))] $($Message)"
}

function Import-WRSOSData {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [string]
    $LiteralPath = "$PSScriptRoot\OSData.ps1"
  )
  try {
    $script:OSData = & $LiteralPath
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Get-WRSOSData {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [ValidateSet("WIM","VHD","Update")]
    [string]
    $Workflow
  )
  try {
    if ($OSData -eq $null) {
      Import-WRSOSData
    }

    $OperatingSystems = @(
      $script:OSData.OperatingSystems
    )

    if ($Workflow.Length -gt 0) {
      $OperatingSystems = @(
        $OperatingSystems |
          Where-Object Workflows -contains $Workflow
      )
    }

    $OperatingSystems
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Invoke-WRSWorkflow_ISOtoWIM {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Source,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Destination
  )
  try {
    Write-Verbose "STARTED extracting pristine wim files from source isos."

    if (-not (Test-Path -LiteralPath $Destination)) {
      New-Item -Path $Destination -ItemType Directory -Force |
        Out-Null
    }

    foreach ($os in Get-WRSOSData -Workflow WIM) {
      $isoPath = Join-Path -Path $Source -ChildPath "$($os.FilePrefix).iso"

      if (-not (Test-Path -LiteralPath $isoPath)) {
        Write-Warning "Source iso for '$($os.FilePrefix)' not found."
        continue
      }

      $wimPath = Join-Path -Path $Destination -ChildPath "$($os.FilePrefix).wim"

      if (Test-Path -LiteralPath $wimPath) {
        Write-Warning "Pristine wim for '$($os.FilePrefix)' already exists. Delete manually to force fresh extraction."
        continue
      }

      Write-Verbose "Extracting '$($os.FilePrefix)' wim."

      $isoRoot = Mount-DiskImage -ImagePath $isoPath -PassThru |
                   Get-Volume |
                   ForEach-Object {$_.DriveLetter + ":\"}
      do {
        Start-Sleep -Milliseconds 250
      } while ((Get-PSDrive | Where-Object Root -eq $isoRoot) -eq $null)

      $wimSrc = Join-Path -Path $isoRoot -ChildPath sources\install.wim

      $destItem = Copy-Item -LiteralPath $wimSrc -Destination $wimPath -PassThru

      if ($destItem.Attributes.HasFlag([System.IO.FileAttributes]::ReadOnly)) {
        $destItem.Attributes = $destItem.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
      }

      Dismount-DiskImage -ImagePath $isoPath
    }

    Write-Verbose "FINISHED extracting pristine wim files from source isos."
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Invoke-WRSWorkflow_WIMPartitioning {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Source,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Destination
  )
  try {
    Write-Verbose "STARTED partitioning wim files by os edition."

    if (-not (Test-Path -LiteralPath $Destination)) {
      New-Item -Path $Destination -ItemType Directory -Force |
        Out-Null
    }

    foreach ($os in Get-WRSOSData -Workflow WIM) {
      $srcPath = Join-Path -Path $Source -ChildPath "$($os.FilePrefix).wim"

      if (-not (Test-Path -LiteralPath $srcPath)) {
        Write-Warning "Source wim for '$($os.FilePrefix)' not found."
        continue
      }

      foreach ($edition in $os.Editions) {
        $destPath = Join-Path -Path $Destination -ChildPath "$($os.FilePrefix,$edition,"Not Updated" -join " - ").wim"

        if (Test-Path -LiteralPath $destPath) {
          Write-Warning "Partitioned wim for '$($os.FilePrefix)'/'$edition'/'Not Updated' already exists. Delete manually to force fresh partitioning."
          continue
        }

        $srcName = @(
          Get-WindowsImage -ImagePath $srcPath |
            Where-Object ImageName -like "* $edition" |
            ForEach-Object ImageName
        )

        if ($srcName.Count -ne 1) {
          Write-Warning "Found $($srcName.Count) '$edition' images in '$($os.FilePrefix)' wim, where exactly 1 was expected."
          continue
        }

        Write-Verbose "Extracting '$($os.FilePrefix)'/'$edition'/'Not Updated'."

        Export-WindowsImage -SourceImagePath $srcPath `
                            -SourceName $srcName[0] `
                            -DestinationImagePath $destPath `
                            -DestinationName $srcName[0] `
                            -CompressionType Maximum |
          Out-Null
      }
    }

    Write-Verbose "FINISHED partitioning wim files by os edition."
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function New-WRSVHD {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Source,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Destination,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $PartitionStyle,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $VHDFormat,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Scratch
  )
  $VhdPath = Join-Path -Path $Scratch -ChildPath "scratch.$VHDFormat"

  New-VHD -Path $VhdPath -SizeBytes 40gb |
    Out-Null

  $disk = Mount-VHD -Path $VhdPath -Passthru |
            Get-Disk

  $disk |
    Initialize-Disk -PartitionStyle $PartitionStyle

  if ($PartitionStyle -eq "GPT") {
    $systemPartition = $disk |
                         New-Partition -Size 100mb -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' # "System"
    $osPartition = $disk |
                     New-Partition -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' # "Basic Data"

    # DiskPart must be substituted for PowerShell to format the system
    # partition, as the MSFT_Volume object representing this partition
    # is not accessible through the underlying CIM interface.

    #$systemVolume = $systemPartition |
    #                  Format-Volume -FileSystem FAT32 -NewFileSystemLabel System -Force -Confirm:$false

    @(
      "select disk $($disk.Number)"
      "select partition $($systemPartition.PartitionNumber)"
      'format fs=fat32 label="System"'
    ) -join [System.Environment]::NewLine |
      & $env:SystemRoot\System32\DiskPart.exe |
      Out-Null
  }
  elseif ($PartitionStyle -eq "MBR") {
    $osPartition = $disk |
                     New-Partition -UseMaximumSize -MbrType IFS -IsActive
  }

  $osVolume = $osPartition |
                Format-Volume -FileSystem NTFS -Force -Confirm:$false

  if ($PartitionStyle -eq "GPT") {
    $systemPartition |
      Add-PartitionAccessPath -AssignDriveLetter

    $systemDrive = $systemPartition |
                     Get-Partition |
                     ForEach-Object {$_.DriveLetter + ":\"}
  }

  $osPartition |
    Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop

  $osDrive = $osPartition |
               Get-Partition |
               ForEach-Object {$_.DriveLetter + ":\"}

  Expand-WindowsImage -ImagePath $Source -Index 1 -ApplyPath $osDrive |
    Out-Null

  if ($PartitionStyle -eq "GPT") {
    $firmwareType = "UEFI"
  }
  elseif ($PartitionStyle -eq "MBR") {
    $systemDrive = $osDrive
    $firmwareType = "BIOS"
  }

  # Any errors that occur while processing this native command should be
  # withheld from output. Redirecting the error stream, as I did before,
  # was effective in withholding error output from the console, but not
  # from a transcript.
  $ErrorActionPreference = "SilentlyContinue"

  Invoke-Expression -Command "C:\Windows\System32\bcdboot.exe $($osDrive)Windows /s $($systemDrive) /v /f $($firmwareType)" |
    Out-Null

  $ErrorActionPreference = "Continue"

  $realErrorCount = @(
    $Global:Error |
      Where-Object FullyQualifiedErrorId -notlike *NativeCommandError*
  ).Count

  # Some faults are expected when servicing certain operating systems. This
  # syntax attempts to nullify these expected errors, but must be revisited
  # if it ever results in an operating system that truly will not boot.
  if ($realErrorCount -eq 0) {
    $Global:Error.Clear()
  }

  Dismount-VHD -Path $VhdPath

  Move-Item -Path $VhdPath -Destination $Destination -Force
}

function Invoke-WRSWorkflow_WIMtoVHD {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Source,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Destination,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Scratch
  )
  try {
    Write-Verbose "STARTED building vhd files from partitioned wims."

    if (-not (Test-Path -LiteralPath $Destination)) {
      New-Item -Path $Destination -ItemType Directory -Force |
        Out-Null
    }

    if (Test-Path -LiteralPath $Scratch) {
      Remove-Item -LiteralPath $Scratch -Recurse -Force
    }
    New-Item -Path $Scratch -ItemType Directory -Force |
      Out-Null

    foreach ($os in Get-WRSOSData -Workflow VHD) {
      $updateStatuses = @(
        "Not Updated"
        if ($os.Workflows -contains "Update") {"Updated"}
      )

      foreach ($edition in $os.Editions) {
        foreach ($updateStatus in $updateStatuses) {
          $wimPath = Join-Path -Path $Source -ChildPath "$($os.FilePrefix,$edition,$updateStatus -join " - ").wim"

          if (-not (Test-Path -LiteralPath $wimPath)) {
            Write-Warning "Source wim for '$($os.FilePrefix)'/'$edition'/'$updateStatus' not found."
            continue
          }

          foreach ($generation in $os.Generations) {
            $generationInfo = $script:OSData.Generations | Where-Object Number -eq $generation

            $partitionStyle = $generationInfo.PartitionStyle
            $vhdFormats = $generationInfo.VHDFormats

            foreach ($vhdFormat in $vhdFormats) {
              $vhdPath = Join-Path -Path $Destination -ChildPath "$($os.FilePrefix,$edition,$partitionStyle,$updateStatus -join " - ").$vhdFormat"

              if (Test-Path -LiteralPath $vhdPath) {
                $wimModDate = Get-Item -LiteralPath $wimPath | ForEach-Object LastWriteTime
                $vhdModDate = Get-Item -LiteralPath $vhdPath | ForEach-Object LastWriteTime

                if ($updateStatus -eq "Not Updated" -or $vhdModDate -gt $wimModDate) {
                  Write-Warning "Destination vhd for '$($os.FilePrefix)'/'$edition'/'$updateStatus'/'$partitionStyle'/'$vhdFormat' already exists. Delete manually to force fresh application."
                  continue
                }
              }

              Write-Verbose "Building vhd for '$($os.FilePrefix)'/'$edition'/'$updateStatus'/'$partitionStyle'/'$vhdFormat'."
              New-WRSVHD -Source $wimPath `
                         -Destination $vhdPath `
                         -PartitionStyle $partitionStyle `
                         -VHDFormat $vhdFormat `
                         -Scratch $Scratch
            }
          }
        }
      }
    }

    Remove-Item -LiteralPath $Scratch -Force -Recurse

    Write-Verbose "FINISHED building vhd files from partitioned wims."
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Invoke-WRSWorkflow_UpdateExporter {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Destination,

    [switch]
    $PromptForClientOperatingSystems
  )
  try {
    Write-Verbose "STARTED windows os update exporter."
    Write-Verbose "Building LoadBuilder configuration."

    $config = New-LoadBuilderConfiguration `
    -Name "OSUpdExp" `
    -Switches @(
      New-LoadBuilderSwitch -Name CTPrivate  -Type Private
      New-LoadBuilderSwitch -Name CTExternal -Type External
    ) `
    -Credentials @(
      New-LoadBuilderCredential -Domain WSUSEnv -UserName Administrator -Password 'Pa$$w0rd'
    )

    $config | Add-LoadBuilderMember `
    -Name DC `
    -OS S2016 `
    -Script $script:scripts.DC `
    -Modules @(
      "Common"
    ) `
    -VMNetworkAdapters @(
      "CTPrivate"
    )

    $clients = @(Get-WRSOSData -Workflow Update)

    if ($PromptForClientOperatingSystems) {
      Write-Verbose "  - Prompting user for operating systems to manage/export."

      $selected = @(
        $clients |
          Select-Object Name,WsusProductName |
          Out-GridView -Title "Select Operating System(s)" -OutputMode Multiple |
          ForEach-Object Name
      )

      $clients = @(
        $clients |
          Where-Object Name -in $selected
      )
    }

    $config | Add-LoadBuilderMember `
    -Name WSUS `
    -OS S2016 `
    -ScriptParameters @{
      Products = @($clients | ForEach-Object WsusProductName | Sort-Object -Unique) -join "|"
      Classifications = @(
        "Critical Updates"
        #"Definition Updates" # Executables, I think. Cannot apply offline. Should I disable?
        "Security Updates"
        "Update Rollups"
        "Updates"
      ) -join "|"
    } `
    -Script $script:scripts.WSUS `
    -Modules @(
      "Common"
    ) `
    -VMProcessorCount 4 `
    -VMMemoryMinimumBytes 8gb `
    -VMMemoryStartupBytes 8gb `
    -VMMemoryMaximumBytes 8gb `
    -VMNetworkAdapters @(
      "CTPrivate"
      "CTExternal"
    ) `
    -VMVHDs @(
      New-LoadBuilderVhd -Name WSUSData -SizeBytes 60gb
    )

    $clientNames = @()

    $inc = 1

    foreach ($os in $clients) {
    foreach ($edition in $os.Editions) {
      $clientNames += $clientName = "$($os.FilePrefix) - $edition"

      $config | Add-LoadBuilderMember `
      -Name $clientName `
      -OS $os.Targeting[0] `
      -OSEdition $edition `
      -OSUpdated $false `
      -ScriptParameters @{
        IPAddress   = "172.16.0.1$($inc.ToString().PadLeft(2, "0"))"
        Description = $clientName
      } `
      -Script $script:scripts.Client `
      -Modules @(
        "Common"
      ) `
      -VMNetworkAdapters @(
        "CTPrivate"
      )

      $inc++
    }
    }

    $config |
      Get-LoadBuilderMember |
      ForEach-Object {
        $_ |
          Set-LoadBuilderMember -VMName "OSUpdExp $($_.Name)"
      }

    $config | Add-LoadBuilderAction @(
      # Init. Domain
      New-LoadBuilderStartAction DC
      New-LoadBuilderWaitAction DC -UseShim

      # Init. WSUS
      New-LoadBuilderStartAction WSUS
      New-LoadBuilderWaitAction WSUS -UseShim

      # Init. Clients
      New-LoadBuilderStartAction $clientNames
      $clientNames |
        ForEach-Object {
          New-LoadBuilderWaitAction $_ -UseShim
        }

      # WSUS may query client status.
      New-LoadBuilderPokeAction WSUS -UseShim

      # WSUS has queried client status.
      New-LoadBuilderWaitAction WSUS -UseShim

      # Stop Clients
      New-LoadBuilderStopAction $clientNames

      # WSUS may approve, download, and export updates.
      New-LoadBuilderPokeAction WSUS -UseShim

      # WSUS has exported updates.
      New-LoadBuilderWaitAction WSUS -UseShim

      New-LoadBuilderStopAction WSUS

      New-LoadBuilderStopAction DC

      New-LoadBuilderCustomAction WSUS -ScriptParameters @{
        Destination = $Destination
      } -Script {
        if (-not (Test-Path -LiteralPath $ScriptParameters.Destination)) {
          New-Item -Path $ScriptParameters.Destination -ItemType Directory -Force |
            Out-Null
        }

        $folders = Get-ChildItem -LiteralPath VHD:\Export -Directory

        foreach ($folder in $folders) {
          $destination = Join-Path -Path $ScriptParameters.Destination `
                                   -ChildPath $folder.Name

          if (Test-Path -LiteralPath $destination) {
            Remove-Item -LiteralPath $destination -Recurse -Force
          }

          Write-Verbose "  - Exporting '$($folder.Name)' updates."
          Copy-Item -LiteralPath $folder.FullName `
                    -Destination $destination -Recurse
        }
      } -MountVhd 1
    )

    $result = Start-LoadBuilder -Configuration $config -Verbose

    Remove-LoadBuilderRealizedLoad -Name $config.Name

    if ($result.'Processing Status' -ne "Complete") {
      throw "An error occurred while running the Update Exporter configuration."
    }

    Write-Verbose "FINISHED windows os update exporter."
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Update-WRSWIM {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    $Source,

    [Parameter(
      Mandatory = $true
    )]
    $Updates,

    [Parameter(
      Mandatory = $true
    )]
    $Destination,

    [Parameter(
      Mandatory = $true
    )]
    $Scratch
  )

  $scratchWim = Join-Path -Path $Scratch -ChildPath scratch.wim
  $scratchMount = New-Item -Path $Scratch -Name mount -ItemType Directory |
                    ForEach-Object FullName

  Copy-Item -LiteralPath $Source -Destination $scratchWim

  Mount-WindowsImage -ImagePath $scratchWim -Path $scratchMount -Index 1 |
    Out-Null

  $dismountParams = @{
    Path = $scratchMount
  }

  try {
    Add-WindowsPackage -PackagePath $Updates `
                       -Path $scratchMount `
                       -ErrorAction Stop `
                       -WarningAction SilentlyContinue `
                       -Verbose:$false |
      Out-Null

    $dismountParams.Save = $true
  } catch {
    $dismountParams.Discard = $true
  }

  if ($dismountParams.ContainsKey("Discard")) {
    Write-Warning "  - Error adding packages. Discarding."
    Dismount-WindowsImage @dismountParams |
      Out-Null

    Remove-Item -LiteralPath $scratchWim
    Remove-Item -LiteralPath $scratchMount

    return
  }

  Write-Verbose "  - Saving and moving to destination location."
  Dismount-WindowsImage @dismountParams |
    Out-Null

  Move-Item -LiteralPath $scratchWim -Destination $Destination -Force
  Remove-Item -LiteralPath $scratchMount
}

function Invoke-WRSWorkflow_WIMUpdating {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $WIM,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Updates,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Scratch
  )
  try {
    Write-Verbose "STARTED applying updates to partitioned wims."

    if (Test-Path -LiteralPath $Scratch) {
      Remove-Item -LiteralPath $Scratch -Recurse -Force
    }
    New-Item -Path $Scratch -ItemType Directory -Force |
      Out-Null

    foreach ($os in Get-WRSOSData -Workflow Update) {
      foreach ($edition in $os.Editions) {
        $params = @{
          Source      = Join-Path -Path $WIM     -ChildPath "$($os.FilePrefix,$edition,"Not Updated" -join " - ").wim"
          Updates     = Join-Path -Path $Updates -ChildPath "$($os.FilePrefix,$edition -join " - ")"
          Destination = Join-Path -Path $WIM     -ChildPath "$($os.FilePrefix,$edition,"Updated" -join " - ").wim"
        }

        if (-not (Test-Path -LiteralPath $params.Source)) {
          Write-Warning "Source wim for '$($os.FilePrefix)'/'$edition'/'Not Updated' not found."
          continue
        }

        if (-not (Test-Path -LiteralPath $params.Updates)) {
          Write-Warning "Updates path for '$($os.FilePrefix)'/'$edition' not found."
          continue
        }

        if (Test-Path -LiteralPath $params.Destination) {
          $updatesModDate = Get-ChildItem -LiteralPath $params.Updates |
                              ForEach-Object LastWriteTime |
                              Sort-Object -Descending |
                              Select-Object -First 1
          $wimModDate = Get-Item -LiteralPath $params.Destination | ForEach-Object LastWriteTime

          if ($wimModDate -gt $updatesModDate) {
            Write-Warning "Destination wim for '$($os.FilePrefix)'/'$edition'/'Updated'/ already exists. Delete manually to force fresh application of updates."
            continue
          }
        }

        $updatesCount = @(
          Get-ChildItem -LiteralPath $params.Updates |
            Where-Object Extension -eq .cab
        ).Count

        if ($updatesCount -eq 0) {
          Write-Warning "Updates path for '$($os.FilePrefix)'/'$edition' contained no cab packages."
          continue
        }

        Write-Verbose "Updating '$($os.FilePrefix)'/'$edition'."
        Update-WRSWIM @params -Scratch $Scratch
      }
    }

    Remove-Item -LiteralPath $Scratch -Force -Recurse

    Write-Verbose "FINISHED applying updates to partitioned wims."
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Invoke-WRSWorkflow_OfficeUpdateExporter {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param()
  try {
    Write-Verbose "STARTED office applications update exporter."

    Write-Verbose "Building LoadBuilder configuration."

    $config = New-LoadBuilderConfiguration `
    -Name "OfUpdExp" `
    -Switches @(
      New-LoadBuilderSwitch -Name CTPrivate  -Type Private
      New-LoadBuilderSwitch -Name CTExternal -Type External
    ) `
    -Credentials @(
      New-LoadBuilderCredential -Domain WSUSEnv -UserName Administrator -Password 'Pa$$w0rd'
    )

    $config | Add-LoadBuilderMember `
    -Name DC `
    -OS S2016 `
    -Script $script:scripts.DC `
    -Modules @(
      "Common"
    ) `
    -VMNetworkAdapters @(
      "CTPrivate"
    )

    $config | Add-LoadBuilderMember `
    -Name WSUS `
    -OS S2016 `
    -ScriptParameters @{
      Products = "Office 2016"
      ExtractMspFiles = $true
    } `
    -Script $script:scripts.WSUS `
    -Modules @(
      "Common"
    ) `
    -VMProcessorCount 4 `
    -VMMemoryMinimumBytes 8gb `
    -VMMemoryStartupBytes 8gb `
    -VMMemoryMaximumBytes 8gb `
    -VMNetworkAdapters @(
      "CTPrivate"
      "CTExternal"
    ) `
    -VMVHDs @(
      New-LoadBuilderVhd -Name WSUSData -SizeBytes 60gb
    )

    $products = @(
      "Office 2016 Pro Plus x64"
      "Visio 2016 Pro x64"
    )

    $clientNames = @()
    $inc = 1

    foreach ($product in $products) {
      $clientNames += $clientName = $product

      $config | Add-LoadBuilderMember `
      -Name $clientName `
      -OS "W10 v1803" `
      -ScriptParameters @{
        IPAddress   = "172.16.0.1$($inc.ToString().PadLeft(2, "0"))"
        Description = $product
        UpdateMode  = "Office"
      } `
      -Script $script:scripts.Client `
      -Modules @(
        "Common"
        "CTPackage"
      ) `
      -Packages @(
        $product
      ) `
      -VMNetworkAdapters @(
        "CTPrivate"
      )

      $inc++
    }

    $config |
      Get-LoadBuilderMember |
      ForEach-Object {
        $_ |
          Set-LoadBuilderMember -VMName "OfUpdExp $($_.Name)"
      }

    $config | Add-LoadBuilderAction @(
      # Init. Domain
      New-LoadBuilderStartAction DC
      New-LoadBuilderWaitAction DC -UseShim

      # Init. WSUS
      New-LoadBuilderStartAction WSUS
      New-LoadBuilderWaitAction WSUS -UseShim

      # Init. Clients
      New-LoadBuilderStartAction $clientNames
      $clientNames |
        ForEach-Object {
          New-LoadBuilderWaitAction $_ -UseShim
        }

      # WSUS may query client status.
      New-LoadBuilderPokeAction WSUS -UseShim

      # WSUS has queried client status.
      New-LoadBuilderWaitAction WSUS -UseShim

      # Stop Clients
      New-LoadBuilderStopAction $clientNames

      # WSUS may approve, download, and export updates.
      New-LoadBuilderPokeAction WSUS -UseShim

      # WSUS has exported updates.
      New-LoadBuilderWaitAction WSUS -UseShim

      New-LoadBuilderStopAction WSUS

      New-LoadBuilderStopAction DC

      New-LoadBuilderCustomAction WSUS -ScriptParameters @{
        Destination = Get-LoadBuilderPath Packages
      } -Script {
        $exportFolders = Get-ChildItem -LiteralPath VHD:\Export -Directory

        foreach ($exportfolder in $exportFolders) {
          $exportContent = @(
            $exportfolder |
              Get-ChildItem
          )

          if ($exportContent.Count -eq 0) {
            Write-Verbose "  - Skipped '$($exportfolder.Name)' export: no updates available for export."
            continue
          }

          $currentFolder = Join-Path -Path $ScriptParameters.Destination `
                                     -ChildPath "$($exportFolder.Name)\Updates"

          if (Test-Path -LiteralPath $currentFolder) {
            $currentContent = @(
              Get-ChildItem -LiteralPath $currentFolder
            )

            $currentLastMod = $currentContent |
                                ForEach-Object LastWriteTime |
                                Sort-Object -Descending |
                                Select-Object -First 1

            $exportLastMod = $exportContent |
                               ForEach-Object LastWriteTime |
                               Sort-Object -Descending |
                               Select-Object -First 1

            if (
              $currentContent.Count -gt 0 -and
              $currentLastMod -ge $exportLastMod
            ) {
              Write-Verbose "  - Skipped '$($exportfolder.Name)' export: No new updates."
              continue
            }

            Remove-Item -LiteralPath $currentFolder -Recurse -Force
          }

          Write-Verbose "  - Exporting '$($exportfolder.Name)' updates."
          Copy-Item -LiteralPath $exportfolder.FullName -Destination $currentFolder -Recurse
        }
      } -MountVhd 1
    )

    $result = Start-LoadBuilder -Configuration $config -Verbose

    Remove-LoadBuilderRealizedLoad -Name $config.Name

    if ($result.'Processing Status' -ne "Complete") {
      throw "An error occurred while running the Update Exporter configuration."
    }

    Write-Verbose "FINISHED office applications update exporter."
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Invoke-WRSWorkflow_VMResourceServicer {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Resources,

    [switch]
    $RebuildAll
  )
  try {
    Write-Verbose "STARTED vm-based resource servicer."

    if ($RebuildAll) {
      Write-Verbose "Rebuilding all content."
    }
    else {
      Write-Verbose "Building content only as needed."
    }

    Write-Verbose "Building LoadBuilder configuration."

    $config = New-LoadBuilderConfiguration -Name "VMResSvc"

    $config | Add-LoadBuilderMember `
    -OS "W10 v1709" `
    -VHDSizeBytes 1tb `
    -Script $script:scripts.ResourceServicer `
    -Modules @(
      "Common"
      "WindowsResourceServicer"
    ) `
    -Packages @(
      New-LoadBuilderPackage -Source (Get-LoadBuilderPath OSData) `
                             -Destination \CT\Modules\WindowsResourceServicer

      if ($RebuildAll) {
        Get-ChildItem -LiteralPath $Resources |
          Where-Object Name -in ISO,Updates |
          ForEach-Object {
            New-LoadBuilderPackage -Source $_.FullName -Destination \res
          }
      }
      else {
        Get-ChildItem -LiteralPath $Resources |
          ForEach-Object {
            New-LoadBuilderPackage -Source $_.FullName -Destination \res
          }
      }
    )

    $config | Add-LoadBuilderAction @(
      New-LoadBuilderCustomAction -Script {
        $VM | Set-VMProcessor -ExposeVirtualizationExtensions $true
      }
      New-LoadBuilderStartAction
      New-LoadBuilderWaitAction
      New-LoadBuilderStopAction

      # Custom action for replacing pre-existing resource content when I'm
      # comfortable with the reliability of this workflow.
    )

    $result = Start-LoadBuilder -Configuration $config -Verbose

    # ...after pre-existing content has been replaced.
    #Remove-LoadBuilderRealizedLoad -Name $config.Name

    if ($result.'Processing Status' -ne "Complete") {
      throw "An error occurred while running the Update Exporter configuration."
    }

    Write-Verbose "FINISHED vm-based resource servicer."

  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

Export-ModuleMember -Function Import-WRSOSData,
                              Invoke-WRSWorkflow_ISOtoWIM,
                              Invoke-WRSWorkflow_WIMPartitioning,
                              Invoke-WRSWorkflow_WIMtoVHD,
                              Invoke-WRSWorkflow_UpdateExporter,
                              Invoke-WRSWorkflow_WIMUpdating,
                              Invoke-WRSWorkflow_OfficeUpdateExporter,
                              Invoke-WRSWorkflow_VMResourceServicer