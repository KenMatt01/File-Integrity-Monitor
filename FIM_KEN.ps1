# At the beginning of the script, import the required modules
Import-Module -Name PowerShellGet -ErrorAction SilentlyContinue
Import-Module -Name PSReadLine -ErrorAction SilentlyContinue

# Define $fileHashDictionary outside the function to keep its state between function calls
$fileHashDictionary = @{}

Function Calculate-File-Hash {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$FilePath,
        [string]$Algorithm = "SHA512"
    )

    $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm
    return $hash
}

Function Erase-Baseline-If-Already-Exists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$BaselineFilePath = "C:\Users\mathe\Desktop\FYP\test_files\"
    )

    if (Test-Path -Path $BaselineFilePath) {
        # Delete the baseline file
        Remove-Item -Path $BaselineFilePath -ErrorAction SilentlyContinue
    }
}

Function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$LogFilePath = "C:\Users\mathe\Desktop\FYP\log.txt"
    )

    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    $logMessage | Out-File -FilePath $LogFilePath -Append
}

Function Send-EmailNotification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Recipient,
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        [Parameter(Mandatory = $true)]
        [string]$Body,
        [string]$AttachmentPath
    )

    $smtpServer = "smtp.gmail.com"
    $smtpPort = 587
    $smtpUsername = "smtptest@gmail.com"
    $smtpPassword = "**************"

    $smtpParams = @{
        SmtpServer = $smtpServer
        Port = $smtpPort
        UseSsl = $true
        Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $smtpUsername, (ConvertTo-SecureString -String $smtpPassword -AsPlainText -Force)
    }

    # Check if the AttachmentPath is provided and not empty
    if ($AttachmentPath -and (Test-Path $AttachmentPath)) {
        # Send email with attachment
        Send-MailMessage -From $smtpUsername -To $Recipient -Subject $Subject -Body $Body -Attachments $AttachmentPath @smtpParams
    } else {
        # Send email without attachment
        Send-MailMessage -From $smtpUsername -To $Recipient -Subject $Subject -Body $Body @smtpParams
    }
}

Function Generate-Report {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ReportFilePath = "C:\Users\mathe\Desktop\FYP\report.txt"
    )

    # Generate the report content
    $reportContent = @"
File Monitoring Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

File Paths and Hashes:
$($fileHashDictionary.GetEnumerator() | ForEach-Object {
    $_.Key + " | " + $_.Value
} | Out-String)
"@

    # Write the report to a temporary file
    $tempReportFile = "C:\Users\mathe\Desktop\FYP\temp_report.txt"
    $reportContent | Out-File -FilePath $tempReportFile -Force

    # Send email only if there are new alerts
    if ($fileAlerts.Count -gt 0) {
        # Combine alerts and report content for the email body
        $emailBody = $fileAlerts -join "`r`n"
        $emailBody += "`r`n`r`n$($reportContent)"

        # Send the combined email with the report
        Send-EmailNotification -Recipient "kenmattr34@gmail.com" -Subject "File Monitoring Report and Alerts" -Body $emailBody -AttachmentPath $tempReportFile
    }

    # Remove the temporary report file
    Remove-Item -Path $tempReportFile -ErrorAction SilentlyContinue
}

Function Monitor-Files {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$BaselineFilePath = "C:\Users\mathe\Desktop\FYP\baseline.txt",
        [int]$PollingInterval = 1
    )

    # Clear the fileHashDictionary at the beginning of each monitoring cycle
    $fileHashDictionary.Clear()

    # Initialize the fileAlerts array to store log messages
    $fileAlerts = @()

    $filesFolderPath = "C:\Users\mathe\Desktop\FYP\test_files"

    # Load file|hash from baseline.txt and store them in a dictionary
    $filePathsAndHashes = Get-Content -Path $BaselineFilePath -ErrorAction SilentlyContinue
    
    if ($filePathsAndHashes) {
        foreach ($f in $filePathsAndHashes) {
            $fileHashDictionary[$f.Split("|")[0]] = $f.Split("|")[1]
        }
    }

    $reportGenerated = $false

    Write-Host "File monitoring started. Press Ctrl+C to stop monitoring."

    while ($true) {
        # Reset fileAlerts array for each monitoring cycle
        $fileAlerts = @()

        $files = Get-ChildItem -Path $filesFolderPath

        # Create lists to hold alerts and deleted files
        $fileAlerts = @()
        $deletedFiles = @()

        foreach ($f in $files) {
            $hash = Calculate-File-Hash -FilePath $f.FullName

            # Notify if a new file has been created
            if (-not $fileHashDictionary.ContainsKey($hash.Path)) {
                # A new file has been created!
                $fileAlerts += "$($hash.Path) has been created!"
                Write-Host $fileAlerts[-1] -ForegroundColor Green
                Write-Log -Message $fileAlerts[-1]
            }
            else {
                # Notify if a file has changed
                if ($fileHashDictionary[$hash.Path] -ne $hash.Hash) {
                    # The file has changed!
                    $fileAlerts += "$($hash.Path) has changed!!!"
                    Write-Host $fileAlerts[-1] -ForegroundColor Yellow
                    Write-Log -Message $fileAlerts[-1]
                }
            }

            # Update the file hash in the dictionary
            $fileHashDictionary[$hash.Path] = $hash.Hash
        }

        # Check if any baseline files have been deleted
        foreach ($key in $fileHashDictionary.Keys) {
            $baselineFileStillExists = Test-Path -Path $key -PathType Leaf
            if (-not $baselineFileStillExists) {
                # One of the baseline files has been deleted, add it to the list for removal
                $deletedFiles += $key
                $fileAlerts += "$($key) has been deleted!"
                Write-Host $fileAlerts[-1] -ForegroundColor Red
                Write-Log -Message $fileAlerts[-1]
            }
        }

        # Remove deleted files from the dictionary outside the foreach loop
        foreach ($deletedFile in $deletedFiles) {
            $fileHashDictionary.Remove($deletedFile)
        }


        if ($fileAlerts.Count -gt 0) {
            # There are file changes or deletions, generate the report content
            $reportContent = @"
File Monitoring Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

File Paths and Hashes:
$($fileHashDictionary.GetEnumerator() | ForEach-Object {
    $_.Key + " | " + $_.Value
} | Out-String)

"@

             # Generate the report
            Generate-Report -ReportFilePath "C:\Users\mathe\Desktop\FYP\report.txt"

            # Combine alerts and report content for the email body
            $emailBody = $fileAlerts -join "`r`n"
            $emailBody += "`r`n`r`n$($reportContent)"

            # Send the combined email with the report
            Send-EmailNotification -Recipient "kenmattr34@gmail.com" -Subject "File Monitoring Report and Alerts" -Body $emailBody -AttachmentPath "C:\Users\mathe\Desktop\FYP\report.txt"

            # Set the flag to indicate that the report has been generated and sent
            $reportGenerated = $true
        }
        else {
            # No file changes or deletions, reset the report flag
            $reportGenerated = $false
        }

        # Wait for the polling interval before the next monitoring cycle
        Start-Sleep -Seconds $PollingInterval
    }
}


# Entry point
$baselineFilePath = "C:\Users\mathe\Desktop\FYP\baseline.txt"
$logFilePath = "C:\Users\mathe\Desktop\FYP\log.txt"

Write-Host ""
Write-Host "What would you like to do?"
Write-Host ""
Write-Host "    A) Collect new Baseline?"
Write-Host "    B) Begin monitoring files with saved Baseline?"
Write-Host ""
$response = Read-Host -Prompt "Please enter 'A' or 'B'"
Write-Host ""

if ($response -eq "A") {
    # Delete baseline.txt if it already exists
    Erase-Baseline-If-Already-Exists -BaselineFilePath $baselineFilePath

    # Calculate Hash from the target files and store in baseline.txt
    # Collect all files in the target folder
    $files = Get-ChildItem -Path C:\Users\mathe\Desktop\FYP\test_files

    # For each file, calculate the hash, and write to baseline.txt
    foreach ($f in $files) {
        $hash = Calculate-File-Hash -FilePath $f.FullName
        "$($hash.Path)|$($hash.Hash)" | Out-File -FilePath $baselineFilePath -Append
    }
}
elseif ($response -eq "B") {
    Monitor-Files -BaselineFilePath $baselineFilePath

    # Monitor files with saved Baseline
}
