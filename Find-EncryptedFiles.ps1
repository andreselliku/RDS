#Requires -Version 4.0
<#
.SYNOPSIS
   Checks for Encrypted Files in a specified folder and logs off the offending user, when a encrypted file is found. Uses ENT.ps1 and functions.ps1. 

.DESCRIPTION
   Checks for Encrypted Files in a specified folder and logs off the offending user, when a encrypted file is found. Uses ENT.ps1 and functions.ps1.

.NOTES
   File Name: Find-EncryptedFiles.ps1
   Author   : Jaan Vahtre
   Version  : 1.0

.EXAMPLE
   Find-EncryptedFiles
#>


#In order to run the script, The necessary variables need to be entered.

function Find-EncryptedFiles () {
    
    [CmdletBinding()]
    param(
        
        [Parameter(Mandatory=$true,
        Position=0,
        HelpMessage="Specify wich folder to scan")]
        [string]
        $SearchDirectory,
        
        [Parameter(Mandatory=$false,
        Position=1,
        HelpMessage="Specify where to log sent email notifications. Defaults to current working directory.")]
        [string]
        $LogFile = $((Resolve-Path .\).Path),
        
        [Parameter(Mandatory=$false,
        Position=2,
        HelpMessage="Specify the full path to ENT tool. Defaults to current working directory.")]
        [string]
        $ENTPath = $((Resolve-Path .\).Path),
        
        [Parameter(Mandatory=$false,
        Position=3,
        HelpMessage = "Specify the path where to place log files. Defaults to current working directory")]
        [string]
        $LogPath = $((Resolve-Path .\).Path),
        
        [Parameter(Mandatory=$false,
        Position=4,
        HelpMessage="Specify the full path to helper functions script. Defaults to current working directory.")]
        [string]
        $FuncPath = $((Resolve-Path .\).Path),
        
        [Parameter(Mandatory=$false,
        Position=4,
        HelpMessage="Set Whether Users are disconnected or not when encryption is found.")]
        [bool]
        $Disconnect = $False,
        
        [Parameter(Mandatory=$false,
        Position=5,
        HelpMessage="Set Whether the algorithm will be evaluated")]
        [bool]
        $EvaluateEntropy = $False,
        
        [Parameter(Mandatory=$false,
        Position=6,
        HelpMessage="Set Whether the algorithm will be evaluated")]
        [bool]
        $EvaluateChi = $False,
        
        [Parameter(Mandatory=$false,
        Position=7,
        HelpMessage="Set Whether the algorithm will be evaluated")]
        [bool]
        $EvaluateMean = $False,
        
        [Parameter(Mandatory=$false,
        Position=8,
        HelpMessage="Set Whether the algorithm will be evaluated")]
        [bool]
        $EvaluateSerial = $False,
        
        [Parameter(Mandatory=$false,
        Position=9,
        HelpMessage="Set Whether the algorithm will be evaluated")]
        [bool]
        $EvaluateMonte = $False,
        
        [Parameter(Mandatory=$false,
        Position=10,
        HelpMessage="Set the Fileshare name, from which the User will be disconnected. If not specified, the user will be disconnected from every share.")]
        [string]
        $FileShareName
    )
 
    #Import helper functions and ENT Program. Expects both to be in the same working directory
    . $FuncPath\functions.ps1
    . $ENTPath\ENT.ps1

    #Set the Variables

    #SentMail LogFile
    #$Logfile = "PATHTO\SentMail.log"

    #First Define the Search Directory
    #$SearchDirectory = "PATHTOSEARCHDIRECTORY"

    #Setup the Path where ENT tool is located.
    #$Path = "PATHTOENTTOOLLOCATION" 

    #Setup where the .csv output will be sent and read.
    $Data = "$LogPath\Data.txt"

    #Setup the path of Encrypted files log.
    $Crypt = "$LogPath\Crypted.txt"

    #Setup the path of Clean files log.
    $Clean = "$LogPath\Clean.txt"

    #Setup the path for SMB Logs.
    $SMBLog = "$LogPath\Log.txt"

    #Setup the FileNames of suspicious files log.
    $EntropyData = "$LogPath\EntropyHit.xlsx"
    $MeanData = "$LogPath\MeanHit.xlsx"
    $ChiData = "$LogPath\ChiHit.xlsx"
    $SerialData = "$LogPath\SerialHit.xlsx"
    $MonteData = "$LogPath\MonteHit.xlsx"

    #Setup the FileNames of Clean files log.
    $EntropyCleanData = "$LogPath\CleanEntropy.xlsx"
    $MeanCleanData = "$LogPath\CleanMean.xlsx"
    $ChiCleanData = "$LogPath\CleanChi.xlsx"
    $SerialCleanData = "$LogPath\CleanSerial.xlsx"
    $MonteCleanData = "$LogPath\CleanMonte.xlsx"


    #Excluded Files list. 
    $ExcludedFileCount = 0
    $ExcludedFiles=@("")

    #Set Whether Users are disconnected or not when encryption is found.
    #$Disconnect = $False

    #Set Whether the algorithm will be evaluated
    #$EvaluateEntropy = $False
    #$EvaluateChi = $False
    #$EvaluateMean = $False
    #$EvaluateSerial = $False
    #$EvaluateMonte = $False

    #Set the Fileshare name, from which the User will be disconnected. If not specified, the user will be disconnected from every share. 
    #$FileShareName = "FILESHARENAME"


    #Set the Encrypted Values for entropy, chi-square, Monte, Serial Correlation and Mean. Optimize in order to get better results, 
    $EncryptedEntropy = 7.986000
    $EncryptedChi = 690
    $EncryptedMean = 127.5
    $LowestEncryptedMean = 127.3
    $HighestEncryptedMean = 127.7
    $LowestEncryptedMonte = 3.12
    $HighestEncryptedMonte = 3.16
    $EncryptedMonte = 3.14
    $EncryptedSerial = 0.001200

    #Start finding the Encrypted Files. The timeout is 1440 minutes, but can be adjusted accordingly. 
    #In addition, it's possible to add a task scheduler script to activate it in Every 1440 Minutes.

    $timeout = new-timespan -Minutes 1440
    $sw = [diagnostics.stopwatch]::StartNew()

    while ($sw.elapsed -lt $timeout){
        FindEncrypted
        start-sleep -seconds 5
    }
    write-host "Program Closed"

}