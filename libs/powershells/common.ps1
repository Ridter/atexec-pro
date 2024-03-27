function ConvertTo-Base64($byteArray) {
    [System.Convert]::ToBase64String($byteArray)
}

function ConvertFrom-Base64($base64String) {
    [System.Convert]::FromBase64String($base64String)
}

function Encrypt-Data($key, $data) {
    $aesManaged = New-Object System.Security.Cryptography.AesManaged
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.Key = $key
    $aesManaged.GenerateIV()
    $encryptor = $aesManaged.CreateEncryptor()
    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    $encryptedData = $encryptor.TransformFinalBlock($utf8Bytes, 0, $utf8Bytes.Length)
    $combinedData = $aesManaged.IV + $encryptedData
    return ConvertTo-Base64 $combinedData
}

function Decrypt-Data($key, $encryptedData) {
    $aesManaged = New-Object System.Security.Cryptography.AesManaged
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $combinedData = ConvertFrom-Base64 $encryptedData
    $aesManaged.IV = $combinedData[0..15]
    $aesManaged.Key = $key
    $decryptor = $aesManaged.CreateDecryptor()
    $encryptedDataBytes = $combinedData[16..$combinedData.Length]
    $decryptedDataBytes = $decryptor.TransformFinalBlock($encryptedDataBytes, 0, $encryptedDataBytes.Length)
    return [System.Text.Encoding]::UTF8.GetString($decryptedDataBytes)
}