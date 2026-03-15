# --- CRYP7L4D Recovery Tool ---

# 1. Input the captured credentials from your Attack Box
$Base64Key = "PASTE_YOUR_KEY_HERE"
$Base64IV  = "PASTE_YOUR_IV_HERE"
$TargetFolder = "$home\Desktop\Financials"

if (Test-Path $TargetFolder) {
    # 2. Reconstruct the AES Key and IV
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = [Convert]::FromBase64String($Base64Key)
    $Aes.IV  = [Convert]::FromBase64String($Base64IV)

    # 3. Find all encrypted files
    $EncryptedFiles = Get-ChildItem $TargetFolder -Filter "*.cryp7"

    foreach ($File in $EncryptedFiles) {
        Write-Host "Restoring: $($File.Name)" -ForegroundColor Cyan
        
        $Bytes = [System.IO.File]::ReadAllBytes($File.FullName)
        $Decryptor = $Aes.CreateDecryptor()
        
        try {
            $DecryptedBytes = $Decryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
            
            # 4. Restore original file and remove .cryp7 extension
            $OriginalName = $File.FullName.Replace(".cryp7", "")
            [System.IO.File]::WriteAllBytes($OriginalName, $DecryptedBytes)
            
            # Remove the encrypted version
            Remove-Item $File.FullName
        } catch {
            Write-Host "Failed to decrypt $($File.Name). Key/IV mismatch." -ForegroundColor Red
        }
    }
    
    # 5. Clean up the ransom note
    if (Test-Path "$home\Desktop\DECRYPT_INFO.txt") {
        Remove-Item "$home\Desktop\DECRYPT_INFO.txt"
    }
    
    Write-Host "Data Recovery Complete." -ForegroundColor Green
}
