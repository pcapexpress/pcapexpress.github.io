# --- 01.W4LLPEPP3R Proof of Concept ---

# 1. Define the remote URL and local path
$url = "https://pcapexpress.github.io/assets/boiler/W4LLPEPP3R.png"
$localPath = "$env:TEMP\bg_update.jpg"

# 2. Download the "Payload" (The Image)
Invoke-WebRequest -Uri $url -OutFile $localPath

# 3. Modify the Registry to set the new wallpaper
$code = @'
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@

Add-Type -TypeDefinition $code

# 4. Apply the change (Set wallpaper and refresh)
# 0x0014 is the SPI_SETDESKWALLPAPER action
# 0x01 | 0x02 tells Windows to update the profile and broadcast the change
[Wallpaper]::SystemParametersInfo(0x0014, 0, $localPath, 0x01 -bor 0x02)

Write-Host "Desktop environment updated successfully." -ForegroundColor Green
